package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
)

var (
	_ Tun       = (*Joiner)(nil)
	_ io.Closer = (*Joiner)(nil)
)

const (
	joinerOffset       = 256
	joinerDefaultMTU   = 1500
	joinerDefaultBatch = 256
	joinerMaxPacket    = 64 << 10
)

var (
	// ErrJoinerClosed is returned after Joiner is closed.
	ErrJoinerClosed = errors.Join(
		os.ErrClosed,
		errors.New("tun: joiner closed"),
	)

	// ErrJoinerSmallOffset is returned when Joiner.Read or Joiner.Write is
	// called with an offset smaller than Joiner's MRO/MWO.
	ErrJoinerSmallOffset = errors.New("tun: joiner offset is too small")

	// ErrJoinerDuplicateTun is returned when a Tun is attached more than once
	// or attached both as the default and as a secondary Tun.
	ErrJoinerDuplicateTun = errors.New("tun: joiner duplicate nested tun")

	// ErrJoinerNilTun is returned when attaching a nil Tun.
	ErrJoinerNilTun = errors.New("tun: joiner nil nested tun")
)

type joinerNested struct {
	t Tun

	mu     sync.Mutex
	up     bool
	closed bool
	cond   *sync.Cond
}

type joinerPending struct {
	packet []byte
	owner  *joinerNested
	pool   bufpool.Pool
}

type joinerRouteBatch struct {
	targets []*joinerNested
	pool    *sync.Pool
}

func (batch *joinerRouteBatch) release() {
	clear(batch.targets)
	batch.targets = batch.targets[:0]
	batch.pool.Put(batch)
}

// Joiner combines several nested Tuns into one virtual Tun.
//
// Packets read from nested Tuns are emitted by Joiner.Read as a single outgoing
// stream. Joiner learns IPv4 and IPv6 source addresses from those outgoing
// packets and later routes Joiner.Write packets to the nested Tun associated
// with their destination address. Packets with unknown or malformed
// destinations are routed to the current default Tun; if no default is
// attached, they are dropped.
//
// NewJoinerWithOptions can enable shared-address routing. That mode first uses
// bounded, expiring TCP, UDP, ICMP echo, and fragment routes. It then uses the
// address and default routes as fallbacks.
//
// Detaching a nested Tun closes it. This is intentional: Tun has no deadline or
// context parameter, so Close is the only portable way to unblock pending
// nested Read or Write calls.
type Joiner struct {
	mu           sync.Mutex
	closed       bool
	done         chan struct{}
	events       chan Event
	eventMu      sync.RWMutex
	eventClosed  bool
	reads        chan detachedTunRead
	writes       chan *detachedTunWrite
	pending      []joinerPending
	pendingHead  int
	defaultTun   *joinerNested
	secondaries  map[Tun]*joinerNested
	nested       map[Tun]*joinerNested
	routes4      map[uint32]*joinerNested
	routes6      map[[16]byte]*joinerNested
	flowRouting  bool
	flowTimeout  time.Duration
	flowLimit    int
	flows        map[joinerFlowKey]*joinerDynamicRoute
	fragments    map[joinerFragmentKey]*joinerDynamicRoute
	dynamicHead  *joinerDynamicRoute
	dynamicTail  *joinerDynamicRoute
	dynamicFree  *joinerDynamicRoute
	dynamicSize  int
	routeStats   JoinerRoutingStats
	now          func() time.Time
	readBatches  sync.Pool
	writeBatches sync.Pool
	mtu          int
	batch        int
	once         sync.Once
	pool         bufpool.Pool
	spawner      gonnect.Spawner
	wg           sync.WaitGroup
}

// NewJoiner creates an empty Joiner.
func NewJoiner(
	spawner gonnect.Spawner,
	pool bufpool.Pool,
) *Joiner {
	return NewJoinerWithOptions(spawner, pool, JoinerOptions{})
}

// NewJoinerWithOptions creates an empty Joiner with the specified routing
// options. Zero timeout and table limit values select safe defaults.
func NewJoinerWithOptions(
	spawner gonnect.Spawner,
	pool bufpool.Pool,
	options JoinerOptions,
) *Joiner {
	flowTimeout, flowLimit := normalizeJoinerOptions(options)
	j := &Joiner{
		done:        make(chan struct{}),
		events:      make(chan Event, 8),
		reads:       make(chan detachedTunRead, channelBufferSize()),
		writes:      make(chan *detachedTunWrite, channelBufferSize()),
		secondaries: make(map[Tun]*joinerNested),
		nested:      make(map[Tun]*joinerNested),
		routes4:     make(map[uint32]*joinerNested),
		routes6:     make(map[[16]byte]*joinerNested),
		flowRouting: options.SharedAddressRouting,
		flowTimeout: flowTimeout,
		flowLimit:   flowLimit,
		flows:       make(map[joinerFlowKey]*joinerDynamicRoute),
		fragments:   make(map[joinerFragmentKey]*joinerDynamicRoute),
		now:         time.Now,
		mtu:         joinerDefaultMTU,
		batch:       joinerDefaultBatch,
		pool:        pool,
		spawner:     spawner,
	}
	if err := spawnWg(
		spawner,
		j.writePump,
		&j.wg,
		"tun.Joiner.writePump",
	); err != nil {
		j.closed = true
		close(j.done)
		j.closeEvents()
		return j
	}
	return j
}

// AttachDefault attaches t as the default nested Tun. If another default Tun is
// already attached, it is detached and closed first.
func (j *Joiner) AttachDefault(t Tun) error {
	if t == nil {
		return ErrJoinerNilTun
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return ErrJoinerClosed
	}
	if _, ok := j.secondaries[t]; ok {
		j.mu.Unlock()
		return ErrJoinerDuplicateTun
	}
	if j.defaultTun != nil && j.defaultTun.t == t {
		j.mu.Unlock()
		return nil
	}
	old := j.defaultTun
	if old != nil {
		j.removeNestedLocked(old)
	}
	n := newJoinerNested(t)
	j.defaultTun = n
	j.nested[t] = n
	j.recalculateLocked()
	j.mu.Unlock()

	if old != nil {
		_ = old.t.Close()
	}
	return j.startNested(n)
}

// AttachSecondary attaches t as a non-default nested Tun.
func (j *Joiner) AttachSecondary(t Tun) error {
	if t == nil {
		return ErrJoinerNilTun
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return ErrJoinerClosed
	}
	if j.defaultTun != nil && j.defaultTun.t == t {
		j.mu.Unlock()
		return ErrJoinerDuplicateTun
	}
	if _, ok := j.secondaries[t]; ok {
		j.mu.Unlock()
		return nil
	}
	n := newJoinerNested(t)
	j.secondaries[t] = n
	j.nested[t] = n
	j.recalculateLocked()
	j.mu.Unlock()

	return j.startNested(n)
}

// Detach detaches and closes t if it is currently attached.
func (j *Joiner) Detach(t Tun) error {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return ErrJoinerClosed
	}
	n := j.nested[t]
	if n != nil {
		j.removeNestedLocked(n)
		j.recalculateLocked()
	}
	j.mu.Unlock()
	if n != nil {
		_ = n.t.Close()
	}
	return nil
}

// DetachDefault detaches and closes the current default Tun, if any.
func (j *Joiner) DetachDefault() error {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return ErrJoinerClosed
	}
	n := j.defaultTun
	if n != nil {
		j.removeNestedLocked(n)
		j.recalculateLocked()
	}
	j.mu.Unlock()
	if n != nil {
		_ = n.t.Close()
	}
	return nil
}

func newJoinerNested(t Tun) *joinerNested {
	n := &joinerNested{t: t, up: true}
	n.cond = sync.NewCond(&n.mu)
	return n
}

func (j *Joiner) File() *os.File { return nil }

func (j *Joiner) IsNative() bool { return false }

func (j *Joiner) MWO() int { return joinerOffset }

func (j *Joiner) MRO() int { return joinerOffset }

func (j *Joiner) MTU() (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0, ErrJoinerClosed
	}
	return j.mtu, nil
}

func (j *Joiner) Name() (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return "", ErrJoinerClosed
	}
	return "TunJoiner", nil
}

func (j *Joiner) Events() <-chan Event { return j.events }

func (j *Joiner) BatchSize() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.batch
}

func (j *Joiner) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < joinerOffset {
		return 0, ErrJoinerSmallOffset
	}
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	for {
		if n, err := j.readPending(bufs, sizes, offset); n > 0 || err != nil {
			return n, err
		}
		select {
		case <-j.done:
			return 0, ErrJoinerClosed
		case r := <-j.reads:
			if r.err != nil {
				if IsTunTermError(r.err) {
					return 0, r.err
				}
				continue
			}
			j.mu.Lock()
			if r.owner == nil || j.nested[r.owner.t] == r.owner {
				for _, packet := range r.bufs {
					j.pending = append(j.pending, joinerPending{
						packet: packet,
						owner:  r.owner,
						pool:   r.pool,
					})
				}
				putDetachedTunReadSlice(r)
			} else {
				releaseDetachedTunRead(r)
			}
			j.mu.Unlock()
		}
	}
}

func (j *Joiner) Write(bufs [][]byte, offset int) (int, error) {
	if offset < joinerOffset {
		return 0, ErrJoinerSmallOffset
	}
	if err := validatePacketOffset(bufs, offset); err != nil {
		return 0, err
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return 0, ErrJoinerClosed
	}
	if len(bufs) == 0 {
		j.mu.Unlock()
		return 0, nil
	}
	var now time.Time
	if j.flowRouting {
		now = j.now()
		j.expireDynamicRoutesLocked(now)
	}
	firstTarget := j.routeLocked(bufs[0], offset, now)
	var targetBatch *joinerRouteBatch
	for i, buf := range bufs {
		if i == 0 {
			continue
		}
		target := j.routeLocked(buf, offset, now)
		if targetBatch == nil && target != firstTarget {
			targetBatch = j.getRouteBatch(len(bufs))
			for previous := range i {
				targetBatch.targets[previous] = firstTarget
			}
		}
		if targetBatch != nil {
			targetBatch.targets[i] = target
		}
	}
	j.mu.Unlock()
	if targetBatch == nil {
		return len(bufs), j.writeToNested(firstTarget, bufs, offset)
	}
	defer targetBatch.release()
	for i := range bufs {
		if err := j.writeToNested(
			targetBatch.targets[i],
			bufs[i:i+1],
			offset,
		); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (j *Joiner) Close() error {
	j.once.Do(func() {
		j.mu.Lock()
		j.closed = true
		nested := make([]*joinerNested, 0, len(j.nested))
		for _, n := range j.nested {
			nested = append(nested, n)
			j.closeNestedLocked(n)
		}
		j.defaultTun = nil
		j.secondaries = nil
		j.nested = nil
		j.routes4 = nil
		j.routes6 = nil
		j.clearDynamicRoutesLocked()
		putJoinerPendingLocked(j.pending[j.pendingHead:])
		j.pending = nil
		j.pendingHead = 0
		j.recalculateLocked()
		close(j.done)
		j.closeEvents()
		j.mu.Unlock()
		for _, n := range nested {
			_ = n.t.Close()
		}
		j.wg.Wait()
		drainDetachedTunReads(j.reads)
	})
	return nil
}

func (j *Joiner) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- *detachedTunWrite,
	<-chan struct{},
	error,
) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, nil, nil, ErrJoinerClosed
	}
	return j.reads, j.writes, j.done, nil
}

func (j *Joiner) readPending(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0, ErrJoinerClosed
	}
	if j.pendingHead == len(j.pending) {
		return 0, nil
	}
	pending := j.pending[j.pendingHead:]
	n := min(len(bufs), len(sizes), len(pending))
	for i := range n {
		size := len(pending[i].packet)
		if offset > len(bufs[i]) || size > len(bufs[i])-offset {
			return i, io.ErrShortBuffer
		}
	}
	for i := range n {
		size := len(pending[i].packet)
		copy(bufs[i][offset:offset+size], pending[i].packet)
		sizes[i] = size
	}
	putJoinerPendingLocked(pending[:n])
	clear(pending[:n])
	j.pendingHead += n
	if j.pendingHead == len(j.pending) {
		j.pending = j.pending[:0]
		j.pendingHead = 0
	}
	return n, nil
}

func (j *Joiner) startNested(n *joinerNested) error {
	if err := spawnWg(j.spawner, func() {
		j.readNested(n)
	}, &j.wg, "tun.Joiner.readNested"); err != nil {
		j.detachNested(n, true)
		return err
	}
	if err := spawn(j.spawner, func() {
		j.watchNestedEvents(n)
	}, "tun.Joiner.events"); err != nil {
		j.detachNested(n, true)
		return err
	}
	return nil
}

func (j *Joiner) readNested(n *joinerNested) {
	batch := batchSizeOf(n.t)
	if batch <= 0 {
		batch = 1
	}
	offset := n.t.MRO()
	readLen := offset + joinerMaxPacket
	if readLen < offset {
		readLen = offset
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(j.pool, readLen)
	}
	defer putBuffers(j.pool, bufs)
	for {
		n.waitUp()
		if n.isClosed() {
			return
		}
		count, err := n.t.Read(bufs, sizes, offset)
		if err != nil {
			if errors.Is(err, ErrDetachedTunDown) {
				n.setUp(false)
				continue
			}
			if IsTunTermError(err) {
				j.detachNested(n, true)
				return
			}
			continue
		}
		if err := validateReadPacketSizes(
			bufs,
			sizes,
			offset,
			count,
		); err != nil {
			continue
		}
		packetBatch := j.getReadBatch(count)
		packets := packetBatch.bufs
		for i := range count {
			size := sizes[i]
			packets[i] = clonePacketBuffer(
				j.pool,
				bufs[i][offset:offset+size],
			)
		}
		j.rememberRoutes(packets, n)
		select {
		case <-j.done:
			putBuffers(j.pool, packets)
			packetBatch.release()
			return
		case j.reads <- detachedTunRead{
			bufs:      packets,
			owner:     n,
			pool:      j.pool,
			readBatch: packetBatch,
		}:
		}
	}
}

func (j *Joiner) getReadBatch(size int) *detachedTunReadBatch {
	batch, _ := j.readBatches.Get().(*detachedTunReadBatch)
	if batch == nil {
		batch = &detachedTunReadBatch{pool: &j.readBatches}
	}
	if cap(batch.bufs) < size {
		batch.bufs = make([][]byte, size)
	} else {
		batch.bufs = batch.bufs[:size]
	}
	return batch
}

func (j *Joiner) getRouteBatch(size int) *joinerRouteBatch {
	batch, _ := j.writeBatches.Get().(*joinerRouteBatch)
	if batch == nil {
		batch = &joinerRouteBatch{pool: &j.writeBatches}
	}
	if cap(batch.targets) < size {
		batch.targets = make([]*joinerNested, size)
	} else {
		batch.targets = batch.targets[:size]
	}
	return batch
}

func (j *Joiner) watchNestedEvents(n *joinerNested) {
	for event := range n.t.Events() {
		switch event {
		case EventDown:
			n.setUp(false)
		case EventUp:
			n.setUp(true)
		case EventMTUUpdate:
			j.mu.Lock()
			j.recalculateLocked()
			j.mu.Unlock()
		}
	}
	j.detachNested(n, false)
}

func (n *joinerNested) waitUp() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for !n.up && !n.closed {
		n.cond.Wait()
	}
}

func (n *joinerNested) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func (n *joinerNested) setUp(up bool) {
	n.mu.Lock()
	n.up = up
	n.cond.Broadcast()
	n.mu.Unlock()
}

func (j *Joiner) writePump() {
	for {
		select {
		case <-j.done:
			drainDetachedTunWrites(j.writes, ErrJoinerClosed)
			return
		case req := <-j.writes:
			bufs, ok := req.take()
			if !ok {
				continue
			}
			n, err := j.Write(bufs, req.offset)
			req.release()
			req.respond(n, err)
		}
	}
}

func (j *Joiner) route(buf []byte, offset int) *joinerNested {
	j.mu.Lock()
	defer j.mu.Unlock()
	var now time.Time
	if j.flowRouting {
		now = j.now()
		j.expireDynamicRoutesLocked(now)
	}
	return j.routeLocked(buf, offset, now)
}

func (j *Joiner) routeLocked(
	buf []byte,
	offset int,
	now time.Time,
) *joinerNested {
	if j.flowRouting {
		return j.routeSharedAddressLocked(buf, offset, now)
	}
	if n := j.packetDestinationRouteLocked(buf, offset); n != nil {
		return n
	}
	return j.defaultTun
}

func (j *Joiner) rememberRoute(packet []byte, n *joinerNested) {
	var now time.Time
	if j.flowRouting {
		now = j.now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.nested[n.t] != n {
		return
	}
	if j.flowRouting {
		j.expireDynamicRoutesLocked(now)
	}
	j.rememberRouteLocked(packet, n, now)
}

func (j *Joiner) rememberRoutes(packets [][]byte, n *joinerNested) {
	var now time.Time
	if j.flowRouting {
		now = j.now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.nested[n.t] != n {
		return
	}
	if j.flowRouting {
		j.expireDynamicRoutesLocked(now)
	}
	for _, packet := range packets {
		j.rememberRouteLocked(packet, n, now)
	}
}

func (j *Joiner) rememberRouteLocked(
	packet []byte,
	n *joinerNested,
	now time.Time,
) {
	if j.flowRouting {
		if parsed, ok := parseJoinerPacket(packet, 0); ok {
			j.rememberParsedSourceRouteLocked(parsed, n)
			if flowKey, hasFlow := joinerReverseFlowKey(parsed); hasFlow {
				j.rememberFlowLocked(flowKey, n, now)
			}
			return
		}
	}
	j.rememberPacketSourceRouteLocked(packet, 0, n)
}

func (j *Joiner) parsedDestinationRouteLocked(
	packet joinerPacket,
) *joinerNested {
	switch packet.version {
	case 4:
		return j.routes4[binary.BigEndian.Uint32(packet.destination[:4])]
	case 6:
		return j.routes6[packet.destination]
	default:
		return nil
	}
}

func (j *Joiner) packetDestinationRouteLocked(
	buf []byte,
	offset int,
) *joinerNested {
	if offset < 0 || offset >= len(buf) {
		return nil
	}
	packet := buf[offset:]
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			return j.routes4[binary.BigEndian.Uint32(packet[16:20])]
		}
	case 6:
		if len(packet) >= 40 {
			var address [16]byte
			copy(address[:], packet[24:40])
			return j.routes6[address]
		}
	}
	return nil
}

func (j *Joiner) rememberParsedSourceRouteLocked(
	packet joinerPacket,
	owner *joinerNested,
) {
	switch packet.version {
	case 4:
		j.routes4[binary.BigEndian.Uint32(packet.source[:4])] = owner
	case 6:
		j.routes6[packet.source] = owner
	}
}

func (j *Joiner) rememberPacketSourceRouteLocked(
	buf []byte,
	offset int,
	owner *joinerNested,
) {
	if offset < 0 || offset >= len(buf) {
		return
	}
	packet := buf[offset:]
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			j.routes4[binary.BigEndian.Uint32(packet[12:16])] = owner
		}
	case 6:
		if len(packet) >= 40 {
			var address [16]byte
			copy(address[:], packet[8:24])
			j.routes6[address] = owner
		}
	}
}

func (j *Joiner) writeToNested(
	n *joinerNested,
	bufs [][]byte,
	offset int,
) error {
	if n == nil || !n.acceptsWrites() {
		return nil
	}
	writeBufs, writeOffset, mustRelease := alignWriteOffset(
		j.pool,
		bufs,
		offset,
		n.t.MWO(),
	)
	if mustRelease {
		defer putBuffers(j.pool, writeBufs)
	}
	for written := 0; written < len(writeBufs); {
		end := min(written+batchSizeOf(n.t), len(writeBufs))
		count, err := n.t.Write(writeBufs[written:end], writeOffset)
		if err != nil {
			if errors.Is(err, ErrDetachedTunDown) {
				n.setUp(false)
				return nil
			}
			if IsTunTermError(err) {
				j.detachNested(n, true)
			}
			return err
		}
		if count <= 0 {
			return errWriteNoProgress
		}
		written += count
	}
	return nil
}

func (n *joinerNested) acceptsWrites() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up && !n.closed
}

func alignWriteOffset(
	pool bufpool.Pool,
	bufs [][]byte,
	offset int,
	nestedOffset int,
) ([][]byte, int, bool) {
	if nestedOffset <= offset {
		return bufs, offset, false
	}
	out := make([][]byte, len(bufs))
	for i := range bufs {
		size := 0
		if offset < len(bufs[i]) {
			size = len(bufs[i]) - offset
		}
		out[i] = bufpool.GetBuffer(pool, nestedOffset+size)
		if size > 0 {
			copy(out[i][nestedOffset:], bufs[i][offset:])
		}
	}
	return out, nestedOffset, true
}

func (j *Joiner) detachNested(n *joinerNested, closeTun bool) {
	j.mu.Lock()
	if j.nested[n.t] != n {
		j.mu.Unlock()
		return
	}
	j.removeNestedLocked(n)
	j.recalculateLocked()
	j.mu.Unlock()
	if closeTun {
		_ = n.t.Close()
	}
}

func (j *Joiner) removeNestedLocked(n *joinerNested) {
	if j.defaultTun == n {
		j.defaultTun = nil
	}
	delete(j.secondaries, n.t)
	delete(j.nested, n.t)
	for key, owner := range j.routes4 {
		if owner == n {
			delete(j.routes4, key)
		}
	}
	for key, owner := range j.routes6 {
		if owner == n {
			delete(j.routes6, key)
		}
	}
	j.removeDynamicRoutesForOwnerLocked(n)
	pending := j.pending[:0]
	for _, packet := range j.pending[j.pendingHead:] {
		if packet.owner != n {
			pending = append(pending, packet)
		} else {
			bufpool.PutBuffer(packet.pool, packet.packet)
		}
	}
	j.pending = pending
	j.pendingHead = 0
	j.closeNestedLocked(n)
}

func putJoinerPendingLocked(pending []joinerPending) {
	for _, packet := range pending {
		bufpool.PutBuffer(packet.pool, packet.packet)
	}
}

func (j *Joiner) closeNestedLocked(n *joinerNested) {
	n.mu.Lock()
	n.closed = true
	n.up = false
	n.cond.Broadcast()
	n.mu.Unlock()
}

func (j *Joiner) recalculateLocked() {
	oldMTU := j.mtu
	j.mtu = joinerDefaultMTU
	j.batch = joinerDefaultBatch
	if len(j.nested) > 0 { //nolint
		first := true
		for _, n := range j.nested {
			if mtu, err := n.t.MTU(); err == nil {
				if first || mtu < j.mtu {
					j.mtu = mtu
				}
			}
			if batch := n.t.BatchSize(); batch > 0 {
				if first || batch > j.batch {
					j.batch = batch
				}
			}
			first = false
		}
		if first {
			j.mtu = joinerDefaultMTU
			j.batch = joinerDefaultBatch
		}
	}
	if oldMTU != j.mtu {
		j.sendEvent(EventMTUUpdate)
	}
}

func (j *Joiner) sendEvent(event Event) {
	j.eventMu.RLock()
	defer j.eventMu.RUnlock()
	if j.eventClosed {
		return
	}
	select {
	case j.events <- event:
	default:
	}
}

func (j *Joiner) closeEvents() {
	j.eventMu.Lock()
	defer j.eventMu.Unlock()
	if j.eventClosed {
		return
	}
	j.eventClosed = true
	close(j.events)
}

type joinerAddressKey struct {
	address [16]byte
	version uint8
}

func (key joinerAddressKey) valid() bool {
	return key.version != 0
}

func packetSrcKey(buf []byte, offset int) joinerAddressKey {
	if offset < 0 || offset >= len(buf) {
		return joinerAddressKey{}
	}
	p := buf[offset:]
	if len(p) < 1 {
		return joinerAddressKey{}
	}
	var key joinerAddressKey
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return joinerAddressKey{}
		}
		key.version = 4
		copy(key.address[:4], p[12:16])
	case 6:
		if len(p) < 40 {
			return joinerAddressKey{}
		}
		key.version = 6
		copy(key.address[:], p[8:24])
	default:
		return joinerAddressKey{}
	}
	return key
}

func packetDstKey(buf []byte, offset int) joinerAddressKey {
	if offset < 0 || offset >= len(buf) {
		return joinerAddressKey{}
	}
	p := buf[offset:]
	if len(p) < 1 {
		return joinerAddressKey{}
	}
	var key joinerAddressKey
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return joinerAddressKey{}
		}
		key.version = 4
		copy(key.address[:4], p[16:20])
	case 6:
		if len(p) < 40 {
			return joinerAddressKey{}
		}
		key.version = 6
		copy(key.address[:], p[24:40])
	default:
		return joinerAddressKey{}
	}
	return key
}
