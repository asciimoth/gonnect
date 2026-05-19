package tun

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/asciimoth/bufpool"
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

// Joiner combines several nested Tuns into one virtual Tun.
//
// Packets read from nested Tuns are emitted by Joiner.Read as a single outgoing
// stream. Joiner learns IPv4 and IPv6 source addresses from those outgoing
// packets and later routes Joiner.Write packets to the nested Tun associated
// with their destination address. Packets with unknown or malformed
// destinations are routed to the current default Tun; if no default is
// attached, they are dropped.
//
// Detaching a nested Tun closes it. This is intentional: Tun has no deadline or
// context parameter, so Close is the only portable way to unblock pending
// nested Read or Write calls.
type Joiner struct {
	mu          sync.Mutex
	closed      bool
	done        chan struct{}
	events      chan Event
	eventMu     sync.RWMutex
	eventClosed bool
	reads       chan detachedTunRead
	writes      chan detachedTunWrite
	pending     []joinerPending
	defaultTun  *joinerNested
	secondaries map[Tun]*joinerNested
	nested      map[Tun]*joinerNested
	routes      map[string]*joinerNested
	mtu         int
	batch       int
	once        sync.Once
	pool        bufpool.Pool
	wg          sync.WaitGroup
}

// NewJoiner creates an empty Joiner.
func NewJoiner(pools ...bufpool.Pool) *Joiner {
	pool := optionalPool(pools)
	j := &Joiner{
		done:        make(chan struct{}),
		events:      make(chan Event, 8),
		reads:       make(chan detachedTunRead, channelBufferSize()),
		writes:      make(chan detachedTunWrite, channelBufferSize()),
		secondaries: make(map[Tun]*joinerNested),
		nested:      make(map[Tun]*joinerNested),
		routes:      make(map[string]*joinerNested),
		mtu:         joinerDefaultMTU,
		batch:       joinerDefaultBatch,
		pool:        pool,
	}
	j.wg.Go(j.writePump)
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
	j.startNested(n)
	return nil
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

	j.startNested(n)
	return nil
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
			} else {
				putBuffers(r.pool, r.bufs)
			}
			j.mu.Unlock()
		}
	}
}

func (j *Joiner) Write(bufs [][]byte, offset int) (int, error) {
	if offset < joinerOffset {
		return 0, ErrJoinerSmallOffset
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return 0, ErrJoinerClosed
	}
	j.mu.Unlock()
	if len(bufs) == 0 {
		return 0, nil
	}

	targets := make([]*joinerNested, len(bufs))
	same := true
	for i := range bufs {
		targets[i] = j.route(bufs[i], offset)
		if i > 0 && targets[i] != targets[0] {
			same = false
		}
	}
	if same {
		return len(bufs), j.writeToNested(targets[0], bufs, offset)
	}
	for i := range bufs {
		if err := j.writeToNested(targets[i], bufs[i:i+1], offset); err != nil {
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
		j.secondaries = make(map[Tun]*joinerNested)
		j.nested = make(map[Tun]*joinerNested)
		j.routes = make(map[string]*joinerNested)
		putJoinerPendingLocked(j.pending)
		j.pending = nil
		j.recalculateLocked()
		close(j.done)
		j.closeEvents()
		j.mu.Unlock()
		for _, n := range nested {
			_ = n.t.Close()
		}
		j.wg.Wait()
	})
	return nil
}

func (j *Joiner) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- detachedTunWrite,
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
	if len(j.pending) == 0 {
		return 0, nil
	}
	n := min(len(bufs), len(sizes), len(j.pending))
	for i := range n {
		if offset > len(bufs[i]) {
			return i, errors.New("tun: joiner read offset beyond buffer")
		}
	}
	for i := range n {
		sizes[i] = copy(bufs[i][offset:], j.pending[i].packet)
	}
	putJoinerPendingLocked(j.pending[:n])
	j.pending = j.pending[n:]
	return n, nil
}

func (j *Joiner) startNested(n *joinerNested) {
	j.wg.Go(func() { j.readNested(n) })
	go j.watchNestedEvents(n)
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
		packets := make([][]byte, count)
		for i := range count {
			size := 0
			if len(bufs[i]) > offset {
				size = min(sizes[i], len(bufs[i])-offset)
			}
			packets[i] = clonePacketBuffer(
				j.pool,
				bufs[i][offset:offset+size],
			)
			j.rememberRoute(packets[i], n)
		}
		select {
		case <-j.done:
			putBuffers(j.pool, packets)
			return
		case j.reads <- detachedTunRead{
			bufs:  packets,
			owner: n,
			pool:  j.pool,
		}:
		}
	}
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
			return
		case req := <-j.writes:
			n, err := j.Write(req.bufs, req.offset)
			putBuffers(req.pool, req.bufs)
			req.resp <- detachedTunWriteResult{n: n, err: err}
		}
	}
}

func (j *Joiner) route(buf []byte, offset int) *joinerNested {
	key := packetDstKey(buf, offset)
	j.mu.Lock()
	defer j.mu.Unlock()
	if key != "" {
		if n := j.routes[key]; n != nil {
			return n
		}
	}
	return j.defaultTun
}

func (j *Joiner) rememberRoute(packet []byte, n *joinerNested) {
	key := packetSrcKey(packet, 0)
	if key == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.nested[n.t] == n {
		j.routes[key] = n
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
	writeBufs, writeOffset, release := alignWriteOffset(
		j.pool,
		bufs,
		offset,
		n.t.MWO(),
	)
	defer release()
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
) ([][]byte, int, func()) {
	if nestedOffset <= offset {
		return bufs, offset, func() {}
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
	return out, nestedOffset, func() { putBuffers(pool, out) }
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
	for key, owner := range j.routes {
		if owner == n {
			delete(j.routes, key)
		}
	}
	pending := j.pending[:0]
	for _, packet := range j.pending {
		if packet.owner != n {
			pending = append(pending, packet)
		} else {
			bufpool.PutBuffer(packet.pool, packet.packet)
		}
	}
	j.pending = pending
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

func packetSrcKey(buf []byte, offset int) string {
	if offset >= len(buf) {
		return ""
	}
	p := buf[offset:]
	if len(p) < 1 {
		return ""
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return ""
		}
		return string(append([]byte{4}, p[12:16]...))
	case 6:
		if len(p) < 40 {
			return ""
		}
		return string(append([]byte{6}, p[8:24]...))
	default:
		return ""
	}
}

func packetDstKey(buf []byte, offset int) string {
	if offset >= len(buf) {
		return ""
	}
	p := buf[offset:]
	if len(p) < 1 {
		return ""
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return ""
		}
		return string(append([]byte{4}, p[16:20]...))
	case 6:
		if len(p) < 40 {
			return ""
		}
		return string(append([]byte{6}, p[24:40]...))
	default:
		return ""
	}
}
