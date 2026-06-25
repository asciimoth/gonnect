package tun

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/asciimoth/bufpool"
)

var (
	_ Tun       = (*DetachedTun)(nil)
	_ io.Closer = (*DetachedTun)(nil)
)

var (
	// ErrDetachedTunDown is returned by Read and Write when the detachable
	// wrapper is down. The wrapped Tun remains open.
	ErrDetachedTunDown = errors.Join(
		os.ErrClosed,
		errors.New("tun: detached wrapper is down"),
	)
	// ErrDetachedTunClosed is returned after the detachable wrapper is closed.
	// The wrapped Tun remains open.
	ErrDetachedTunClosed = errors.Join(
		os.ErrClosed,
		errors.New("tun: detached wrapper is closed"),
	)
)

type detachedTunRead struct {
	bufs  [][]byte
	sizes []int
	owner *joinerNested
	pool  bufpool.Pool
	err   error
}

type detachedTunWrite struct {
	bufs   [][]byte
	offset int
	pool   bufpool.Pool
	resp   chan detachedTunWriteResult
}

type detachedTunWriteResult struct {
	n   int
	err error
}

type tunChannelSource interface {
	sourceSnapshot() (
		<-chan detachedTunRead,
		chan<- detachedTunWrite,
		<-chan struct{},
		error,
	)
}

// DetachedTun is an independently stoppable wrapper around a Tun.
//
// Down and Close affect only the wrapper and do not close the wrapped Tun.
// Pending Read and Write calls on the wrapper return when the wrapper is taken
// down or closed. To make that possible for arbitrary Tun implementations,
// DetachedTun copies packet data at the wrapper boundary and uses internal
// read/write pumps. If the wrapped Tun blocks without any cancellation support,
// a pump goroutine may remain blocked inside the wrapped Tun until that wrapped
// operation completes; caller buffers are not used by those goroutines.
//
// Tun implementations are generally single-consumer/single-producer devices.
// Creating more than one active DetachedTun for the same underlying Tun, or
// using the wrapped Tun directly while a DetachedTun is active, can reorder or
// steal packets just like concurrent direct reads from the same Tun would.
//
// When wrapping another DetachedTun, Detach flattens the data path onto the
// first wrapper's pumps. Nested wrappers still have independent Down and Close
// state, but they do not add another pump or another packet-copy stage.
type DetachedTun struct {
	wrapped Tun
	parent  *DetachedTun
	source  tunChannelSource

	mu            sync.RWMutex
	up            bool
	closed        bool
	gen           uint64
	done          chan struct{}
	effectiveDone chan struct{}
	parentDone    <-chan struct{}
	ownsPumps     bool
	reads         chan detachedTunRead
	writes        chan detachedTunWrite
	readSrc       <-chan detachedTunRead
	writeSrc      chan<- detachedTunWrite
	events        chan Event
	eventMu       sync.RWMutex
	eventClosed   bool
	eventSubs     map[chan Event]struct{}
	once          sync.Once
	mtu           int
	mro           int
	mwo           int
	batch         int
	readLen       int
	native        bool
	pool          bufpool.Pool
}

// Detach creates an independently stoppable wrapper around t. If t is already a
// DetachedTun, the new wrapper shares t's underlying pumps instead of wrapping
// the public Read and Write methods again.
func Detach(t Tun, pools ...bufpool.Pool) *DetachedTun {
	pool := optionalPool(pools)
	if parent, ok := t.(*DetachedTun); ok {
		return detachNested(parent, pool)
	}
	if source, ok := t.(tunChannelSource); ok {
		return detachSource(t, source, pool)
	}
	mtu, err := t.MTU()
	if err != nil || mtu < 0 {
		mtu = 64 << 10
	}
	d := &DetachedTun{
		wrapped:   t,
		up:        true,
		gen:       1,
		ownsPumps: true,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       mtu,
		mro:       t.MRO(),
		mwo:       t.MWO(),
		batch:     t.BatchSize(),
		native:    t.IsNative(),
		pool:      pool,
	}
	if d.batch <= 0 {
		d.batch = 1
	}
	d.readLen = d.mro + d.mtu
	if d.readLen < d.mro {
		d.readLen = d.mro
	}
	d.startLocked()
	d.startEventPump(t.Events())
	d.sendEvent(EventUp)
	return d
}

func detachSource(
	t Tun,
	source tunChannelSource,
	pool bufpool.Pool,
) *DetachedTun {
	mtu, err := t.MTU()
	if err != nil || mtu < 0 {
		mtu = 64 << 10
	}
	d := &DetachedTun{
		wrapped:   t,
		source:    source,
		up:        true,
		gen:       1,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       mtu,
		mro:       t.MRO(),
		mwo:       t.MWO(),
		batch:     t.BatchSize(),
		native:    t.IsNative(),
		pool:      pool,
	}
	if d.batch <= 0 {
		d.batch = 1
	}
	d.readLen = d.mro + d.mtu
	if d.readLen < d.mro {
		d.readLen = d.mro
	}
	d.startLocked()
	d.startEventPump(t.Events())
	d.sendEvent(EventUp)
	return d
}

func detachNested(parent *DetachedTun, pool bufpool.Pool) *DetachedTun {
	d := &DetachedTun{
		wrapped:   parent.wrapped,
		parent:    parent,
		up:        true,
		gen:       1,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       parent.mtu,
		mro:       parent.mro,
		mwo:       parent.mwo,
		batch:     parent.batch,
		readLen:   parent.readLen,
		native:    parent.native,
		pool:      pool,
	}
	d.startLocked()
	d.startEventPump(parent.subscribeEvents())
	d.sendEvent(EventUp)
	return d
}

// Up re-enables the wrapper. It does not call Up or otherwise mutate the
// wrapped Tun.
func (d *DetachedTun) Up() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrDetachedTunClosed
	}
	if d.up {
		return nil
	}
	d.gen++
	d.up = true
	d.startLocked()
	d.sendEvent(EventUp)
	return nil
}

// Down stops this wrapper and releases pending Read and Write calls. It does
// not close the wrapped Tun.
func (d *DetachedTun) Down() error {
	d.mu.Lock()
	if d.closed || !d.up {
		d.mu.Unlock()
		return nil
	}
	d.up = false
	d.gen++
	done := d.done
	d.mu.Unlock()

	close(done)
	d.sendEvent(EventDown)
	return nil
}

// IsUp reports whether this wrapper is currently up.
func (d *DetachedTun) IsUp() (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.up, nil
}

// Close permanently closes this wrapper. It does not close the wrapped Tun.
func (d *DetachedTun) Close() error {
	d.once.Do(func() {
		d.mu.Lock()
		wasUp := d.up
		if wasUp {
			d.up = false
			d.gen++
			close(d.done)
		}
		d.closed = true
		d.mu.Unlock()
		if wasUp {
			d.sendEvent(EventDown)
		}
		d.closeEvents()
	})
	return nil
}

func (d *DetachedTun) File() *os.File { return d.wrapped.File() }

func (d *DetachedTun) IsNative() bool { return d.native }

func (d *DetachedTun) MWO() int { return d.mwo }

func (d *DetachedTun) MRO() int { return d.mro }

func (d *DetachedTun) MTU() (int, error) {
	if err := d.stateErr(); err != nil {
		return 0, err
	}
	return d.wrapped.MTU()
}

func (d *DetachedTun) Name() (string, error) {
	if err := d.stateErr(); err != nil {
		return "", err
	}
	return d.wrapped.Name()
}

func (d *DetachedTun) Events() <-chan Event { return d.events }

func (d *DetachedTun) BatchSize() int { return d.batch }

func (d *DetachedTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if offset < 0 {
		return 0, errors.New("tun: negative read offset")
	}
	reads, done, err := d.channels()
	if err != nil {
		return 0, err
	}
	select {
	case <-done:
		return 0, ErrDetachedTunDown
	case r := <-reads:
		if r.err != nil {
			return 0, r.err
		}
		n := min(len(bufs), len(sizes), len(r.bufs))
		defer putBuffers(r.pool, r.bufs)
		for i := range n {
			if offset > len(bufs[i]) {
				return i, errors.New("tun: read offset beyond buffer")
			}
			sizes[i] = copy(bufs[i][offset:], r.bufs[i])
		}
		return n, nil
	}
}

func (d *DetachedTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("tun: negative write offset")
	}
	writes, done, err := d.writeChannel()
	if err != nil {
		return 0, err
	}
	req := detachedTunWrite{
		bufs:   cloneWriteBufs(d.pool, bufs, offset),
		offset: offset,
		pool:   d.pool,
		resp:   make(chan detachedTunWriteResult, 1),
	}
	select {
	case <-done:
		putBuffers(req.pool, req.bufs)
		return 0, ErrDetachedTunDown
	case writes <- req:
	}
	select {
	case <-done:
		return 0, ErrDetachedTunDown
	case res := <-req.resp:
		return res.n, res.err
	}
}

func (d *DetachedTun) startLocked() {
	d.done = make(chan struct{})
	if d.ownsPumps {
		d.effectiveDone = d.done
		d.reads = make(chan detachedTunRead, channelBufferSize())
		d.writes = make(chan detachedTunWrite, channelBufferSize())
		d.readSrc = d.reads
		d.writeSrc = d.writes
		gen := d.gen
		done := d.done
		reads := d.reads
		writes := d.writes
		go d.readPump(gen, done, reads)
		go d.writePump(gen, done, writes)
		return
	}
	_ = d.refreshNestedLocked()
}

func (d *DetachedTun) refreshNestedLocked() error {
	source := d.source
	if source == nil {
		source = d.parent
	}
	readSrc, writeSrc, parentDone, err := source.sourceSnapshot()
	if err != nil {
		return err
	}
	if d.effectiveDone != nil &&
		d.parentDone == parentDone &&
		!closedChan(d.effectiveDone) {
		d.readSrc = readSrc
		d.writeSrc = writeSrc
		return nil
	}
	d.parentDone = parentDone
	d.readSrc = readSrc
	d.writeSrc = writeSrc
	d.effectiveDone = make(chan struct{})
	done := d.done
	effectiveDone := d.effectiveDone
	go func() {
		select {
		case <-done:
		case <-parentDone:
		}
		close(effectiveDone)
	}()
	return nil
}

func (d *DetachedTun) channels() (
	<-chan detachedTunRead,
	<-chan struct{},
	error,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil, ErrDetachedTunClosed
	}
	if !d.up {
		return nil, nil, ErrDetachedTunDown
	}
	if !d.ownsPumps {
		if err := d.refreshNestedLocked(); err != nil {
			return nil, nil, err
		}
	}
	return d.readSrc, d.effectiveDone, nil
}

func (d *DetachedTun) writeChannel() (
	chan<- detachedTunWrite,
	<-chan struct{},
	error,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil, ErrDetachedTunClosed
	}
	if !d.up {
		return nil, nil, ErrDetachedTunDown
	}
	if !d.ownsPumps {
		if err := d.refreshNestedLocked(); err != nil {
			return nil, nil, err
		}
	}
	return d.writeSrc, d.effectiveDone, nil
}

func (d *DetachedTun) stateErr() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return ErrDetachedTunClosed
	}
	if !d.up {
		return ErrDetachedTunDown
	}
	if !d.ownsPumps {
		if d.parent == nil {
			return nil
		}
		return d.parent.stateErr()
	}
	return nil
}

func (d *DetachedTun) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- detachedTunWrite,
	<-chan struct{},
	error,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, nil, nil, ErrDetachedTunClosed
	}
	if !d.up {
		return nil, nil, nil, ErrDetachedTunDown
	}
	if !d.ownsPumps {
		if err := d.refreshNestedLocked(); err != nil {
			return nil, nil, nil, err
		}
	}
	return d.readSrc, d.writeSrc, d.effectiveDone, nil
}

func (d *DetachedTun) readPump(
	gen uint64,
	done <-chan struct{},
	reads chan<- detachedTunRead,
) {
	bufs := make([][]byte, d.batch)
	sizes := make([]int, d.batch)
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(d.pool, d.readLen)
	}
	defer putBuffers(d.pool, bufs)
	for {
		n, err := d.wrapped.Read(bufs, sizes, d.mro)
		if err != nil {
			if !d.generationActive(gen) {
				return
			}
			select {
			case <-done:
			case reads <- detachedTunRead{err: err}:
			}
			return
		}
		packets := make([][]byte, n)
		for i := range n {
			size := 0
			if len(bufs[i]) > d.mro {
				size = min(sizes[i], len(bufs[i])-d.mro)
			}
			packets[i] = clonePacketBuffer(
				d.pool,
				bufs[i][d.mro:d.mro+size],
			)
		}
		if !d.generationActive(gen) {
			d.forwardStaleRead(packets)
			return
		}
		select {
		case <-done:
			putBuffers(d.pool, packets)
			return
		case reads <- detachedTunRead{
			bufs:  packets,
			sizes: sizes[:n],
			pool:  d.pool,
		}:
		}
	}
}

func (d *DetachedTun) forwardStaleRead(packets [][]byte) {
	d.mu.RLock()
	if !d.up || d.closed || !d.ownsPumps {
		d.mu.RUnlock()
		putBuffers(d.pool, packets)
		return
	}
	reads := d.reads
	done := d.done
	d.mu.RUnlock()

	select {
	case <-done:
		putBuffers(d.pool, packets)
	case reads <- detachedTunRead{bufs: packets, pool: d.pool}:
	}
}

func (d *DetachedTun) writePump(
	gen uint64,
	done <-chan struct{},
	writes <-chan detachedTunWrite,
) {
	for {
		select {
		case <-done:
			return
		case req := <-writes:
			n, err := d.wrapped.Write(req.bufs, req.offset)
			putBuffers(req.pool, req.bufs)
			if !d.generationActive(gen) {
				req.resp <- detachedTunWriteResult{err: ErrDetachedTunDown}
				return
			}
			req.resp <- detachedTunWriteResult{n: n, err: err}
			if err != nil {
				return
			}
		}
	}
}

func (d *DetachedTun) generationActive(gen uint64) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.up && !d.closed && d.gen == gen
}

func closedChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (d *DetachedTun) startEventPump(events <-chan Event) {
	go func() {
		down := false
		for event := range events {
			switch event {
			case EventDown:
				down = true
			case EventUp:
				if !down {
					continue
				}
				down = false
			}
			d.sendEvent(event)
		}
		d.closeFromWrapped(down)
	}()
}

func (d *DetachedTun) closeFromWrapped(down bool) {
	d.once.Do(func() {
		d.mu.Lock()
		wasUp := d.up
		if wasUp {
			d.up = false
			d.gen++
			if d.done != nil {
				close(d.done)
			}
		}
		d.closed = true
		d.mu.Unlock()
		if wasUp && !down {
			d.sendEvent(EventDown)
		}
		d.closeEvents()
	})
}

func (d *DetachedTun) subscribeEvents() <-chan Event {
	ch := make(chan Event, 8)
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	if d.eventClosed {
		close(ch)
		return ch
	}
	d.eventSubs[ch] = struct{}{}
	return ch
}

func (d *DetachedTun) sendEvent(event Event) {
	d.eventMu.RLock()
	defer d.eventMu.RUnlock()
	if d.eventClosed {
		return
	}
	select {
	case d.events <- event:
	default:
	}
	for sub := range d.eventSubs {
		select {
		case sub <- event:
		default:
		}
	}
}

func (d *DetachedTun) closeEvents() {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	if d.eventClosed {
		return
	}
	d.eventClosed = true
	close(d.events)
	for sub := range d.eventSubs {
		close(sub)
		delete(d.eventSubs, sub)
	}
}

func optionalPool(pools []bufpool.Pool) bufpool.Pool {
	if len(pools) == 0 {
		return nil
	}
	return pools[0]
}

func clonePacketBuffer(pool bufpool.Pool, packet []byte) []byte {
	buf := bufpool.GetBuffer(pool, len(packet))
	copy(buf, packet)
	return buf[:len(packet)]
}

func putBuffers(pool bufpool.Pool, bufs [][]byte) {
	for _, buf := range bufs {
		bufpool.PutBuffer(pool, buf)
	}
}

func cloneWriteBufs(pool bufpool.Pool, bufs [][]byte, offset int) [][]byte {
	out := make([][]byte, len(bufs))
	for i := range bufs {
		if offset >= len(bufs[i]) {
			out[i] = bufpool.GetBuffer(pool, offset)
			continue
		}
		out[i] = bufpool.GetBuffer(pool, len(bufs[i]))
		copy(out[i][offset:], bufs[i][offset:])
	}
	return out
}
