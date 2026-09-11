package tun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
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
	// ErrDetachedTunFailed identifies a terminal failure in a detached Tun's
	// read or write pump. The returned error also contains the source cause.
	ErrDetachedTunFailed = errors.New("tun: detached pump failed")
)

const detachedTunFallbackReadPacketSize = 64 << 10

// DetachOptions controls the initial read capacity of an owning DetachedTun.
type DetachOptions struct {
	// MinReadPacketSize is the minimum packet size, before MRO is added, for
	// buffers supplied to the source Tun. A value less than one disables the
	// hint. Dynamic growth keeps correctness independent of this value.
	MinReadPacketSize int
}

type detachedTunRead struct {
	bufs      [][]byte
	sizes     []int
	owner     *joinerNested
	pool      bufpool.Pool
	readBatch *detachedTunReadBatch
	err       error
}

type detachedTunReadBatch struct {
	bufs [][]byte
	pool *sync.Pool
}

func (batch *detachedTunReadBatch) release() {
	clear(batch.bufs)
	batch.bufs = batch.bufs[:0]
	batch.pool.Put(batch)
}

type detachedTunWrite struct {
	mu         sync.Mutex
	bufs       [][]byte
	offset     int
	pool       bufpool.Pool
	owner      *DetachedTun
	resp       chan detachedTunWriteResult
	taken      bool
	finishOnce sync.Once
}

type detachedTunWriteResult struct {
	n   int
	err error
}

type tunChannelSource interface {
	sourceSnapshot() (
		<-chan detachedTunRead,
		chan<- *detachedTunWrite,
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
//
// A terminal read or write pump error puts the owning wrapper in a failed
// state. The wrapper sends one EventDown for this transition, and future I/O
// returns an error that matches ErrDetachedTunFailed and the source cause. In
// contrast to a source EventDown, a pump failure cannot be reversed by Up.
type DetachedTun struct {
	wrapped Tun
	parent  *DetachedTun
	source  tunChannelSource

	mu            sync.RWMutex
	up            bool
	closed        bool
	failed        error
	gen           uint64
	done          chan struct{}
	effectiveDone chan struct{}
	parentDone    <-chan struct{}
	ownsPumps     bool
	reads         chan detachedTunRead
	writes        chan *detachedTunWrite
	readSrc       <-chan detachedTunRead
	writeSrc      chan<- *detachedTunWrite
	events        chan Event
	eventMu       sync.RWMutex
	eventClosed   bool
	eventSubs     map[chan Event]struct{}
	once          sync.Once
	wg            sync.WaitGroup
	waitMu        sync.Mutex
	waitCond      *sync.Cond
	pendingWrites int
	mtu           int
	mro           int
	mwo           int
	batch         int
	readLen       int
	native        bool
	pool          bufpool.Pool
	spawner       gonnect.Spawner
}

// Detach creates an independently stoppable wrapper around t. If t is already a
// DetachedTun, the new wrapper shares t's underlying pumps instead of wrapping
// the public Read and Write methods again.
func Detach(
	t Tun,
	spawner gonnect.Spawner,
	pool bufpool.Pool,
) *DetachedTun {
	return DetachWithOptions(t, spawner, pool, DetachOptions{})
}

// DetachWithOptions creates an independently stoppable wrapper around t.
//
// If the initial MTU is unavailable or is not positive, the owning wrapper
// uses 64 KiB as its initial read packet size. This fallback changes only
// internal buffer sizing; MTU continues to report the source value.
func DetachWithOptions(
	t Tun,
	spawner gonnect.Spawner,
	pool bufpool.Pool,
	opts DetachOptions,
) *DetachedTun {
	if parent, ok := t.(*DetachedTun); ok {
		return detachNested(parent, pool, spawner, opts)
	}
	if source, ok := t.(tunChannelSource); ok {
		return detachSource(t, source, pool, spawner, opts)
	}
	mtu, err := t.MTU()
	if err != nil || mtu <= 0 {
		mtu = detachedTunFallbackReadPacketSize
	}
	mro := t.MRO()
	packetSize := max(mtu, opts.MinReadPacketSize)
	readLen, capacityErr := detachedTunReadLen(mro, packetSize)
	d := &DetachedTun{
		wrapped:   t,
		up:        true,
		gen:       1,
		ownsPumps: true,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       mtu,
		mro:       mro,
		mwo:       t.MWO(),
		batch:     t.BatchSize(),
		native:    t.IsNative(),
		pool:      pool,
		spawner:   spawner,
		readLen:   readLen,
	}
	d.waitCond = sync.NewCond(&d.waitMu)
	if d.batch <= 0 {
		d.batch = 1
	}
	if capacityErr != nil {
		d.failConstruction(capacityErr)
		return d
	}
	if err := d.startLocked(); err != nil {
		d.failConstruction(err)
		return d
	}
	if err := d.startEventPump(t.Events()); err != nil {
		d.failConstruction(err)
		return d
	}
	d.sendUpIfHealthy()
	return d
}

func detachSource(
	t Tun,
	source tunChannelSource,
	pool bufpool.Pool,
	spawner gonnect.Spawner,
	opts DetachOptions,
) *DetachedTun {
	mtu, err := t.MTU()
	if err != nil || mtu <= 0 {
		mtu = detachedTunFallbackReadPacketSize
	}
	mro := t.MRO()
	packetSize := max(mtu, opts.MinReadPacketSize)
	readLen, capacityErr := detachedTunReadLen(mro, packetSize)
	d := &DetachedTun{
		wrapped:   t,
		source:    source,
		up:        true,
		gen:       1,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       mtu,
		mro:       mro,
		mwo:       t.MWO(),
		batch:     t.BatchSize(),
		native:    t.IsNative(),
		pool:      pool,
		spawner:   spawner,
		readLen:   readLen,
	}
	d.waitCond = sync.NewCond(&d.waitMu)
	if d.batch <= 0 {
		d.batch = 1
	}
	if capacityErr != nil {
		d.failConstruction(capacityErr)
		return d
	}
	if err := d.startLocked(); err != nil {
		d.failConstruction(err)
		return d
	}
	if err := d.startEventPump(t.Events()); err != nil {
		d.failConstruction(err)
		return d
	}
	d.sendUpIfHealthy()
	return d
}

func detachNested(
	parent *DetachedTun,
	pool bufpool.Pool,
	spawner gonnect.Spawner,
	opts DetachOptions,
) *DetachedTun {
	parent.mu.RLock()
	mtu := parent.mtu
	mro := parent.mro
	mwo := parent.mwo
	batch := parent.batch
	readLen := parent.readLen
	native := parent.native
	wrapped := parent.wrapped
	parent.mu.RUnlock()
	d := &DetachedTun{
		wrapped:   wrapped,
		parent:    parent,
		up:        true,
		gen:       1,
		events:    make(chan Event, 8),
		eventSubs: make(map[chan Event]struct{}),
		mtu:       mtu,
		mro:       mro,
		mwo:       mwo,
		batch:     batch,
		readLen:   readLen,
		native:    native,
		pool:      pool,
		spawner:   spawner,
	}
	d.waitCond = sync.NewCond(&d.waitMu)
	if err := parent.growReadPacketSize(opts.MinReadPacketSize); err != nil {
		d.failConstruction(err)
		return d
	}
	if err := d.startLocked(); err != nil {
		d.failConstruction(err)
		return d
	}
	if err := d.startEventPump(parent.subscribeEvents()); err != nil {
		d.failConstruction(err)
		return d
	}
	d.sendUpIfHealthy()
	return d
}

// Up re-enables the wrapper. It does not call Up or otherwise mutate the
// wrapped Tun.
func (d *DetachedTun) Up() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrDetachedTunClosed
	}
	if d.failed != nil {
		err := d.failed
		d.mu.Unlock()
		return err
	}
	if d.up {
		if !d.ownsPumps {
			if err := d.refreshNestedLocked(); err != nil {
				d.mu.Unlock()
				return err
			}
		}
		d.mu.Unlock()
		return nil
	}
	d.gen++
	d.up = true
	if err := d.startLocked(); err != nil {
		d.up = false
		if d.ownsPumps {
			failure, emit := d.setFailureLocked(err)
			if emit {
				d.sendEvent(EventDown)
			}
			d.mu.Unlock()
			return failure
		}
		d.mu.Unlock()
		return err
	}
	d.sendEvent(EventUp)
	d.mu.Unlock()
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
	return d.stateErr() == nil, nil
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
		reads := d.reads
		ownsPumps := d.ownsPumps
		d.closed = true
		d.mu.Unlock()
		if ownsPumps {
			drainDetachedTunReads(reads)
		}
		if wasUp {
			d.sendEvent(EventDown)
		}
		d.closeEvents()
	})
	return nil
}

// Wait waits until this detached wrapper no longer owns buffers allocated from
// the pool passed to Detach.
//
// Wait is intended to be called after Close, usually after the wrapped Tun has
// also been closed or otherwise unblocked. If one of this wrapper's pumps, or a
// parent/source pump servicing this wrapper's write request, is blocked in the
// wrapped Tun, Wait may block until that operation returns.
//
// Wait is safe to call multiple times.
func (d *DetachedTun) Wait() {
	d.wg.Wait()
	d.waitMu.Lock()
	defer d.waitMu.Unlock()
	for d.pendingWrites > 0 {
		d.waitCond.Wait()
	}
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
		return 0, d.operationErr(ErrDetachedTunDown)
	case r := <-reads:
		if err := d.stateErr(); err != nil {
			releaseDetachedTunRead(r)
			return 0, err
		}
		if r.err != nil {
			return 0, r.err
		}
		n := min(len(bufs), len(sizes), len(r.bufs))
		defer releaseDetachedTunRead(r)
		for i := range n {
			size := len(r.bufs[i])
			if offset > len(bufs[i]) || size > len(bufs[i])-offset {
				return i, io.ErrShortBuffer
			}
			copy(bufs[i][offset:offset+size], r.bufs[i])
			sizes[i] = size
		}
		return n, nil
	}
}

func (d *DetachedTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("tun: negative write offset")
	}
	if err := validatePacketOffset(bufs, offset); err != nil {
		return 0, err
	}
	writes, done, req, err := d.writeRequest(bufs, offset)
	if err != nil {
		return 0, err
	}
	if err := enqueueDetachedTunWrite(
		writes,
		done,
		req,
		ErrDetachedTunDown,
	); err != nil {
		return 0, err
	}
	select {
	case <-done:
		err := d.operationErr(ErrDetachedTunDown)
		req.cancel(err)
		return 0, err
	case res := <-req.resp:
		if err := d.stateErr(); err != nil {
			return 0, err
		}
		return res.n, res.err
	}
}

func (d *DetachedTun) writeRequest(
	bufs [][]byte,
	offset int,
) (
	chan<- *detachedTunWrite,
	<-chan struct{},
	*detachedTunWrite,
	error,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed != nil {
		return nil, nil, nil, d.failed
	}
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
	d.addPendingWrite()
	req := newDetachedTunWrite(d, d.pool, bufs, offset)
	return d.writeSrc, d.effectiveDone, req, nil
}

func (d *DetachedTun) startLocked() error {
	d.done = make(chan struct{})
	if d.ownsPumps {
		d.effectiveDone = d.done
		d.reads = make(chan detachedTunRead, channelBufferSize())
		d.writes = make(chan *detachedTunWrite, channelBufferSize())
		d.readSrc = d.reads
		d.writeSrc = d.writes
		gen := d.gen
		done := d.done
		reads := d.reads
		writes := d.writes
		if err := spawnWg(d.spawner, func() {
			d.readPump(gen, done, reads)
		}, &d.wg, "tun.DetachedTun.readPump"); err != nil {
			close(d.done)
			return err
		}
		if err := spawnWg(d.spawner, func() {
			d.writePump(gen, done, writes)
		}, &d.wg, "tun.DetachedTun.writePump"); err != nil {
			close(d.done)
			return err
		}
		return nil
	}
	return d.refreshNestedLocked()
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
	if d.failed != nil {
		return nil, nil, d.failed
	}
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

func (d *DetachedTun) addPendingWrite() {
	d.waitMu.Lock()
	d.pendingWrites++
	d.waitMu.Unlock()
}

func (d *DetachedTun) finishPendingWrite() {
	d.waitMu.Lock()
	d.pendingWrites--
	if d.pendingWrites == 0 {
		d.waitCond.Broadcast()
	}
	d.waitMu.Unlock()
}

func (d *DetachedTun) stateErr() error {
	d.mu.RLock()
	failed := d.failed
	closed := d.closed
	up := d.up
	parent := d.parent
	source := d.source
	ownsPumps := d.ownsPumps
	d.mu.RUnlock()
	if failed != nil {
		return failed
	}
	if closed {
		return ErrDetachedTunClosed
	}
	if !up {
		return ErrDetachedTunDown
	}
	if parent != nil {
		return parent.stateErr()
	}
	if !ownsPumps && source != nil {
		_, _, _, err := source.sourceSnapshot()
		return err
	}
	return nil
}

func (d *DetachedTun) operationErr(fallback error) error {
	if err := d.stateErr(); err != nil {
		return err
	}
	return fallback
}

func (d *DetachedTun) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- *detachedTunWrite,
	<-chan struct{},
	error,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed != nil {
		return nil, nil, nil, d.failed
	}
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
	reads chan detachedTunRead,
) {
	readLen := d.readLength()
	bufs := make([][]byte, d.batch)
	sizes := make([]int, d.batch)
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(d.pool, readLen)
	}
	defer func() { putBuffers(d.pool, bufs) }()
	for {
		if target := d.readLength(); target > readBufferLength(bufs) {
			bufs = replaceReadBuffers(d.pool, bufs, target)
		}
		clear(sizes)
		n, err := d.wrapped.Read(bufs, sizes, d.mro)
		if err != nil {
			if !d.generationActive(gen) {
				return
			}
			if d.handleSourceReadError(gen, done, reads, bufs, sizes, err) {
				continue
			}
			return
		}
		if validationErr := validateReadPacketSizes(
			bufs,
			sizes,
			d.mro,
			n,
		); validationErr != nil {
			if d.handleInvalidRead(gen, bufs, sizes, validationErr) {
				continue
			}
			return
		}
		packets := make([][]byte, n)
		for i := range n {
			size := sizes[i]
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
			if d.isClosed() {
				drainDetachedTunReads(reads)
			}
			return
		case reads <- detachedTunRead{
			bufs: packets,
			pool: d.pool,
		}:
			if d.isClosed() {
				drainDetachedTunReads(reads)
				return
			}
		}
	}
}

func (d *DetachedTun) handleSourceReadError(
	gen uint64,
	done <-chan struct{},
	reads chan detachedTunRead,
	bufs [][]byte,
	sizes []int,
	err error,
) bool {
	if errors.Is(err, io.ErrShortBuffer) {
		return d.recoverReadCapacity(gen, bufs, sizes, err)
	}
	if IsTunTermError(err) {
		_ = d.failPump(gen, err)
		return false
	}
	if d.sendReadError(done, reads, err) {
		return true
	}
	if d.isClosed() {
		drainDetachedTunReads(reads)
	}
	return false
}

func (d *DetachedTun) handleInvalidRead(
	gen uint64,
	bufs [][]byte,
	sizes []int,
	err error,
) bool {
	if errors.Is(err, io.ErrShortBuffer) {
		return d.recoverReadCapacity(gen, bufs, sizes, err)
	}
	_ = d.failPump(gen, err)
	return false
}

func (d *DetachedTun) recoverReadCapacity(
	gen uint64,
	bufs [][]byte,
	sizes []int,
	cause error,
) bool {
	grew, err := d.growAfterCapacityError(bufs, sizes)
	if err != nil {
		_ = d.failPump(gen, errors.Join(cause, err))
		return false
	}
	if grew {
		return true
	}
	_ = d.failPump(
		gen,
		fmt.Errorf("tun: read capacity did not increase: %w", cause),
	)
	return false
}

func (d *DetachedTun) sendReadError(
	done <-chan struct{},
	reads chan<- detachedTunRead,
	err error,
) bool {
	select {
	case <-done:
		return false
	case reads <- detachedTunRead{err: err}:
		return true
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
	writes <-chan *detachedTunWrite,
) {
	for {
		select {
		case <-done:
			drainDetachedTunWrites(
				writes,
				d.operationErr(ErrDetachedTunDown),
			)
			return
		case req := <-writes:
			bufs, ok := req.take()
			if !ok {
				continue
			}
			n, err := d.wrapped.Write(bufs, req.offset)
			req.release()
			if !d.generationActive(gen) {
				stateErr := d.operationErr(ErrDetachedTunDown)
				req.respond(0, stateErr)
				drainDetachedTunWrites(writes, stateErr)
				return
			}
			if err != nil {
				failure := d.failPump(gen, err)
				req.respond(n, failure)
				drainDetachedTunWrites(writes, failure)
				return
			}
			req.respond(n, nil)
		}
	}
}

func (d *DetachedTun) generationActive(gen uint64) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.up && !d.closed && d.failed == nil && d.gen == gen
}

func (d *DetachedTun) isClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

func closedChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func detachedTunReadLen(mro int, packetSize int) (int, error) {
	if mro < 0 {
		return 0, fmt.Errorf("tun: negative MRO %d", mro)
	}
	if packetSize <= 0 {
		return 0, fmt.Errorf("tun: invalid read packet size %d", packetSize)
	}
	maxInt := int(^uint(0) >> 1)
	if packetSize > maxInt-mro {
		return 0, fmt.Errorf(
			"tun: MRO %d and read packet size %d overflow int",
			mro,
			packetSize,
		)
	}
	return mro + packetSize, nil
}

func (d *DetachedTun) readLength() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.readLen
}

func (d *DetachedTun) growReadPacketSize(packetSize int) error {
	if packetSize <= 0 {
		return nil
	}
	if !d.ownsPumps {
		if d.parent != nil {
			return d.parent.growReadPacketSize(packetSize)
		}
		return nil
	}
	readLen, err := detachedTunReadLen(d.mro, packetSize)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if readLen > d.readLen {
		d.readLen = readLen
	}
	d.mu.Unlock()
	return nil
}

func (d *DetachedTun) recordMTU(mtu int) error {
	if mtu <= 0 {
		return nil
	}
	if err := d.growReadPacketSize(mtu); err != nil {
		return err
	}
	d.mu.Lock()
	d.mtu = mtu
	d.mu.Unlock()
	return nil
}

func (d *DetachedTun) growAfterCapacityError(
	bufs [][]byte,
	sizes []int,
) (bool, error) {
	oldLen := readBufferLength(bufs)
	if mtu, err := d.wrapped.MTU(); err == nil && mtu > 0 {
		if err := d.recordMTU(mtu); err != nil {
			return false, err
		}
	}
	for _, size := range sizes {
		if size <= 0 {
			continue
		}
		if err := d.growReadPacketSize(size); err != nil {
			return false, err
		}
	}
	return d.readLength() > oldLen, nil
}

func readBufferLength(bufs [][]byte) int {
	if len(bufs) == 0 {
		return 0
	}
	length := len(bufs[0])
	for _, buf := range bufs[1:] {
		length = min(length, len(buf))
	}
	return length
}

func replaceReadBuffers(
	pool bufpool.Pool,
	old [][]byte,
	readLen int,
) [][]byte {
	bufs := make([][]byte, len(old))
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(pool, readLen)
	}
	putBuffers(pool, old)
	return bufs
}

func (d *DetachedTun) setFailureLocked(cause error) (error, bool) {
	if d.failed != nil {
		return d.failed, false
	}
	if cause == nil {
		cause = errors.New("tun: detached pump stopped")
	}
	d.failed = errors.Join(ErrDetachedTunFailed, cause)
	emit := d.up
	if d.up {
		d.up = false
		d.gen++
	}
	if d.done != nil && !closedChan(d.done) {
		close(d.done)
	}
	return d.failed, emit
}

func (d *DetachedTun) failPump(gen uint64, cause error) error {
	d.mu.Lock()
	if d.closed || d.failed != nil || !d.up || d.gen != gen {
		err := d.failed
		if err == nil {
			err = ErrDetachedTunDown
		}
		d.mu.Unlock()
		return err
	}
	failure, emit := d.setFailureLocked(cause)
	reads := d.reads
	writes := d.writes
	if emit {
		d.sendEvent(EventDown)
	}
	d.mu.Unlock()

	drainDetachedTunReads(reads)
	drainDetachedTunWrites(writes, failure)
	return failure
}

func (d *DetachedTun) failConstruction(cause error) {
	d.mu.Lock()
	failure, emit := d.setFailureLocked(cause)
	reads := d.reads
	writes := d.writes
	if emit {
		d.sendEvent(EventDown)
	}
	d.mu.Unlock()
	if d.ownsPumps {
		drainDetachedTunReads(reads)
		drainDetachedTunWrites(writes, failure)
	}
}

func (d *DetachedTun) sendUpIfHealthy() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.up && !d.closed && d.failed == nil {
		d.sendEvent(EventUp)
	}
}

func (d *DetachedTun) startEventPump(events <-chan Event) error {
	return spawn(d.spawner, func() {
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
			case EventMTUUpdate:
				if d.ownsPumps {
					mtu, err := d.wrapped.MTU()
					if err == nil {
						if err := d.recordMTU(mtu); err != nil {
							d.failCurrentPump(err)
							continue
						}
					}
				}
			}
			d.sendWrappedEvent(event)
		}
		d.closeFromWrapped(down)
	}, "tun.DetachedTun.events")
}

func (d *DetachedTun) failCurrentPump(cause error) {
	d.mu.RLock()
	gen := d.gen
	d.mu.RUnlock()
	_ = d.failPump(gen, cause)
}

func (d *DetachedTun) sendWrappedEvent(event Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.failed != nil {
		return
	}
	d.sendEvent(event)
}

func (d *DetachedTun) closeFromWrapped(down bool) {
	var parentFailure error
	if d.parent != nil {
		if err := d.parent.stateErr(); errors.Is(err, ErrDetachedTunFailed) {
			parentFailure = err
		}
	}
	d.once.Do(func() {
		d.mu.Lock()
		if d.failed == nil && parentFailure != nil {
			d.failed = parentFailure
		}
		wasUp := d.up
		if wasUp {
			d.up = false
			d.gen++
			if d.done != nil {
				close(d.done)
			}
		}
		reads := d.reads
		ownsPumps := d.ownsPumps
		d.closed = true
		d.mu.Unlock()
		if ownsPumps {
			drainDetachedTunReads(reads)
		}
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

func putDetachedTunReadSlice(r detachedTunRead) {
	if r.readBatch != nil {
		r.readBatch.release()
	}
}

func releaseDetachedTunRead(r detachedTunRead) {
	putBuffers(r.pool, r.bufs)
	putDetachedTunReadSlice(r)
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

func newDetachedTunWrite(
	owner *DetachedTun,
	pool bufpool.Pool,
	bufs [][]byte,
	offset int,
) *detachedTunWrite {
	return &detachedTunWrite{
		bufs:   cloneWriteBufs(pool, bufs, offset),
		offset: offset,
		pool:   pool,
		owner:  owner,
		resp:   make(chan detachedTunWriteResult, 1),
	}
}

func enqueueDetachedTunWrite(
	writes chan<- *detachedTunWrite,
	done <-chan struct{},
	req *detachedTunWrite,
	err error,
) error {
	select {
	case <-done:
		req.cancel(err)
		return err
	case writes <- req:
		return nil
	}
}

func drainDetachedTunWrites(
	writes <-chan *detachedTunWrite,
	err error,
) {
	for {
		select {
		case req, ok := <-writes:
			if !ok {
				return
			}
			req.cancel(err)
		default:
			return
		}
	}
}

func drainDetachedTunReads(reads <-chan detachedTunRead) {
	for {
		select {
		case req, ok := <-reads:
			if !ok {
				return
			}
			releaseDetachedTunRead(req)
		default:
			return
		}
	}
}

func (req *detachedTunWrite) take() ([][]byte, bool) {
	req.mu.Lock()
	defer req.mu.Unlock()
	if req.taken || req.bufs == nil {
		return nil, false
	}
	req.taken = true
	return req.bufs, true
}

func (req *detachedTunWrite) release() {
	req.mu.Lock()
	bufs := req.bufs
	pool := req.pool
	req.bufs = nil
	req.mu.Unlock()

	putBuffers(pool, bufs)
	req.finish()
}

func (req *detachedTunWrite) cancel(err error) {
	req.mu.Lock()
	if req.taken || req.bufs == nil {
		req.mu.Unlock()
		return
	}
	bufs := req.bufs
	pool := req.pool
	req.bufs = nil
	req.mu.Unlock()

	putBuffers(pool, bufs)
	req.finish()
	req.respond(0, err)
}

func (req *detachedTunWrite) finish() {
	req.finishOnce.Do(func() {
		if req.owner != nil {
			req.owner.finishPendingWrite()
		}
	})
}

func (req *detachedTunWrite) respond(n int, err error) {
	select {
	case req.resp <- detachedTunWriteResult{n: n, err: err}:
	default:
	}
}
