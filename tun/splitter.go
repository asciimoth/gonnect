package tun

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/asciimoth/bufpool"
)

var (
	_ Tun       = (*SplitFrontend)(nil)
	_ io.Closer = (*Splitter)(nil)
	_ io.Closer = (*SplitFrontend)(nil)
)

const (
	splitterFrontendCount = 16
	splitterDefaultOffset = 256
	splitterDefaultMTU    = 1500
	splitterDefaultBatch  = 256
	splitterMaxPacket     = 64 << 10
)

var (
	// ErrSplitterClosed is returned after Splitter is closed.
	ErrSplitterClosed = errors.Join(
		os.ErrClosed,
		errors.New("tun: splitter closed"),
	)

	// ErrSplitterFrontendClosed is returned after a SplitFrontend is closed.
	ErrSplitterFrontendClosed = errors.Join(
		os.ErrClosed,
		errors.New("tun: splitter frontend closed"),
	)

	// ErrSplitterFrontendDown is returned by SplitFrontend operations while
	// that frontend is down. The Splitter and backend Tun remain open.
	ErrSplitterFrontendDown = errors.Join(
		os.ErrClosed,
		errors.New("tun: splitter frontend is down"),
	)

	// ErrSplitterSmallOffset is returned when SplitFrontend.Read or
	// SplitFrontend.Write is called with an offset smaller than its MRO/MWO.
	ErrSplitterSmallOffset = errors.New(
		"tun: splitter frontend offset is too small",
	)

	// ErrSplitterNilTun is returned when attaching a nil backend Tun.
	ErrSplitterNilTun = errors.New("tun: splitter nil backend tun")
)

// SplitRouter selects the SplitFrontend that should receive a packet read from
// the backend Tun.
//
// Splitter calls Lock once per backend read batch, calls Route for each packet
// in that batch, then calls Unlock. Route receives the packet buffer and offset
// as returned by the backend Tun, plus the backend's IsNative value. It must
// return a frontend index in the inclusive range 1..16. Any other value drops
// the packet. A nil router routes every packet to frontend 1.
type SplitRouter interface {
	Lock()
	Unlock()
	Route(buf []byte, offset int, isNative bool) int
}

type splitterBackend struct {
	t Tun

	mu     sync.Mutex
	up     bool
	closed bool
	done   chan struct{}
	cond   *sync.Cond
}

// Splitter fans one backend Tun out to up to 16 virtual Tun frontends.
//
// Backend reads are routed to frontends through the current SplitRouter. Writes
// from any active frontend are forwarded to the current backend. The backend
// can be attached, detached, or replaced at runtime; detaching closes the
// backend to unblock in-flight backend I/O.
type Splitter struct {
	mu          sync.Mutex
	closed      bool
	done        chan struct{}
	backend     *splitterBackend
	router      SplitRouter
	frontends   [splitterFrontendCount]*SplitFrontend
	writes      chan *detachedTunWrite
	mro         int
	mwo         int
	mtu         int
	batch       int
	eventSerial uint64
	once        sync.Once
	pool        bufpool.Pool
	wg          sync.WaitGroup
}

// SplitFrontend is one virtual Tun produced by Splitter.Get.
//
// Closing or taking a frontend down affects only that frontend. Packets routed
// to a closed, down, or never-created frontend are dropped.
type SplitFrontend struct {
	s     *Splitter
	index int

	mu            sync.Mutex
	up            bool
	closed        bool
	done          chan struct{}
	effectiveDone chan struct{}
	parentDone    <-chan struct{}
	reads         chan detachedTunRead
	events        chan Event
	eventMu       sync.RWMutex
	eventClosed   bool
	once          sync.Once
}

// NewSplitter creates a Splitter with no attached backend.
func NewSplitter(pools ...bufpool.Pool) *Splitter {
	pool := optionalPool(pools)
	s := &Splitter{
		done:   make(chan struct{}),
		writes: make(chan *detachedTunWrite, channelBufferSize()),
		mro:    splitterDefaultOffset,
		mwo:    splitterDefaultOffset,
		mtu:    splitterDefaultMTU,
		batch:  splitterDefaultBatch,
		pool:   pool,
	}
	s.wg.Go(s.writePump)
	return s
}

// Attach replaces the current backend Tun with t. The previous backend, if
// any, is detached and closed.
func (s *Splitter) Attach(t Tun) error {
	if t == nil {
		return ErrSplitterNilTun
	}
	n := newSplitterBackend(t)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSplitterClosed
	}
	old := s.backend
	if old != nil {
		s.closeBackendLocked(old)
	}
	s.backend = n
	s.recalculateLocked()
	s.mu.Unlock()

	if old != nil {
		_ = old.t.Close()
	}
	s.startBackend(n)
	return nil
}

// Detach removes and closes the current backend Tun, if any.
func (s *Splitter) Detach() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSplitterClosed
	}
	n := s.backend
	if n != nil {
		s.backend = nil
		s.closeBackendLocked(n)
		s.recalculateLocked()
	}
	s.mu.Unlock()
	if n != nil {
		_ = n.t.Close()
	}
	return nil
}

// Get returns a new frontend for index. Valid indexes are 1 through 16. If a
// previous frontend exists for that index, it is closed first.
func (s *Splitter) Get(index int) *SplitFrontend {
	if index < 1 || index > splitterFrontendCount {
		return nil
	}
	f := &SplitFrontend{
		s:      s,
		index:  index,
		up:     true,
		reads:  make(chan detachedTunRead),
		events: make(chan Event, 8),
	}
	f.startLocked()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		f.closed = true
		close(f.done)
		f.closeEvents()
		return f
	}
	old := s.frontends[index-1]
	s.frontends[index-1] = f
	s.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	f.sendEvent(EventUp)
	return f
}

// SetRouter installs r as the current packet router. Passing nil removes the
// router and restores the default route to frontend 1.
func (s *Splitter) SetRouter(r SplitRouter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.router = r
}

// RemoveRouter removes the current SplitRouter.
func (s *Splitter) RemoveRouter() { s.SetRouter(nil) }

// ResetRouter replaces the current SplitRouter with r.
func (s *Splitter) ResetRouter(r SplitRouter) { s.SetRouter(r) }

// Close closes the Splitter, all frontends, and the current backend.
func (s *Splitter) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		backend := s.backend
		s.backend = nil
		if backend != nil {
			s.closeBackendLocked(backend)
		}
		frontends := s.frontends
		s.frontends = [splitterFrontendCount]*SplitFrontend{}
		close(s.done)
		s.mu.Unlock()

		for _, f := range frontends {
			if f != nil {
				_ = f.Close()
			}
		}
		if backend != nil {
			_ = backend.t.Close()
		}
		s.wg.Wait()
	})
	return nil
}

func newSplitterBackend(t Tun) *splitterBackend {
	n := &splitterBackend{t: t, up: true, done: make(chan struct{})}
	n.cond = sync.NewCond(&n.mu)
	return n
}

func (s *Splitter) startBackend(n *splitterBackend) {
	s.wg.Go(func() { s.readBackend(n) })
	go s.watchBackendEvents(n)
}

func (s *Splitter) readBackend(n *splitterBackend) {
	batch := batchSizeOf(n.t)
	offset := n.t.MRO()
	readLen := offset + splitterMaxPacket
	if readLen < offset {
		readLen = offset
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(s.pool, readLen)
	}
	defer putBuffers(s.pool, bufs)
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
				s.detachBackend(n, true)
				return
			}
			continue
		}
		targets := s.routeBatch(n, bufs, count, offset)
		if len(targets) == 0 {
			continue
		}
		s.deliverBatch(n, bufs, sizes, count, offset, targets)
	}
}

func (s *Splitter) routeBatch(
	n *splitterBackend,
	bufs [][]byte,
	count int,
	offset int,
) []int {
	router, native, ok := s.routerSnapshot(n)
	if !ok {
		return nil
	}
	targets := make([]int, count)
	if router == nil {
		for i := range targets {
			targets[i] = 1
		}
		return targets
	}
	router.Lock()
	defer router.Unlock()
	for i := range count {
		targets[i] = router.Route(bufs[i], offset, native)
	}
	return targets
}

func (s *Splitter) deliverBatch(
	n *splitterBackend,
	bufs [][]byte,
	sizes []int,
	count int,
	offset int,
	targets []int,
) {
	if !s.backendActive(n) {
		return
	}
	same := true
	for i := 1; i < len(targets); i++ {
		if targets[i] != targets[0] {
			same = false
			break
		}
	}
	if same {
		if f := s.frontendForRoute(targets[0]); f != nil {
			f.deliver(
				cloneBackendPackets(s.pool, bufs, sizes, count, offset),
				n.done,
			)
		}
		return
	}
	for i := range count {
		if f := s.frontendForRoute(targets[i]); f != nil {
			f.deliver(
				cloneBackendPackets(
					s.pool,
					bufs[i:i+1],
					sizes[i:i+1],
					1,
					offset,
				),
				n.done,
			)
		}
	}
}

func (s *Splitter) routerSnapshot(
	n *splitterBackend,
) (SplitRouter, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.backend != n {
		return nil, false, false
	}
	return s.router, n.t.IsNative(), true
}

func (s *Splitter) backendActive(n *splitterBackend) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.backend == n
}

func (s *Splitter) frontendForRoute(index int) *SplitFrontend {
	if index < 1 || index > splitterFrontendCount {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	f := s.frontends[index-1]
	if f == nil || !f.acceptsReads() {
		return nil
	}
	return f
}

func (s *Splitter) watchBackendEvents(n *splitterBackend) {
	for event := range n.t.Events() {
		switch event {
		case EventDown:
			n.setUp(false)
		case EventUp:
			n.setUp(true)
		case EventMTUUpdate:
			s.mu.Lock()
			if s.backend == n {
				s.recalculateLocked()
			}
			s.mu.Unlock()
		}
	}
	s.detachBackend(n, false)
}

func (s *Splitter) detachBackend(n *splitterBackend, closeTun bool) {
	s.mu.Lock()
	if s.backend != n {
		s.mu.Unlock()
		return
	}
	s.backend = nil
	s.closeBackendLocked(n)
	s.recalculateLocked()
	s.mu.Unlock()
	if closeTun {
		_ = n.t.Close()
	}
}

func (s *Splitter) closeBackendLocked(n *splitterBackend) {
	n.mu.Lock()
	if !n.closed {
		n.closed = true
		n.up = false
		close(n.done)
		n.cond.Broadcast()
	}
	n.mu.Unlock()
}

func (s *Splitter) writePump() {
	for {
		select {
		case <-s.done:
			drainDetachedTunWrites(s.writes, ErrSplitterClosed)
			return
		case req := <-s.writes:
			bufs, ok := req.take()
			if !ok {
				continue
			}
			n, err := s.writeToBackend(bufs, req.offset)
			req.release()
			req.respond(n, err)
		}
	}
}

func (s *Splitter) writeToBackend(bufs [][]byte, offset int) (int, error) {
	n := s.backendForWrite()
	if n == nil {
		return len(bufs), nil
	}
	writeBufs, writeOffset, release := alignWriteOffset(
		s.pool,
		bufs,
		offset,
		n.t.MWO(),
	)
	defer release()
	written := 0
	for written < len(writeBufs) {
		end := min(written+batchSizeOf(n.t), len(writeBufs))
		count, err := n.t.Write(writeBufs[written:end], writeOffset)
		if err != nil {
			if errors.Is(err, ErrDetachedTunDown) {
				n.setUp(false)
				return len(bufs), nil
			}
			if IsTunTermError(err) {
				s.detachBackend(n, true)
			}
			return written, err
		}
		if count <= 0 {
			return written, errWriteNoProgress
		}
		written += count
	}
	return len(bufs), nil
}

func (s *Splitter) backendForWrite() *splitterBackend {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.backend
	if s.closed || n == nil || !n.acceptsWrites() {
		return nil
	}
	return n
}

func (s *Splitter) recalculateLocked() {
	oldMTU := s.mtu
	s.mro = splitterDefaultOffset
	s.mwo = splitterDefaultOffset
	s.mtu = splitterDefaultMTU
	s.batch = splitterDefaultBatch
	if s.backend != nil {
		s.mro = s.backend.t.MRO()
		s.mwo = s.backend.t.MWO()
		s.batch = s.backend.t.BatchSize()
		if s.batch <= 0 {
			s.batch = splitterDefaultBatch
		}
		if mtu, err := s.backend.t.MTU(); err == nil && mtu >= 0 {
			s.mtu = mtu
		}
	}
	if oldMTU != s.mtu {
		s.eventSerial++
		for _, f := range s.frontends {
			if f != nil {
				f.sendEvent(EventMTUUpdate)
			}
		}
	}
}

func (s *Splitter) metadata() (mro, mwo, mtu, batch int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, 0, 0, ErrSplitterClosed
	}
	return s.mro, s.mwo, s.mtu, s.batch, nil
}

func (n *splitterBackend) waitUp() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for !n.up && !n.closed {
		n.cond.Wait()
	}
}

func (n *splitterBackend) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func (n *splitterBackend) setUp(up bool) {
	n.mu.Lock()
	n.up = up
	n.cond.Broadcast()
	n.mu.Unlock()
}

func (n *splitterBackend) acceptsWrites() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up && !n.closed
}

func cloneBackendPackets(
	pool bufpool.Pool,
	bufs [][]byte,
	sizes []int,
	count int,
	offset int,
) [][]byte {
	packets := make([][]byte, count)
	for i := range count {
		size := 0
		if offset < len(bufs[i]) {
			size = min(sizes[i], len(bufs[i])-offset)
		}
		packets[i] = clonePacketBuffer(pool, bufs[i][offset:offset+size])
	}
	return packets
}

// Up re-enables this frontend.
func (f *SplitFrontend) Up() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSplitterFrontendClosed
	}
	if f.up {
		return nil
	}
	f.up = true
	f.startLocked()
	f.sendEvent(EventUp)
	return nil
}

// Down stops this frontend and releases pending Read and Write calls. It does
// not affect the Splitter or backend Tun.
func (f *SplitFrontend) Down() error {
	f.mu.Lock()
	if f.closed || !f.up {
		f.mu.Unlock()
		return nil
	}
	f.up = false
	done := f.done
	f.mu.Unlock()

	close(done)
	f.sendEvent(EventDown)
	return nil
}

// IsUp reports whether this frontend is currently up.
func (f *SplitFrontend) IsUp() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false, ErrSplitterFrontendClosed
	}
	return f.up, nil
}

func (f *SplitFrontend) Close() error {
	f.once.Do(func() {
		f.mu.Lock()
		wasUp := f.up
		if wasUp {
			f.up = false
			close(f.done)
		}
		f.closed = true
		f.mu.Unlock()
		if wasUp {
			f.sendEvent(EventDown)
		}
		f.closeEvents()
	})
	return nil
}

func (f *SplitFrontend) File() *os.File { return nil }

func (f *SplitFrontend) IsNative() bool { return false }

func (f *SplitFrontend) MWO() int {
	_, mwo, _, _, _ := f.s.metadata()
	return mwo
}

func (f *SplitFrontend) MRO() int {
	mro, _, _, _, _ := f.s.metadata()
	return mro
}

func (f *SplitFrontend) MTU() (int, error) {
	if err := f.stateErr(); err != nil {
		return 0, err
	}
	_, _, mtu, _, err := f.s.metadata()
	return mtu, err
}

func (f *SplitFrontend) Name() (string, error) {
	if err := f.stateErr(); err != nil {
		return "", err
	}
	return "TunSplitter", nil
}

func (f *SplitFrontend) Events() <-chan Event { return f.events }

func (f *SplitFrontend) BatchSize() int {
	_, _, _, batch, _ := f.s.metadata()
	if batch <= 0 {
		return splitterDefaultBatch
	}
	return batch
}

func (f *SplitFrontend) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if offset < f.MRO() {
		return 0, ErrSplitterSmallOffset
	}
	reads, done, err := f.channels()
	if err != nil {
		return 0, err
	}
	select {
	case <-done:
		return 0, ErrSplitterFrontendDown
	case r := <-reads:
		if r.err != nil {
			return 0, r.err
		}
		n := min(len(bufs), len(sizes), len(r.bufs))
		defer putBuffers(r.pool, r.bufs)
		for i := range n {
			if offset > len(bufs[i]) {
				return i, errors.New(
					"tun: splitter frontend read offset beyond buffer",
				)
			}
			sizes[i] = copy(bufs[i][offset:], r.bufs[i])
		}
		return n, nil
	}
}

func (f *SplitFrontend) Write(bufs [][]byte, offset int) (int, error) {
	if offset < f.MWO() {
		return 0, ErrSplitterSmallOffset
	}
	writes, done, err := f.writeChannel()
	if err != nil {
		return 0, err
	}
	select {
	case <-done:
		return 0, ErrSplitterFrontendDown
	default:
	}
	req := newDetachedTunWrite(nil, f.s.pool, bufs, offset)
	if err := enqueueDetachedTunWrite(
		writes,
		done,
		req,
		ErrSplitterFrontendDown,
	); err != nil {
		return 0, err
	}
	select {
	case <-done:
		req.cancel(ErrSplitterFrontendDown)
		return 0, ErrSplitterFrontendDown
	case res := <-req.resp:
		return res.n, res.err
	}
}

func (f *SplitFrontend) startLocked() {
	f.done = make(chan struct{})
	f.refreshEffectiveDoneLocked()
}

func (f *SplitFrontend) refreshEffectiveDoneLocked() {
	parentDone := f.s.done
	if f.effectiveDone != nil &&
		f.parentDone == parentDone &&
		!closedChan(f.effectiveDone) {
		return
	}
	f.parentDone = parentDone
	f.effectiveDone = make(chan struct{})
	done := f.done
	effectiveDone := f.effectiveDone
	go func() {
		select {
		case <-done:
		case <-parentDone:
		}
		close(effectiveDone)
	}()
}

func (f *SplitFrontend) channels() (
	<-chan detachedTunRead,
	<-chan struct{},
	error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, nil, ErrSplitterFrontendClosed
	}
	if !f.up {
		return nil, nil, ErrSplitterFrontendDown
	}
	f.refreshEffectiveDoneLocked()
	return f.reads, f.effectiveDone, nil
}

func (f *SplitFrontend) writeChannel() (
	chan<- *detachedTunWrite,
	<-chan struct{},
	error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, nil, ErrSplitterFrontendClosed
	}
	if !f.up {
		return nil, nil, ErrSplitterFrontendDown
	}
	f.refreshEffectiveDoneLocked()
	return f.s.writes, f.effectiveDone, nil
}

func (f *SplitFrontend) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- *detachedTunWrite,
	<-chan struct{},
	error,
) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, nil, nil, ErrSplitterFrontendClosed
	}
	if !f.up {
		return nil, nil, nil, ErrSplitterFrontendDown
	}
	f.refreshEffectiveDoneLocked()
	return f.reads, f.s.writes, f.effectiveDone, nil
}

func (f *SplitFrontend) stateErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSplitterFrontendClosed
	}
	if !f.up {
		return ErrSplitterFrontendDown
	}
	return nil
}

func (f *SplitFrontend) acceptsReads() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up && !f.closed
}

func (f *SplitFrontend) deliver(packets [][]byte, backendDone <-chan struct{}) {
	f.mu.Lock()
	if f.closed || !f.up {
		f.mu.Unlock()
		putBuffers(f.s.pool, packets)
		return
	}
	reads := f.reads
	done := f.effectiveDone
	f.mu.Unlock()

	select {
	case <-backendDone:
		putBuffers(f.s.pool, packets)
	case <-done:
		putBuffers(f.s.pool, packets)
	case reads <- detachedTunRead{bufs: packets, pool: f.s.pool}:
	}
}

func (f *SplitFrontend) sendEvent(event Event) {
	f.eventMu.RLock()
	defer f.eventMu.RUnlock()
	if f.eventClosed {
		return
	}
	select {
	case f.events <- event:
	default:
	}
}

func (f *SplitFrontend) closeEvents() {
	f.eventMu.Lock()
	defer f.eventMu.Unlock()
	if f.eventClosed {
		return
	}
	f.eventClosed = true
	close(f.events)
}
