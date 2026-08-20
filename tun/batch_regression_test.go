// nolint
package tun

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
)

var errMockTooManySegments = errors.New("too many segments")
var errMockStopRead = errors.New("stop read")

type mockReadResult struct {
	packets [][]byte
	err     error
}

type mockTun struct {
	mu   sync.Mutex
	cond *sync.Cond

	batchSize int
	mtu       int
	mwo       int
	mro       int

	reads     []mockReadResult
	readCalls int
	closed    bool

	writeLimit     int
	writeCalls     []int
	writtenPackets [][]byte

	events chan Event
}

type mtuSignalTun struct {
	*mockTun
	once sync.Once
	seen chan struct{}
}

func (t *mtuSignalTun) MTU() (int, error) {
	t.once.Do(func() {
		close(t.seen)
	})
	return t.mockTun.MTU()
}

func newMockTun(batchSize, mtu, mwo, mro int) *mockTun {
	t := &mockTun{
		batchSize: batchSize,
		mtu:       mtu,
		mwo:       mwo,
		mro:       mro,
		events:    make(chan Event),
	}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func waitForForwarderMutex(
	t *testing.T,
	f *Forwarder,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		if f.mu.TryLock() {
			f.mu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(
				"forwarder mutex stayed locked while config send was blocked",
			)
		}
		time.Sleep(time.Millisecond)
	}
}

func (t *mockTun) File() *os.File { return nil }
func (t *mockTun) IsNative() bool { return false }
func (t *mockTun) MWO() int       { return t.mwo }
func (t *mockTun) MRO() int       { return t.mro }
func (t *mockTun) MTU() (int, error) {
	return t.mtu, nil
}
func (t *mockTun) Name() (string, error) {
	return "mock", nil
}
func (t *mockTun) Events() <-chan Event { return t.events }
func (t *mockTun) BatchSize() int       { return t.batchSize }

func (t *mockTun) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.cond.Broadcast()
	return nil
}

func (t *mockTun) enqueueRead(result mockReadResult) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reads = append(t.reads, result)
	t.cond.Broadcast()
}

func (t *mockTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.readCalls++

	for len(t.reads) == 0 && !t.closed {
		t.cond.Wait()
	}
	if len(t.reads) == 0 {
		return 0, os.ErrClosed
	}

	result := t.reads[0]
	t.reads = t.reads[1:]

	if result.err != nil && len(result.packets) == 0 {
		return 0, result.err
	}
	if len(bufs) < len(result.packets) || len(sizes) < len(result.packets) {
		return 0, errMockTooManySegments
	}

	for i := range result.packets {
		sizes[i] = copy(bufs[i][offset:], result.packets[i])
	}
	return len(result.packets), result.err
}

func (t *mockTun) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, os.ErrClosed
	}

	written := len(bufs)
	if t.writeLimit > 0 && written > t.writeLimit {
		written = t.writeLimit
	}
	if t.batchSize > 0 && written > t.batchSize {
		written = t.batchSize
	}
	for i := range written {
		t.writtenPackets = append(
			t.writtenPackets,
			bytes.Clone(bufs[i][offset:]),
		)
	}
	t.writeCalls = append(t.writeCalls, written)
	t.cond.Broadcast()
	return written, nil
}

func (t *mockTun) waitForWrittenPackets(
	count int,
	timeout time.Duration,
) [][]byte {
	deadline := time.Now().Add(timeout)
	for {
		t.mu.Lock()
		done := len(t.writtenPackets) >= count
		out := make([][]byte, len(t.writtenPackets))
		for i := range t.writtenPackets {
			out[i] = bytes.Clone(t.writtenPackets[i])
		}
		t.mu.Unlock()

		if done || time.Now().After(deadline) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (t *mockTun) recordedWriteCalls() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]int(nil), t.writeCalls...)
}

func (t *mockTun) readCallCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.readCalls
}

func TestCopyOneWayUsesIndependentReadAndWriteBatchSizes(t *testing.T) {
	t.Parallel()

	src := newMockTun(4, 1500, 0, 0)
	dst := newMockTun(1, 1500, 0, 0)
	dst.writeLimit = 1

	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		},
	})
	src.enqueueRead(mockReadResult{err: errMockStopRead})

	err := copyOneWay(src, dst, 0)
	if !errors.Is(err, errMockStopRead) {
		t.Fatalf("copyOneWay() error = %v, want %v", err, errMockStopRead)
	}

	wantPackets := [][]byte{
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}
	if got := dst.waitForWrittenPackets(
		len(wantPackets),
		time.Second,
	); !reflect.DeepEqual(
		got,
		wantPackets,
	) {
		t.Fatalf("written packets = %q, want %q", got, wantPackets)
	}

	if got := dst.recordedWriteCalls(); !reflect.DeepEqual(
		got,
		[]int{1, 1, 1},
	) {
		t.Fatalf("write calls = %v, want [1 1 1]", got)
	}
}

func TestCopyOneWayRetriesRetryableReadCapacityError(t *testing.T) {
	t.Parallel()

	src := newMockTun(4, 1500, 0, 0)
	dst := newMockTun(2, 1500, 0, 0)

	src.enqueueRead(mockReadResult{err: errMockTooManySegments})
	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("after-retry"),
		},
	})
	src.enqueueRead(mockReadResult{err: errMockStopRead})

	err := copyOneWay(src, dst, 0)
	if !errors.Is(err, errMockStopRead) {
		t.Fatalf("copyOneWay() error = %v, want %v", err, errMockStopRead)
	}

	wantPackets := [][]byte{[]byte("after-retry")}
	if got := dst.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		wantPackets,
	) {
		t.Fatalf("written packets = %q, want %q", got, wantPackets)
	}
}

func TestForwarderSetReadTunDoesNotHoldMutexDuringConfigSend(t *testing.T) {
	t.Parallel()

	frw := &Forwarder{
		chCfgRead: make(chan *frwCfg, 2),
	}
	frw.chCfgRead <- &frwCfg{}
	frw.chCfgRead <- &frwCfg{}

	src := &mtuSignalTun{
		mockTun: newMockTun(1, 1500, 0, 0),
		seen:    make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		frw.SetReadTun(src)
	}()

	<-src.seen
	waitForForwarderMutex(t, frw, 100*time.Millisecond)

	<-frw.chCfgRead
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SetReadTun stayed blocked after config channel had space")
	}
}

func TestForwarderSetWriteTunDoesNotHoldMutexDuringConfigSend(t *testing.T) {
	t.Parallel()

	frw := &Forwarder{
		chCfgWrite: make(chan *frwCfg, 2),
	}
	frw.chCfgWrite <- &frwCfg{}
	frw.chCfgWrite <- &frwCfg{}

	dst := &mtuSignalTun{
		mockTun: newMockTun(1, 1500, 0, 0),
		seen:    make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		frw.SetWriteTun(dst)
	}()

	<-dst.seen
	waitForForwarderMutex(t, frw, 100*time.Millisecond)

	<-frw.chCfgWrite
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SetWriteTun stayed blocked after config channel had space")
	}
}

func TestForwarderUsesIndependentReadAndWriteBatchSizes(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	src := newMockTun(4, 1500, 2, 3)
	dst := newMockTun(1, 1500, 5, 7)
	dst.writeLimit = 1

	frw := NewForwarder(pool, nil)
	defer frw.Stop()

	frw.SetReadTun(src)
	frw.SetWriteTun(dst)

	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		},
	})

	wantPackets := [][]byte{
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	}
	if got := dst.waitForWrittenPackets(
		len(wantPackets),
		time.Second,
	); !reflect.DeepEqual(
		got,
		wantPackets,
	) {
		t.Fatalf("written packets = %q, want %q", got, wantPackets)
	}

	if got := dst.recordedWriteCalls(); !reflect.DeepEqual(
		got,
		[]int{1, 1, 1},
	) {
		t.Fatalf("write calls = %v, want [1 1 1]", got)
	}
}

func TestForwarderRetriesRetryableReadCapacityError(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	src := newMockTun(4, 1500, 0, 0)
	dst := newMockTun(2, 1500, 0, 0)

	frw := NewForwarder(pool, nil)
	defer frw.Stop()

	frw.SetReadTun(src)
	frw.SetWriteTun(dst)

	src.enqueueRead(mockReadResult{err: errMockTooManySegments})
	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("after-retry"),
		},
	})

	wantPackets := [][]byte{[]byte("after-retry")}
	if got := dst.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		wantPackets,
	) {
		t.Fatalf("written packets = %q, want %q", got, wantPackets)
	}
}

func TestP2PUsesIndependentReadAndWriteBatchSizes(t *testing.T) {
	t.Parallel()

	src := newMockTun(4, 1500, 0, 0)
	dst := newMockTun(1, 1500, 0, 0)
	dst.writeLimit = 1

	p2p := NewP2P(nil, nil)
	defer p2p.Stop()

	p2p.SetA(src)
	p2p.SetB(dst)

	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("left"),
			[]byte("right"),
		},
	})

	wantPackets := [][]byte{
		[]byte("left"),
		[]byte("right"),
	}
	if got := dst.waitForWrittenPackets(
		len(wantPackets),
		time.Second,
	); !reflect.DeepEqual(
		got,
		wantPackets,
	) {
		t.Fatalf("written packets = %q, want %q", got, wantPackets)
	}
}

func TestIOReadUsesTunBatchSizeAndBuffersRemainingPackets(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	src := newMockTun(4, 1500, 0, 0)
	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		},
	})

	r := NewIO(src, pool)

	buf := make([]byte, 16)

	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("first read error = %v", err)
	}
	if got := string(buf[:n]); got != "one" {
		t.Fatalf("first read = %q, want %q", got, "one")
	}

	n, err = r.Read(buf)
	if err != nil {
		t.Fatalf("second read error = %v", err)
	}
	if got := string(buf[:n]); got != "two" {
		t.Fatalf("second read = %q, want %q", got, "two")
	}

	n, err = r.Read(buf)
	if err != nil {
		t.Fatalf("third read error = %v", err)
	}
	if got := string(buf[:n]); got != "three" {
		t.Fatalf("third read = %q, want %q", got, "three")
	}

	src.Close()
	_, err = r.Read(buf)
	if !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("final read error = %v, want closed/EOF", err)
	}

	if got := src.readCallCount(); got != 2 {
		t.Fatalf("underlying read calls = %d, want 2", got)
	}
}

func TestIOPendingReadShortBufferKeepsPacket(t *testing.T) {
	t.Parallel()

	src := newMockTun(2, 32, 0, 0)
	src.enqueueRead(mockReadResult{
		packets: [][]byte{[]byte("a"), []byte("bcde")},
	})
	w := NewIO(src, nil)

	buf := make([]byte, 1)
	n, err := w.Read(buf)
	if err != nil || n != 1 || string(buf) != "a" {
		t.Fatalf("first Read() = %d, %v, %q; want 1, nil, a", n, err, buf)
	}

	n, err = w.Read(make([]byte, 2))
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short Read() = %d, %v; want 0, io.ErrShortBuffer", n, err)
	}

	buf = make([]byte, 4)
	n, err = w.Read(buf)
	if err != nil || n != 4 || string(buf) != "bcde" {
		t.Fatalf("retry Read() = %d, %v, %q; want 4, nil, bcde", n, err, buf)
	}
}

func TestDetachedTunReadShortBuffer(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	src := newMockTun(1, 32, 0, 0)
	d := Detach(src, nil, pool)
	defer func() {
		_ = d.Close()
		_ = src.Close()
		d.Wait()
	}()

	src.enqueueRead(mockReadResult{packets: [][]byte{[]byte("abcd")}})
	sizes := make([]int, 1)
	n, err := d.Read([][]byte{make([]byte, 2)}, sizes, 0)
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() = %d, %v; want 0, io.ErrShortBuffer", n, err)
	}
}

func TestSplitFrontendReadShortBuffer(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	backend := newMockTun(1, 32, 0, 0)
	s := NewSplitter(nil, pool)
	defer func() { _ = s.Close() }()
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)
	if err := f.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}

	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("abcd")}})
	sizes := make([]int, 1)
	n, err := f.Read([][]byte{make([]byte, 2)}, sizes, 0)
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() = %d, %v; want 0, io.ErrShortBuffer", n, err)
	}
}

func TestJoinerReadShortBuffer(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	src := newMockTun(1, 32, 0, 0)
	j := NewJoiner(nil, pool)
	defer func() { _ = j.Close() }()
	if err := j.AttachSecondary(src); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}

	src.enqueueRead(mockReadResult{packets: [][]byte{[]byte("abcd")}})
	sizes := make([]int, 1)
	n, err := j.Read([][]byte{make([]byte, j.MRO()+2)}, sizes, j.MRO())
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() = %d, %v; want 0, io.ErrShortBuffer", n, err)
	}
}

func TestJoinerWriteOffsetBeyondBuffer(t *testing.T) {
	t.Parallel()

	j := NewJoiner(nil, nil)
	defer func() { _ = j.Close() }()

	n, err := j.Write([][]byte{make([]byte, j.MWO())}, j.MWO()+1)
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Write() = %d, %v; want 0, io.ErrShortBuffer", n, err)
	}
}

func TestSplitterDropsOversizedBackendPacket(t *testing.T) {
	t.Parallel()

	backend := &oversizedReadTun{
		mockTun: newMockTun(1, 32, 0, 0),
		ready:   make(chan struct{}),
	}
	s := NewSplitter(nil, nil)
	defer func() { _ = s.Close() }()
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)
	if err := f.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}

	<-backend.ready
	done := make(chan error, 1)
	go func() {
		_, err := f.Read([][]byte{make([]byte, 32)}, make([]int, 1), 0)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("frontend received invalid packet; Read() error = %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = s.Close()
	<-done
}

type oversizedReadTun struct {
	*mockTun
	ready chan struct{}
	once  bool
}

func (t *oversizedReadTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if !t.once {
		t.once = true
		close(t.ready)
		sizes[0] = len(bufs[0]) - offset + 1
		return 1, nil
	}
	return t.mockTun.Read(bufs, sizes, offset)
}
