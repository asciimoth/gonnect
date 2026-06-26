// nolint
package tun

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
)

const queuedWriteLeakRaceIterations = 64

func TestDetachedTunQueuedWriteBuffersReturnedOnClose(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	base := newBlockingWriteTun(1, 1500, 0, 0)
	d := Detach(base, pool)

	base.waitReadStarted(t, "detached base read", 1)
	first := writeTunAsync(d, "first")
	base.waitWriteStarted(t, "detached first write", 1)
	second := writeTunAsync(d, "second")
	waitQueueLen(t, "detached queued write", func() int {
		return len(d.writes)
	}, 1)

	if err := d.Close(); err != nil {
		t.Fatalf("DetachedTun.Close() error = %v", err)
	}
	assertWriteDone(t, "detached first write", first)
	assertWriteDone(t, "detached second write", second)

	base.releaseWrites()
	if err := base.Close(); err != nil {
		t.Fatalf("base Close() error = %v", err)
	}
	base.waitWriteFinished(t, "detached base write", 1)
	base.waitReadFinished(t, "detached base read", 1)
	d.wg.Wait()

	pool.Close()
}

func TestSplitterQueuedWriteBuffersReturnedOnClose(t *testing.T) {
	for range queuedWriteLeakRaceIterations {
		pool := bufpool.NewTestDebugPool(t)
		base := newBlockingWriteTun(1, 1500, 0, 0)
		s := NewSplitter(pool)
		f := s.Get(1)
		if err := s.Attach(base); err != nil {
			t.Fatalf("Splitter.Attach() error = %v", err)
		}

		base.waitReadStarted(t, "splitter backend read", 1)
		first := writeTunAsync(f, "first")
		base.waitWriteStarted(t, "splitter first write", 1)
		second := writeTunAsync(f, "second")
		waitQueueLen(t, "splitter queued write", func() int {
			return len(s.writes)
		}, 1)

		if err := s.Close(); err != nil {
			t.Fatalf("Splitter.Close() error = %v", err)
		}
		assertWriteDone(t, "splitter first write", first)
		assertWriteDone(t, "splitter second write", second)

		pool.Close()
	}
}

func TestJoinerQueuedWriteBuffersReturnedOnClose(t *testing.T) {
	for range queuedWriteLeakRaceIterations {
		pool := bufpool.NewTestDebugPool(t)
		base := newBlockingWriteTun(1, 1500, 0, 0)
		j := NewJoiner(pool)
		if err := j.AttachDefault(base); err != nil {
			t.Fatalf("Joiner.AttachDefault() error = %v", err)
		}
		d := Detach(j, pool)

		base.waitReadStarted(t, "joiner nested read", 1)
		first := writeTunAsync(d, "first")
		base.waitWriteStarted(t, "joiner first write", 1)
		second := writeTunAsync(d, "second")
		waitQueueLen(t, "joiner queued write", func() int {
			return len(j.writes)
		}, 1)

		if err := j.Close(); err != nil {
			t.Fatalf("Joiner.Close() error = %v", err)
		}
		if err := d.Close(); err != nil {
			t.Fatalf("detached Joiner Close() error = %v", err)
		}
		assertWriteDone(t, "joiner first write", first)
		assertWriteDone(t, "joiner second write", second)

		pool.Close()
	}
}

func TestDetachedTunQueuedReadBuffersReturnedOnClose(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	base := newQueuedReadTun(1, 1500, 0, 0)
	d := Detach(base, pool)

	base.waitReadStarted(t, "detached base read", 1)
	base.queueRead([]byte("queued-read"))
	waitQueueLen(t, "detached queued read", func() int {
		return len(d.reads)
	}, 1)

	if err := d.Close(); err != nil {
		t.Fatalf("DetachedTun.Close() error = %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("base Close() error = %v", err)
	}
	d.wg.Wait()

	pool.Close()
}

func TestJoinerQueuedReadBuffersReturnedOnClose(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	base := newQueuedReadTun(1, 1500, 0, 0)
	j := NewJoiner(pool)
	if err := j.AttachDefault(base); err != nil {
		t.Fatalf("Joiner.AttachDefault() error = %v", err)
	}

	base.waitReadStarted(t, "joiner nested read", 1)
	base.queueRead([]byte("queued-read"))
	waitQueueLen(t, "joiner queued read", func() int {
		return len(j.reads)
	}, 1)

	if err := j.Close(); err != nil {
		t.Fatalf("Joiner.Close() error = %v", err)
	}

	pool.Close()
}

type blockingWriteTun struct {
	done           chan struct{}
	events         chan Event
	writeStarted   chan struct{}
	writeFinished  chan struct{}
	readStarted    chan struct{}
	readFinished   chan struct{}
	releaseWriteCh chan struct{}
	closeOnce      sync.Once
	releaseOnce    sync.Once
	batch          int
	mtu            int
	mwo            int
	mro            int
}

func newBlockingWriteTun(batch, mtu, mwo, mro int) *blockingWriteTun {
	return &blockingWriteTun{
		done:           make(chan struct{}),
		events:         make(chan Event),
		writeStarted:   make(chan struct{}, 16),
		writeFinished:  make(chan struct{}, 16),
		readStarted:    make(chan struct{}, 16),
		readFinished:   make(chan struct{}, 16),
		releaseWriteCh: make(chan struct{}),
		batch:          batch,
		mtu:            mtu,
		mwo:            mwo,
		mro:            mro,
	}
}

func (t *blockingWriteTun) File() *os.File { return nil }
func (t *blockingWriteTun) IsNative() bool { return false }
func (t *blockingWriteTun) MWO() int       { return t.mwo }
func (t *blockingWriteTun) MRO() int       { return t.mro }
func (t *blockingWriteTun) MTU() (int, error) {
	return t.mtu, nil
}
func (t *blockingWriteTun) Name() (string, error) {
	return "blocking-write-tun", nil
}
func (t *blockingWriteTun) Events() <-chan Event { return t.events }
func (t *blockingWriteTun) BatchSize() int       { return t.batch }

func (t *blockingWriteTun) Read(
	_ [][]byte,
	_ []int,
	_ int,
) (int, error) {
	signalRegressionEvent(t.readStarted)
	defer signalRegressionEvent(t.readFinished)
	<-t.done
	return 0, os.ErrClosed
}

func (t *blockingWriteTun) Write(bufs [][]byte, _ int) (int, error) {
	signalRegressionEvent(t.writeStarted)
	defer signalRegressionEvent(t.writeFinished)
	select {
	case <-t.releaseWriteCh:
		return len(bufs), nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *blockingWriteTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func (t *blockingWriteTun) releaseWrites() {
	t.releaseOnce.Do(func() {
		close(t.releaseWriteCh)
	})
}

func (t *blockingWriteTun) waitReadStarted(
	tb testing.TB,
	label string,
	count int,
) {
	tb.Helper()
	waitRegressionSignals(tb, label, t.readStarted, count)
}

func (t *blockingWriteTun) waitReadFinished(
	tb testing.TB,
	label string,
	count int,
) {
	tb.Helper()
	waitRegressionSignals(tb, label, t.readFinished, count)
}

func (t *blockingWriteTun) waitWriteStarted(
	tb testing.TB,
	label string,
	count int,
) {
	tb.Helper()
	waitRegressionSignals(tb, label, t.writeStarted, count)
}

func (t *blockingWriteTun) waitWriteFinished(
	tb testing.TB,
	label string,
	count int,
) {
	tb.Helper()
	waitRegressionSignals(tb, label, t.writeFinished, count)
}

type queuedReadTun struct {
	done        chan struct{}
	events      chan Event
	packets     chan []byte
	readStarted chan struct{}
	closeOnce   sync.Once
	batch       int
	mtu         int
	mwo         int
	mro         int
}

func newQueuedReadTun(batch, mtu, mwo, mro int) *queuedReadTun {
	return &queuedReadTun{
		done:        make(chan struct{}),
		events:      make(chan Event),
		packets:     make(chan []byte, 16),
		readStarted: make(chan struct{}, 16),
		batch:       batch,
		mtu:         mtu,
		mwo:         mwo,
		mro:         mro,
	}
}

func (t *queuedReadTun) File() *os.File { return nil }
func (t *queuedReadTun) IsNative() bool { return false }
func (t *queuedReadTun) MWO() int       { return t.mwo }
func (t *queuedReadTun) MRO() int       { return t.mro }
func (t *queuedReadTun) MTU() (int, error) {
	return t.mtu, nil
}
func (t *queuedReadTun) Name() (string, error) { return "queued-read-tun", nil }
func (t *queuedReadTun) Events() <-chan Event  { return t.events }
func (t *queuedReadTun) BatchSize() int        { return t.batch }

func (t *queuedReadTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	signalRegressionEvent(t.readStarted)
	select {
	case packet := <-t.packets:
		if len(bufs) == 0 || len(sizes) == 0 {
			return 0, errMockTooManySegments
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *queuedReadTun) Write(bufs [][]byte, _ int) (int, error) {
	select {
	case <-t.done:
		return 0, os.ErrClosed
	default:
		return len(bufs), nil
	}
}

func (t *queuedReadTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func (t *queuedReadTun) queueRead(packet []byte) {
	t.packets <- append([]byte(nil), packet...)
}

func (t *queuedReadTun) waitReadStarted(
	tb testing.TB,
	label string,
	count int,
) {
	tb.Helper()
	waitRegressionSignals(tb, label, t.readStarted, count)
}

type writeResult struct {
	n   int
	err error
}

func writeTunAsync(tun Tun, payload string) <-chan writeResult {
	ch := make(chan writeResult, 1)
	go func() {
		n, err := tun.Write(
			[][]byte{withOffset(tun.MWO(), []byte(payload))},
			tun.MWO(),
		)
		ch <- writeResult{n: n, err: err}
	}()
	return ch
}

func assertWriteDone(
	t *testing.T,
	label string,
	ch <-chan writeResult,
) {
	t.Helper()
	select {
	case res := <-ch:
		if res.err != nil && !errors.Is(res.err, os.ErrClosed) {
			t.Fatalf("%s error = %v, want nil or closed", label, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s timed out", label)
	}
}

func waitQueueLen(
	t *testing.T,
	label string,
	queueLen func() int,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := queueLen(); got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s queue len = %d, want at least %d", label, queueLen(), want)
}

func signalRegressionEvent(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func waitRegressionSignals(
	tb testing.TB,
	label string,
	ch <-chan struct{},
	count int,
) {
	tb.Helper()
	for i := 0; i < count; i++ {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			tb.Fatalf("%s signal count = %d, want %d", label, i, count)
		}
	}
}
