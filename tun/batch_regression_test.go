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

func (t *mockTun) File() *os.File { return nil }
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

func TestForwarderUsesIndependentReadAndWriteBatchSizes(t *testing.T) {
	t.Parallel()

	src := newMockTun(4, 1500, 2, 3)
	dst := newMockTun(1, 1500, 5, 7)
	dst.writeLimit = 1

	frw := NewForwarder(nil)
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

	src := newMockTun(4, 1500, 0, 0)
	dst := newMockTun(2, 1500, 0, 0)

	frw := NewForwarder(nil)
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

	p2p := NewP2P(nil)
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

	src := newMockTun(4, 1500, 0, 0)
	src.enqueueRead(mockReadResult{
		packets: [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		},
	})

	r := NewIO(src, nil)

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
