//nolint:testpackage // These tests inspect internal read-capacity state.
package tun

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
)

type capacityRead struct {
	packet        []byte
	reportSize    int
	setReportSize bool
	count         int
	setCount      bool
	err           error
}

type capacityTun struct {
	mu       sync.RWMutex
	mtu      int
	mtuErr   error
	mro      int
	batch    int
	events   chan Event
	reads    chan capacityRead
	readCaps chan int
	done     chan struct{}
	once     sync.Once
	active   atomic.Int32
	overlap  atomic.Bool
	readCall atomic.Int32
	writeErr error
}

func newCapacityTun(batch, mtu, mro int) *capacityTun {
	return &capacityTun{
		mtu:      mtu,
		mro:      mro,
		batch:    batch,
		events:   make(chan Event, 16),
		reads:    make(chan capacityRead, 16),
		readCaps: make(chan int, 16),
		done:     make(chan struct{}),
	}
}

func (t *capacityTun) File() *os.File { return nil }

func (t *capacityTun) IsNative() bool { return false }

func (t *capacityTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if t.active.Add(1) != 1 {
		t.overlap.Store(true)
	}
	defer t.active.Add(-1)
	t.readCall.Add(1)

	packetCapacity := -1
	if len(bufs) > 0 && offset >= 0 && offset <= len(bufs[0]) {
		packetCapacity = len(bufs[0]) - offset
	}
	select {
	case t.readCaps <- packetCapacity:
	case <-t.done:
		return 0, os.ErrClosed
	}

	select {
	case <-t.done:
		return 0, os.ErrClosed
	case result := <-t.reads:
		if (result.setReportSize || result.reportSize > 0) && len(sizes) > 0 {
			sizes[0] = result.reportSize
		}
		if len(result.packet) > 0 && len(bufs) > 0 && offset <= len(bufs[0]) {
			copy(bufs[0][offset:], result.packet)
			if result.reportSize == 0 && len(sizes) > 0 {
				sizes[0] = len(result.packet)
			}
		}
		if result.err != nil {
			return 0, result.err
		}
		if result.setCount {
			return result.count, nil
		}
		return 1, nil
	}
}

func (t *capacityTun) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.RLock()
	err := t.writeErr
	t.mu.RUnlock()
	if err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (t *capacityTun) MWO() int { return 0 }

func (t *capacityTun) MRO() int { return t.mro }

func (t *capacityTun) MTU() (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mtu, t.mtuErr
}

func (t *capacityTun) Name() (string, error) { return "capacity", nil }

func (t *capacityTun) Events() <-chan Event { return t.events }

func (t *capacityTun) Close() error {
	t.once.Do(func() {
		close(t.done)
		close(t.events)
	})
	return nil
}

func (t *capacityTun) BatchSize() int { return t.batch }

func (t *capacityTun) setMTU(mtu int) {
	t.mu.Lock()
	t.mtu = mtu
	t.mu.Unlock()
	t.events <- EventMTUUpdate
}

func (t *capacityTun) setWriteError(err error) {
	t.mu.Lock()
	t.writeErr = err
	t.mu.Unlock()
}

func TestDetachedTunGrowsAfterOversizedSuccessfulRead(t *testing.T) {
	for _, batch := range []int{1, 128} {
		t.Run(strconv.Itoa(batch), func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			source := newCapacityTun(batch, 1420, 8)
			detached := Detach(source, nil, pool)
			t.Cleanup(func() {
				_ = detached.Close()
				_ = source.Close()
				detached.Wait()
				pool.Close()
			})

			assertReadCapacity(t, source, 1420)
			source.setMTU(1428)
			source.reads <- capacityRead{reportSize: 1428}
			assertReadCapacity(t, source, 1428)

			packet := bytes.Repeat([]byte{7}, 1428)
			source.reads <- capacityRead{packet: packet}
			got := make([]byte, len(packet))
			sizes := make([]int, batch)
			n, err := detached.Read([][]byte{got}, sizes, 0)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if n != 1 || sizes[0] != len(packet) || !bytes.Equal(got, packet) {
				t.Fatalf(
					"Read() = %d, size %d; packet was changed",
					n,
					sizes[0],
				)
			}
			if source.overlap.Load() {
				t.Fatal("source Read calls overlapped")
			}
		})
	}
}

func TestDetachedTunGrowsAfterTypedShortBuffer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, pool)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
		pool.Close()
	})

	assertReadCapacity(t, source, 1420)
	source.setMTU(9000)
	source.reads <- capacityRead{err: io.ErrShortBuffer}
	assertReadCapacity(t, source, 9000)

	packet := bytes.Repeat([]byte{9}, 9000)
	source.reads <- capacityRead{packet: packet}
	got := make([]byte, len(packet))
	sizes := make([]int, 1)
	n, err := detached.Read([][]byte{got}, sizes, 0)
	if err != nil || n != 1 {
		t.Fatalf("Read() = %d, %v, want 1, nil", n, err)
	}
	if len(sizes) != 1 || sizes[0] != len(packet) {
		t.Fatalf("Read() size = %d, want %d", sizes[0], len(packet))
	}
	if !bytes.Equal(got, packet) {
		t.Fatal("Read() packet was changed")
	}
}

func TestDetachWithOptionsSetsInitialReadPacketSize(t *testing.T) {
	source := newCapacityTun(1, 1420, 4)
	detached := DetachWithOptions(
		source,
		nil,
		nil,
		DetachOptions{MinReadPacketSize: 9000},
	)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})

	assertReadCapacity(t, source, 9000)
}

func TestDetachedTunInvalidInitialMTUUsesFallback(t *testing.T) {
	for _, mtu := range []int{0, -1} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			source := newCapacityTun(1, mtu, 0)
			detached := Detach(source, nil, nil)
			t.Cleanup(func() {
				_ = detached.Close()
				_ = source.Close()
				detached.Wait()
			})
			assertReadCapacity(t, source, detachedTunFallbackReadPacketSize)
		})
	}

	source := newCapacityTun(1, 1420, 0)
	source.mtuErr = errors.New("MTU unavailable")
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertReadCapacity(t, source, detachedTunFallbackReadPacketSize)
}

func TestDetachedTunReadCapacityOverflowFailsConstruction(t *testing.T) {
	source := newCapacityTun(1, 1, int(^uint(0)>>1))
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})

	assertDetachedFailed(t, detached, nil)
	if calls := source.readCall.Load(); calls != 0 {
		t.Fatalf("source Read calls = %d, want 0", calls)
	}
}

func TestDetachedTunTerminalReadFailurePropagatesToNestedWrappers(
	t *testing.T,
) {
	source := newCapacityTun(1, 1420, 0)
	root := Detach(source, nil, nil)
	chain := make([]*DetachedTun, 1, 9)
	chain[0] = root
	for range 8 {
		chain = append(chain, Detach(chain[len(chain)-1], nil, nil))
	}
	t.Cleanup(func() {
		for i := len(chain) - 1; i >= 0; i-- {
			_ = chain[i].Close()
		}
		_ = source.Close()
		root.Wait()
	})
	for _, detached := range chain {
		assertEvent(t, detached.Events(), EventUp)
	}

	assertReadCapacity(t, source, 1420)
	cause := errors.New("terminal read failure")
	source.reads <- capacityRead{err: cause}
	assertEvent(t, root.Events(), EventDown)
	for i, detached := range chain {
		up, err := detached.IsUp()
		if err != nil || up {
			t.Fatalf("chain[%d].IsUp() = %v, %v, want false, nil", i, up, err)
		}
		buf := make([]byte, 1420)
		_, err = detached.Read([][]byte{buf}, make([]int, 1), 0)
		if !errors.Is(err, ErrDetachedTunFailed) || !errors.Is(err, cause) {
			t.Fatalf("chain[%d].Read() error = %v", i, err)
		}
	}
	if err := root.Up(); !errors.Is(err, cause) {
		t.Fatalf("Up() error = %v, want saved cause", err)
	}
	assertNoEvent(t, root.Events())
}

func TestDetachedTunTerminalWriteFailureChangesHealth(t *testing.T) {
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertEvent(t, detached.Events(), EventUp)
	assertReadCapacity(t, source, 1420)

	cause := errors.New("terminal write failure")
	source.setWriteError(cause)
	_, err := detached.Write([][]byte{{1}}, 0)
	if !errors.Is(err, ErrDetachedTunFailed) || !errors.Is(err, cause) {
		t.Fatalf("Write() error = %v", err)
	}
	assertDetachedFailed(t, detached, cause)
	assertEvent(t, detached.Events(), EventDown)
	assertNoEvent(t, detached.Events())
}

func TestDetachedTunSpawnerFailuresAreNotHealthy(t *testing.T) {
	for _, failAfter := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(failAfter), func(t *testing.T) {
			source := newCapacityTun(1, 1420, 0)
			spawnErr := errors.New("spawn failed")
			spawner := &countingFailingSpawner{
				failAfter: failAfter,
				err:       spawnErr,
			}
			detached := Detach(source, spawner, nil)
			_ = source.Close()
			detached.Wait()
			t.Cleanup(func() { _ = detached.Close() })

			assertDetachedFailed(t, detached, spawnErr)
		})
	}
}

func assertReadCapacity(t *testing.T, source *capacityTun, want int) {
	t.Helper()
	select {
	case got := <-source.readCaps:
		if got != want {
			t.Fatalf("source read packet capacity = %d, want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("source Read did not start with capacity %d", want)
	}
}

func assertDetachedFailed(t *testing.T, detached *DetachedTun, cause error) {
	t.Helper()
	up, err := detached.IsUp()
	if err != nil || up {
		t.Fatalf("IsUp() = %v, %v, want false, nil", up, err)
	}
	_, err = detached.Read([][]byte{make([]byte, 1)}, make([]int, 1), 0)
	if !errors.Is(err, ErrDetachedTunFailed) {
		t.Fatalf("Read() error = %v, want ErrDetachedTunFailed", err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("Read() error = %v, want cause %v", err, cause)
	}
	_, writeErr := detached.Write([][]byte{{1}}, 0)
	if !errors.Is(writeErr, ErrDetachedTunFailed) {
		t.Fatalf("Write() error = %v, want ErrDetachedTunFailed", writeErr)
	}
	if cause != nil && !errors.Is(writeErr, cause) {
		t.Fatalf("Write() error = %v, want cause %v", writeErr, cause)
	}
}

func assertEvent(t *testing.T, events <-chan Event, want Event) {
	t.Helper()
	select {
	case got := <-events:
		if got != want {
			t.Fatalf("Events() = %v, want %v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Events() timed out waiting for %v", want)
	}
}

func assertNoEvent(t *testing.T, events <-chan Event) {
	t.Helper()
	select {
	case event := <-events:
		t.Fatalf("Events() = %v, want no event", event)
	case <-time.After(50 * time.Millisecond):
	}
}
