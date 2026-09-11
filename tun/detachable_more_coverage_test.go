//nolint:testpackage // These tests exercise internal detached-Tun state.
package tun

import (
	"errors"
	"io"
	"testing"
	"time"
)

type detachedTemporaryError struct{}

func (*detachedTemporaryError) Error() string   { return "temporary read error" }
func (*detachedTemporaryError) Temporary() bool { return true }

type channelSourceTun struct {
	*capacityTun
	reads      chan detachedTunRead
	writes     chan *detachedTunWrite
	sourceDone chan struct{}
	sourceErr  error
}

func newChannelSourceTun(batch, mtu, mro int) *channelSourceTun {
	return &channelSourceTun{
		capacityTun: newCapacityTun(batch, mtu, mro),
		reads:       make(chan detachedTunRead, 1),
		writes:      make(chan *detachedTunWrite, 1),
		sourceDone:  make(chan struct{}),
	}
}

func (t *channelSourceTun) sourceSnapshot() (
	<-chan detachedTunRead,
	chan<- *detachedTunWrite,
	<-chan struct{},
	error,
) {
	if t.sourceErr != nil {
		return nil, nil, nil, t.sourceErr
	}
	return t.reads, t.writes, t.sourceDone, nil
}

func TestDetachedTunContinuesAfterTemporaryReadError(t *testing.T) {
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertReadCapacity(t, source, 1420)

	wantErr := &detachedTemporaryError{}
	source.reads <- capacityRead{err: wantErr}
	_, err := detached.Read([][]byte{make([]byte, 1420)}, make([]int, 1), 0)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Read() error = %v, want %v", err, wantErr)
	}
	if up, upErr := detached.IsUp(); upErr != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, upErr)
	}

	assertReadCapacity(t, source, 1420)
	source.reads <- capacityRead{packet: []byte("ok")}
	buf := make([]byte, 1420)
	sizes := make([]int, 1)
	n, err := detached.Read([][]byte{buf}, sizes, 0)
	if err != nil || n != 1 {
		t.Fatalf("Read() = %d, %v, want 1, nil", n, err)
	}
	if len(sizes) != 1 || sizes[0] != 2 || string(buf[:2]) != "ok" {
		t.Fatalf("Read() size and packet = %v, %q", sizes, buf[:2])
	}
}

func TestDetachedTunShortBufferWithoutLargerTargetFails(t *testing.T) {
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertEvent(t, detached.Events(), EventUp)
	assertReadCapacity(t, source, 1420)

	source.reads <- capacityRead{err: io.ErrShortBuffer}
	assertEvent(t, detached.Events(), EventDown)
	assertDetachedFailed(t, detached, io.ErrShortBuffer)
	if calls := source.readCall.Load(); calls != 1 {
		t.Fatalf("source Read calls = %d, want 1", calls)
	}
}

func TestDetachedTunCapacityRecoveryUsesReportedSizeWhenMTUFails(
	t *testing.T,
) {
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertReadCapacity(t, source, 1420)

	source.mu.Lock()
	source.mtuErr = errors.New("MTU unavailable during recovery")
	source.mu.Unlock()
	source.reads <- capacityRead{reportSize: 1500}
	assertReadCapacity(t, source, 1500)

	source.reads <- capacityRead{packet: []byte{1}}
	buf := make([]byte, 1)
	sizes := make([]int, 1)
	if n, err := detached.Read([][]byte{buf}, sizes, 0); err != nil || n != 1 {
		t.Fatalf("Read() = %d, %v, want 1, nil", n, err)
	}
}

func TestDetachedTunInvalidSuccessfulReadFails(t *testing.T) {
	tests := []struct {
		name   string
		result capacityRead
	}{
		{
			name: "packet count",
			result: capacityRead{
				count:    2,
				setCount: true,
			},
		},
		{
			name: "negative packet size",
			result: capacityRead{
				reportSize:    -1,
				setReportSize: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCapacityTun(1, 1420, 0)
			detached := Detach(source, nil, nil)
			t.Cleanup(func() {
				_ = detached.Close()
				_ = source.Close()
				detached.Wait()
			})
			assertEvent(t, detached.Events(), EventUp)
			assertReadCapacity(t, source, 1420)

			source.reads <- test.result
			assertEvent(t, detached.Events(), EventDown)
			assertDetachedFailed(t, detached, nil)
		})
	}
}

func TestDetachedTunReadCapacityOverflowAfterConstruction(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	tests := []struct {
		name   string
		update func(*capacityTun)
	}{
		{
			name: "MTU event",
			update: func(source *capacityTun) {
				source.setMTU(maxInt)
			},
		},
		{
			name: "reported size",
			update: func(source *capacityTun) {
				source.reads <- capacityRead{reportSize: maxInt}
			},
		},
		{
			name: "MTU during retry",
			update: func(source *capacityTun) {
				source.mu.Lock()
				source.mtu = maxInt
				source.mu.Unlock()
				source.reads <- capacityRead{err: io.ErrShortBuffer}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCapacityTun(1, 1420, 1)
			detached := Detach(source, nil, nil)
			t.Cleanup(func() {
				_ = detached.Close()
				_ = source.Close()
				detached.Wait()
			})
			assertEvent(t, detached.Events(), EventUp)
			assertReadCapacity(t, source, 1420)

			test.update(source)
			assertEvent(t, detached.Events(), EventDown)
			assertDetachedFailed(t, detached, nil)
		})
	}
}

func TestDetachChannelSourceConstructionBranches(t *testing.T) {
	t.Run("owning batch normalization", func(t *testing.T) {
		source := newCapacityTun(0, 1420, 0)
		detached := Detach(source, nil, nil)
		t.Cleanup(func() {
			_ = detached.Close()
			_ = source.Close()
			detached.Wait()
		})
		if detached.BatchSize() != 1 {
			t.Fatalf("BatchSize() = %d, want 1", detached.BatchSize())
		}
		assertReadCapacity(t, source, 1420)
	})

	t.Run("fallback and batch normalization", func(t *testing.T) {
		source := newChannelSourceTun(0, 0, 4)
		detached := DetachWithOptions(
			source,
			nil,
			nil,
			DetachOptions{MinReadPacketSize: 9000},
		)
		t.Cleanup(func() {
			_ = detached.Close()
			_ = source.Close()
		})
		if detached.BatchSize() != 1 {
			t.Fatalf("BatchSize() = %d, want 1", detached.BatchSize())
		}
		if detached.readLen != 4+detachedTunFallbackReadPacketSize {
			t.Fatalf("readLen = %d", detached.readLen)
		}
		assertEvent(t, detached.Events(), EventUp)
		if err := detached.Up(); err != nil {
			t.Fatalf("Up() error = %v", err)
		}
	})

	t.Run("capacity overflow", func(t *testing.T) {
		source := newChannelSourceTun(1, 1, int(^uint(0)>>1))
		detached := Detach(source, nil, nil)
		t.Cleanup(func() {
			_ = detached.Close()
			_ = source.Close()
		})
		assertDetachedFailed(t, detached, nil)
	})

	t.Run("source snapshot error", func(t *testing.T) {
		source := newChannelSourceTun(1, 1420, 0)
		wantErr := errors.New("source snapshot failed")
		source.sourceErr = wantErr
		detached := Detach(source, nil, nil)
		t.Cleanup(func() {
			_ = detached.Close()
			_ = source.Close()
		})
		assertDetachedFailed(t, detached, wantErr)
	})

	t.Run("event pump spawn error", func(t *testing.T) {
		source := newChannelSourceTun(1, 1420, 0)
		wantErr := errors.New("event spawn failed")
		detached := Detach(source, &failingSpawner{err: wantErr}, nil)
		t.Cleanup(func() {
			_ = detached.Close()
			_ = source.Close()
		})
		assertDetachedFailed(t, detached, wantErr)
	})
}

func TestDetachNestedOptionAndConstructionFailures(t *testing.T) {
	t.Run("option grows root", func(t *testing.T) {
		source := newCapacityTun(1, 1420, 0)
		root := Detach(source, nil, nil)
		assertReadCapacity(t, source, 1420)
		child := DetachWithOptions(
			root,
			nil,
			nil,
			DetachOptions{MinReadPacketSize: 9000},
		)
		t.Cleanup(func() {
			_ = child.Close()
			_ = root.Close()
			_ = source.Close()
			root.Wait()
		})

		source.reads <- capacityRead{packet: []byte{1}}
		if n, err := child.Read(
			[][]byte{make([]byte, 1)},
			make([]int, 1),
			0,
		); err != nil || n != 1 {
			t.Fatalf("Read() = %d, %v, want 1, nil", n, err)
		}
		assertReadCapacity(t, source, 9000)

		grandchild := DetachWithOptions(
			child,
			nil,
			nil,
			DetachOptions{MinReadPacketSize: 12000},
		)
		t.Cleanup(func() { _ = grandchild.Close() })
		source.reads <- capacityRead{packet: []byte{2}}
		if n, err := grandchild.Read(
			[][]byte{make([]byte, 1)},
			make([]int, 1),
			0,
		); err != nil || n != 1 {
			t.Fatalf("grandchild Read() = %d, %v, want 1, nil", n, err)
		}
		assertReadCapacity(t, source, 12000)
	})

	t.Run("parent down", func(t *testing.T) {
		source := newCapacityTun(1, 1420, 0)
		root := Detach(source, nil, nil)
		assertReadCapacity(t, source, 1420)
		if err := root.Down(); err != nil {
			t.Fatalf("Down() error = %v", err)
		}
		child := Detach(root, nil, nil)
		t.Cleanup(func() {
			_ = child.Close()
			_ = root.Close()
			_ = source.Close()
			root.Wait()
		})
		assertDetachedFailed(t, child, ErrDetachedTunDown)
	})

	t.Run("event pump spawn error", func(t *testing.T) {
		source := newCapacityTun(1, 1420, 0)
		root := Detach(source, nil, nil)
		assertReadCapacity(t, source, 1420)
		wantErr := errors.New("nested event spawn failed")
		child := Detach(root, &failingSpawner{err: wantErr}, nil)
		t.Cleanup(func() {
			_ = child.Close()
			_ = root.Close()
			_ = source.Close()
			root.Wait()
		})
		assertDetachedFailed(t, child, wantErr)
	})
}

func TestDetachedTunUpErrorBranches(t *testing.T) {
	source := newCapacityTun(1, 1420, 0)
	root := Detach(source, nil, nil)
	child := Detach(root, nil, nil)
	t.Cleanup(func() {
		_ = child.Close()
		_ = root.Close()
		_ = source.Close()
		root.Wait()
	})
	assertReadCapacity(t, source, 1420)

	if err := child.Up(); err != nil {
		t.Fatalf("healthy child Up() error = %v", err)
	}
	if err := root.Down(); err != nil {
		t.Fatalf("root Down() error = %v", err)
	}
	if err := root.Down(); err != nil {
		t.Fatalf("second root Down() error = %v", err)
	}
	if err := child.Up(); !errors.Is(err, ErrDetachedTunDown) {
		t.Fatalf("child Up() error = %v, want ErrDetachedTunDown", err)
	}
	if _, err := child.Write([][]byte{{1}}, 0); !errors.Is(
		err,
		ErrDetachedTunDown,
	) {
		t.Fatalf("child Write() error = %v, want ErrDetachedTunDown", err)
	}
	if err := child.Down(); err != nil {
		t.Fatalf("child Down() error = %v", err)
	}
	if err := child.Up(); !errors.Is(err, ErrDetachedTunDown) {
		t.Fatalf("down child Up() error = %v, want ErrDetachedTunDown", err)
	}

	root.spawner = &failingSpawner{err: errors.New("restart spawn failed")}
	if err := root.Up(); !errors.Is(err, ErrDetachedTunFailed) {
		t.Fatalf("root Up() error = %v, want ErrDetachedTunFailed", err)
	}
	if err := root.Up(); !errors.Is(err, ErrDetachedTunFailed) {
		t.Fatalf("failed root Up() error = %v", err)
	}

	closedSource := newCapacityTun(1, 1420, 0)
	closed := Detach(closedSource, nil, nil)
	assertReadCapacity(t, closedSource, 1420)
	_ = closed.Close()
	_ = closedSource.Close()
	closed.Wait()
	if err := closed.Up(); !errors.Is(err, ErrDetachedTunClosed) {
		t.Fatalf("closed Up() error = %v", err)
	}
}

func TestDetachedTunInternalStateAndChannelBranches(t *testing.T) {
	if _, err := detachedTunReadLen(-1, 1); err == nil {
		t.Fatal("detachedTunReadLen accepted a negative MRO")
	}
	if _, err := detachedTunReadLen(0, 0); err == nil {
		t.Fatal("detachedTunReadLen accepted a zero packet size")
	}
	if got := readBufferLength(nil); got != 0 {
		t.Fatalf("readBufferLength(nil) = %d, want 0", got)
	}

	standalone := &DetachedTun{up: true}
	if err := standalone.growReadPacketSize(1); err != nil {
		t.Fatalf("growReadPacketSize() error = %v", err)
	}
	if err := standalone.recordMTU(0); err != nil {
		t.Fatalf("recordMTU(0) error = %v", err)
	}
	if got := standalone.operationErr(io.EOF); !errors.Is(got, io.EOF) {
		t.Fatalf("operationErr() = %v, want io.EOF", got)
	}

	d := &DetachedTun{
		events:    make(chan Event, 1),
		eventSubs: make(map[chan Event]struct{}),
	}
	sub := d.subscribeEvents()
	d.sendEvent(EventUp)
	d.sendEvent(EventDown)
	for range cap(sub) {
		d.sendEvent(EventMTUUpdate)
	}
	d.closeEvents()
	d.sendEvent(EventUp)
	d.closeEvents()
	late := d.subscribeEvents()
	select {
	case _, ok := <-late:
		if ok {
			t.Fatal("late event subscription remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("late event subscription did not close")
	}

	done := make(chan struct{})
	close(done)
	req := newDetachedTunWrite(nil, nil, [][]byte{{1}}, 1)
	if err := enqueueDetachedTunWrite(
		make(chan *detachedTunWrite),
		done,
		req,
		io.EOF,
	); !errors.Is(err, io.EOF) {
		t.Fatalf("enqueueDetachedTunWrite() error = %v", err)
	}

	writes := make(chan *detachedTunWrite)
	close(writes)
	drainDetachedTunWrites(writes, io.EOF)
	reads := make(chan detachedTunRead)
	close(reads)
	drainDetachedTunReads(reads)

	resp := &detachedTunWrite{resp: make(chan detachedTunWriteResult, 1)}
	resp.respond(1, nil)
	resp.respond(2, io.EOF)

	pump := &DetachedTun{
		up:        true,
		gen:       1,
		done:      make(chan struct{}),
		events:    make(chan Event, 1),
		eventSubs: make(map[chan Event]struct{}),
	}
	if err := pump.failPump(2, io.EOF); !errors.Is(err, ErrDetachedTunDown) {
		t.Fatalf("stale failPump() error = %v", err)
	}
	firstFailure := pump.failPump(1, nil)
	if !errors.Is(firstFailure, ErrDetachedTunFailed) {
		t.Fatalf("failPump() error = %v", firstFailure)
	}
	if got := pump.failPump(1, io.EOF); !errors.Is(got, firstFailure) {
		t.Fatalf("second failPump() error = %v, want saved error", got)
	}

	closedDone := make(chan struct{})
	close(closedDone)
	if pump.sendReadError(
		closedDone,
		make(chan detachedTunRead),
		io.EOF,
	) {
		t.Fatal("sendReadError() sent after done closed")
	}

	downWrapper := &DetachedTun{}
	downWrapper.forwardStaleRead([][]byte{{1}})
	healthyWrapper := &DetachedTun{
		up:        true,
		ownsPumps: true,
		reads:     make(chan detachedTunRead, 1),
		done:      make(chan struct{}),
	}
	healthyWrapper.forwardStaleRead([][]byte{{2}})
	read := <-healthyWrapper.reads
	releaseDetachedTunRead(read)
}

func TestDetachedTunPublicInputErrors(t *testing.T) {
	source := newCapacityTun(1, 1420, 0)
	detached := Detach(source, nil, nil)
	t.Cleanup(func() {
		_ = detached.Close()
		_ = source.Close()
		detached.Wait()
	})
	assertReadCapacity(t, source, 1420)

	if _, err := detached.Read(nil, nil, -1); err == nil {
		t.Fatal("Read() accepted a negative offset")
	}
	if _, err := detached.Write(nil, -1); err == nil {
		t.Fatal("Write() accepted a negative offset")
	}
	if _, err := detached.Write([][]byte{{1}}, 2); !errors.Is(
		err,
		io.ErrShortBuffer,
	) {
		t.Fatalf("Write() error = %v, want io.ErrShortBuffer", err)
	}
}

var _ interface {
	Temporary() bool
} = (*detachedTemporaryError)(nil)

var _ tunChannelSource = (*channelSourceTun)(nil)
