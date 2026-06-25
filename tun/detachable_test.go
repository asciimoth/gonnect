// nolint
package tun_test

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

func TestDetachedTunDownUnblocksPendingRead(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := wrapper.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not unblock Read()")
	}

	done := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{1}}, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrapped Tun was closed by wrapper Down(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped Tun did not remain usable after wrapper Down()")
	}
}

func TestDetachedTunDownUnblocksPendingWrite(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([][]byte{{7}}, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Write() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not unblock Write()")
	}

	buf := make([]byte, 1500)
	sizes := make([]int, 1)
	_, err := b.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("wrapped Tun was closed by wrapper Down(): %v", err)
	}
}

func TestDetachedTunCloseDoesNotCloseWrappedTun(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := wrapper.Write(
		[][]byte{{1}},
		0,
	); !errors.Is(
		err,
		os.ErrClosed,
	) {
		t.Fatalf("Write() after Close() error = %v, want closed error", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{1}}, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrapped Tun was closed by wrapper Close(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped Tun did not remain usable after wrapper Close()")
	}
}

func TestDetachedTunCloseUnblocksPendingRead(t *testing.T) {
	base := newEventTun(1500)
	defer closeTestTun(t, base)
	wrapper := tun.Detach(base)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := wrapper.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()
	base.WaitReadStarted(t)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertAsyncErr(
		t,
		"pending Read after DetachedTun.Close",
		errCh,
		os.ErrClosed,
	)
}

func TestDetachedTunCloseUnblocksPendingWrite(t *testing.T) {
	base := newEventTun(1500)
	defer closeTestTun(t, base)
	wrapper := tun.Detach(base)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([][]byte{{7}}, 0)
		errCh <- err
	}()
	base.WaitWriteStarted(t)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertAsyncErr(
		t,
		"pending Write after DetachedTun.Close",
		errCh,
		os.ErrClosed,
	)
}

func TestDetachedTunWrappedCloseUnblocksPendingRead(t *testing.T) {
	base := newEventTun(1500)
	wrapper := tun.Detach(base)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := wrapper.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()
	base.WaitReadStarted(t)

	if err := base.Close(); err != nil {
		t.Fatalf("base Close() error = %v", err)
	}
	assertAsyncErr(t, "pending Read after wrapped Close", errCh, os.ErrClosed)
}

func TestDetachedTunWrappedCloseUnblocksPendingWrite(t *testing.T) {
	base := newEventTun(1500)
	wrapper := tun.Detach(base)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([][]byte{{8}}, 0)
		errCh <- err
	}()
	base.WaitWriteStarted(t)

	if err := base.Close(); err != nil {
		t.Fatalf("base Close() error = %v", err)
	}
	assertAsyncErr(t, "pending Write after wrapped Close", errCh, os.ErrClosed)
}

func TestDetachedTunIsNativeCachedFromWrappedTun(t *testing.T) {
	base := newEventTun(1500)
	base.SetNative(true)
	wrapper := tun.Detach(base)
	child := tun.Detach(wrapper)
	t.Cleanup(func() {
		closeTestTun(t, child)
		closeTestTun(t, wrapper)
		closeTestTun(t, base)
	})

	if !wrapper.IsNative() {
		t.Fatal(
			"DetachedTun IsNative() = false, want wrapped Tun native status",
		)
	}
	if !child.IsNative() {
		t.Fatal(
			"nested DetachedTun IsNative() = false, want parent native status",
		)
	}

	base.SetNative(false)
	if !wrapper.IsNative() {
		t.Fatal("DetachedTun IsNative() changed after construction")
	}
	if !child.IsNative() {
		t.Fatal("nested DetachedTun IsNative() changed after construction")
	}
	if got := base.NativeCalls(); got != 1 {
		t.Fatalf("wrapped Tun IsNative() calls = %d, want 1", got)
	}
}

func TestNestedDetachedTunParentCloseUnblocksPendingChildRead(t *testing.T) {
	base := newEventTun(1500)
	defer closeTestTun(t, base)
	parent := tun.Detach(base)
	child := tun.Detach(parent)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := child.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()
	base.WaitReadStarted(t)

	if err := parent.Close(); err != nil {
		t.Fatalf("parent Close() error = %v", err)
	}
	assertAsyncErr(
		t,
		"pending child Read after parent Close",
		errCh,
		os.ErrClosed,
	)
}

func TestNestedDetachedTunParentCloseUnblocksPendingChildWrite(t *testing.T) {
	base := newEventTun(1500)
	defer closeTestTun(t, base)
	parent := tun.Detach(base)
	child := tun.Detach(parent)

	errCh := make(chan error, 1)
	go func() {
		_, err := child.Write([][]byte{{9}}, 0)
		errCh <- err
	}()
	base.WaitWriteStarted(t)

	if err := parent.Close(); err != nil {
		t.Fatalf("parent Close() error = %v", err)
	}
	assertAsyncErr(
		t,
		"pending child Write after parent Close",
		errCh,
		os.ErrClosed,
	)
}

func TestNestedDetachedTunParentDownUnblocksChildRead(t *testing.T) {
	a, _ := tun.Pipe(1, 1500, 0, 0)
	parent := tun.Detach(a)
	child := tun.Detach(parent)
	grandchild := tun.Detach(child)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := grandchild.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := parent.Down(); err != nil {
		t.Fatalf("parent Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("nested Read() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent Down() did not unblock nested Read()")
	}
}

func TestNestedDetachedTunChildDownDoesNotStopParent(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	parent := tun.Detach(a)
	child := tun.Detach(parent)

	if err := child.Down(); err != nil {
		t.Fatalf("child Down() error = %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{9}}, 0)
		writeDone <- err
	}()

	buf := make([]byte, 1500)
	sizes := make([]int, 1)
	n, err := parent.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("parent Read() after child Down() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("parent Read() n = %d, want 1", n)
	}
	if len(sizes) == 0 {
		t.Fatal("parent Read() sizes is empty")
	}
	size := sizes[0]
	if size != 1 {
		t.Fatalf("parent Read() size = %d, want 1", size)
	}
	if buf[0] != 9 {
		t.Fatalf(
			"parent Read() byte = %d, want 9",
			buf[0],
		)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("peer Write() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer Write() did not complete")
	}
}

func TestNestedDetachedTunLongChainDownUpCloseScopeAndEvents(t *testing.T) {
	base := newEventTun(1500)
	defer closeTestTun(t, base)

	chain := detachedTunChain(base, 6)
	drainDetachedUpEvents(t, chain)
	assertDetachedPacketIO(t, "initial chain", chain[5], base, 11)

	if err := chain[2].Down(); err != nil {
		t.Fatalf("chain[2].Down() error = %v", err)
	}
	assertDetachedMTU(t, chain[:2], 1500)
	assertDetachedMTUErr(t, chain[2:], os.ErrClosed)
	assertDetachedEvents(t, chain[2:], tun.EventDown)
	assertNoDetachedEvents(t, chain[:2])
	assertDetachedPacketIO(t, "after middle down", chain[1], base, 12)
	assertDetachedPacketIOErr(t, "down wrapper", chain[2])

	if err := chain[2].Up(); err != nil {
		t.Fatalf("chain[2].Up() error = %v", err)
	}
	assertDetachedMTU(t, chain, 1500)
	assertDetachedEvents(t, chain[2:], tun.EventUp)
	assertNoDetachedEvents(t, chain[:2])
	assertDetachedPacketIO(t, "after middle up", chain[5], base, 14)

	if err := chain[2].Close(); err != nil {
		t.Fatalf("chain[2].Close() error = %v", err)
	}
	assertDetachedMTU(t, chain[:2], 1500)
	assertDetachedMTUErr(t, chain[2:], os.ErrClosed)
	assertDetachedEvents(t, chain[2:], tun.EventDown)
	assertDetachedEventsClosed(t, chain[2:])
	assertNoDetachedEvents(t, chain[:2])
	assertDetachedPacketIO(t, "after middle close", chain[1], base, 15)
	assertDetachedPacketIOErr(t, "closed wrapper", chain[2])

	replacement := tun.Detach(chain[1])
	assertDetachedEvent(t, 2, replacement.Events(), tun.EventUp)
	assertDetachedPacketIO(t, "replacement wrapper", replacement, base, 17)
	assertDetachedMTU(
		t,
		[]*tun.DetachedTun{chain[0], chain[1], replacement},
		1500,
	)
	assertDetachedMTUErr(t, chain[2:], os.ErrClosed)
	assertDetachedEventsClosed(t, chain[2:])

	replacementChild := tun.Detach(replacement)
	assertDetachedEvent(t, 3, replacementChild.Events(), tun.EventUp)
	assertDetachedPacketIO(t, "replacement child", replacementChild, base, 18)
	assertNoDetachedEvents(
		t,
		[]*tun.DetachedTun{chain[0], chain[1], replacement},
	)
}

func TestNestedDetachedTunLongChainMTUUpdatePropagation(t *testing.T) {
	base := newEventTun(1280)
	defer closeTestTun(t, base)

	chain := detachedTunChain(base, 8)
	drainDetachedUpEvents(t, chain)
	assertDetachedPacketIO(t, "initial mtu chain", chain[7], base, 21)

	base.SetMTU(1420)

	assertDetachedMTU(t, chain, 1420)
	assertDetachedEvents(t, chain, tun.EventMTUUpdate)
	assertNoDetachedEvents(t, chain)
	assertDetachedPacketIO(t, "after mtu 1420", chain[7], base, 22)

	base.SetMTU(900)

	assertDetachedMTU(t, chain, 900)
	assertDetachedEvents(t, chain, tun.EventMTUUpdate)
	assertNoDetachedEvents(t, chain)
	assertDetachedPacketIO(t, "after mtu 900", chain[7], base, 23)
}

type eventTun struct {
	mu          sync.RWMutex
	mtu         int
	events      chan tun.Event
	in          *tun.Channel
	out         *tun.Channel
	reads       chan struct{}
	writes      chan struct{}
	done        chan struct{}
	once        sync.Once
	native      bool
	nativeCalls int
}

func newEventTun(mtu int) *eventTun {
	return &eventTun{
		mtu:    mtu,
		events: make(chan tun.Event, 16),
		in:     tun.NewChan(),
		out:    tun.NewChan(),
		reads:  make(chan struct{}, 16),
		writes: make(chan struct{}, 16),
		done:   make(chan struct{}),
	}
}

func (t *eventTun) File() *os.File { return nil }

func (t *eventTun) IsNative() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nativeCalls++
	return t.native
}

func (t *eventTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	signalStarted(t.reads)
	n, err := t.in.Read(bufs, sizes, offset)
	if errors.Is(err, os.ErrClosed) {
		return n, os.ErrClosed
	}
	return n, err
}

func (t *eventTun) Write(bufs [][]byte, offset int) (int, error) {
	signalStarted(t.writes)
	n, err := t.out.Write(bufs, offset)
	if errors.Is(err, os.ErrClosed) {
		return n, os.ErrClosed
	}
	return n, err
}

func (t *eventTun) MWO() int { return 0 }

func (t *eventTun) MRO() int { return 0 }

func (t *eventTun) MTU() (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mtu, nil
}

func (t *eventTun) Name() (string, error) { return "event-tun", nil }

func (t *eventTun) Events() <-chan tun.Event { return t.events }

func (t *eventTun) Close() error {
	t.once.Do(func() {
		close(t.done)
		_ = t.in.Close()
		_ = t.out.Close()
		close(t.events)
	})
	return nil
}

func (t *eventTun) BatchSize() int { return 1 }

func (t *eventTun) SetMTU(mtu int) {
	t.mu.Lock()
	t.mtu = mtu
	t.mu.Unlock()
	t.events <- tun.EventMTUUpdate
}

func (t *eventTun) SetNative(native bool) {
	t.mu.Lock()
	t.native = native
	t.mu.Unlock()
}

func (t *eventTun) NativeCalls() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.nativeCalls
}

func (t *eventTun) Send(packet []byte) error {
	_, err := t.in.Write([][]byte{packet}, 0)
	return err
}

func (t *eventTun) Recv() ([]byte, error) {
	buf := make([]byte, 64)
	sizes := make([]int, 1)
	n, err := t.out.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, errors.New("unexpected packet count")
	}
	if len(sizes) == 0 || sizes[0] < 0 || sizes[0] > len(buf) {
		return nil, errors.New("unexpected packet size")
	}
	size := sizes[0]
	return append([]byte(nil), buf[:size]...), nil
}

func (t *eventTun) WaitReadStarted(tb testing.TB) {
	tb.Helper()
	waitStarted(tb, "base Read", t.reads)
}

func (t *eventTun) WaitWriteStarted(tb testing.TB) {
	tb.Helper()
	waitStarted(tb, "base Write", t.writes)
}

func signalStarted(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func waitStarted(tb testing.TB, label string, ch <-chan struct{}) {
	tb.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		tb.Fatalf("%s did not start", label)
	}
}

func closeTestTun(tb testing.TB, t tun.Tun) {
	tb.Helper()
	if err := t.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		tb.Errorf("Close() error = %v", err)
	}
}

func detachedTunChain(base tun.Tun, n int) []*tun.DetachedTun {
	chain := make([]*tun.DetachedTun, n)
	current := base
	for i := range chain {
		chain[i] = tun.Detach(current)
		current = chain[i]
	}
	return chain
}

func drainDetachedUpEvents(t *testing.T, chain []*tun.DetachedTun) {
	t.Helper()
	assertDetachedEvents(t, chain, tun.EventUp)
	assertNoDetachedEvents(t, chain)
}

func assertDetachedMTU(
	t *testing.T,
	chain []*tun.DetachedTun,
	want int,
) {
	t.Helper()
	for i, tun := range chain {
		mtu, err := tun.MTU()
		if err != nil {
			t.Fatalf("chain[%d].MTU() error = %v", i, err)
		}
		if mtu != want {
			t.Fatalf("chain[%d].MTU() = %d, want %d", i, mtu, want)
		}
	}
}

func assertDetachedMTUErr(
	t *testing.T,
	chain []*tun.DetachedTun,
	want error,
) {
	t.Helper()
	for i, tun := range chain {
		_, err := tun.MTU()
		if !errors.Is(err, want) {
			t.Fatalf("chain[%d].MTU() error = %v, want %v", i, err, want)
		}
	}
}

func assertDetachedEvents(
	t *testing.T,
	chain []*tun.DetachedTun,
	want tun.Event,
) {
	t.Helper()
	for i, tun := range chain {
		assertDetachedEvent(t, i, tun.Events(), want)
	}
}

func assertDetachedPacketIO(
	t *testing.T,
	label string,
	dst tun.Tun,
	peer *eventTun,
	value byte,
) {
	t.Helper()
	assertDetachedPacketRead(t, label, dst, peer, value)
	assertDetachedPacketWrite(t, label, dst, peer, value+100)
}

func assertDetachedPacketRead(
	t *testing.T,
	label string,
	dst tun.Tun,
	peer *eventTun,
	value byte,
) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- peer.Send([]byte{value})
	}()

	buf := make([]byte, 64)
	sizes := make([]int, 1)
	n, err := dst.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("%s: Read() error = %v", label, err)
	}
	if n != 1 {
		t.Fatalf("%s: Read() packet count = %d, want 1", label, n)
	}
	if len(sizes) == 0 || sizes[0] != 1 {
		size := 0
		if len(sizes) > 0 {
			size = sizes[0]
		}
		t.Fatalf("%s: Read() size = %d, want 1", label, size)
	}
	if len(buf) == 0 {
		t.Fatalf("%s: Read() buffer is empty", label)
	}
	got := buf[0]
	if got != value {
		t.Fatalf(
			"%s: Read() byte = %d, want %d",
			label,
			got,
			value,
		)
	}
	assertAsyncErr(t, label+": peer send", errCh, nil)
}

func assertDetachedPacketWrite(
	t *testing.T,
	label string,
	dst tun.Tun,
	peer *eventTun,
	value byte,
) {
	t.Helper()
	packetCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		packet, err := peer.Recv()
		if err != nil {
			errCh <- err
			return
		}
		packetCh <- packet
		errCh <- nil
	}()

	n, err := dst.Write([][]byte{{value}}, 0)
	if err != nil {
		t.Fatalf("%s: Write() error = %v", label, err)
	}
	if n != 1 {
		t.Fatalf("%s: Write() n = %d, want 1", label, n)
	}
	assertAsyncErr(t, label+": peer recv", errCh, nil)

	select {
	case packet := <-packetCh:
		if len(packet) != 1 || packet[0] != value {
			t.Fatalf("%s: peer received %v, want [%d]", label, packet, value)
		}
	default:
		t.Fatalf("%s: peer did not receive packet", label)
	}
}

func assertDetachedPacketIOErr(
	t *testing.T,
	label string,
	dst tun.Tun,
) {
	t.Helper()
	buf := make([]byte, 64)
	sizes := make([]int, 1)
	_, err := dst.Read([][]byte{buf}, sizes, 0)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("%s: Read() error = %v, want closed error", label, err)
	}

	_, err = dst.Write([][]byte{{1}}, 0)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("%s: Write() error = %v, want closed error", label, err)
	}
}

func assertAsyncErr(
	t *testing.T,
	label string,
	errCh <-chan error,
	want error,
) {
	t.Helper()
	select {
	case err := <-errCh:
		if !errors.Is(err, want) {
			t.Fatalf("%s error = %v, want %v", label, err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s timed out", label)
	}
}

func assertDetachedEvent(
	t *testing.T,
	i int,
	events <-chan tun.Event,
	want tun.Event,
) {
	t.Helper()
	select {
	case got, ok := <-events:
		if !ok {
			t.Fatalf("chain[%d].Events() closed, want %v", i, want)
		}
		if got != want {
			t.Fatalf("chain[%d].Events() = %v, want %v", i, got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("chain[%d].Events() timed out waiting for %v", i, want)
	}
}

func assertDetachedEventsClosed(t *testing.T, chain []*tun.DetachedTun) {
	t.Helper()
	for i, tun := range chain {
		select {
		case event, ok := <-tun.Events():
			if ok {
				t.Fatalf(
					"chain[%d].Events() = %v, want closed channel",
					i,
					event,
				)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("chain[%d].Events() did not close", i)
		}
	}
}

func assertNoDetachedEvents(t *testing.T, chain []*tun.DetachedTun) {
	t.Helper()
	for i, tun := range chain {
		select {
		case event, ok := <-tun.Events():
			if ok {
				t.Fatalf("chain[%d].Events() = %v, want no event", i, event)
			}
			t.Fatalf("chain[%d].Events() closed unexpectedly", i)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
