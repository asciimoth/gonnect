// nolint
package tun

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

type staticSplitRouter struct {
	mu      sync.Mutex
	targets []int
	next    int
	locks   int
	unlocks int
}

func (r *staticSplitRouter) Lock() {
	r.mu.Lock()
	r.locks++
}

func (r *staticSplitRouter) Unlock() {
	r.unlocks++
	r.mu.Unlock()
}

func (r *staticSplitRouter) Route(_ []byte, _ int, _ bool) int {
	if len(r.targets) == 0 {
		return 1
	}
	target := r.targets[r.next%len(r.targets)]
	r.next++
	return target
}

func TestSplitterMetadataMTUEventsAndOffsets(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	f := s.Get(1)
	if f == nil {
		t.Fatal("Get(1) = nil")
	}
	if got := f.MRO(); got != 256 {
		t.Fatalf("default MRO() = %d, want 256", got)
	}
	if got := f.MWO(); got != 256 {
		t.Fatalf("default MWO() = %d, want 256", got)
	}
	if got := f.BatchSize(); got != 256 {
		t.Fatalf("default BatchSize() = %d, want 256", got)
	}
	if mtu, err := f.MTU(); err != nil || mtu != 1500 {
		t.Fatalf("default MTU() = %d, %v; want 1500, nil", mtu, err)
	}

	backend := newMockTun(4, 1400, 7, 5)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	assertSplitFrontendEvent(t, f, EventMTUUpdate)
	if got := f.MRO(); got != 5 {
		t.Fatalf("attached MRO() = %d, want 5", got)
	}
	if got := f.MWO(); got != 7 {
		t.Fatalf("attached MWO() = %d, want 7", got)
	}
	if got := f.BatchSize(); got != 4 {
		t.Fatalf("attached BatchSize() = %d, want 4", got)
	}
	if mtu, err := f.MTU(); err != nil || mtu != 1400 {
		t.Fatalf("attached MTU() = %d, %v; want 1400, nil", mtu, err)
	}

	buf := make([]byte, f.MRO()+32)
	if _, err := f.Read(
		[][]byte{buf},
		[]int{0},
		f.MRO()-1,
	); !errors.Is(
		err,
		ErrSplitterSmallOffset,
	) {
		t.Fatalf(
			"Read small offset error = %v, want %v",
			err,
			ErrSplitterSmallOffset,
		)
	}
	if _, err := f.Write(
		[][]byte{make([]byte, f.MWO()+1)},
		f.MWO()-1,
	); !errors.Is(
		err,
		ErrSplitterSmallOffset,
	) {
		t.Fatalf(
			"Write small offset error = %v, want %v",
			err,
			ErrSplitterSmallOffset,
		)
	}

	backend.mtu = 1300
	go func() { backend.events <- EventMTUUpdate }()
	assertSplitFrontendEvent(t, f, EventMTUUpdate)
	if mtu, err := f.MTU(); err != nil || mtu != 1300 {
		t.Fatalf("updated MTU() = %d, %v; want 1300, nil", mtu, err)
	}

	if err := s.Detach(); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	assertSplitFrontendEvent(t, f, EventMTUUpdate)
	if got := f.MRO(); got != 256 {
		t.Fatalf("detached MRO() = %d, want 256", got)
	}
	if got := f.MWO(); got != 256 {
		t.Fatalf("detached MWO() = %d, want 256", got)
	}
	if got := f.BatchSize(); got != 256 {
		t.Fatalf("detached BatchSize() = %d, want 256", got)
	}
	if mtu, err := f.MTU(); err != nil || mtu != 1500 {
		t.Fatalf("detached MTU() = %d, %v; want 1500, nil", mtu, err)
	}
	assertMockClosed(t, "detached backend", backend)
}

func TestSplitterRoutesBackendReadsToFrontends(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	router := &staticSplitRouter{targets: []int{2}}
	s.SetRouter(router)
	backend := newMockTun(4, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f1 := s.Get(1)
	f2 := s.Get(2)

	packets := [][]byte{[]byte("one"), []byte("two")}
	backend.enqueueRead(mockReadResult{packets: packets})
	got := readSplitFrontendPackets(t, f2, 2)
	if !reflect.DeepEqual(got, packets) {
		t.Fatalf("frontend 2 packets = %q, want %q", got, packets)
	}
	if router.locks != 1 || router.unlocks != 1 {
		t.Fatalf(
			"router lock/unlock = %d/%d, want 1/1",
			router.locks,
			router.unlocks,
		)
	}

	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("default")}})
	got = readSplitFrontendPackets(t, f2, 1)
	if !reflect.DeepEqual(got, [][]byte{[]byte("default")}) {
		t.Fatalf("frontend 2 default packets = %q", got)
	}

	s.RemoveRouter()
	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("first")}})
	got = readSplitFrontendPackets(t, f1, 1)
	if !reflect.DeepEqual(got, [][]byte{[]byte("first")}) {
		t.Fatalf("frontend 1 packets = %q", got)
	}
}

func TestSplitterDropsInvalidDownAndMissingFrontends(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	backend := newMockTun(4, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)
	s.SetRouter(&staticSplitRouter{targets: []int{17, 2, 1}})
	if err := f.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	backend.enqueueRead(mockReadResult{
		packets: [][]byte{[]byte("bad"), []byte("missing"), []byte("down")},
	})
	assertNoSplitFrontendRead(t, f, 100*time.Millisecond)
}

func TestSplitterDetachDropsBlockedBackendDelivery(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	backend := newMockTun(1, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)

	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("stale")}})
	eventuallyMockReadCalls(t, backend, 1)
	if err := s.Detach(); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}

	assertNoSplitFrontendRead(t, f, 100*time.Millisecond)
}

func TestSplitterGetReplacesAndClosesOldFrontend(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	old := s.Get(3)
	newFrontend := s.Get(3)
	if old == newFrontend {
		t.Fatal("Get(3) returned the old frontend")
	}
	_, err := old.MTU()
	if !errors.Is(err, ErrSplitterFrontendClosed) {
		t.Fatalf(
			"old MTU() error = %v, want %v",
			err,
			ErrSplitterFrontendClosed,
		)
	}

	backend := newMockTun(1, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	s.SetRouter(&staticSplitRouter{targets: []int{3}})
	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("new")}})
	got := readSplitFrontendPackets(t, newFrontend, 1)
	if !reflect.DeepEqual(got, [][]byte{[]byte("new")}) {
		t.Fatalf("new frontend packets = %q", got)
	}
}

func TestSplitterFrontendWritesToBackendAndDropsWhenDetached(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	backend := newMockTun(2, 1500, 3, 4)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)
	packet := withOffset(f.MWO(), []byte("incoming"))
	if n, err := f.Write([][]byte{packet}, f.MWO()); err != nil || n != 1 {
		t.Fatalf("Write() = %d, %v; want 1, nil", n, err)
	}
	if got := backend.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{[]byte("incoming")},
	) {
		t.Fatalf("backend packets = %q", got)
	}

	if err := s.Detach(); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	packet = withOffset(f.MWO(), []byte("dropped"))
	if n, err := f.Write([][]byte{packet}, f.MWO()); err != nil || n != 1 {
		t.Fatalf("detached Write() = %d, %v; want 1, nil", n, err)
	}
}

func TestSplitterAutoDetachesTerminalBackendReadError(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	backend := newMockTun(1, 1400, 0, 0)
	f := s.Get(1)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	assertSplitFrontendEvent(t, f, EventMTUUpdate)
	backend.enqueueRead(mockReadResult{err: os.ErrClosed})
	eventuallySplitFrontendMTU(t, f, 1500)
	assertMockClosed(t, "terminal backend", backend)
}

func TestDetachSplitFrontendUsesFrontendChannelPath(t *testing.T) {
	s := NewSplitter()
	defer s.Close()

	backend := newMockTun(2, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f := s.Get(1)
	d := Detach(f)
	defer d.Close()

	backend.enqueueRead(mockReadResult{packets: [][]byte{[]byte("out")}})
	buf := make([]byte, d.MRO()+32)
	sizes := make([]int, 1)
	if n, err := d.Read([][]byte{buf}, sizes, d.MRO()); err != nil || n != 1 {
		t.Fatalf("detached Read() = %d, %v; want 1, nil", n, err)
	}
	if got := buf[d.MRO() : d.MRO()+sizes[0]]; !reflect.DeepEqual(
		got,
		[]byte("out"),
	) {
		t.Fatalf("detached Read packet = %q", got)
	}

	packet := withOffset(d.MWO(), []byte("in"))
	if n, err := d.Write([][]byte{packet}, d.MWO()); err != nil || n != 1 {
		t.Fatalf("detached Write() = %d, %v; want 1, nil", n, err)
	}
	if got := backend.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{[]byte("in")},
	) {
		t.Fatalf("backend packets = %q", got)
	}
}

func readSplitFrontendPackets(
	t *testing.T,
	f Tun,
	count int,
) [][]byte {
	t.Helper()
	out := make([][]byte, 0, count)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(out) < count {
			batch := min(f.BatchSize(), count-len(out))
			bufs := make([][]byte, batch)
			sizes := make([]int, batch)
			for i := range bufs {
				bufs[i] = make([]byte, f.MRO()+64)
			}
			n, err := f.Read(bufs, sizes, f.MRO())
			if err != nil {
				t.Errorf("Read() error = %v", err)
				return
			}
			for i := range n {
				out = append(
					out,
					append([]byte(nil), bufs[i][f.MRO():f.MRO()+sizes[i]]...),
				)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Read() timed out")
	}
	return out
}

func assertNoSplitFrontendRead(
	t *testing.T,
	f Tun,
	timeout time.Duration,
) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, f.MRO()+64)
		sizes := make([]int, 1)
		_, err := f.Read([][]byte{buf}, sizes, f.MRO())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read() returned a packet, want drop/block")
		}
	case <-time.After(timeout):
	}
}

func assertSplitFrontendEvent(t *testing.T, f *SplitFrontend, want Event) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got, ok := <-f.Events():
			if !ok {
				t.Fatalf("Events() closed before %v", want)
			}
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event %v", want)
		}
	}
}

func eventuallySplitFrontendMTU(t *testing.T, f *SplitFrontend, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, err := f.MTU()
		if err == nil && got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, err := f.MTU()
	t.Fatalf("MTU() = %d, %v; want %d, nil", got, err, want)
}

func eventuallyMockReadCalls(t *testing.T, tun *mockTun, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := tun.readCallCount(); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("read calls = %d, want at least %d", tun.readCallCount(), want)
}
