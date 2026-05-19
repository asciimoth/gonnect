// nolint
package tun

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestJoinerMetadataAndMTUEvents(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	if got := j.MRO(); got != 256 {
		t.Fatalf("MRO() = %d, want 256", got)
	}
	if got := j.MWO(); got != 256 {
		t.Fatalf("MWO() = %d, want 256", got)
	}
	if j.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	name, err := j.Name()
	if err != nil {
		t.Fatalf("Name() error = %v", err)
	}
	if name != "TunJoiner" {
		t.Fatalf("Name() = %q, want TunJoiner", name)
	}
	if mtu, err := j.MTU(); err != nil || mtu != 1500 {
		t.Fatalf("empty MTU() = %d, %v; want 1500, nil", mtu, err)
	}
	if got := j.BatchSize(); got != 256 {
		t.Fatalf("empty BatchSize() = %d, want 256", got)
	}

	a := newMockTun(4, 1400, 0, 0)
	if err := j.AttachDefault(a); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	assertJoinerEvent(t, j, EventMTUUpdate)
	if mtu, err := j.MTU(); err != nil || mtu != 1400 {
		t.Fatalf("MTU() = %d, %v; want 1400, nil", mtu, err)
	}
	if got := j.BatchSize(); got != 4 {
		t.Fatalf("BatchSize() = %d, want 4", got)
	}

	b := newMockTun(9, 1200, 0, 0)
	if err := j.AttachSecondary(b); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
	assertJoinerEvent(t, j, EventMTUUpdate)
	if mtu, err := j.MTU(); err != nil || mtu != 1200 {
		t.Fatalf("MTU() = %d, %v; want 1200, nil", mtu, err)
	}
	if got := j.BatchSize(); got != 9 {
		t.Fatalf("BatchSize() = %d, want 9", got)
	}

	b.mu.Lock()
	b.mtu = 1300
	b.mu.Unlock()
	go func() { b.events <- EventMTUUpdate }()
	assertJoinerEvent(t, j, EventMTUUpdate)
	if mtu, err := j.MTU(); err != nil || mtu != 1300 {
		t.Fatalf("MTU() = %d, %v; want 1300, nil", mtu, err)
	}
}

func TestJoinerRoutesByLearnedIPSource(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	def := newMockTun(4, 1500, 0, 0)
	sec := newMockTun(4, 1500, 0, 0)
	if err := j.AttachDefault(def); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}

	learned := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	sec.enqueueRead(mockReadResult{packets: [][]byte{learned}})
	if got := readJoinerPacket(t, j); !reflect.DeepEqual(got, learned) {
		t.Fatalf("Read() packet = %v, want %v", got, learned)
	}

	toLearned := withOffset(
		j.MWO(),
		ipv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}),
	)
	if n, err := j.Write([][]byte{toLearned}, j.MWO()); err != nil || n != 1 {
		t.Fatalf("Write() = %d, %v; want 1, nil", n, err)
	}
	if got := sec.waitForWrittenPackets(1, time.Second); len(got) != 1 {
		t.Fatalf("secondary written packets = %d, want 1", len(got))
	}
	if got := def.waitForWrittenPackets(1, 50*time.Millisecond); len(got) != 0 {
		t.Fatalf("default written packets = %d, want 0", len(got))
	}

	unknown := withOffset(
		j.MWO(),
		ipv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 99}),
	)
	if n, err := j.Write([][]byte{unknown}, j.MWO()); err != nil || n != 1 {
		t.Fatalf("Write unknown = %d, %v; want 1, nil", n, err)
	}
	if got := def.waitForWrittenPackets(1, time.Second); len(got) != 1 {
		t.Fatalf("default written packets = %d, want 1", len(got))
	}
}

func TestJoinerReadBuffersRemainingPackets(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	sec := newMockTun(4, 1500, 0, 0)
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
	packets := [][]byte{
		ipv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 9}),
		ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 9}),
		ipv4Packet([4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 9}),
	}
	sec.enqueueRead(mockReadResult{packets: packets})

	first := readJoinerPackets(t, j, 2)
	if !reflect.DeepEqual(first, packets[:2]) {
		t.Fatalf("first read = %v, want %v", first, packets[:2])
	}
	second := readJoinerPackets(t, j, 2)
	if !reflect.DeepEqual(second, packets[2:]) {
		t.Fatalf("second read = %v, want %v", second, packets[2:])
	}
}

func TestJoinerRejectsSmallOffsets(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	buf := make([]byte, j.MRO()+64)
	sizes := make([]int, 1)
	if _, err := j.Read(
		[][]byte{buf},
		sizes,
		j.MRO()-1,
	); !errors.Is(
		err,
		ErrJoinerSmallOffset,
	) {
		t.Fatalf("Read() error = %v, want %v", err, ErrJoinerSmallOffset)
	}
	if _, err := j.Write(
		[][]byte{buf},
		j.MWO()-1,
	); !errors.Is(
		err,
		ErrJoinerSmallOffset,
	) {
		t.Fatalf("Write() error = %v, want %v", err, ErrJoinerSmallOffset)
	}
}

func TestJoinerDetachClosesTunAndForgetsRoutes(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	def := newMockTun(4, 1500, 0, 0)
	sec := newMockTun(4, 1300, 0, 0)
	if err := j.AttachDefault(def); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}

	learned := ipv4Packet([4]byte{10, 0, 0, 7}, [4]byte{10, 0, 0, 1})
	sec.enqueueRead(mockReadResult{packets: [][]byte{learned}})
	_ = readJoinerPacket(t, j)

	if err := j.Detach(sec); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	sec.mu.Lock()
	closed := sec.closed
	sec.mu.Unlock()
	if !closed {
		t.Fatal("secondary was not closed on detach")
	}

	toDetached := withOffset(
		j.MWO(),
		ipv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 7}),
	)
	if n, err := j.Write([][]byte{toDetached}, j.MWO()); err != nil || n != 1 {
		t.Fatalf("Write() = %d, %v; want 1, nil", n, err)
	}
	if got := def.waitForWrittenPackets(1, time.Second); len(got) != 1 {
		t.Fatalf("default written packets = %d, want 1", len(got))
	}
}

func TestJoinerAutoDetachesTerminalReadError(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	sec := newMockTun(4, 1200, 0, 0)
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
	sec.enqueueRead(mockReadResult{err: os.ErrClosed})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := j.BatchSize(); got == 256 {
			sec.mu.Lock()
			closed := sec.closed
			sec.mu.Unlock()
			if !closed {
				t.Fatal("terminal nested tun was detached but not closed")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("terminal nested tun was not auto-detached")
}

func TestDetachJoinerUsesJoinerDataPath(t *testing.T) {
	j := NewJoiner()
	defer j.Close()

	sec := newMockTun(4, 1500, 0, 0)
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
	d := Detach(j)
	defer d.Close()

	learned := ipv4Packet([4]byte{10, 0, 0, 8}, [4]byte{10, 0, 0, 1})
	sec.enqueueRead(mockReadResult{packets: [][]byte{learned}})

	buf := make([]byte, d.MRO()+128)
	sizes := make([]int, 1)
	if n, err := d.Read([][]byte{buf}, sizes, d.MRO()); err != nil || n != 1 {
		t.Fatalf("detached Read() = %d, %v; want 1, nil", n, err)
	}
	if got := buf[d.MRO() : d.MRO()+sizes[0]]; !reflect.DeepEqual(
		got,
		learned,
	) {
		t.Fatalf("detached Read() packet = %v, want %v", got, learned)
	}

	reply := withOffset(
		d.MWO(),
		ipv4Packet([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 8}),
	)
	if n, err := d.Write([][]byte{reply}, d.MWO()); err != nil || n != 1 {
		t.Fatalf("detached Write() = %d, %v; want 1, nil", n, err)
	}
	if got := sec.waitForWrittenPackets(1, time.Second); len(got) != 1 {
		t.Fatalf("secondary written packets = %d, want 1", len(got))
	}
}

func TestJoinerDetachedTunComplexTopologyStateEventsAndFlow(t *testing.T) {
	inner := NewJoiner()
	defer inner.Close()
	outer := NewJoiner()
	defer outer.Close()

	innerDefault := newMockTun(3, 1400, 0, 0)
	edge := newMockTun(5, 1300, 0, 0)
	outerDefault := newMockTun(2, 1450, 0, 0)

	edgeRoot := Detach(edge)
	assertTunEvent(t, "edgeRoot initial", edgeRoot.Events(), EventUp)
	edgeChild := Detach(edgeRoot)
	assertTunEvent(t, "edgeChild initial", edgeChild.Events(), EventUp)

	if err := inner.AttachDefault(innerDefault); err != nil {
		t.Fatalf("inner AttachDefault() error = %v", err)
	}
	assertJoinerEvent(t, inner, EventMTUUpdate)
	assertTunMTU(t, "inner after default", inner, 1400)
	assertTunBatch(t, "inner after default", inner, 3)

	if err := inner.AttachSecondary(edgeChild); err != nil {
		t.Fatalf("inner AttachSecondary(edgeChild) error = %v", err)
	}
	assertJoinerEvent(t, inner, EventMTUUpdate)
	assertTunMTU(t, "inner after edge attach", inner, 1300)
	assertTunBatch(t, "inner after edge attach", inner, 5)

	innerDetached := Detach(inner)
	assertTunEvent(t, "innerDetached initial", innerDetached.Events(), EventUp)

	if err := outer.AttachDefault(outerDefault); err != nil {
		t.Fatalf("outer AttachDefault() error = %v", err)
	}
	assertJoinerEvent(t, outer, EventMTUUpdate)
	assertTunMTU(t, "outer after default", outer, 1450)
	assertTunBatch(t, "outer after default", outer, 2)

	if err := outer.AttachSecondary(innerDetached); err != nil {
		t.Fatalf("outer AttachSecondary(innerDetached) error = %v", err)
	}
	assertJoinerEvent(t, outer, EventMTUUpdate)
	assertTunMTU(t, "outer after inner attach", outer, 1300)
	assertTunBatch(t, "outer after inner attach", outer, 5)

	edgeIP := [4]byte{10, 77, 0, 2}
	peerIP := [4]byte{10, 77, 0, 1}
	assertTopologyFlow(
		t,
		"initial edge flow",
		outer,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := innerDetached.Down(); err != nil {
		t.Fatalf("innerDetached.Down() error = %v", err)
	}
	assertTunMTUErr(t, "innerDetached down", innerDetached, os.ErrClosed)
	assertNoTunEvent(t, "outer after innerDetached down", outer.Events())
	assertRoutedWriteDropped(
		t,
		"down innerDetached route",
		outer,
		edgeIP,
		peerIP,
		edge,
	)
	assertUnknownRoutesToDefault(
		t,
		"outer fallback while innerDetached down",
		outer,
		outerDefault,
	)

	if err := innerDetached.Up(); err != nil {
		t.Fatalf("innerDetached.Up() error = %v", err)
	}
	assertTunMTU(t, "innerDetached up", innerDetached, 1300)
	assertNoTunEvent(t, "outer after innerDetached up", outer.Events())
	assertTopologyFlow(
		t,
		"edge flow after innerDetached up",
		outer,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := edgeRoot.Down(); err != nil {
		t.Fatalf("edgeRoot.Down() error = %v", err)
	}
	assertTunEvent(t, "edgeRoot down", edgeRoot.Events(), EventDown)
	assertTunMTUErr(t, "edgeRoot down", edgeRoot, os.ErrClosed)
	eventuallyTunMTUErr(t, "edgeChild after root down", edgeChild, os.ErrClosed)
	assertTunMTU(t, "outer after edgeRoot down", outer, 1300)
	assertNoTunEvent(t, "outer after edgeRoot down", outer.Events())
	assertRoutedWriteDropped(t, "down edge route", outer, edgeIP, peerIP, edge)
	assertUnknownRoutesToDefault(
		t,
		"outer fallback while edge down",
		outer,
		outerDefault,
	)

	if err := edgeRoot.Up(); err != nil {
		t.Fatalf("edgeRoot.Up() error = %v", err)
	}
	assertTunEvent(t, "edgeRoot up", edgeRoot.Events(), EventUp)
	eventuallyTunMTU(t, "edgeChild after root up", edgeChild, 1300)
	assertTunMTU(t, "outer after edgeRoot up", outer, 1300)
	assertNoTunEvent(t, "outer after edgeRoot up", outer.Events())
	assertTopologyFlow(
		t,
		"edge flow after edgeRoot up",
		outer,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := edgeChild.Close(); err != nil {
		t.Fatalf("edgeChild.Close() error = %v", err)
	}
	assertTunMTUErr(t, "edgeChild closed", edgeChild, os.ErrClosed)
	assertTunEvent(
		t,
		"outer after edgeChild close",
		outer.Events(),
		EventMTUUpdate,
	)
	assertTunMTU(t, "outer after edgeChild close", outer, 1400)
	assertTunBatch(t, "inner after edgeChild close", inner, 3)
	assertTunBatch(t, "outer after edgeChild close", outer, 5)

	replacement := Detach(edgeRoot)
	assertTunEvent(t, "replacement initial", replacement.Events(), EventUp)
	if err := inner.AttachSecondary(replacement); err != nil {
		t.Fatalf("inner AttachSecondary(replacement) error = %v", err)
	}
	assertTunEvent(
		t,
		"outer after replacement attach",
		outer.Events(),
		EventMTUUpdate,
	)
	assertTunMTU(t, "outer after replacement attach", outer, 1300)
	assertTunBatch(t, "outer after replacement attach", outer, 5)
	assertTopologyFlow(
		t,
		"edge flow after replacement attach",
		outer,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := edgeRoot.Close(); err != nil {
		t.Fatalf("edgeRoot.Close() error = %v", err)
	}
	assertTunEvent(t, "edgeRoot close down", edgeRoot.Events(), EventDown)
	assertTunEventsClosed(t, "edgeRoot close", edgeRoot.Events())
	eventuallyTunMTUErr(
		t,
		"replacement after root close",
		replacement,
		os.ErrClosed,
	)
	assertTunEvent(
		t,
		"outer after edgeRoot close",
		outer.Events(),
		EventMTUUpdate,
	)
	assertTunMTU(t, "outer after edgeRoot close", outer, 1400)
	assertTunBatch(t, "inner after edgeRoot close", inner, 3)
	assertTunBatch(t, "outer after edgeRoot close", outer, 5)
	assertWriteDeliveredTo(
		t,
		"old edge route falls back to inner default",
		outer,
		edgeIP,
		peerIP,
		innerDefault,
	)

	newDefault := newMockTun(7, 1250, 0, 0)
	if err := inner.AttachDefault(newDefault); err != nil {
		t.Fatalf("inner AttachDefault(newDefault) error = %v", err)
	}
	assertTunEvent(t, "outer after new default", outer.Events(), EventMTUUpdate)
	assertTunMTU(t, "outer after new default", outer, 1250)
	assertTunBatch(t, "inner after new default", inner, 7)
	assertTunBatch(t, "outer after new default", outer, 5)
	assertMockClosed(t, "old inner default", innerDefault)
	assertWriteDeliveredTo(
		t,
		"old edge route uses new inner default",
		outer,
		edgeIP,
		peerIP,
		newDefault,
	)
}

func readJoinerPacket(t *testing.T, j *Joiner) []byte {
	t.Helper()
	packets := readJoinerPackets(t, j, 1)
	if len(packets) != 1 {
		t.Fatalf("Read() returned %d packets, want 1", len(packets))
	}
	return packets[0]
}

func readJoinerPackets(t *testing.T, j *Joiner, count int) [][]byte {
	t.Helper()
	type result struct {
		packets [][]byte
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		bufs := make([][]byte, count)
		sizes := make([]int, count)
		for i := range bufs {
			bufs[i] = make([]byte, j.MRO()+128)
		}
		n, err := j.Read(bufs, sizes, j.MRO())
		packets := make([][]byte, n)
		for i := range n {
			packets[i] = append(
				[]byte(nil),
				bufs[i][j.MRO():j.MRO()+sizes[i]]...,
			)
		}
		ch <- result{packets: packets, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("Read() error = %v", res.err)
		}
		return res.packets
	case <-time.After(time.Second):
		t.Fatal("Read() timed out")
	}
	return nil
}

func assertJoinerEvent(t *testing.T, j *Joiner, want Event) {
	t.Helper()
	select {
	case got := <-j.Events():
		if got != want {
			t.Fatalf("event = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for event %v", want)
	}
}

func assertTunEvent(
	t *testing.T,
	label string,
	events <-chan Event,
	want Event,
) {
	t.Helper()
	select {
	case got, ok := <-events:
		if !ok {
			t.Fatalf("%s: Events() closed, want %v", label, want)
		}
		if got != want {
			t.Fatalf("%s: Events() = %v, want %v", label, got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s: timed out waiting for event %v", label, want)
	}
}

func assertNoTunEvent(t *testing.T, label string, events <-chan Event) {
	t.Helper()
	select {
	case got, ok := <-events:
		if !ok {
			t.Fatalf("%s: Events() closed unexpectedly", label)
		}
		t.Fatalf("%s: Events() = %v, want no event", label, got)
	case <-time.After(50 * time.Millisecond):
	}
}

func assertTunEventsClosed(
	t *testing.T,
	label string,
	events <-chan Event,
) {
	t.Helper()
	select {
	case got, ok := <-events:
		if ok {
			t.Fatalf("%s: Events() = %v, want closed channel", label, got)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s: Events() did not close", label)
	}
}

func assertTunMTU(t *testing.T, label string, tun Tun, want int) {
	t.Helper()
	got, err := tun.MTU()
	if err != nil {
		t.Fatalf("%s: MTU() error = %v", label, err)
	}
	if got != want {
		t.Fatalf("%s: MTU() = %d, want %d", label, got, want)
	}
}

func eventuallyTunMTU(t *testing.T, label string, tun Tun, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got, err := tun.MTU()
		if err == nil && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: MTU() = %d, %v; want %d, nil", label, got, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertTunMTUErr(t *testing.T, label string, tun Tun, want error) {
	t.Helper()
	_, err := tun.MTU()
	if !errors.Is(err, want) {
		t.Fatalf("%s: MTU() error = %v, want %v", label, err, want)
	}
}

func eventuallyTunMTUErr(t *testing.T, label string, tun Tun, want error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, err := tun.MTU()
		if errors.Is(err, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: MTU() error = %v, want %v", label, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertTunBatch(t *testing.T, label string, tun Tun, want int) {
	t.Helper()
	if got := tun.BatchSize(); got != want {
		t.Fatalf("%s: BatchSize() = %d, want %d", label, got, want)
	}
}

func assertTopologyFlow(
	t *testing.T,
	label string,
	top Tun,
	source *mockTun,
	src [4]byte,
	dst [4]byte,
	sink *mockTun,
) {
	t.Helper()
	packet := ipv4Packet(src, dst)
	source.enqueueRead(mockReadResult{packets: [][]byte{packet}})
	if got := readTunPacket(t, label, top); !reflect.DeepEqual(got, packet) {
		t.Fatalf("%s: Read() packet = %v, want %v", label, got, packet)
	}
	assertWriteDeliveredTo(t, label, top, src, dst, sink)
}

func assertWriteDeliveredTo(
	t *testing.T,
	label string,
	top Tun,
	dst [4]byte,
	src [4]byte,
	sink *mockTun,
) {
	t.Helper()
	before := mockWrittenCount(sink)
	reply := withOffset(top.MWO(), ipv4Packet(src, dst))
	if n, err := top.Write([][]byte{reply}, top.MWO()); err != nil || n != 1 {
		t.Fatalf("%s: Write() = %d, %v; want 1, nil", label, n, err)
	}
	if got := sink.waitForWrittenPackets(
		before+1,
		time.Second,
	); len(
		got,
	) != before+1 {
		t.Fatalf(
			"%s: written packet count = %d, want %d",
			label,
			len(got),
			before+1,
		)
	}
}

func assertRoutedWriteDropped(
	t *testing.T,
	label string,
	top Tun,
	dst [4]byte,
	src [4]byte,
	sink *mockTun,
) {
	t.Helper()
	before := mockWrittenCount(sink)
	reply := withOffset(top.MWO(), ipv4Packet(src, dst))
	if n, err := top.Write([][]byte{reply}, top.MWO()); err != nil || n != 1 {
		t.Fatalf("%s: Write() = %d, %v; want 1, nil", label, n, err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := mockWrittenCount(sink); got != before {
		t.Fatalf("%s: written packet count = %d, want %d", label, got, before)
	}
}

func assertUnknownRoutesToDefault(
	t *testing.T,
	label string,
	top Tun,
	defaultTun *mockTun,
) {
	t.Helper()
	before := mockWrittenCount(defaultTun)
	packet := withOffset(
		top.MWO(),
		ipv4Packet([4]byte{10, 200, 0, 1}, [4]byte{10, 200, 0, 99}),
	)
	if n, err := top.Write([][]byte{packet}, top.MWO()); err != nil || n != 1 {
		t.Fatalf("%s: Write() = %d, %v; want 1, nil", label, n, err)
	}
	if got := defaultTun.waitForWrittenPackets(
		before+1,
		time.Second,
	); len(
		got,
	) != before+1 {
		t.Fatalf(
			"%s: default written packet count = %d, want %d",
			label,
			len(got),
			before+1,
		)
	}
}

func readTunPacket(t *testing.T, label string, tun Tun) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
		n      int
		size   int
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, tun.MRO()+128)
		sizes := make([]int, 1)
		n, err := tun.Read([][]byte{buf}, sizes, tun.MRO())
		res := result{err: err, n: n}
		if n > 0 {
			res.size = sizes[0]
			res.packet = append(
				[]byte(nil),
				buf[tun.MRO():tun.MRO()+sizes[0]]...,
			)
		}
		ch <- res
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("%s: Read() error = %v", label, res.err)
		}
		if res.n != 1 {
			t.Fatalf("%s: Read() n = %d, want 1", label, res.n)
		}
		if res.size <= 0 {
			t.Fatalf("%s: Read() size = %d, want positive", label, res.size)
		}
		return res.packet
	case <-time.After(time.Second):
		t.Fatalf("%s: Read() timed out", label)
	}
	return nil
}

func mockWrittenCount(tun *mockTun) int {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return len(tun.writtenPackets)
}

func assertMockClosed(t *testing.T, label string, tun *mockTun) {
	t.Helper()
	tun.mu.Lock()
	closed := tun.closed
	tun.mu.Unlock()
	if !closed {
		t.Fatalf("%s: tun is not closed", label)
	}
}

func ipv4Packet(src, dst [4]byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return p
}

func withOffset(offset int, packet []byte) []byte {
	buf := make([]byte, offset+len(packet))
	copy(buf[offset:], packet)
	return buf
}
