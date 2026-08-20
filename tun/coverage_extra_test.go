// nolint
package tun

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestCallbackTUN(t *testing.T) {
	readErr := errors.New("read")
	writeErr := errors.New("write")
	base := &fakeTun{
		readN:    2,
		readErr:  readErr,
		writeN:   3,
		writeErr: writeErr,
	}
	var readN, writeN int
	var gotReadErr, gotWriteErr error
	cb := &CallbackTUN{
		Tun: base,
		OnRead: func(n int, err error) {
			readN = n
			gotReadErr = err
		},
		OnWrite: func(n int, err error) {
			writeN = n
			gotWriteErr = err
		},
	}
	if cb.IsNative() {
		t.Fatal("CallbackTUN IsNative() = true, want false")
	}
	if n, err := cb.Read(nil, nil, 0); n != 2 || !errors.Is(err, readErr) {
		t.Fatalf("Read = %d, %v, want 2 readErr", n, err)
	}
	if readN != 2 || !errors.Is(gotReadErr, readErr) {
		t.Fatalf("OnRead = %d, %v, want 2 readErr", readN, gotReadErr)
	}
	if n, err := cb.Write(nil, 0); n != 3 || !errors.Is(err, writeErr) {
		t.Fatalf("Write = %d, %v, want 3 writeErr", n, err)
	}
	if writeN != 3 || !errors.Is(gotWriteErr, writeErr) {
		t.Fatalf("OnWrite = %d, %v, want 3 writeErr", writeN, gotWriteErr)
	}
}

func TestSplitterFrontendAccessorsAndState(t *testing.T) {
	s := NewSplitter(nil, nil)
	defer s.Close()
	f := s.Get(1)
	if f == nil {
		t.Fatal("Get(1) = nil")
	}
	if s.Get(0) != nil || s.Get(splitterFrontendCount+1) != nil {
		t.Fatal("Get accepted invalid index")
	}
	if f.File() != nil || f.IsNative() {
		t.Fatal("split frontend native accessors returned unexpected values")
	}
	if f.MWO() != splitterDefaultOffset || f.MRO() != splitterDefaultOffset {
		t.Fatalf("split frontend offsets = %d/%d", f.MWO(), f.MRO())
	}
	if mtu, err := f.MTU(); err != nil || mtu != splitterDefaultMTU {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if name, err := f.Name(); err != nil || name != "TunSplitter" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	if f.BatchSize() != splitterDefaultBatch {
		t.Fatalf("BatchSize = %d, want %d", f.BatchSize(), splitterDefaultBatch)
	}
	if up, err := f.IsUp(); err != nil || !up {
		t.Fatalf("IsUp = %v, %v, want true nil", up, err)
	}
	if err := f.Down(); err != nil {
		t.Fatalf("Down error = %v", err)
	}
	if up, err := f.IsUp(); err != nil || up {
		t.Fatalf("IsUp after Down = %v, %v, want false nil", up, err)
	}
	if err := f.Up(); err != nil {
		t.Fatalf("Up error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if _, err := f.IsUp(); !errors.Is(err, ErrSplitterFrontendClosed) {
		t.Fatalf(
			"IsUp after Close error = %v, want ErrSplitterFrontendClosed",
			err,
		)
	}
}

func TestJoinerAccessorsAndClosedState(t *testing.T) {
	j := NewJoiner(nil, nil)
	if j.File() != nil || j.IsNative() {
		t.Fatal("joiner native accessors returned unexpected values")
	}
	if j.MWO() != joinerOffset || j.MRO() != joinerOffset {
		t.Fatalf("joiner offsets = %d/%d", j.MWO(), j.MRO())
	}
	if mtu, err := j.MTU(); err != nil || mtu != joinerDefaultMTU {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if name, err := j.Name(); err != nil || name != "TunJoiner" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	if j.BatchSize() != joinerDefaultBatch {
		t.Fatalf("BatchSize = %d, want %d", j.BatchSize(), joinerDefaultBatch)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if _, err := j.MTU(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("MTU after Close error = %v, want ErrJoinerClosed", err)
	}
	if _, err := j.Name(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("Name after Close error = %v, want ErrJoinerClosed", err)
	}
}

func TestJoinerAttachDetachErrorsAndDefaults(t *testing.T) {
	j := NewJoiner(nil, nil)
	defer j.Close()

	if err := j.AttachDefault(nil); !errors.Is(err, ErrJoinerNilTun) {
		t.Fatalf("AttachDefault(nil) error = %v, want ErrJoinerNilTun", err)
	}
	if err := j.AttachSecondary(nil); !errors.Is(err, ErrJoinerNilTun) {
		t.Fatalf("AttachSecondary(nil) error = %v, want ErrJoinerNilTun", err)
	}

	def := &fakeTun{}
	if err := j.AttachDefault(def); err != nil {
		t.Fatalf("AttachDefault(def) error = %v", err)
	}
	if err := j.AttachDefault(def); err != nil {
		t.Fatalf("duplicate AttachDefault(def) error = %v", err)
	}
	if err := j.AttachSecondary(def); !errors.Is(err, ErrJoinerDuplicateTun) {
		t.Fatalf("AttachSecondary(def) error = %v, want duplicate", err)
	}
	if err := j.DetachDefault(); err != nil {
		t.Fatalf("DetachDefault() error = %v", err)
	}
	if err := j.DetachDefault(); err != nil {
		t.Fatalf("empty DetachDefault() error = %v", err)
	}

	sec := &fakeTun{}
	if err := j.AttachSecondary(sec); err != nil {
		t.Fatalf("AttachSecondary(sec) error = %v", err)
	}
	if err := j.AttachDefault(sec); !errors.Is(err, ErrJoinerDuplicateTun) {
		t.Fatalf("AttachDefault(sec) error = %v, want duplicate", err)
	}

	if err := j.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := j.AttachDefault(&fakeTun{}); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("AttachDefault after Close error = %v, want closed", err)
	}
	if err := j.AttachSecondary(&fakeTun{}); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("AttachSecondary after Close error = %v, want closed", err)
	}
	if err := j.Detach(&fakeTun{}); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("Detach after Close error = %v, want closed", err)
	}
	if err := j.DetachDefault(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("DetachDefault after Close error = %v, want closed", err)
	}
}

func TestJoinerConstructorSpawnFailureCloses(t *testing.T) {
	spawner := &failingSpawner{err: errors.New("spawn failed")}
	j := NewJoiner(spawner, nil)

	if _, err := j.MTU(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("MTU() error = %v, want ErrJoinerClosed", err)
	}
	if _, ok := <-j.Events(); ok {
		t.Fatal("Events() remained open after spawn failure")
	}
}

func TestJoinerStartNestedSpawnFailuresDetach(t *testing.T) {
	spawner := &countingFailingSpawner{
		failAfter: 1,
		err:       errors.New("spawn failed"),
	}
	j := NewJoiner(spawner, nil)
	defer j.Close()

	nested := &fakeTun{}
	if err := j.AttachDefault(nested); !errors.Is(err, spawner.err) {
		t.Fatalf("AttachDefault() error = %v, want spawn failure", err)
	}
	if err := j.Detach(nested); err != nil {
		t.Fatalf("Detach after failed attach error = %v", err)
	}
}

func TestValidatePacketHelpers(t *testing.T) {
	if err := validatePacketOffset(
		nil,
		-1,
	); !errors.Is(
		err,
		errTunInvalidOffset,
	) {
		t.Fatalf("negative offset error = %v, want invalid offset", err)
	}
	if err := validatePacketOffset(
		[][]byte{{1}},
		2,
	); !errors.Is(
		err,
		io.ErrShortBuffer,
	) {
		t.Fatalf("large offset error = %v, want short buffer", err)
	}
	if err := validatePacketOffset([][]byte{{1}}, 1); err != nil {
		t.Fatalf("valid offset error = %v", err)
	}

	bufs := [][]byte{{0, 1, 2}}
	sizes := []int{2}
	if err := validateReadPacketSizes(
		bufs,
		sizes,
		-1,
		1,
	); !errors.Is(
		err,
		errTunInvalidOffset,
	) {
		t.Fatalf("negative read offset error = %v, want invalid offset", err)
	}
	if err := validateReadPacketSizes(
		bufs,
		sizes,
		0,
		-1,
	); !errors.Is(
		err,
		errTunInvalidReadCount,
	) {
		t.Fatalf("negative count error = %v, want invalid count", err)
	}
	if err := validateReadPacketSizes(
		bufs,
		sizes,
		0,
		2,
	); !errors.Is(
		err,
		errTunInvalidReadCount,
	) {
		t.Fatalf("large count error = %v, want invalid count", err)
	}
	sizes[0] = -1
	if err := validateReadPacketSizes(
		bufs,
		sizes,
		0,
		1,
	); !errors.Is(
		err,
		errTunInvalidPacketSize,
	) {
		t.Fatalf("negative size error = %v, want invalid packet size", err)
	}
	sizes[0] = 4
	if err := validateReadPacketSizes(
		bufs,
		sizes,
		0,
		1,
	); !errors.Is(
		err,
		io.ErrShortBuffer,
	) {
		t.Fatalf("large size error = %v, want short buffer", err)
	}
	sizes[0] = 2
	if err := validateReadPacketSizes(bufs, sizes, 1, 1); err != nil {
		t.Fatalf("valid read sizes error = %v", err)
	}
}

func TestBatchHelpersAndWriteNoProgress(t *testing.T) {
	if got := batchSizeOf(&fakeTun{batchSize: 0}); got != 1 {
		t.Fatalf("batchSizeOf(zero) = %d, want 1", got)
	}
	if got := batchSizeOf(&fakeTun{batchSize: 3}); got != 3 {
		t.Fatalf("batchSizeOf(3) = %d, want 3", got)
	}
	if got := channelBufferSize(); got < 1 {
		t.Fatalf("channelBufferSize() = %d, want positive", got)
	}

	err := writePackets(&fakeTun{writeN: 0}, [][]byte{{1}}, 0)
	if !errors.Is(err, errWriteNoProgress) {
		t.Fatalf("writePackets() error = %v, want no progress", err)
	}
}

func TestForwarderAndSplitterConstructorSpawnFailures(t *testing.T) {
	spawnErr := errors.New("spawn failed")

	f := NewForwarder(nil, &failingSpawner{err: spawnErr})
	if !f.stopped {
		t.Fatal("NewForwarder() did not mark forwarder stopped")
	}
	f.Stop()

	s := NewSplitter(&failingSpawner{err: spawnErr}, nil)
	if err := s.Attach(&fakeTun{}); !errors.Is(err, ErrSplitterClosed) {
		t.Fatalf("Attach() error = %v, want ErrSplitterClosed", err)
	}
	if _, ok := <-s.done; ok {
		t.Fatal("splitter done channel is open after spawn failure")
	}
}

func TestJoinerPacketKeyHelpersAndOffsetAlignment(t *testing.T) {
	ip4 := append([]byte{0xaa}, ipv4Packet(
		[4]byte{10, 1, 2, 3},
		[4]byte{10, 4, 5, 6},
	)...)
	if got := packetSrcKey(ip4, 1); got != string([]byte{4, 10, 1, 2, 3}) {
		t.Fatalf("packetSrcKey IPv4 = %v", []byte(got))
	}
	if got := packetDstKey(ip4, 1); got != string([]byte{4, 10, 4, 5, 6}) {
		t.Fatalf("packetDstKey IPv4 = %v", []byte(got))
	}

	ip6 := make([]byte, 41)
	ip6[1] = 0x60
	copy(ip6[9:25], []byte("abcdefghijklmnop"))
	copy(ip6[25:41], []byte("qrstuvwxyzABCDEF"))
	if got := packetSrcKey(
		ip6,
		1,
	); got != string(
		append([]byte{6}, []byte("abcdefghijklmnop")...),
	) {
		t.Fatalf("packetSrcKey IPv6 = %v", []byte(got))
	}
	if got := packetDstKey(
		ip6,
		1,
	); got != string(
		append([]byte{6}, []byte("qrstuvwxyzABCDEF")...),
	) {
		t.Fatalf("packetDstKey IPv6 = %v", []byte(got))
	}
	for _, packet := range [][]byte{
		nil,
		{0x40},
		{0x60},
		{0xf0},
	} {
		if got := packetSrcKey(packet, 0); got != "" {
			t.Fatalf("packetSrcKey(%v) = %q, want empty", packet, got)
		}
		if got := packetDstKey(packet, 0); got != "" {
			t.Fatalf("packetDstKey(%v) = %q, want empty", packet, got)
		}
	}
	if got := packetSrcKey([]byte{0x45}, 1); got != "" {
		t.Fatalf("packetSrcKey at len offset = %q, want empty", got)
	}

	in := [][]byte{{0, 1, 2, 3}}
	same, offset, release := alignWriteOffset(nil, in, 1, 1)
	defer release()
	if len(same) != 1 || &same[0][0] != &in[0][0] || offset != 1 {
		t.Fatalf("same offset alignment changed buffer or offset")
	}

	aligned, offset, release := alignWriteOffset(nil, in, 2, 5)
	defer release()
	if offset != 5 {
		t.Fatalf("aligned offset = %d, want 5", offset)
	}
	if got, want := aligned[0][5:], []byte{2, 3}; string(got) != string(want) {
		t.Fatalf("aligned payload = %v, want %v", got, want)
	}

	emptyAligned, _, release := alignWriteOffset(nil, [][]byte{{1}}, 2, 4)
	defer release()
	if len(emptyAligned[0]) != 4 {
		t.Fatalf("empty aligned len = %d, want 4", len(emptyAligned[0]))
	}
}

type fakeTun struct {
	readN     int
	readErr   error
	writeN    int
	writeErr  error
	batchSize int
}

func (t *fakeTun) File() *os.File { return nil }
func (t *fakeTun) IsNative() bool { return false }
func (t *fakeTun) Read([][]byte, []int, int) (int, error) {
	return t.readN, t.readErr
}
func (t *fakeTun) Write([][]byte, int) (int, error) {
	return t.writeN, t.writeErr
}
func (t *fakeTun) MWO() int { return 0 }
func (t *fakeTun) MRO() int { return 0 }
func (t *fakeTun) MTU() (int, error) {
	return 1280, nil
}
func (t *fakeTun) Name() (string, error) {
	return "fake", nil
}
func (t *fakeTun) Events() <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}
func (t *fakeTun) Close() error { return nil }
func (t *fakeTun) BatchSize() int {
	return t.batchSize
}

type failingSpawner struct {
	err error
}

func (s *failingSpawner) Spawn(func(), string) (uint64, error) {
	return 0, s.err
}

func (s *failingSpawner) SpawnWg(
	func(),
	*sync.WaitGroup,
	string,
) (uint64, error) {
	return 0, s.err
}

type countingFailingSpawner struct {
	count     int
	failAfter int
	err       error
}

func (s *countingFailingSpawner) Spawn(
	worker func(),
	name string,
) (uint64, error) {
	s.count++
	if s.count > s.failAfter {
		return 0, s.err
	}
	go worker()
	return uint64(s.count), nil
}

func (s *countingFailingSpawner) SpawnWg(
	worker func(),
	wg *sync.WaitGroup,
	name string,
) (uint64, error) {
	s.count++
	if s.count > s.failAfter {
		return 0, s.err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker()
	}()
	return uint64(s.count), nil
}

var (
	_ gonnect.Spawner = (*failingSpawner)(nil)
	_ gonnect.Spawner = (*countingFailingSpawner)(nil)
)
