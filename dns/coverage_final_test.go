package dns //nolint:testpackage // Covers unexported DNS helpers.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCoverageMessageCopyNilAndAdditionalData(t *testing.T) {
	if (*Message)(nil).Copy() != nil {
		t.Fatal("nil Message Copy() returned non-nil")
	}

	msg := &Message{
		Authorities: []Resource{{
			Name: "example.test.",
			Data: []byte{1, 2, 3},
		}},
		Additionals: []Resource{{
			Name: "extra.example.test.",
			Data: []byte{4, 5, 6},
		}},
	}
	cp := msg.Copy()
	cp.Authorities[0].Data[0] = 9
	cp.Additionals[0].Data[0] = 9
	if msg.Authorities[0].Data[0] != 1 || msg.Additionals[0].Data[0] != 4 {
		t.Fatal("Message Copy() did not deep-copy all resource data")
	}
}

func TestCoverageQueryCanceledSend(t *testing.T) {
	upstream := newStaticDNS()
	defer func() { _ = upstream.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Query(ctx, upstream, aQuery("example.test.")); err == nil {
		t.Fatal("Query(canceled context) error = nil")
	}
}

func TestCoverageWireErrorBranches(t *testing.T) {
	if got := absName(""); got != "." {
		t.Fatalf("absName(empty) = %q, want .", got)
	}
	if got := absName("."); got != "." {
		t.Fatalf("absName(root) = %q, want .", got)
	}
	if segments, ok := txtSegments([]byte{3, 'a'}); ok || segments != nil {
		t.Fatal("txtSegments(incomplete) ok = true")
	}

	for _, rr := range []Resource{
		{Name: "example.test.", Type: TypeA, Class: ClassIN, Data: []byte{1}},
		{Name: "example.test.", Type: TypeAAAA, Class: ClassIN, Data: []byte{1}},
		{Name: "example.test.", Type: TypeMX, Class: ClassIN, Data: []byte{1}},
		{Name: "example.test.", Type: TypeSRV, Class: ClassIN, Data: []byte{1}},
	} {
		if _, err := Pack(
			&Message{Response: true, Answers: []Resource{rr}},
		); err == nil {
			t.Fatalf("Pack(%d with invalid data) error = nil", rr.Type)
		}
	}

	if _, err := Unpack([]byte{0}); err == nil {
		t.Fatal("Unpack(short packet) error = nil")
	}
}

func TestCoverageIPPacketHelperBranches(t *testing.T) {
	if _, ok := parseDNSIPPacket(nil); ok {
		t.Fatal("parseDNSIPPacket(nil) ok = true")
	}
	if _, ok := parseDNSIPPacket([]byte{0xf0}); ok {
		t.Fatal("parseDNSIPPacket(unknown version) ok = true")
	}
	if _, ok := parseDNSIPv4Packet([]byte{0x40}); ok {
		t.Fatal("parseDNSIPv4Packet(short) ok = true")
	}
	if _, ok := parseDNSIPv6Packet([]byte{0x60}); ok {
		t.Fatal("parseDNSIPv6Packet(short) ok = true")
	}
	if _, ok := parseDNSUDP(make([]byte, 7), 0, 7); ok {
		t.Fatal("parseDNSUDP(short) ok = true")
	}
	if udpSegment(make([]byte, 7), 0, 7) != nil {
		t.Fatal("udpSegment(short) != nil")
	}

	req := ipPacketRequest{version: 9}
	if _, ok := buildDNSIPResponse(
		req,
		responseFor(aQuery("example.test.")),
	); ok {
		t.Fatal("buildDNSIPResponse(unknown version) ok = true")
	}
	req.version = 4
	if _, ok := buildDNSIPResponse(req, &Message{
		Response: true,
		Answers: []Resource{{
			Name:  string(make([]byte, 64)) + ".",
			Type:  TypeCNAME,
			Class: ClassIN,
			Data:  []byte("example.test."),
		}},
	}); ok {
		t.Fatal("buildDNSIPResponse(unpackable DNS) ok = true")
	}

	udp := make([]byte, 8)
	if validUDPChecksumIPv4(
		[]byte{1, 1, 1, 1},
		[]byte{2, 2, 2, 2},
		udp,
	) != true {
		t.Fatal("validUDPChecksumIPv4(zero checksum) = false")
	}
	binary.BigEndian.PutUint16(udp[6:8], 1)
	if validUDPChecksumIPv4([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, udp) {
		t.Fatal("validUDPChecksumIPv4(bad checksum) = true")
	}
	if validUDPChecksumIPv6(
		make([]byte, 16),
		make([]byte, 16),
		make([]byte, 7),
	) {
		t.Fatal("validUDPChecksumIPv6(short) = true")
	}
}

func TestCoverageIPPacketAdapterQueryAndEmitBranches(t *testing.T) {
	adapter := NewIPPacketAdapterWithOptions(nil, nil, PacketOptions{
		RequestTimeout: time.Millisecond,
	})
	resp := adapter.query(context.Background(), aQuery("example.test."))
	if resp == nil || resp.RCode != RCodeServerFailure {
		t.Fatalf("query(nil upstream) = %#v", resp)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	adapter.upstream = newStaticDNS()
	defer func() { _ = adapter.upstream.Close() }()
	if resp := adapter.query(ctx, aQuery("example.test.")); resp != nil {
		t.Fatalf("query(canceled context) = %#v, want nil", resp)
	}

	var called bool
	adapter.callback = func([]byte) { called = true }
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	adapter.emit([]byte{1})
	if called {
		t.Fatal("emit called callback after Close")
	}
	adapter.FeedPacket(nil)
}

func TestCoverageMemoryStorageAndCacheHelpers(t *testing.T) {
	storage := NewMemoryStorage()
	now := time.Now()
	storage.Set("", nil, now)
	storage.Set("", &Message{Response: true, RCode: RCodeNameError}, now)
	storage.Set("", &Message{Response: true, RCode: RCodeSuccess}, now)
	if _, ok := storage.Get("", now); ok {
		t.Fatal("storage Get(empty after ignored sets) ok = true")
	}

	msg := &Message{
		Response: true,
		RCode:    RCodeSuccess,
		Questions: []Question{{
			Name:  "example.test.",
			Type:  TypeA,
			Class: ClassIN,
		}},
		Answers: []Resource{{
			Name:  "example.test.",
			Type:  TypeA,
			Class: ClassIN,
			TTL:   1,
			Data:  []byte{127, 0, 0, 1},
		}},
	}
	storage.Set("", msg, now)
	got, ok := storage.Get(cacheKey(msg), now)
	if !ok || got == nil {
		t.Fatal("storage Get(cached message) miss")
	}
	got.Answers[0].Data[0] = 9
	again, _ := storage.Get(cacheKey(msg), now)
	if again.Answers[0].Data[0] != 127 {
		t.Fatal("storage Get() returned aliased message")
	}
	if _, ok := storage.Get(cacheKey(msg), now.Add(2*time.Second)); ok {
		t.Fatal("storage Get(expired message) ok = true")
	}
	storage.Delete(cacheKey(msg))

	if cacheKey(nil) != "" || cacheKey(&Message{}) != "" {
		t.Fatal("cacheKey empty message was not empty")
	}
	if ip := resourceIP(
		Resource{Type: TypeA, Class: ClassIN, Data: []byte{1}},
	); ip != nil {
		t.Fatalf("resourceIP(invalid A) = %v", ip)
	}
	if ip := resourceIP(Resource{
		Type:  TypeAAAA,
		Class: ClassIN,
		Data:  net.ParseIP("2001:db8::1").To16(),
	}); ip == nil {
		t.Fatal("resourceIP(valid AAAA) = nil")
	}
}

func TestCoverageDNSProviderSpawnErrorResponse(t *testing.T) {
	wantErr := errors.New("spawn failed")
	provider := newProvider(
		func(context.Context, Request) {},
		errWgSpawner{err: wantErr},
	)
	defer func() { _ = provider.Close() }()

	reply := make(chan Response, 1)
	provider.Requests() <- Request{Reply: reply}
	got := <-reply
	if !errors.Is(got.Err, wantErr) {
		t.Fatalf("provider spawn error = %v, want %v", got.Err, wantErr)
	}
}

type errWgSpawner struct {
	err error
}

func (s errWgSpawner) Spawn(worker func(), _ string) (uint64, error) {
	go worker()
	return 0, nil
}

func (s errWgSpawner) SpawnWg(
	func(),
	*sync.WaitGroup,
	string,
) (uint64, error) {
	return 0, s.err
}
