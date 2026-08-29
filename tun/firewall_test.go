// Tests in this file use private packet parsing and test support functions.
package tun //nolint:testpackage

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestFirewallReadFiltersOutgoingBatchAndTracksResponse(t *testing.T) {
	backend := newFirewallTestTun(4)
	blocked := firewallIPv4Packet(
		6,
		"10.0.0.1",
		"192.0.2.10",
		40000,
		80,
	)
	allowed := firewallIPv4Packet(
		17,
		"10.0.0.1",
		"198.51.100.53",
		40001,
		53,
	)
	backend.queueRead(blocked, allowed)

	firewall := NewFirewall(backend, &gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Ports:   []uint16{80},
		}},
	})
	bufs := [][]byte{make([]byte, 256), make([]byte, 256)}
	sizes := make([]int, len(bufs))
	n, err := firewall.Read(bufs, sizes, 8)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 1 || sizes[0] != len(allowed) ||
		string(bufs[0][8:8+sizes[0]]) != string(allowed) {
		t.Fatalf(
			"Read() returned n=%d sizes=%v, want only allowed packet",
			n,
			sizes,
		)
	}

	response := firewallIPv4Packet(
		17,
		"198.51.100.53",
		"10.0.0.1",
		53,
		40001,
	)
	if n, err := firewall.Write([][]byte{response}, 0); err != nil || n != 1 {
		t.Fatalf("response Write() = %d, %v, want 1, nil", n, err)
	}
	if got := backend.writtenPackets(); len(got) != 1 ||
		string(got[0]) != string(response) {
		t.Fatalf("backend writes = %d, want response packet", len(got))
	}

	unsolicited := firewallIPv4Packet(
		17,
		"198.51.100.53",
		"10.0.0.1",
		53,
		40002,
	)
	if n, err := firewall.Write(
		[][]byte{unsolicited},
		0,
	); err != nil ||
		n != 1 {
		t.Fatalf("unsolicited Write() = %d, %v, want consumed", n, err)
	}
	if got := backend.writtenPackets(); len(got) != 1 {
		t.Fatalf("backend writes = %d after denied packet, want 1", len(got))
	}
}

func TestFirewallIncomingRulesIPv6ExtensionsAndConfigSwap(t *testing.T) {
	backend := newFirewallTestTun(2)
	cfg := &gonnect.FirewallConfig{Include: []gonnect.FirewallRule{{
		Network: "tcp",
		Hosts:   []string{"203.0.113.0/24"},
		Ports:   []uint16{443},
	}}}
	firewall := NewFirewall(backend, cfg)
	cfg.Include[0].Ports[0] = 80

	allowed := firewallIPv4Packet(
		6,
		"203.0.113.9",
		"10.0.0.1",
		50000,
		443,
	)
	denied := firewallIPv4Packet(
		6,
		"203.0.114.9",
		"10.0.0.1",
		50000,
		443,
	)
	if n, err := firewall.Write(
		[][]byte{denied, allowed},
		0,
	); err != nil ||
		n != 2 {
		t.Fatalf("Write() = %d, %v, want 2, nil", n, err)
	}
	if got := backend.writtenPackets(); len(got) != 1 ||
		string(got[0]) != string(allowed) {
		t.Fatalf("backend writes = %d, want only included TCP packet", len(got))
	}

	active := firewall.GetConfig()
	active.Include[0].Ports[0] = 22
	if firewall.GetConfig().Include[0].Ports[0] != 443 {
		t.Fatal("GetConfig() returned shared data")
	}

	ipv6 := firewallIPv6HopUDP(
		"2001:db8::1",
		"2001:db8::2",
		41000,
		5353,
	)
	flow, ok := parseFirewallPacket(ipv6)
	if !ok || flow.network() != "udp6" || flow.srcPort != 41000 ||
		flow.dstPort != 5353 {
		t.Fatalf("IPv6 extension parse = %+v, %v", flow, ok)
	}

	firewall.SetConfig(&gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
		Network: "udp",
		Hosts:   []string{"2001:db8::2"},
		Ports:   []uint16{5353},
	}}})
	backend.queueRead(ipv6)
	backend.queueReadError(io.EOF)
	bufs := [][]byte{make([]byte, 256)}
	sizes := make([]int, 1)
	if n, err := firewall.Read(
		bufs,
		sizes,
		0,
	); n != 0 ||
		!errors.Is(err, io.EOF) {
		t.Fatalf("blocked Read() = %d, %v, want 0, EOF", n, err)
	}
}

func TestFirewallTunMetadataAndMalformedPackets(t *testing.T) {
	backend := newFirewallTestTun(3)
	firewall := NewFirewall(backend, nil)
	if firewall.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	if firewall.File() != nil {
		t.Fatal("File() is not nil")
	}
	if firewall.GetWrapped() != backend || firewall.GetTun() != backend {
		t.Fatal("wrapped Tun accessors returned the wrong value")
	}
	if firewall.MRO() != 4 || firewall.MWO() != 8 || firewall.BatchSize() != 3 {
		t.Fatal("Tun shape was not delegated")
	}
	if mtu, err := firewall.MTU(); err != nil || mtu != 1500 {
		t.Fatalf("MTU() = %d, %v", mtu, err)
	}
	if name, err := firewall.Name(); err != nil || name != "firewall-test" {
		t.Fatalf("Name() = %q, %v", name, err)
	}
	if firewall.Events() != backend.events {
		t.Fatal("Events() was not delegated")
	}
	if _, ok := parseFirewallPacket([]byte{0x70}); ok {
		t.Fatal("parseFirewallPacket() accepted a non-IP packet")
	}
	if _, ok := parseFirewallPacket([]byte{0x45}); ok {
		t.Fatal("parseFirewallPacket() accepted a short IPv4 packet")
	}
	if n, err := firewall.Write([][]byte{{0x70}}, 0); err != nil || n != 1 {
		t.Fatalf("malformed Write() = %d, %v, want consumed", n, err)
	}
	if len(backend.writtenPackets()) != 0 {
		t.Fatal("malformed packet reached backend")
	}
	if err := firewall.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestFirewallOptimizesInstalledConfig(t *testing.T) {
	source := &gonnect.FirewallConfig{Include: []gonnect.FirewallRule{
		{
			Network: " UDP ",
			Hosts:   []string{"192.0.2.1"},
			Ports:   []uint16{53},
		},
		{
			Network: "udp",
			Hosts:   []string{"192.0.2.1"},
			Ports:   []uint16{54},
		},
	}}
	firewall := NewFirewall(newFirewallTestTun(1), source)

	active := firewall.GetConfig()
	if len(active.Include) != 1 ||
		len(active.Include[0].PortRanges) != 1 ||
		active.Include[0].PortRanges[0] != (gonnect.FirewallPortRange{
			First: 53,
			Last:  54,
		}) {
		t.Fatalf("installed config was not optimized: %#v", active.Include)
	}
	if source.Include[0].Network != " UDP " {
		t.Fatal("NewFirewall modified its source config")
	}
}

func TestFirewallAllowsRelatedICMPError(t *testing.T) {
	backend := newFirewallTestTun(1)
	firewall := NewFirewall(backend, nil)
	original := firewallIPv4Packet(
		17,
		"10.0.0.1",
		"198.51.100.1",
		42000,
		33434,
	)
	backend.queueRead(original)
	bufs := [][]byte{make([]byte, 256)}
	sizes := make([]int, 1)
	if n, err := firewall.Read(bufs, sizes, 0); err != nil || n != 1 {
		t.Fatalf("outgoing Read() = %d, %v", n, err)
	}

	icmp := make([]byte, 20+8+len(original))
	icmp[0] = 0x45
	// The test packet has a fixed, small size.
	binary.BigEndian.PutUint16(icmp[2:4], uint16(len(icmp))) //nolint:gosec
	icmp[8] = 64
	icmp[9] = 1
	copy(icmp[12:16], netip.MustParseAddr("192.0.2.254").AsSlice())
	copy(icmp[16:20], netip.MustParseAddr("10.0.0.1").AsSlice())
	icmp[20] = 3
	copy(icmp[28:], original)
	if n, err := firewall.Write([][]byte{icmp}, 0); err != nil || n != 1 {
		t.Fatalf("related ICMP Write() = %d, %v", n, err)
	}
	if got := backend.writtenPackets(); len(got) != 1 ||
		string(got[0]) != string(icmp) {
		t.Fatalf("backend writes = %d, want related ICMP error", len(got))
	}

	unrelated := append([]byte(nil), icmp...)
	copy(unrelated[28+16:28+20], netip.MustParseAddr("203.0.113.1").AsSlice())
	if n, err := firewall.Write([][]byte{unrelated}, 0); err != nil || n != 1 {
		t.Fatalf("unrelated ICMP Write() = %d, %v", n, err)
	}
	if got := backend.writtenPackets(); len(got) != 1 {
		t.Fatalf("backend writes = %d after unrelated ICMP, want 1", len(got))
	}
}

func TestFirewallDetachedPipeChain(t *testing.T) {
	local, peer := Pipe(1, 1500, 0, 0)
	defer closeFirewallTestTun(local)
	defer closeFirewallTestTun(peer)
	firewall := NewFirewall(local, nil)
	detached := Detach(firewall, nil, nil)
	defer closeFirewallTestTun(detached)

	outgoing := firewallIPv4Packet(
		17,
		"10.10.0.1",
		"10.10.0.2",
		45000,
		53,
	)
	writeResult := make(chan error, 1)
	go func() {
		_, err := peer.Write([][]byte{outgoing}, 0)
		writeResult <- err
	}()
	bufs := [][]byte{make([]byte, 1600)}
	sizes := make([]int, 1)
	n, err := detached.Read(bufs, sizes, 0)
	if err != nil || n != 1 ||
		!firewallTestPacketMatches(bufs, sizes, outgoing) {
		t.Fatalf("chain Read() = %d, %v", n, err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("peer outgoing Write() error = %v", err)
	}

	response := firewallIPv4Packet(
		17,
		"10.10.0.2",
		"10.10.0.1",
		53,
		45000,
	)
	readResult := make(chan error, 1)
	go func() {
		readBufs := [][]byte{make([]byte, 1600)}
		readSizes := make([]int, 1)
		n, err := peer.Read(readBufs, readSizes, 0)
		if err == nil &&
			(n != 1 || !firewallTestPacketMatches(
				readBufs,
				readSizes,
				response,
			)) {
			err = errors.New("peer received the wrong response")
		}
		readResult <- err
	}()
	if n, err := detached.Write([][]byte{response}, 0); err != nil || n != 1 {
		t.Fatalf("chain response Write() = %d, %v", n, err)
	}
	select {
	case err := <-readResult:
		if err != nil {
			t.Fatalf("peer response Read() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("response did not traverse Firewall and DetachedTun chain")
	}
}

type firewallTestRead struct {
	packets [][]byte
	err     error
}

type firewallTestTun struct {
	batch  int
	events chan Event
	reads  chan firewallTestRead
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func newFirewallTestTun(batch int) *firewallTestTun {
	return &firewallTestTun{
		batch:  batch,
		events: make(chan Event),
		reads:  make(chan firewallTestRead, 8),
	}
}

func (t *firewallTestTun) queueRead(packets ...[]byte) {
	t.reads <- firewallTestRead{packets: packets}
}

func (t *firewallTestTun) queueReadError(err error) {
	t.reads <- firewallTestRead{err: err}
}

func (t *firewallTestTun) File() *os.File { return nil }
func (t *firewallTestTun) IsNative() bool { return true }
func (t *firewallTestTun) MWO() int       { return 8 }
func (t *firewallTestTun) MRO() int       { return 4 }
func (t *firewallTestTun) MTU() (int, error) {
	return 1500, nil
}
func (t *firewallTestTun) Name() (string, error) { return "firewall-test", nil }
func (t *firewallTestTun) Events() <-chan Event  { return t.events }
func (t *firewallTestTun) BatchSize() int        { return t.batch }

func (t *firewallTestTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	read := <-t.reads
	if read.err != nil {
		return 0, read.err
	}
	n := min(len(read.packets), len(bufs), len(sizes))
	for i := range n {
		copy(bufs[i][offset:], read.packets[i])
		sizes[i] = len(read.packets[i])
	}
	return n, nil
}

func (t *firewallTestTun) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, buf := range bufs {
		t.writes = append(t.writes, append([]byte(nil), buf[offset:]...))
	}
	return len(bufs), nil
}

func (t *firewallTestTun) Close() error {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.events)
	}
	t.mu.Unlock()
	return nil
}

func (t *firewallTestTun) writtenPackets() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][]byte, len(t.writes))
	for i := range t.writes {
		out[i] = append([]byte(nil), t.writes[i]...)
	}
	return out
}

func firewallIPv4Packet(
	proto byte,
	src, dst string,
	srcPort, dstPort uint16,
) []byte {
	packet := make([]byte, 28)
	if proto == 6 {
		packet = make([]byte, 40)
	}
	packet[0] = 0x45
	// The test packet has a fixed, small size.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet))) //nolint:gosec
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], netip.MustParseAddr(src).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	return packet
}

func closeFirewallTestTun(tun io.Closer) {
	_ = tun.Close()
}

func firewallTestPacketMatches(bufs [][]byte, sizes []int, want []byte) bool {
	if len(bufs) == 0 || len(sizes) == 0 {
		return false
	}
	size := sizes[0]
	return size >= 0 && size <= len(bufs[0]) &&
		string(bufs[0][:size]) == string(want)
}

func firewallIPv6HopUDP(
	src, dst string,
	srcPort, dstPort uint16,
) []byte {
	packet := make([]byte, 56)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 16)
	packet[6] = 0
	packet[7] = 64
	copy(packet[8:24], netip.MustParseAddr(src).AsSlice())
	copy(packet[24:40], netip.MustParseAddr(dst).AsSlice())
	packet[40] = 17
	packet[41] = 0
	binary.BigEndian.PutUint16(packet[48:50], srcPort)
	binary.BigEndian.PutUint16(packet[50:52], dstPort)
	return packet
}
