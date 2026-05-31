// nolint
package routing

import (
	"encoding/binary"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
)

func TestBytecodeRouterCfgRoutesByBytecode(t *testing.T) {
	addr6 := netip.MustParseAddr("2001:db8::1")
	subnet6 := netip.MustParsePrefix("2001:db8:abcd::/48")
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		Strings:     []string{"example.com"},
		Regexps:     []*regexp.Regexp{regexp.MustCompile(`^api\.`)},
		IPv4Addrs:   []uint32{ip4(192, 0, 2, 10)},
		IPv4Subnets: []IPv4Subnet{{Addr: ip4(10, 0, 0, 0), Bits: 8}},
		IPv6Addrs:   []netip.Addr{addr6},
		IPv6Subnets: []netip.Prefix{subnet6},
		DialTCP: append(
			append(param16(OP_ADDR_S, 0), OP_SLOT, 2),
			append(param16(OP_ADDR4, 0), OP_SLOT, 3)...,
		),
		ListenTCP: append(param16(OP_LPORT, 80), OP_SLOT, 4),
		DialUDP: append(
			append([]byte{OP_UDP}, param16(OP_PORT, 53)...),
			OP_AND, OP_SLOT, 5,
		),
		RouteUDP: append(
			append(param16(OP_LSNET4, 0), param16(OP_ADDR6, 0)...),
			OP_OR, OP_SLOT, 6,
		),
		Lookup: append(
			append([]byte{OP_FQDN}, param16(OP_ADDR_RE, 0)...),
			OP_AND, OP_SLOT, 7,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.DialTCP("tcp", "", "example.com:443"); got != 2 {
		t.Fatalf("DialTCP string route = %d, want 2", got)
	}
	if got := cfg.DialTCP("tcp", "", "192.0.2.10:443"); got != 3 {
		t.Fatalf("DialTCP IPv4 route = %d, want 3", got)
	}
	if got := cfg.DialTCP("tcp", "", "other.example:443"); got != 0 {
		t.Fatalf("DialTCP default route = %d, want 0", got)
	}
	if got := cfg.ListenTCP("tcp", "127.0.0.1:http"); got != 4 {
		t.Fatalf("ListenTCP service port route = %d, want 4", got)
	}
	if got := cfg.DialUDP("udp", "", "8.8.8.8:dns"); got != 5 {
		t.Fatalf("DialUDP service port route = %d, want 5", got)
	}
	if got := cfg.RouteUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53},
	); got != 6 {
		t.Fatalf("RouteUDP local subnet route = %d, want 6", got)
	}
	if got := cfg.RouteUDP(
		"udp6",
		&net.UDPAddr{IP: net.ParseIP("2001:db8:abcd::2"), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53},
	); got != 6 {
		t.Fatalf("RouteUDP IPv6 address route = %d, want 6", got)
	}
	if got := cfg.Lookup("ip", "api.example.com"); got != 7 {
		t.Fatalf("Lookup route = %d, want 7", got)
	}
	if got := cfg.Lookup("ip", "2001:db8::1"); got != 0 {
		t.Fatalf("Lookup IP route = %d, want 0", got)
	}
}

func TestBytecodeRouterCfgNetworkFamily(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		DialTCP: append(
			append([]byte{OP_NET4, OP_SLOT, 2, OP_NET6, OP_SLOT, 3}, OP_TRUE),
			OP_SLOT, 1,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	tests := []struct {
		network string
		raddr   string
		want    int
	}{
		{network: "tcp4", raddr: "example.com:80", want: 2},
		{network: "tcp6", raddr: "example.com:80", want: 3},
		{network: "tcp", raddr: "192.0.2.1:80", want: 2},
		{network: "tcp", raddr: "[2001:db8::1]:80", want: 3},
		{network: "tcp", raddr: "example.com:80", want: 1},
	}
	for _, tt := range tests {
		if got := cfg.DialTCP(tt.network, "", tt.raddr); got != tt.want {
			t.Fatalf(
				"DialTCP(%q, %q) = %d, want %d",
				tt.network,
				tt.raddr,
				got,
				tt.want,
			)
		}
	}
}

func TestBytecodeRouterCfgPortMatchesBareService(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		Lookup: append(param16(OP_PORT, 80), OP_SLOT, 2),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.Lookup("tcp", "http"); got != 2 {
		t.Fatalf("Lookup bare service route = %d, want 2", got)
	}
	if got := cfg.Lookup("tcp", "80"); got != 2 {
		t.Fatalf("Lookup bare numeric port route = %d, want 2", got)
	}
	if got := cfg.Lookup("udp", "ntp"); got != 0 {
		t.Fatalf("Lookup wrong service route = %d, want 0", got)
	}
}

func TestBytecodeRouterCfgIPChecksOnWrongAddressTypeAreFalse(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		IPv4Addrs:   []uint32{0},
		IPv4Subnets: []IPv4Subnet{{Addr: 0, Bits: 0}},
		DialTCP: append(
			append(param16(OP_ADDR4, 0), OP_SLOT, 2),
			append(param16(OP_SNET4, 0), OP_SLOT, 3)...,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.DialTCP("tcp", "", "example.com:80"); got != 0 {
		t.Fatalf("FQDN IPv4 checks route = %d, want 0", got)
	}
	if got := cfg.DialTCP("tcp", "", "[2001:db8::1]:80"); got != 0 {
		t.Fatalf("IPv6 IPv4 checks route = %d, want 0", got)
	}
	if got := cfg.DialTCP("tcp", "", "192.0.2.1:80"); got != 3 {
		t.Fatalf("IPv4 /0 subnet route = %d, want 3", got)
	}
}

func TestBytecodeRouterCfgConstructionCopiesRules(t *testing.T) {
	code := append(param16(OP_ADDR_S, 0), OP_SLOT, 2)
	rules := BytecodeRules{
		Strings: []string{"example.com"},
		DialTCP: code,
	}
	cfg, err := NewBytecodeRouterCfg(rules)
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}
	rules.Strings[0] = "changed.example"
	code[0] = OP_TRUE

	if got := cfg.DialTCP("tcp", "", "example.com:80"); got != 2 {
		t.Fatalf("route after mutating source rules = %d, want 2", got)
	}
}

func TestBytecodeRouterCfgValidation(t *testing.T) {
	validPrefix := netip.MustParsePrefix("2001:db8::/32")
	tests := []struct {
		name  string
		rules BytecodeRules
		want  string
	}{
		{
			name:  "unknown opcode",
			rules: BytecodeRules{DialTCP: []byte{255}},
			want:  "unknown opcode",
		},
		{
			name: "split opcode",
			rules: BytecodeRules{
				DialTCP: append([]byte{OP_RULE}, param64Bytes(1)...),
			},
			want: "not valid for RouterCfg",
		},
		{
			name:  "missing uint8 param",
			rules: BytecodeRules{DialTCP: []byte{OP_TRUE, OP_SLOT}},
			want:  "missing uint8 parameter",
		},
		{
			name:  "missing uint16 param",
			rules: BytecodeRules{DialTCP: []byte{OP_ADDR_S, 0}},
			want:  "missing uint16 parameter",
		},
		{
			name:  "string index",
			rules: BytecodeRules{DialTCP: param16(OP_ADDR_S, 0)},
			want:  "string index 0 out of range 0",
		},
		{
			name: "regexp nil",
			rules: BytecodeRules{
				Regexps: []*regexp.Regexp{nil},
			},
			want: "regexp 0 is nil",
		},
		{
			name: "regexp index",
			rules: BytecodeRules{
				DialTCP: param16(OP_ADDR_RE, 0),
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "slot range",
			rules: BytecodeRules{
				DialTCP: []byte{OP_TRUE, OP_SLOT, 17},
			},
			want: "slot 17 out of range",
		},
		{
			name: "stack underflow",
			rules: BytecodeRules{
				DialTCP: []byte{OP_AND},
			},
			want: "stack underflow",
		},
		{
			name: "lookup laddr op",
			rules: BytecodeRules{
				Lookup: []byte{OP_LFQDN},
			},
			want: "local-address opcode",
		},
		{
			name: "invalid IPv4 subnet",
			rules: BytecodeRules{
				IPv4Subnets: []IPv4Subnet{{Bits: 33}},
			},
			want: "prefix length 33",
		},
		{
			name: "invalid IPv6 address",
			rules: BytecodeRules{
				IPv6Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			},
			want: "IPv6 address 0",
		},
		{
			name: "invalid IPv6 subnet",
			rules: BytecodeRules{
				IPv6Subnets: []netip.Prefix{
					netip.MustParsePrefix("192.0.2.0/24"),
				},
			},
			want: "IPv6 subnet 0",
		},
		{
			name: "valid IPv6 subnet referenced",
			rules: BytecodeRules{
				IPv6Subnets: []netip.Prefix{validPrefix},
				DialTCP:     append(param16(OP_SNET6, 0), OP_SLOT, 2),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeRouterCfg(tt.rules)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("NewBytecodeRouterCfg() succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf(
					"NewBytecodeRouterCfg() error = %q, want substring %q",
					err,
					tt.want,
				)
			}
		})
	}
}

func TestBytecodeSplitRouterRoutesPackets(t *testing.T) {
	matcher := &testIPMatcher{}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher:   matcher,
		IPv4Addrs: []uint32{ip4(192, 0, 2, 2)},
		Route: append(
			append(
				append(
					append([]byte{OP_NET4, OP_TCP}, OP_AND),
					param16(OP_ADDR4, 0)...,
				),
				OP_AND,
			),
			append(param16(OP_PORT, 443), OP_AND, OP_SLOT, 4)...,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)
	buf := append([]byte{0xaa, 0xbb, 0xcc}, pkt...)
	cfg.Lock()
	got := cfg.Route(buf, 3, false)
	cfg.Unlock()
	if got != 4 {
		t.Fatalf("Route() = %d, want 4", got)
	}
	if matcher.locks != 1 || matcher.unlocks != 1 {
		t.Fatalf(
			"matcher locks = %d/%d, want 1/1",
			matcher.locks,
			matcher.unlocks,
		)
	}
	if got := cfg.Route(buf[:3], 3, false); got != 0 {
		t.Fatalf("Route(malformed) = %d, want 0", got)
	}
}

func TestBytecodeSplitRouterMatcherCaching(t *testing.T) {
	matcher := &testIPMatcher{
		rules: map[uint64]bool{42: true},
		info: &sysnet.NetInfo{
			UID:       1000,
			User:      "alice",
			RouteMark: -7,
			PID:       123,
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher: matcher,
		Strings: []string{"alice"},
		Route: append(
			append(
				append(
					append([]byte{OP_RULE}, param64Bytes(42)...),
					append([]byte{OP_RULE}, param64Bytes(42)...)...,
				),
				OP_AND,
			),
			append(
				append(
					append(param64(OP_UID, 1000), param16(OP_UNAME, 0)...),
					OP_AND,
				),
				append(param32(OP_MARK, ^uint32(6)), OP_AND, OP_SLOT, 8)...,
			)...,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	if got := cfg.Route(
		ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2),
		0,
		true,
	); got != 8 {
		t.Fatalf("Route() = %d, want 8", got)
	}
	if matcher.matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matcher.matchCalls)
	}
	if matcher.infoCalls != 1 {
		t.Fatalf("PktInfo calls = %d, want 1", matcher.infoCalls)
	}
}

func TestBytecodeSplitRouterSkipsMatcherForNonNativePackets(t *testing.T) {
	matcher := &testIPMatcher{
		rules: map[uint64]bool{42: true},
		info: &sysnet.NetInfo{
			UID: 1000,
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher: matcher,
		Route: append(
			append(
				append([]byte{OP_RULE}, param64Bytes(42)...),
				param64(OP_UID, 1000)...,
			),
			OP_OR, OP_SLOT, 8,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	if got := cfg.Route(
		ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2),
		0,
		false,
	); got != 0 {
		t.Fatalf("Route(non-native) = %d, want 0", got)
	}
	if matcher.matchCalls != 0 {
		t.Fatalf("Match calls = %d, want 0", matcher.matchCalls)
	}
	if matcher.infoCalls != 0 {
		t.Fatalf("PktInfo calls = %d, want 0", matcher.infoCalls)
	}
}

func TestBytecodeSplitRouterValidation(t *testing.T) {
	_, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher: &testIPMatcher{},
		Route:   param16(OP_UNAME, 0),
	})
	if err == nil ||
		!strings.Contains(err.Error(), "string index 0 out of range 0") {
		t.Fatalf(
			"NewBytecodeSplitRouter() error = %v, want string index error",
			err,
		)
	}
	_, err = NewBytecodeSplitRouter(SplitBytecodeRules{})
	if err == nil || !strings.Contains(err.Error(), "matcher is nil") {
		t.Fatalf(
			"NewBytecodeSplitRouter(nil matcher) error = %v, want nil matcher error",
			err,
		)
	}
}

func param16(op byte, param uint16) []byte {
	out := []byte{op, 0, 0}
	binary.LittleEndian.PutUint16(out[1:], param)
	return out
}

func param32(op byte, param uint32) []byte {
	out := []byte{op, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[1:], param)
	return out
}

func param64(op byte, param uint64) []byte {
	return append([]byte{op}, param64Bytes(param)...)
}

func param64Bytes(param uint64) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, param)
	return out
}

func ip4(a, b, c, d byte) uint32 {
	return binary.BigEndian.Uint32([]byte{a, b, c, d})
}

func ipv4TCPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50
	return pkt
}

type testIPMatcher struct {
	locks, unlocks int
	matchCalls     int
	infoCalls      int
	rules          map[uint64]bool
	info           *sysnet.NetInfo
}

func (m *testIPMatcher) Lock() { m.locks++ }

func (m *testIPMatcher) Unlock() { m.unlocks++ }

func (m *testIPMatcher) Map(sysnet.Rule) uint64 { return 0 }

func (m *testIPMatcher) UnMap(uint64) {}

func (m *testIPMatcher) UnMapAll() {}

func (m *testIPMatcher) Match(_ []byte, rule uint64) bool {
	m.matchCalls++
	return m.rules[rule]
}

func (m *testIPMatcher) PktInfo(_ []byte) *sysnet.NetInfo {
	m.infoCalls++
	return m.info
}

func (m *testIPMatcher) Close() error { return nil }
