//nolint:testpackage
package routing

import (
	"net/netip"
	"regexp"
	"testing"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

var benchmarkRouteSlot int

func BenchmarkBytecodeSplitRouterRouteStatic(b *testing.B) {
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{},
		IPv4Addrs: []uint32{
			ip4(192, 0, 2, 2),
			ip4(10, 0, 0, 1),
		},
		IPv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(10, 0, 0, 0), Bits: 24},
		},
		RouteCacheTTL: -1,
		Route: slotWhen(andAll(
			[]byte{OP_NET4},
			[]byte{OP_TCP},
			param16(OP_ADDR4, 0),
			param16(OP_LADDR4, 1),
			param16(OP_SNET4, 0),
			param16(OP_LSNET4, 1),
			param16(OP_PORT, 443),
			param16(OP_LPORT, 12345),
		), 2),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, false)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteDNSCacheSuppliedNoStringOps(
	b *testing.B,
) {
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System:          &sysnetdebug.System{},
		DNSCacheStorage: gdns.NewMemoryStorage(),
		IPv4Addrs: []uint32{
			ip4(192, 0, 2, 2),
			ip4(10, 0, 0, 1),
		},
		RouteCacheTTL: -1,
		Route: slotWhen(andAll(
			[]byte{OP_NET4},
			[]byte{OP_TCP},
			param16(OP_ADDR4, 0),
			param16(OP_LADDR4, 1),
			param16(OP_PORT, 443),
			param16(OP_LPORT, 12345),
		), 2),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, false)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteDNSCacheGuardedFalse(b *testing.B) {
	storage := gdns.NewMemoryStorage()
	setTestPTR(storage, "192.0.2.2", "dst.test.")
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System:          &sysnetdebug.System{},
		Strings:         []string{"dst.test."},
		DNSCacheStorage: storage,
		IPv4Addrs:       []uint32{ip4(203, 0, 113, 1)},
		RouteCacheTTL:   -1,
		Route: slotWhen(andAll(
			[]byte{OP_TCP},
			param16(OP_ADDR4, 0),
			param16(OP_ADDR_S, 0),
		), 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, false)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteDNSCacheHit(b *testing.B) {
	storage := gdns.NewMemoryStorage()
	setTestPTR(storage, "192.0.2.2", "dst.test.")
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System:          &sysnetdebug.System{},
		Strings:         []string{"dst.test."},
		DNSCacheStorage: storage,
		RouteCacheTTL:   -1,
		Route:           slotWhen(param16(OP_ADDR_S, 0), 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, false)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteDNSCacheMiss(b *testing.B) {
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System:          &sysnetdebug.System{},
		Strings:         []string{"dst.test."},
		DNSCacheStorage: gdns.NewMemoryStorage(),
		RouteCacheTTL:   -1,
		Route:           slotWhen(param16(OP_ADDR_S, 0), 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, false)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteComplex(b *testing.B) {
	rule := sysnet.Rule{Type: "test", Rule: "native rule with spaces"}
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
				return got == rule &&
					flow.Proto == "tcp" &&
					flow.LocalPort == 12345 &&
					flow.RemotePort == 443, nil
			},
		},
		Rules: []sysnet.Rule{rule},
		Strings: []string{
			"192.0.2.2",
			"10.0.0.1",
			"2001:db8::2",
			"2001:db8::1",
		},
		Regexps: []*regexp.Regexp{
			regexp.MustCompile(`^192\.0\.2\.`),
			regexp.MustCompile(`^10\.0\.0\.`),
			regexp.MustCompile(`^2001:db8::`),
			regexp.MustCompile(`^ali`),
		},
		IPv4Addrs: []uint32{
			ip4(192, 0, 2, 2),
			ip4(10, 0, 0, 1),
		},
		IPv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(10, 0, 0, 0), Bits: 24},
		},
		IPv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::2"),
			netip.MustParseAddr("2001:db8::1"),
		},
		IPv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
		},
		RouteCacheTTL: -1,
		Route:         complexSplitRoute(),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, true)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteRuleRepeated(b *testing.B) {
	rule := sysnet.Rule{Type: "test", Rule: "repeated flow"}
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
				return got == rule &&
					flow.Proto == "tcp" &&
					flow.LocalPort == 12345 &&
					flow.RemotePort == 443, nil
			},
		},
		Rules:         []sysnet.Rule{rule},
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, true)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteRuleVaryingFlow(b *testing.B) {
	rule := sysnet.Rule{Type: "test", Rule: "varying flow"}
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
				return got == rule &&
					flow.Proto == "tcp" &&
					flow.RemotePort == 443, nil
			},
		},
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	packets := make([][]byte, 1024)
	for i := range packets {
		hi := byte(i >> 8)       //nolint:gosec // i is bounded by len(packets).
		lo := byte(i)            //nolint:gosec // i is bounded by len(packets).
		port := uint16(1024 + i) //nolint:gosec // i is bounded by len(packets).
		packets[i] = ipv4TCPPacket(
			[4]byte{10, 0, hi, lo},
			[4]byte{192, 0, 2, 2},
			port,
			443,
		)
	}

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for i := 0; b.Loop(); i++ {
		slot = router.Route(packets[i&(len(packets)-1)], 0, true)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteRuleGuardedFalse(b *testing.B) {
	rule := sysnet.Rule{Type: "test", Rule: "guarded flow"}
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
				return got == rule &&
					flow.Proto == "tcp" &&
					flow.RemotePort == 443, nil
			},
		},
		Rules:         []sysnet.Rule{rule},
		IPv4Addrs:     []uint32{ip4(203, 0, 113, 1)},
		RuleCacheTTL:  -1,
		RouteCacheTTL: -1,
		Route: slotWhen(andAll(
			[]byte{OP_TCP},
			param16(OP_ADDR4, 0),
			param16(OP_RULE, 0),
		), 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		slot = router.Route(pkt, 0, true)
	}
	benchmarkRouteSlot = slot
}

func BenchmarkBytecodeSplitRouterRouteResultCacheSmallBatch(b *testing.B) {
	rule := sysnet.Rule{Type: "test", Rule: "cached batch flow"}
	router := newBenchmarkSplitRouter(b, SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
				return got == rule &&
					flow.Proto == "tcp" &&
					flow.LocalPort == 12345 &&
					flow.RemotePort == 443, nil
			},
		},
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)

	b.ReportAllocs()
	b.ResetTimer()
	var slot int
	for b.Loop() {
		router.Lock()
		slot ^= router.Route(pkt, 0, true)
		slot ^= router.Route(pkt, 0, true)
		slot ^= router.Route(pkt, 0, true)
		router.Unlock()
	}
	benchmarkRouteSlot = slot
}

func newBenchmarkSplitRouter(
	b *testing.B,
	rules SplitBytecodeRules,
) SplitRouter {
	b.Helper()
	router, err := NewBytecodeSplitRouter(rules)
	if err != nil {
		b.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}
	b.Cleanup(func() { _ = router.Close() })
	return router
}
