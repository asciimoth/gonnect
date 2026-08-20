package subnet

import (
	"math/big"
	"math/rand"
	"net"
	"testing"
)

func TestCombinedAllocatorInternalEdgeBranches(t *testing.T) {
	alloc := NewCombinedAllocator(
		mustCIDRForInternalTest(t, "192.0.2.0/29"),
		nil,
		32,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	if got := newCombinedPoolSubnet(&net.IPNet{
		IP:   net.IP{1, 2, 3},
		Mask: net.CIDRMask(24, 32),
	}); got != nil {
		t.Fatalf("newCombinedPoolSubnet(invalid) = %v, want nil", got)
	}

	if got, gotSubnet := alloc.AllocIP4(); got != nil || gotSubnet != nil {
		t.Fatalf(
			"AllocIP4 with /32 pool prefix = %v, %v, want nils",
			got,
			gotSubnet,
		)
	}

	alloc.ReserveIP(net.ParseIP("192.0.2.1"))
	alloc.ReserveIP(net.ParseIP("192.0.2.1"))
	alloc.FreeIP(net.ParseIP("192.0.2.1"))
	reserved := alloc.reservedIPs[ipReservationKey(normalizeAnyIP(net.ParseIP("192.0.2.1")))]
	if reserved == nil || reserved.count != 1 {
		t.Fatalf("reserved count after one free = %#v, want count 1", reserved)
	}
	alloc.FreeIP(net.ParseIP("192.0.2.1"))
	if reserved := alloc.reservedIPs[ipReservationKey(normalizeAnyIP(net.ParseIP("192.0.2.1")))]; reserved != nil {
		t.Fatalf(
			"reserved count after second free = %#v, want removed",
			reserved,
		)
	}

	if got := randomBigInt(
		rand.New(rand.NewSource(1)), //nolint:gosec // Deterministic test RNG.
		big.NewInt(0),
	); got.Sign() != 0 {
		t.Fatalf("randomBigInt(non-positive) = %v, want 0", got)
	}
	largeLimit := new(big.Int).Lsh(big.NewInt(1), 70)
	if got := randomBigInt(
		rand.New(rand.NewSource(1)), //nolint:gosec // Deterministic test RNG.
		largeLimit,
	); got.Sign() < 0 ||
		got.Cmp(largeLimit) >= 0 {
		t.Fatalf("randomBigInt(large) = %v, want in range", got)
	}
}

func TestCombinedAllocatorRemovePoolSubnetLocked(t *testing.T) {
	alloc := NewCombinedAllocator(
		nil,
		nil,
		32,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	alloc.poolSubnets[32] = []*combinedPoolSubnet{
		newCombinedPoolSubnet(mustCIDRForInternalTest(t, "192.0.2.0/29")),
		newCombinedPoolSubnet(mustCIDRForInternalTest(t, "198.51.100.0/29")),
	}

	normalized := normalizeSubnet(
		mustCIDRForInternalTest(t, "192.0.2.0/29"),
	)
	alloc.removePoolSubnetLocked(normalized)
	if len(alloc.poolSubnets[32]) != 1 ||
		!alloc.poolSubnets[32][0].network.IP.Equal(
			net.ParseIP("198.51.100.0"),
		) {
		t.Fatalf("poolSubnets after remove = %#v", alloc.poolSubnets[32])
	}

	alloc.removePoolSubnetLocked(normalizeSubnet(
		mustCIDRForInternalTest(t, "203.0.113.0/29"),
	))
	if len(alloc.poolSubnets[32]) != 1 {
		t.Fatalf(
			"missing remove changed poolSubnets: %#v",
			alloc.poolSubnets[32],
		)
	}
}

func mustCIDRForInternalTest(t *testing.T, s string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q) error = %v", s, err)
	}
	return network
}
