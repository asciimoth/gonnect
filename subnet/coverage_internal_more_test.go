package subnet //nolint:testpackage // Covers unexported allocator branches.

import (
	"math/big"
	"net"
	"testing"
)

func TestCoverageSubnetAllocatorInternalBranches(t *testing.T) {
	empty := NewSubnetAllocator(nil, nil)
	if got := empty.AllocSubnet4(24); got != nil {
		t.Fatalf("nil parent AllocSubnet4() = %v, want nil", got)
	}
	malformed := NewSubnetAllocator(
		&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)},
		nil,
	)
	if got := malformed.AllocSubnet4(24); got != nil {
		t.Fatalf("malformed parent AllocSubnet4() = %v, want nil", got)
	}

	alloc := NewSubnetAllocator(mustCIDRForInternalTest(t, "192.0.2.0/29"), nil)
	a, ok := alloc.(*subnetAllocator)
	if !ok {
		t.Fatalf("NewSubnetAllocator() = %T, want *subnetAllocator", alloc)
	}

	a.reserve(nil)
	a.reserve(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)})
	if len(a.reserved) != 0 {
		t.Fatalf("invalid reservations changed state: %#v", a.reserved)
	}

	ipv6 := mustCIDRForInternalTest(t, "2001:db8::/126")
	a.reserve(ipv6)
	if got := len(a.sortedBlockers()); got != 0 {
		t.Fatalf("sortedBlockers() with IPv6 blocker = %d, want 0", got)
	}

	before := len(a.reserved)
	a.FreeSubnet(mustCIDRForInternalTest(t, "198.51.100.0/30"))
	if got := len(a.reserved); got != before {
		t.Fatalf(
			"FreeSubnet(missing) changed reservations to %d, want %d",
			got,
			before,
		)
	}
	a.FreeSubnet(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)})
	if got := len(a.reserved); got != before {
		t.Fatalf(
			"FreeSubnet(malformed) changed reservations to %d, want %d",
			got,
			before,
		)
	}
}

func TestCoverageCombinedAllocatorInternalBranches(t *testing.T) {
	alloc := NewCombinedAllocator(
		mustCIDRForInternalTest(t, "192.0.2.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	alloc.reserveSubnetLocked(nil)
	alloc.reserveSubnetLocked(&net.IPNet{
		IP:   net.IP{1, 2, 3},
		Mask: net.CIDRMask(24, 32),
	})
	if len(alloc.reservedSubnets) != 0 {
		t.Fatalf(
			"invalid subnet reservations changed state: %#v",
			alloc.reservedSubnets,
		)
	}

	normalized := normalizeSubnet(mustCIDRForInternalTest(t, "192.0.2.0/30"))
	if alloc.freeReservedSubnetLocked(normalized) {
		t.Fatal("freeReservedSubnetLocked(missing) = true, want false")
	}

	alloc.reserveSubnetLocked(normalized.network)
	alloc.reserveSubnetLocked(normalized.network)
	if alloc.freeReservedSubnetLocked(normalized) {
		t.Fatal("freeReservedSubnetLocked(refcount) = true, want false")
	}
	if got := alloc.reservedSubnets[subnetMapKey(
		normalized.network,
		normalized.bits,
		normalized.prefix,
	)].count; got != 1 {
		t.Fatalf("reserved count = %d, want 1", got)
	}

	alloc.reserveIPLocked(nil)
	alloc.reserveIPLocked(net.IP{1, 2, 3})
	if got := normalizeAnyIP(net.IP{1, 2, 3}); got != nil {
		t.Fatalf("normalizeAnyIP(short) = %#v, want nil", got)
	}
}

func TestCoverageSubnetUtilityBranches(t *testing.T) {
	emptyIPAlloc := NewIPAllocator(nil, nil)
	if ip, network := emptyIPAlloc.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("nil network AllocIP4() = %v, %v; want nil, nil", ip, network)
	}
	malformedIPAlloc := NewIPAllocator(
		&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)},
		nil,
	)
	if ip, network := malformedIPAlloc.AllocIP4(); ip != nil || network != nil {
		t.Fatalf(
			"malformed network AllocIP4() = %v, %v; want nil, nil",
			ip,
			network,
		)
	}

	invalid := &net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)}
	if _, err := IPIndex(invalid, big.NewInt(0)); err == nil {
		t.Fatal("IPIndex(invalid IP) error = nil, want error")
	}

	if got := intToIP(
		new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5}),
		32,
	); !got.Equal(
		net.IPv4(2, 3, 4, 5),
	) {
		t.Fatalf("intToIP(truncate) = %v, want 2.3.4.5", got)
	}

	if got := normalizeIPForBits(net.ParseIP("192.0.2.1"), 0); got != nil {
		t.Fatalf("normalizeIPForBits(invalid bits) = %v, want nil", got)
	}
}
