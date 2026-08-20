package subnet //nolint:testpackage // Covers unexported allocator branches.

import (
	"net"
	"testing"
)

func TestCoverageIPAllocatorRefcountWrapAndFilterBranches(t *testing.T) {
	noUsable := NewIPAllocator(mustCIDRForInternalTest(t, "192.0.2.0/31"), nil)
	if ip, network := noUsable.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("AllocIP4(/31) = %v, %v; want nil, nil", ip, network)
	}

	alloc := NewIPAllocator(mustCIDRForInternalTest(t, "192.0.2.0/30"), nil)
	alloc.ReserveIP(net.IPv4(192, 0, 2, 1))
	alloc.ReserveIP(net.IPv4(192, 0, 2, 1))
	alloc.FreeIP(net.IPv4(192, 0, 2, 1))
	ip, _ := alloc.AllocIP4()
	if !ip.Equal(net.IPv4(192, 0, 2, 2)) {
		t.Fatalf("AllocIP4() with refcounted reserve = %v, want 192.0.2.2", ip)
	}
	alloc.FreeIP(net.IPv4(192, 0, 2, 1))
	alloc.FreeIP(ip)
	ip, _ = alloc.AllocIP4()
	if !ip.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("AllocIP4() after freeing reserve = %v, want 192.0.2.1", ip)
	}
	alloc.FreeIP(net.IPv4(198, 51, 100, 1))
	alloc.FreeAllIP()
	ip, _ = alloc.AllocIP4()
	if !ip.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("AllocIP4() after FreeAllIP = %v, want 192.0.2.1", ip)
	}

	filtered := NewIPAllocator(
		mustCIDRForInternalTest(t, "10.0.0.0/16"),
		func(net.IP) bool { return false },
	)
	if ip, network := filtered.AllocIP4(); ip != nil || network != nil {
		t.Fatalf("filtered AllocIP4() = %v, %v; want nil, nil", ip, network)
	}
}

func TestCoverageIPAllocatorIPv6AndInternalBranches(t *testing.T) {
	alloc := NewIPAllocator(mustCIDRForInternalTest(t, "2001:db8::/126"), nil)
	if ip, network := alloc.AllocIP4(); ip != nil || network != nil {
		t.Fatalf(
			"IPv6 allocator AllocIP4() = %v, %v; want nil, nil",
			ip,
			network,
		)
	}
	ip, network := alloc.AllocIP6()
	if ip == nil || network == nil {
		t.Fatalf("AllocIP6() = %v, %v; want allocation", ip, network)
	}

	internal, ok := alloc.(*ipAllocator)
	if !ok {
		t.Fatalf("NewIPAllocator() = %T, want *ipAllocator", alloc)
	}
	internal.next = nil
	ip, _ = internal.alloc()
	if !ip.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("alloc() with nil next = %v, want 2001:db8::2", ip)
	}
	internal.next = net.ParseIP("2001:db8::ffff")
	ip, _ = internal.alloc()
	if ip != nil {
		t.Fatalf("alloc() after exhausted small IPv6 range = %v, want nil", ip)
	}
}
