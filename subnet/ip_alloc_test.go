// nolint
package subnet_test

import (
	"net"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestNewIPAllocator(t *testing.T) {
	t.Run("nil subnets", func(t *testing.T) {
		alloc := subnet.NewIPAllocator(nil, nil)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("IPv4 only", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("IPv6 only", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/64")
		alloc := subnet.NewIPAllocator(nil, ipnet)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("both IPv4 and IPv6", func(t *testing.T) {
		_, ipnet4, _ := net.ParseCIDR("192.168.1.0/24")
		_, ipnet6, _ := net.ParseCIDR("fd00::/64")
		alloc := subnet.NewIPAllocator(ipnet4, ipnet6)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})
}

func TestIPAllocatorAlloc4(t *testing.T) {
	t.Run("allocates from /24", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		ip4 := ip.To4()
		if ip4 == nil {
			t.Fatal("expected IPv4 address")
		}

		if ip4[0] != 192 || ip4[1] != 168 || ip4[2] != 1 {
			t.Errorf("expected 192.168.1.x, got %v", ip)
		}
	})

	t.Run("skips network address", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		if ip.Equal(net.ParseIP("192.168.1.0")) {
			t.Error("should not allocate network address")
		}
	})

	t.Run("skips broadcast address", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		// Allocate all IPs
		var allocated []net.IP
		for range 256 {
			ip := alloc.Alloc4()
			if ip == nil {
				break
			}
			allocated = append(allocated, ip)
		}

		// Verify broadcast (192.168.1.255) was not allocated
		for _, ip := range allocated {
			if ip.Equal(net.ParseIP("192.168.1.255")) {
				t.Error("should not allocate broadcast address")
			}
		}
	})

	t.Run("allocates sequential IPs", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip1 := alloc.Alloc4()
		ip2 := alloc.Alloc4()
		ip3 := alloc.Alloc4()

		if ip1 == nil || ip2 == nil || ip3 == nil {
			t.Fatal("expected non-nil IPs")
		}

		// Should be different
		if ip1.Equal(ip2) || ip2.Equal(ip3) || ip1.Equal(ip3) {
			t.Errorf("expected different IPs, got %v, %v, %v", ip1, ip2, ip3)
		}
	})

	t.Run("exhausts /30", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/30")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		// /30 has 4 addresses, skip network and broadcast = 2 usable
		count := 0
		for range 10 {
			ip := alloc.Alloc4()
			if ip == nil {
				break
			}
			count++
		}

		if count != 2 {
			t.Errorf("expected 2 allocations, got %d", count)
		}
	})

	t.Run("returns nil when exhausted", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/30")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		// Exhaust all
		for range 10 {
			alloc.Alloc4()
		}

		ip := alloc.Alloc4()
		if ip != nil {
			t.Errorf("expected nil when exhausted, got %v", ip)
		}
	})

	t.Run("returns nil when no IPv4 subnet", func(t *testing.T) {
		alloc := subnet.NewIPAllocator(nil, nil)
		ip := alloc.Alloc4()
		if ip != nil {
			t.Errorf("expected nil when no IPv4 subnet, got %v", ip)
		}
	})
}

func TestIPAllocatorAlloc6(t *testing.T) {
	t.Run("allocates from /126", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/126")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		ip := alloc.Alloc6()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		if ip.To4() != nil {
			t.Fatal("expected IPv6 address")
		}
	})

	t.Run("allocates sequential IPv6s", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/124")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		ip1 := alloc.Alloc6()
		ip2 := alloc.Alloc6()
		ip3 := alloc.Alloc6()

		if ip1 == nil || ip2 == nil || ip3 == nil {
			t.Fatal("expected non-nil IPs")
		}

		// Should be different
		if ip1.Equal(ip2) || ip2.Equal(ip3) || ip1.Equal(ip3) {
			t.Errorf("expected different IPs, got %v, %v, %v", ip1, ip2, ip3)
		}
	})

	t.Run("skips first and last IPv6", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/126")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		// Allocate all IPs
		var allocated []net.IP
		for range 10 {
			ip := alloc.Alloc6()
			if ip == nil {
				break
			}
			allocated = append(allocated, ip)
		}

		// Verify first (fd00::) and last (fd00::3) were not allocated
		for _, ip := range allocated {
			if ip.Equal(net.ParseIP("fd00::")) {
				t.Error("should not allocate first IPv6 in subnet")
			}
			if ip.Equal(net.ParseIP("fd00::3")) {
				t.Error("should not allocate last IPv6 in subnet")
			}
		}
	})

	t.Run("exhausts /126", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/126")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		// /126 has 4 addresses, skip first and last = 2 usable
		count := 0
		for range 10 {
			ip := alloc.Alloc6()
			if ip == nil {
				break
			}
			count++
		}

		if count != 2 {
			t.Errorf("expected 2 allocations, got %d", count)
		}
	})

	t.Run("returns nil when exhausted", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/126")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		// Exhaust all
		for range 10 {
			alloc.Alloc6()
		}

		ip := alloc.Alloc6()
		if ip != nil {
			t.Errorf("expected nil when exhausted, got %v", ip)
		}
	})

	t.Run("returns nil when no IPv6 subnet", func(t *testing.T) {
		alloc := subnet.NewIPAllocator(nil, nil)
		ip := alloc.Alloc6()
		if ip != nil {
			t.Errorf("expected nil when no IPv6 subnet, got %v", ip)
		}
	})
}

func TestIPAllocatorReserve(t *testing.T) {
	t.Run("reserves IPv4", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip := net.ParseIP("192.168.1.100")
		alloc.Reserve(ip)

		// Allocate until we get to .100 or exhaust
		found := false
		for range 254 {
			allocIP := alloc.Alloc4()
			if allocIP == nil {
				break
			}
			if allocIP.Equal(ip) {
				found = true
				break
			}
		}

		if found {
			t.Error("reserved IP should not be allocated")
		}
	})

	t.Run("reserves IPv6", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/64")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		ip := net.ParseIP("fd00::100")
		alloc.Reserve(ip)

		// Allocate some IPs
		for range 10 {
			allocIP := alloc.Alloc6()
			if allocIP == nil {
				break
			}
			if allocIP.Equal(ip) {
				t.Error("reserved IPv6 should not be allocated")
			}
		}
	})
}

func TestIPAllocatorFree(t *testing.T) {
	t.Run("frees IPv4", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		alloc.Free(ip)

		// Should be able to allocate again
		ip2 := alloc.Alloc4()
		if ip2 == nil {
			t.Fatal("expected non-nil IP after free")
		}
	})

	t.Run("frees IPv6", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/64")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		ip := alloc.Alloc6()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		alloc.Free(ip)

		// Should be able to allocate again
		ip2 := alloc.Alloc6()
		if ip2 == nil {
			t.Fatal("expected non-nil IP after free")
		}
	})

	t.Run("free non-reserved is noop", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		ip := net.ParseIP("192.168.1.100")
		alloc.Free(ip) // should not panic
	})
}

func TestIPAllocatorFreeAll(t *testing.T) {
	t.Run("frees all IPv4", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.0/30")
		alloc := subnet.NewIPAllocator(ipnet, nil)

		// Exhaust all
		for range 10 {
			alloc.Alloc4()
		}

		alloc.FreeAll()

		// Should be able to allocate again
		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP after FreeAll")
		}
	})

	t.Run("frees all IPv6", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("fd00::/126")
		alloc := subnet.NewIPAllocator(nil, ipnet)

		// Exhaust all
		for range 10 {
			alloc.Alloc6()
		}

		alloc.FreeAll()

		// Should be able to allocate again
		ip := alloc.Alloc6()
		if ip == nil {
			t.Fatal("expected non-nil IP after FreeAll")
		}
	})
}

func TestIPAllocatorThreadSafety(t *testing.T) {
	_, ipnet4, _ := net.ParseCIDR("192.168.1.0/24")
	_, ipnet6, _ := net.ParseCIDR("fd00::/64")
	alloc := subnet.NewIPAllocator(ipnet4, ipnet6)

	done := make(chan bool)

	// Launch multiple goroutines allocating and freeing
	for range 10 {
		go func() {
			for range 10 {
				ip4 := alloc.Alloc4()
				if ip4 != nil {
					alloc.Free(ip4)
				}
				ip6 := alloc.Alloc6()
				if ip6 != nil {
					alloc.Free(ip6)
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}
}

func TestNewRandomIPAllocator(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("with config", func(t *testing.T) {
		config := &subnet.RandomIPAllocatorConfig{
			IPv4Config: &subnet.RandomAllocatorConfig{},
			IPv6Config: &subnet.RandomAllocatorConfig{},
		}
		alloc := subnet.NewRandomIPAllocator(config)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})
}

func TestRandomIPAllocatorAlloc4(t *testing.T) {
	t.Run("allocates IPv4", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		ip4 := ip.To4()
		if ip4 == nil {
			t.Fatal("expected IPv4 address")
		}

		// Should be in 10.0.0.0/8 range
		if ip4[0] != 10 {
			t.Errorf("expected 10.x.x.x, got %v", ip)
		}
	})

	t.Run("allocates unique IPs", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ips := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			ip := alloc.Alloc4()
			if ip == nil {
				t.Fatalf("expected non-nil IP at iteration %d", i)
			}
			if _, exists := ips[ip.String()]; exists {
				t.Errorf("duplicate IP allocated: %s", ip)
			}
			ips[ip.String()] = struct{}{}
		}
	})

	t.Run("allocates new subnets on demand", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		// Allocate many IPs - this should span multiple subnets
		ips := make(map[string]struct{})
		for i := 0; i < 500; i++ {
			ip := alloc.Alloc4()
			if ip == nil {
				t.Fatalf("expected non-nil IP at iteration %d", i)
			}
			if _, exists := ips[ip.String()]; exists {
				t.Errorf("duplicate IP allocated: %s", ip)
			}
			ips[ip.String()] = struct{}{}
		}

		// Verify we got IPs from multiple subnets (different 3rd octets)
		subnets := make(map[string]struct{})
		for ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip4 := ip.To4(); ip4 != nil {
				// Group by /24 subnet
				subnetKey := net.IPNet{
					IP:   net.IP{ip4[0], ip4[1], ip4[2], 0},
					Mask: net.CIDRMask(24, 32),
				}
				subnets[subnetKey.String()] = struct{}{}
			}
		}

		// Should have allocated from multiple subnets
		if len(subnets) < 2 {
			t.Errorf(
				"expected allocations from multiple subnets, got %d",
				len(subnets),
			)
		}
	})
}

func TestRandomIPAllocatorAlloc6(t *testing.T) {
	t.Run("allocates IPv6", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := alloc.Alloc6()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		if ip.To4() != nil {
			t.Fatal("expected IPv6 address")
		}
	})

	t.Run("allocates unique IPs", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ips := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			ip := alloc.Alloc6()
			if ip == nil {
				t.Fatalf("expected non-nil IP at iteration %d", i)
			}
			if _, exists := ips[ip.String()]; exists {
				t.Errorf("duplicate IPv6 allocated: %s", ip)
			}
			ips[ip.String()] = struct{}{}
		}
	})
}

func TestRandomIPAllocatorReserve(t *testing.T) {
	t.Run("reserves IPv4", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := net.ParseIP("10.100.100.50")
		alloc.Reserve(ip)

		// Allocate some IPs - the reserved one should not appear
		for i := 0; i < 100; i++ {
			allocIP := alloc.Alloc4()
			if allocIP == nil {
				break
			}
			if allocIP.Equal(ip) {
				t.Error("reserved IP should not be allocated")
			}
		}
	})

	t.Run("reserves IPv6", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := net.ParseIP("fd00::100")
		alloc.Reserve(ip)

		// Allocate some IPs
		for i := 0; i < 100; i++ {
			allocIP := alloc.Alloc6()
			if allocIP == nil {
				break
			}
			if allocIP.Equal(ip) {
				t.Error("reserved IPv6 should not be allocated")
			}
		}
	})
}

func TestRandomIPAllocatorFree(t *testing.T) {
	t.Run("frees IPv4", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		alloc.Free(ip)

		// The IP should be available again (may not get same one due to random nature)
		// But we should be able to allocate more
		ip2 := alloc.Alloc4()
		if ip2 == nil {
			t.Fatal("expected non-nil IP after free")
		}
	})

	t.Run("frees IPv6", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := alloc.Alloc6()
		if ip == nil {
			t.Fatal("expected non-nil IP")
		}

		alloc.Free(ip)

		ip2 := alloc.Alloc6()
		if ip2 == nil {
			t.Fatal("expected non-nil IP after free")
		}
	})

	t.Run("free non-reserved is noop", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		ip := net.ParseIP("10.100.100.100")
		alloc.Free(ip) // should not panic
	})
}

func TestRandomIPAllocatorFreeAll(t *testing.T) {
	t.Run("frees all", func(t *testing.T) {
		alloc := subnet.NewRandomIPAllocator(nil)

		// Allocate many IPs (will span multiple subnets)
		ips := make([]net.IP, 0)
		for i := 0; i < 100; i++ {
			ip := alloc.Alloc4()
			if ip == nil {
				break
			}
			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			t.Fatal("expected some allocations")
		}

		alloc.FreeAll()

		// Should be able to allocate again
		ip := alloc.Alloc4()
		if ip == nil {
			t.Fatal("expected non-nil IP after FreeAll")
		}
	})
}

func TestRandomIPAllocatorThreadSafety(t *testing.T) {
	alloc := subnet.NewRandomIPAllocator(nil)

	done := make(chan bool)

	// Launch multiple goroutines allocating and freeing
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				ip4 := alloc.Alloc4()
				if ip4 != nil {
					alloc.Free(ip4)
				}
				ip6 := alloc.Alloc6()
				if ip6 != nil {
					alloc.Free(ip6)
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestRandomIPAllocatorMixedOperations(t *testing.T) {
	alloc := subnet.NewRandomIPAllocator(nil)

	// Allocate some IPs
	ip1 := alloc.Alloc4()
	if ip1 == nil {
		t.Fatal("expected non-nil IP")
	}

	ip2 := alloc.Alloc6()
	if ip2 == nil {
		t.Fatal("expected non-nil IPv6")
	}

	// Reserve an external IP
	externalIP := net.ParseIP("10.200.200.200")
	alloc.Reserve(externalIP)

	// Free an allocated IP
	alloc.Free(ip1)

	// Allocate more
	ip3 := alloc.Alloc4()
	if ip3 == nil {
		t.Fatal("expected non-nil IP")
	}

	// FreeAll
	alloc.FreeAll()

	// Should still be able to allocate
	ip4 := alloc.Alloc4()
	if ip4 == nil {
		t.Fatal("expected non-nil IP after FreeAll")
	}

	_ = ip3
	_ = ip4
}
