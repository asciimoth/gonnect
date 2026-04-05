// nolint
package subnet_test

import (
	"net"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func parseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

func TestNewAllocator(t *testing.T) {
	t.Run("empty subnets", func(t *testing.T) {
		alloc := subnet.NewAllocator(nil)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("single subnet", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("multiple subnets", func(t *testing.T) {
		subnets := []*net.IPNet{
			parseCIDR(t, "10.0.0.0/24"),
			parseCIDR(t, "10.0.1.0/24"),
			parseCIDR(t, "192.168.1.0/24"),
		}
		alloc := subnet.NewAllocator(subnets)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})
}

func TestAllocatorPrefixes(t *testing.T) {
	t.Run("returns supported prefixes", func(t *testing.T) {
		subnets := []*net.IPNet{
			parseCIDR(t, "10.0.0.0/24"),
			parseCIDR(t, "10.0.1.0/25"),
			parseCIDR(t, "192.168.1.0/16"),
		}
		alloc := subnet.NewAllocator(subnets)
		prefixes := alloc.Prefixes()

		// Should contain 24, 25, 16
		expected := map[int]bool{16: false, 24: false, 25: false}
		for _, p := range prefixes {
			if _, ok := expected[p]; !ok {
				t.Errorf("unexpected prefix: %d", p)
			}
			expected[p] = true
		}
		for p, found := range expected {
			if !found {
				t.Errorf("missing expected prefix: %d", p)
			}
		}
	})

	t.Run("empty allocator", func(t *testing.T) {
		alloc := subnet.NewAllocator(nil)
		prefixes := alloc.Prefixes()
		if len(prefixes) != 0 {
			t.Errorf("expected empty prefixes, got %v", prefixes)
		}
	})
}

func TestAllocatorReserve(t *testing.T) {
	t.Run("reserve subnet from pool", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		// Reserve the entire pool
		pool := parseCIDR(t, "10.0.0.0/24")
		alloc.Reserve(pool)

		// Try to allocate /25 - should fail since pool is reserved
		result := alloc.Alloc(25)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("reserve partial subnet", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		// Reserve half of the pool
		half := parseCIDR(t, "10.0.0.0/25")
		alloc.Reserve(half)

		// Should still be able to allocate the other half
		result := alloc.Alloc(25)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		expected := parseCIDR(t, "10.0.0.128/25")
		if result.String() != expected.String() {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}

func TestAllocatorAlloc(t *testing.T) {
	t.Run("allocate single /24", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		expected := parseCIDR(t, "10.0.0.0/24")
		if result.String() != expected.String() {
			t.Errorf("expected %v, got %v", expected, result)
		}

		// Second allocation should fail
		result2 := alloc.Alloc(24)
		if result2 != nil {
			t.Errorf("expected nil, got %v", result2)
		}
	})

	t.Run("allocate smaller prefix from larger pool", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(25)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Should be either first or second half
		expected1 := parseCIDR(t, "10.0.0.0/25")
		expected2 := parseCIDR(t, "10.0.0.128/25")
		if result.String() != expected1.String() &&
			result.String() != expected2.String() {
			t.Errorf("expected %v or %v, got %v", expected1, expected2, result)
		}
	})

	t.Run("allocate with prefix 0 (any)", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(0)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Should allocate the entire /24
		expected := parseCIDR(t, "10.0.0.0/24")
		if result.String() != expected.String() {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("allocate from multiple pools", func(t *testing.T) {
		subnets := []*net.IPNet{
			parseCIDR(t, "10.0.0.0/24"),
			parseCIDR(t, "192.168.1.0/24"),
		}
		alloc := subnet.NewAllocator(subnets)

		// First allocation should come from first pool
		result1 := alloc.Alloc(24)
		if result1 == nil {
			t.Fatal("expected non-nil result1")
		}

		// Second allocation should come from second pool
		result2 := alloc.Alloc(24)
		if result2 == nil {
			t.Fatal("expected non-nil result2")
		}

		// Third allocation should fail
		result3 := alloc.Alloc(24)
		if result3 != nil {
			t.Errorf("expected nil, got %v", result3)
		}
	})

	t.Run("exhaust all subnets", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/30")}
		alloc := subnet.NewAllocator(subnets)

		// /30 has 4 addresses, should be able to allocate 4 /32s
		count := 0
		for i := range 4 {
			result := alloc.Alloc(32)
			if result == nil {
				t.Fatalf("expected non-nil result at iteration %d", i)
			}
			count++
		}

		// Next should fail
		result := alloc.Alloc(32)
		if result != nil {
			t.Errorf("expected nil after exhaustion, got %v", result)
		}

		if count != 4 {
			t.Errorf("expected 4 allocations, got %d", count)
		}
	})

	t.Run("allocate unsupported prefix", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(16)
		if result != nil {
			t.Errorf("expected nil for unsupported prefix, got %v", result)
		}
	})
}

func TestAllocatorFree(t *testing.T) {
	t.Run("free allocated subnet", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		// Allocate
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Second allocation should fail
		result2 := alloc.Alloc(24)
		if result2 != nil {
			t.Errorf("expected nil, got %v", result2)
		}

		// Free
		alloc.Free(result)

		// Should be able to allocate again
		result3 := alloc.Alloc(24)
		if result3 == nil {
			t.Fatal("expected non-nil result after free")
		}
	})

	t.Run("free non-reserved subnet (noop)", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/24")}
		alloc := subnet.NewAllocator(subnets)

		// Free something that was never allocated - should not panic
		ipnet := parseCIDR(t, "10.0.0.0/24")
		alloc.Free(ipnet)
	})

	t.Run("free and reallocate multiple times", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/25")}
		alloc := subnet.NewAllocator(subnets)

		for i := range 3 {
			result := alloc.Alloc(25)
			if result == nil {
				t.Fatalf("iteration %d: expected non-nil result", i)
			}

			alloc.Free(result)
		}
	})
}

func TestAllocatorThreadSafety(t *testing.T) {
	subnets := []*net.IPNet{parseCIDR(t, "10.0.0.0/16")}
	alloc := subnet.NewAllocator(subnets)

	done := make(chan bool)

	// Launch multiple goroutines allocating and freeing
	for range 10 {
		go func() {
			for range 10 {
				result := alloc.Alloc(24)
				if result != nil {
					alloc.Free(result)
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

func TestAllocatorIPv6(t *testing.T) {
	t.Run("allocate IPv6 subnet", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "fd00::/64")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(64)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		expected := parseCIDR(t, "fd00::/64")
		if result.String() != expected.String() {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("allocate smaller IPv6 prefix", func(t *testing.T) {
		subnets := []*net.IPNet{parseCIDR(t, "fd00::/48")}
		alloc := subnet.NewAllocator(subnets)

		result := alloc.Alloc(64)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Should be a /64 within the /48
		ones, bits := result.Mask.Size()
		if bits != 128 {
			t.Errorf("expected IPv6 mask, got %v", result.Mask)
		}
		if ones != 64 {
			t.Errorf("expected /64 mask, got /%d", ones)
		}
	})
}

func TestNewRandomAllocator(t *testing.T) {
	t.Run("with nil config", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("with empty config", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{})
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})

	t.Run("with filter config", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{
			Filter: func(n *net.IPNet) bool { return true },
		})
		if alloc == nil {
			t.Fatal("expected non-nil allocator")
		}
	})
}

func TestRandomAllocatorPrefixes(t *testing.T) {
	alloc := subnet.NewRandomAllocator(nil)
	prefixes := alloc.Prefixes()

	if len(prefixes) != 1 {
		t.Fatalf("expected 1 prefix, got %d: %v", len(prefixes), prefixes)
	}
	if prefixes[0] != 24 {
		t.Errorf("expected prefix 24, got %d", prefixes[0])
	}
}

func TestRandomAllocatorAlloc(t *testing.T) {
	t.Run("allocates /24 subnet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		ones, bits := result.Mask.Size()
		if ones != 24 {
			t.Errorf("expected /24 mask, got /%d", ones)
		}
		if bits != 32 {
			t.Errorf("expected IPv4 mask, got %d bits", bits)
		}
	})

	t.Run("allocates with prefix 0", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		result := alloc.Alloc(0)
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		ones, _ := result.Mask.Size()
		if ones != 24 {
			t.Errorf("expected /24 mask for prefix 0, got /%d", ones)
		}
	})

	t.Run("rejects unsupported prefix", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		result := alloc.Alloc(16)
		if result != nil {
			t.Errorf("expected nil for prefix 16, got %v", result)
		}
	})

	t.Run("rejects prefix 25", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		result := alloc.Alloc(25)
		if result != nil {
			t.Errorf("expected nil for prefix 25, got %v", result)
		}
	})

	t.Run("avoids 0-24 in second octet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		for i := range 100 {
			result := alloc.Alloc(24)
			if result == nil {
				t.Fatalf("allocation %d failed", i)
			}

			if result.IP[1] <= 24 {
				t.Errorf(
					"second octet %d is <= 24 in subnet %s",
					result.IP[1],
					result.String(),
				)
			}

			alloc.Free(result)
		}
	})

	t.Run("avoids 0-24 in third octet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		for i := range 100 {
			result := alloc.Alloc(24)
			if result == nil {
				t.Fatalf("allocation %d failed", i)
			}

			if result.IP[2] <= 24 {
				t.Errorf(
					"third octet %d is <= 24 in subnet %s",
					result.IP[2],
					result.String(),
				)
			}

			alloc.Free(result)
		}
	})

	t.Run("always uses 10.x.x.0", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		for i := range 100 {
			result := alloc.Alloc(24)
			if result == nil {
				t.Fatalf("allocation %d failed", i)
			}

			if result.IP[0] != 10 {
				t.Errorf(
					"first octet is not 10, got %d in subnet %s",
					result.IP[0],
					result.String(),
				)
			}
			if result.IP[3] != 0 {
				t.Errorf(
					"fourth octet is not 0, got %d in subnet %s",
					result.IP[3],
					result.String(),
				)
			}

			alloc.Free(result)
		}
	})

	t.Run("returns different subnets", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		allocated := make(map[string]bool)
		for i := range 50 {
			result := alloc.Alloc(24)
			if result == nil {
				t.Fatalf("allocation %d failed", i)
			}

			cidr := result.String()
			if allocated[cidr] {
				t.Errorf("duplicate allocation: %s", cidr)
			}
			allocated[cidr] = true
		}
	})

	t.Run("does not reuse freed subnets immediately", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		// Allocate and free a subnet
		result1 := alloc.Alloc(24)
		if result1 == nil {
			t.Fatal("expected non-nil result")
		}
		firstCIDR := result1.String()
		alloc.Free(result1)

		// Allocate again - should get a different one (random)
		result2 := alloc.Alloc(24)
		if result2 == nil {
			t.Fatal("expected non-nil result")
		}

		// Note: This is probabilistic - with 230*230 possible subnets,
		// collision is extremely unlikely but theoretically possible
		secondCIDR := result2.String()
		if firstCIDR == secondCIDR {
			t.Logf(
				"warning: got same subnet twice (unlikely but possible): %s",
				firstCIDR,
			)
		}
	})
}

func TestRandomAllocatorReserve(t *testing.T) {
	t.Run("reserves valid subnet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		// Manually create a valid /24
		subnet := &net.IPNet{
			IP:   net.IP{10, 100, 100, 0},
			Mask: net.CIDRMask(24, 32),
		}

		alloc.Reserve(subnet)

		// Try to allocate - should still work since random won't hit this exact one often
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("ignores invalid subnet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		// Try to reserve a /16 (invalid for random allocator)
		subnet := &net.IPNet{
			IP:   net.IP{10, 100, 0, 0},
			Mask: net.CIDRMask(16, 32),
		}

		alloc.Reserve(subnet)

		// Should still be able to allocate
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("ignores subnet outside range", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		// Try to reserve a 192.168.x.0/24 (outside 10.0.0.0/8)
		subnet := &net.IPNet{
			IP:   net.IP{192, 168, 100, 0},
			Mask: net.CIDRMask(24, 32),
		}

		alloc.Reserve(subnet)

		// Should still be able to allocate
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("ignores subnet with low octets", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		// Try to reserve 10.10.10.0/24 (second octet <= 24)
		subnet := &net.IPNet{
			IP:   net.IP{10, 10, 100, 0},
			Mask: net.CIDRMask(24, 32),
		}

		alloc.Reserve(subnet)

		// Should still be able to allocate
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
}

func TestRandomAllocatorFree(t *testing.T) {
	t.Run("frees allocated subnet", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		alloc.Free(result)

		// Should still be able to allocate
		result2 := alloc.Alloc(24)
		if result2 == nil {
			t.Fatal("expected non-nil result after free")
		}
	})

	t.Run("free non-reserved is noop", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(nil)

		subnet := &net.IPNet{
			IP:   net.IP{10, 100, 100, 0},
			Mask: net.CIDRMask(24, 32),
		}

		// Should not panic
		alloc.Free(subnet)
	})
}

func TestRandomAllocatorFreeAll(t *testing.T) {
	alloc := subnet.NewRandomAllocator(nil)

	// Allocate several subnets
	for i := range 10 {
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatalf("allocation %d failed", i)
		}
	}

	// Free all
	alloc.FreeAll()

	// Should be able to allocate again
	result := alloc.Alloc(24)
	if result == nil {
		t.Fatal("expected non-nil result after FreeAll")
	}
}

func TestRandomAllocatorFilter(t *testing.T) {
	t.Run("filter rejects all", func(t *testing.T) {
		alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{
			Filter: func(n *net.IPNet) bool { return false },
		})

		result := alloc.Alloc(24)
		if result != nil {
			t.Errorf("expected nil when filter rejects all, got %v", result)
		}
	})

	t.Run("filter accepts specific range", func(t *testing.T) {
		// Only accept subnets where second octet is 200-254
		alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{
			Filter: func(n *net.IPNet) bool {
				return n.IP.To4()[1] >= 200
			},
		})

		// Should eventually find a match
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		if result.IP.To4()[1] < 200 {
			t.Errorf(
				"filter should ensure second octet >= 200, got %d",
				result.IP.To4()[1],
			)
		}
	})

	t.Run("filter avoids specific subnets", func(t *testing.T) {
		// Avoid 10.100.100.0/24
		avoidCIDR := "10.100.100.0/24"
		alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{
			Filter: func(n *net.IPNet) bool {
				return n.String() != avoidCIDR
			},
		})

		// Allocate many times and ensure we never get the avoided subnet
		for i := range 100 {
			result := alloc.Alloc(24)
			if result == nil {
				t.Fatalf("allocation %d failed", i)
			}

			if result.String() == avoidCIDR {
				t.Errorf("got avoided subnet: %s", avoidCIDR)
			}

			alloc.Free(result)
		}
	})
}

func TestRandomAllocatorThreadSafety(t *testing.T) {
	alloc := subnet.NewRandomAllocator(nil)

	done := make(chan bool)

	// Launch multiple goroutines allocating and freeing
	for range 10 {
		go func() {
			for range 10 {
				result := alloc.Alloc(24)
				if result != nil {
					alloc.Free(result)
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

func TestRandomAllocatorExhaustion(t *testing.T) {
	// This test verifies that the allocator returns nil when it cannot find
	// a valid subnet after max attempts (simulating exhaustion scenario)

	// Use a filter that rejects everything after 5 allocations
	var mu sync.Mutex
	count := 0
	alloc := subnet.NewRandomAllocator(&subnet.RandomAllocatorConfig{
		Filter: func(n *net.IPNet) bool {
			mu.Lock()
			defer mu.Unlock()
			// Allow first 5 allocations, then reject all
			if count < 5 {
				count++
				return true
			}
			return false
		},
	})

	// First 5 allocations should succeed
	for i := 1; i <= 5; i++ {
		result := alloc.Alloc(24)
		if result == nil {
			t.Fatalf("expected allocation %d to succeed", i)
		}
	}

	// After 5 allocations, filter rejects all - should return nil
	result := alloc.Alloc(24)
	if result != nil {
		t.Errorf(
			"expected allocation to fail after filter rejects, got %v",
			result,
		)
	}
}
