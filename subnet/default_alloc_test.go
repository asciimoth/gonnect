// nolint
package subnet_test

import (
	"math/rand"
	"net"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestDefaultAllocatorUsesFixedParentsAndPoolPrefixes(t *testing.T) {
	alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})

	ip4, pool4 := alloc.AllocIP4()
	if ip4 == nil {
		t.Fatal("AllocIP4() returned nil")
	}
	if !mustParseCIDR(t, "10.0.0.0/8").Contains(ip4) {
		t.Fatalf("AllocIP4() = %v, want address inside 10.0.0.0/8", ip4)
	}
	if prefix, bits := pool4.Mask.Size(); prefix != 24 || bits != 32 {
		t.Fatalf("AllocIP4() pool = %v, want IPv4 /24", pool4)
	}

	ip6, pool6 := alloc.AllocIP6()
	if ip6 == nil {
		t.Fatal("AllocIP6() returned nil")
	}
	if ip6.To16() == nil || ip6.To4() != nil || ip6[0] != 0xfd {
		t.Fatalf("AllocIP6() = %v, want fd00::/8 ULA address", ip6)
	}
	if prefix, bits := pool6.Mask.Size(); prefix != 64 || bits != 128 {
		t.Fatalf("AllocIP6() pool = %v, want IPv6 /64", pool6)
	}
}

func TestDefaultAllocatorGeneratedULAIsReproducibleAndUsesProvidedRNG(
	t *testing.T,
) {
	seed := int64(99)
	expectedRNG := rand.New(rand.NewSource(seed))
	expected := expectedULA48(expectedRNG)

	alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
		Rng: rand.New(rand.NewSource(seed)),
	})
	got := alloc.AllocSubnet6(48)
	if got == nil || got.String() != expected.String() {
		t.Fatalf("AllocSubnet6(48) = %v, want %v", got, expected)
	}

	first := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
	second := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
	firstULA := first.AllocSubnet6(48)
	secondULA := second.AllocSubnet6(48)
	if firstULA == nil || secondULA == nil ||
		firstULA.String() != secondULA.String() {
		t.Fatalf("nil-rng ULA mismatch: %v != %v", firstULA, secondULA)
	}
}

func TestDefaultAllocatorBuiltinBansBlockCommonCIDRs(t *testing.T) {
	alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
		SubnetFilter: func(candidate *net.IPNet) bool {
			return candidate.String() == "10.88.0.0/16"
		},
	})

	if got := alloc.AllocSubnet4(16); got != nil {
		t.Fatalf(
			"AllocSubnet4(16) = %v, want nil because 10.88.0.0/16 is built-in banned",
			got,
		)
	}
}

func TestDefaultAllocatorMergesConfigBansAndFilters(t *testing.T) {
	t.Run("caller IP ban", func(t *testing.T) {
		reference := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
		firstIP := allocIP4(reference)
		if firstIP == nil {
			t.Fatal("reference AllocIP4() returned nil")
		}

		alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
			BannedIPs: []net.IP{firstIP},
		})
		if got := allocIP4(alloc); got == nil || got.Equal(firstIP) {
			t.Fatalf(
				"AllocIP4() = %v, want an address other than banned %v",
				got,
				firstIP,
			)
		}
	})

	t.Run("caller subnet ban", func(t *testing.T) {
		alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
			BannedSubnets: []*net.IPNet{mustParseCIDR(t, "10.200.0.0/16")},
			SubnetFilter: func(candidate *net.IPNet) bool {
				return candidate.String() == "10.200.0.0/16"
			},
		})

		if got := alloc.AllocSubnet4(16); got != nil {
			t.Fatalf(
				"AllocSubnet4(16) = %v, want nil because caller ban is merged",
				got,
			)
		}
	})

	t.Run("ip filter", func(t *testing.T) {
		var calls int
		alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
			IPFilter: func(net.IP) bool {
				calls++
				return false
			},
		})

		if got := allocIP4(alloc); got != nil {
			t.Fatalf(
				"AllocIP4() = %v, want nil when IPFilter rejects every IP",
				got,
			)
		}
		if calls != 254 {
			t.Fatalf(
				"IPFilter calls = %d, want 254 usable addresses in one /24 pool",
				calls,
			)
		}
	})

	t.Run("subnet filter", func(t *testing.T) {
		var calls int
		alloc := subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{
			SubnetFilter: func(*net.IPNet) bool {
				calls++
				return false
			},
		})

		if got := alloc.AllocSubnet4(32); got != nil {
			t.Fatalf(
				"AllocSubnet4(32) = %v, want nil when SubnetFilter rejects every subnet",
				got,
			)
		}
		if calls != 1000 {
			t.Fatalf("SubnetFilter calls = %d, want 1000", calls)
		}
	})
}

func expectedULA48(rng *rand.Rand) *net.IPNet {
	ip := net.IP{
		0xfd,
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		byte(rng.Intn(256)),
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(48, 128)}
}
