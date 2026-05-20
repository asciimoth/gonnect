// nolint
package subnet

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q) error = %v", cidr, err)
	}
	return ipnet
}

func TestAllocatorFreeAllAndInvalidPrefixBranches(t *testing.T) {
	alloc := NewAllocator([]*net.IPNet{mustCIDR(t, "10.0.0.0/24")})
	first := alloc.Alloc(24)
	if first == nil {
		t.Fatal("Alloc(24) = nil, want subnet")
	}
	if got := alloc.Alloc(24); got != nil {
		t.Fatalf("second Alloc(24) = %v, want nil", got)
	}
	alloc.FreeAll()
	if got := alloc.Alloc(24); got == nil || got.String() != first.String() {
		t.Fatalf("Alloc after FreeAll = %v, want %v", got, first)
	}
	if got := alloc.Alloc(23); got != nil {
		t.Fatalf("Alloc(23) = %v, want nil", got)
	}
}

func TestAllocatorCopiesInputAndResults(t *testing.T) {
	available := []*net.IPNet{mustCIDR(t, "10.0.0.0/24")}
	alloc := NewAllocator(available)
	available[0].IP[0] = 192
	got := alloc.Alloc(24)
	if got == nil || got.String() != "10.0.0.0/24" {
		t.Fatalf("Alloc after input mutation = %v, want 10.0.0.0/24", got)
	}
	got.IP[0] = 172
	alloc.FreeAll()
	got = alloc.Alloc(24)
	if got == nil || got.String() != "10.0.0.0/24" {
		t.Fatalf("Alloc after result mutation = %v, want 10.0.0.0/24", got)
	}
}

func TestRandomAllocatorRejectingFilterExhaustsAttempts(t *testing.T) {
	alloc := NewRandomAllocator(&RandomAllocatorConfig{
		Filter: func(*net.IPNet) bool { return false },
	})
	if got := alloc.Alloc(24); got != nil {
		t.Fatalf("Alloc with rejecting filter = %v, want nil", got)
	}
	if got := alloc.Alloc(16); got != nil {
		t.Fatalf("Alloc unsupported prefix = %v, want nil", got)
	}
}
