package subnet_test

import (
	"net"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestSubnetAllocatorAllocSubnet4Sequential(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "10.0.0.0/24"), nil)

	want := []string{
		"10.0.0.0/26",
		"10.0.0.64/26",
		"10.0.0.128/26",
		"10.0.0.192/26",
	}
	for i, cidr := range want {
		got := alloc.AllocSubnet4(26)
		if got == nil || got.String() != cidr {
			t.Fatalf("allocation %d = %v, want %s", i, got, cidr)
		}
	}
	if got := alloc.AllocSubnet4(26); got != nil {
		t.Fatalf("allocation after exhaustion = %v, want nil", got)
	}
}

func TestSubnetAllocatorAllocSubnet6Sequential(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "2001:db8::/124"), nil)

	want := []string{
		"2001:db8::/126",
		"2001:db8::4/126",
		"2001:db8::8/126",
		"2001:db8::c/126",
	}
	for i, cidr := range want {
		got := alloc.AllocSubnet6(126)
		if got == nil || got.String() != cidr {
			t.Fatalf("allocation %d = %v, want %s", i, got, cidr)
		}
	}
	if got := alloc.AllocSubnet6(126); got != nil {
		t.Fatalf("allocation after exhaustion = %v, want nil", got)
	}
}

func TestSubnetAllocatorFilterSkipsRejectedSubnets(t *testing.T) {
	rejected := true
	alloc := subnet.NewSubnetAllocator(
		mustParseCIDR(t, "10.0.0.0/24"),
		func(candidate *net.IPNet) bool {
			if rejected && candidate.String() == "10.0.0.0/26" {
				rejected = false
				return false
			}
			return true
		},
	)

	if got := alloc.AllocSubnet4(
		26,
	); got == nil ||
		got.String() != "10.0.0.64/26" {
		t.Fatalf("first allocation = %v, want 10.0.0.64/26", got)
	}
	if got := alloc.AllocSubnet4(
		26,
	); got == nil ||
		got.String() != "10.0.0.0/26" {
		t.Fatalf("second allocation = %v, want skipped subnet 10.0.0.0/26", got)
	}
}

func TestSubnetAllocatorFilterStopsAfterMaxAttempts(t *testing.T) {
	var calls int
	alloc := subnet.NewSubnetAllocator(
		mustParseCIDR(t, "10.0.0.0/20"),
		func(*net.IPNet) bool {
			calls++
			return false
		},
	)

	if got := alloc.AllocSubnet4(32); got != nil {
		t.Fatalf("allocation with rejecting filter = %v, want nil", got)
	}
	if calls != 1000 {
		t.Fatalf("filter calls = %d, want 1000", calls)
	}
}

func TestSubnetAllocatorAvoidsReservedSubnetsWithDifferentSizes(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "10.0.0.0/24"), nil)

	alloc.ReserveSubnet(mustParseCIDR(t, "10.0.0.0/25"))
	got := alloc.AllocSubnet4(26)
	if got == nil || got.String() != "10.0.0.128/26" {
		t.Fatalf(
			"allocation after /25 reservation = %v, want 10.0.0.128/26",
			got,
		)
	}

	alloc.ReserveSubnet(mustParseCIDR(t, "10.0.0.196/30"))
	if got = alloc.AllocSubnet4(26); got != nil {
		t.Fatalf("allocation containing reserved /30 = %v, want nil", got)
	}
}

func TestSubnetAllocatorDoesNotAllocateOverOrInsideExistingAllocation(
	t *testing.T,
) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "192.0.2.0/24"), nil)

	first := alloc.AllocSubnet4(26)
	if first == nil || first.String() != "192.0.2.0/26" {
		t.Fatalf("first allocation = %v, want 192.0.2.0/26", first)
	}

	second := alloc.AllocSubnet4(25)
	if second == nil || second.String() != "192.0.2.128/25" {
		t.Fatalf("second allocation = %v, want 192.0.2.128/25", second)
	}

	if subnet.Overlap([]*net.IPNet{first, second}) {
		t.Fatalf("allocated overlapping subnets: %v and %v", first, second)
	}
}

func TestSubnetAllocatorTracksOutsideReservations(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "10.1.2.0/24"), nil)
	supernet := mustParseCIDR(t, "10.0.0.0/8")

	alloc.ReserveSubnet(supernet)
	alloc.ReserveSubnet(supernet)
	if got := alloc.AllocSubnet4(24); got != nil {
		t.Fatalf(
			"allocation inside reserved outside supernet = %v, want nil",
			got,
		)
	}

	alloc.FreeSubnet(supernet)
	if got := alloc.AllocSubnet4(24); got != nil {
		t.Fatalf("allocation after one free = %v, want nil", got)
	}

	alloc.FreeSubnet(supernet)
	got := alloc.AllocSubnet4(24)
	if got == nil || got.String() != "10.1.2.0/24" {
		t.Fatalf(
			"allocation after freeing supernet = %v, want 10.1.2.0/24",
			got,
		)
	}
}

func TestSubnetAllocatorIgnoresUnrelatedOutsideReservations(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "10.1.2.0/24"), nil)

	alloc.ReserveSubnet(mustParseCIDR(t, "192.0.2.0/24"))
	got := alloc.AllocSubnet4(25)
	if got == nil || got.String() != "10.1.2.0/25" {
		t.Fatalf(
			"allocation with unrelated outside reservation = %v, want 10.1.2.0/25",
			got,
		)
	}
}

func TestSubnetAllocatorNormalizesReservedSubnetKeys(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "192.0.2.0/24"), nil)

	alloc.ReserveSubnet(&net.IPNet{
		IP:   net.ParseIP("192.0.2.1"),
		Mask: net.CIDRMask(26, 32),
	})

	got := alloc.AllocSubnet4(26)
	if got == nil || got.String() != "192.0.2.64/26" {
		t.Fatalf(
			"allocation after non-network IP reservation = %v, want 192.0.2.64/26",
			got,
		)
	}

	alloc.FreeSubnet(&net.IPNet{
		IP:   net.IP{192, 0, 2, 0},
		Mask: net.CIDRMask(26, 32),
	})
	got = alloc.AllocSubnet4(26)
	if got == nil || got.String() != "192.0.2.0/26" {
		t.Fatalf(
			"allocation after free with 4-byte IP = %v, want 192.0.2.0/26",
			got,
		)
	}
}

func TestSubnetAllocatorFreeAllSubnets(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "198.51.100.0/30"), nil)

	alloc.ReserveSubnet(mustParseCIDR(t, "198.51.100.0/31"))
	alloc.ReserveSubnet(mustParseCIDR(t, "198.51.100.2/31"))
	if got := alloc.AllocSubnet4(31); got != nil {
		t.Fatalf("allocation before FreeAllSubnets = %v, want nil", got)
	}

	alloc.FreeAllSubnets()
	got := alloc.AllocSubnet4(31)
	if got == nil || got.String() != "198.51.100.0/31" {
		t.Fatalf(
			"allocation after FreeAllSubnets = %v, want 198.51.100.0/31",
			got,
		)
	}
}

func TestSubnetAllocatorOwnsParentCopy(t *testing.T) {
	parent := mustParseCIDR(t, "203.0.113.0/24")
	alloc := subnet.NewSubnetAllocator(parent, nil)

	parent.IP[3] = 128
	parent.Mask = net.CIDRMask(25, 32)

	got := alloc.AllocSubnet4(25)
	if got == nil || got.String() != "203.0.113.0/25" {
		t.Fatalf(
			"allocation after parent mutation = %v, want 203.0.113.0/25",
			got,
		)
	}
}

func TestSubnetAllocatorInvalidPrefixAndWrongFamilyReturnNil(t *testing.T) {
	ipv4 := subnet.NewSubnetAllocator(mustParseCIDR(t, "192.0.2.0/24"), nil)
	if got := ipv4.AllocSubnet6(64); got != nil {
		t.Fatalf("AllocSubnet6 from IPv4 parent = %v, want nil", got)
	}
	if got := ipv4.AllocSubnet4(23); got != nil {
		t.Fatalf(
			"AllocSubnet4 with prefix broader than parent = %v, want nil",
			got,
		)
	}
	if got := ipv4.AllocSubnet4(33); got != nil {
		t.Fatalf("AllocSubnet4 with invalid prefix = %v, want nil", got)
	}

	ipv6 := subnet.NewSubnetAllocator(mustParseCIDR(t, "2001:db8::/64"), nil)
	if got := ipv6.AllocSubnet4(24); got != nil {
		t.Fatalf("AllocSubnet4 from IPv6 parent = %v, want nil", got)
	}
}

func TestSubnetAllocatorConcurrentAllocationsAreUnique(t *testing.T) {
	alloc := subnet.NewSubnetAllocator(mustParseCIDR(t, "10.0.0.0/24"), nil)
	const workers = 64

	var wg sync.WaitGroup
	subnets := make(chan string, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := alloc.AllocSubnet4(32); got != nil {
				subnets <- got.String()
			}
		}()
	}
	wg.Wait()
	close(subnets)

	seen := make(map[string]struct{})
	for cidr := range subnets {
		if _, ok := seen[cidr]; ok {
			t.Fatalf("duplicate allocation %s", cidr)
		}
		seen[cidr] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("allocated %d subnets, want %d", len(seen), workers)
	}
}

func TestExtendIPNet(t *testing.T) {
	tests := []struct {
		name     string
		base     *net.IPNet
		numBits  int
		index    int
		wantCIDR string
		wantErr  bool
	}{
		{
			name:     "IPv4 first child",
			base:     mustParseCIDR(t, "192.0.2.0/24"),
			numBits:  2,
			index:    0,
			wantCIDR: "192.0.2.0/26",
		},
		{
			name:     "IPv4 last child",
			base:     mustParseCIDR(t, "192.0.2.0/24"),
			numBits:  2,
			index:    3,
			wantCIDR: "192.0.2.192/26",
		},
		{
			name:     "IPv6 child",
			base:     mustParseCIDR(t, "2001:db8::/64"),
			numBits:  2,
			index:    1,
			wantCIDR: "2001:db8:0:0:4000::/66",
		},
		{
			name:    "nil base",
			base:    nil,
			wantErr: true,
		},
		{
			name:    "negative numBits",
			base:    mustParseCIDR(t, "192.0.2.0/24"),
			numBits: -1,
			index:   0,
			wantErr: true,
		},
		{
			name:    "numBits exceeds address size",
			base:    mustParseCIDR(t, "192.0.2.0/24"),
			numBits: 9,
			index:   0,
			wantErr: true,
		},
		{
			name:    "negative index",
			base:    mustParseCIDR(t, "192.0.2.0/24"),
			numBits: 1,
			index:   -1,
			wantErr: true,
		},
		{
			name:    "index out of range",
			base:    mustParseCIDR(t, "192.0.2.0/24"),
			numBits: 2,
			index:   4,
			wantErr: true,
		},
		{
			name: "malformed base",
			base: &net.IPNet{
				IP:   net.ParseIP("192.0.2.0"),
				Mask: net.IPMask{255, 0, 255, 0},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := subnet.ExtendIPNet(tt.base, tt.numBits, tt.index)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ExtendIPNet() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtendIPNet() error = %v, want nil", err)
			}
			if got.String() != tt.wantCIDR {
				t.Fatalf("ExtendIPNet() = %v, want %s", got, tt.wantCIDR)
			}
		})
	}
}
