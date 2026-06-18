// nolint
package subnet_test

import (
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestCombinedAllocatorImplementsBothInterfaces(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "192.0.2.0/29"),
		mustParseCIDR(t, "2001:db8::/125"),
		30,
		126,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	var ipAlloc subnet.IPAllocator = alloc
	var subnetAlloc subnet.SubnetAllocator = alloc

	if ip := allocIP4(ipAlloc); !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("AllocIP4 through interface = %v, want 192.0.2.1", ip)
	}
	if got := subnetAlloc.AllocSubnet6(
		126,
	); got == nil ||
		got.String() != "2001:db8::4/126" {
		t.Fatalf(
			"AllocSubnet6 through interface = %v, want 2001:db8::4/126",
			got,
		)
	}
}

func TestCombinedAllocatorIPAllocationUsesAndExtendsPool(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "192.0.2.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	want := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.5"),
		net.ParseIP("192.0.2.6"),
	}
	wantSubnets := []string{
		"192.0.2.0/30",
		"192.0.2.0/30",
		"192.0.2.4/30",
		"192.0.2.4/30",
	}
	for i, wantIP := range want {
		got, gotSubnet := alloc.AllocIP4()
		if !got.Equal(wantIP) {
			t.Fatalf("allocation %d = %v, want %v", i, got, wantIP)
		}
		if gotSubnet == nil || gotSubnet.String() != wantSubnets[i] {
			t.Fatalf(
				"allocation %d subnet = %v, want %s",
				i,
				gotSubnet,
				wantSubnets[i],
			)
		}
	}
	if got, gotSubnet := alloc.AllocIP4(); got != nil || gotSubnet != nil {
		t.Fatalf("allocation after pool exhaustion = %v, want nil", got)
	}
}

func TestCombinedAllocatorSubnetAllocationSeesIPPoolReservations(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "198.51.100.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	if ip := allocIP4(alloc); !ip.Equal(net.ParseIP("198.51.100.1")) {
		t.Fatalf("initial IP allocation = %v, want 198.51.100.1", ip)
	}

	got := alloc.AllocSubnet4(30)
	if got == nil || got.String() != "198.51.100.4/30" {
		t.Fatalf(
			"subnet allocation after IP pool allocation = %v, want 198.51.100.4/30",
			got,
		)
	}
	if got = alloc.AllocSubnet4(30); got != nil {
		t.Fatalf("third /30 allocation = %v, want nil", got)
	}
}

func TestCombinedAllocatorSubnetAllocationBlockedByReservedAndBannedIPs(
	t *testing.T,
) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "10.0.0.0/24"),
		nil,
		30,
		0,
		nil,
		nil,
		[]net.IP{net.ParseIP("10.0.0.1")},
		nil,
		nil,
	)
	alloc.ReserveIP(net.ParseIP("10.0.0.70"))

	got := alloc.AllocSubnet4(26)
	if got == nil || got.String() != "10.0.0.128/26" {
		t.Fatalf("allocation blocked by IPs = %v, want 10.0.0.128/26", got)
	}
}

func TestCombinedAllocatorSubnetAllocationAvoidsBannedAndReservedSubnets(
	t *testing.T,
) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "10.1.0.0/24"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		[]*net.IPNet{mustParseCIDR(t, "10.1.0.0/26")},
		nil,
	)
	alloc.ReserveSubnet(mustParseCIDR(t, "10.1.0.64/26"))

	got := alloc.AllocSubnet4(26)
	if got == nil || got.String() != "10.1.0.128/26" {
		t.Fatalf("allocation blocked by subnets = %v, want 10.1.0.128/26", got)
	}
}

func TestCombinedAllocatorSubnetAllocationUsesProvidedRandomGenerator(
	t *testing.T,
) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "10.3.0.0/24"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		rand.New(rand.NewSource(1)),
	)

	got := alloc.AllocSubnet4(26)
	if got == nil || got.String() != "10.3.0.128/26" {
		t.Fatalf(
			"randomized subnet allocation = %v, want 10.3.0.128/26",
			got,
		)
	}
}

func TestCombinedAllocatorNilRandomGeneratorIsReproducible(t *testing.T) {
	newAlloc := func() *subnet.CombinedAllocator {
		return subnet.NewCombinedAllocator(
			mustParseCIDR(t, "10.4.0.0/24"),
			nil,
			28,
			0,
			nil,
			nil,
			nil,
			nil,
			nil,
		)
	}
	first := newAlloc()
	second := newAlloc()

	for i := 0; i < 8; i++ {
		firstIP, firstSubnet := first.AllocIP4()
		secondIP, secondSubnet := second.AllocIP4()
		if !firstIP.Equal(secondIP) ||
			firstSubnet == nil ||
			secondSubnet == nil ||
			firstSubnet.String() != secondSubnet.String() {
			t.Fatalf(
				"allocation %d mismatch: (%v, %v) != (%v, %v)",
				i,
				firstIP,
				firstSubnet,
				secondIP,
				secondSubnet,
			)
		}
	}
}

func TestCombinedAllocatorIPAllocationAvoidsBannedAndReservedIPs(t *testing.T) {
	banned := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "203.0.113.0/28"),
		nil,
		30,
		0,
		nil,
		nil,
		[]net.IP{net.ParseIP("203.0.113.1")},
		nil,
		nil,
	)

	if got := allocIP4(banned); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf(
			"allocation with banned IP in first pool candidate = %v, want 203.0.113.9",
			got,
		)
	}

	reserved := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "203.0.113.0/29"),
		nil,
		29,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if got := allocIP4(reserved); !got.Equal(net.ParseIP("203.0.113.1")) {
		t.Fatalf("initial allocation = %v, want 203.0.113.1", got)
	}
	reserved.ReserveIP(net.ParseIP("203.0.113.2"))
	if got := allocIP4(reserved); !got.Equal(net.ParseIP("203.0.113.3")) {
		t.Fatalf(
			"allocation with reserved IP in owned pool = %v, want 203.0.113.3",
			got,
		)
	}
}

func TestCombinedAllocatorReserveIPOutsideOwnedSubnets(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "192.0.2.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	alloc.ReserveIP(net.ParseIP("192.0.2.5"))
	got := alloc.AllocSubnet4(30)
	if got == nil || got.String() != "192.0.2.0/30" {
		t.Fatalf("first subnet allocation = %v, want 192.0.2.0/30", got)
	}
	if got = alloc.AllocSubnet4(30); got != nil {
		t.Fatalf("subnet containing externally reserved IP = %v, want nil", got)
	}
}

func TestCombinedAllocatorReserveSubnetOutsideParentCanBlockParent(
	t *testing.T,
) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "10.2.3.0/24"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	supernet := mustParseCIDR(t, "10.0.0.0/8")

	alloc.ReserveSubnet(supernet)
	if got := alloc.AllocSubnet4(24); got != nil {
		t.Fatalf("allocation inside reserved supernet = %v, want nil", got)
	}

	alloc.FreeSubnet(supernet)
	if got := alloc.AllocSubnet4(
		24,
	); got == nil ||
		got.String() != "10.2.3.0/24" {
		t.Fatalf(
			"allocation after freeing supernet = %v, want 10.2.3.0/24",
			got,
		)
	}
}

func TestCombinedAllocatorFiltersAndRetryLimits(t *testing.T) {
	t.Run("IP", func(t *testing.T) {
		var calls int
		alloc := subnet.NewCombinedAllocator(
			mustParseCIDR(t, "192.0.0.0/20"),
			nil,
			20,
			0,
			func(net.IP) bool {
				calls++
				return false
			},
			nil,
			nil,
			nil,
			nil,
		)

		if got := allocIP4(alloc); got != nil {
			t.Fatalf("allocation with rejecting IP filter = %v, want nil", got)
		}
		if calls != 1000 {
			t.Fatalf("IP filter calls = %d, want 1000", calls)
		}
	})

	t.Run("Subnet", func(t *testing.T) {
		var calls int
		alloc := subnet.NewCombinedAllocator(
			mustParseCIDR(t, "10.0.0.0/20"),
			nil,
			30,
			0,
			nil,
			func(*net.IPNet) bool {
				calls++
				return false
			},
			nil,
			nil,
			nil,
		)

		if got := alloc.AllocSubnet4(32); got != nil {
			t.Fatalf(
				"allocation with rejecting subnet filter = %v, want nil",
				got,
			)
		}
		if calls != 1000 {
			t.Fatalf("subnet filter calls = %d, want 1000", calls)
		}
	})
}

func TestCombinedAllocatorFreeKeepsOnlyOneEmptyPoolSubnet(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "192.0.2.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	ips := []net.IP{
		allocIP4(alloc),
		allocIP4(alloc),
		allocIP4(alloc),
		allocIP4(alloc),
	}
	for _, ip := range ips {
		alloc.FreeIP(ip)
	}

	got := alloc.AllocSubnet4(30)
	if got == nil || got.String() != "192.0.2.4/30" {
		t.Fatalf(
			"subnet allocation after empty pool cleanup = %v, want freed 192.0.2.4/30",
			got,
		)
	}
	if got = alloc.AllocSubnet4(30); got != nil {
		t.Fatalf(
			"second subnet allocation after cleanup = %v, want nil because one empty pool subnet remains",
			got,
		)
	}
}

func TestCombinedAllocatorFreeAllDoesNotRemoveBans(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "198.51.100.0/29"),
		nil,
		30,
		0,
		nil,
		nil,
		[]net.IP{net.ParseIP("198.51.100.1")},
		[]*net.IPNet{mustParseCIDR(t, "198.51.100.4/30")},
		nil,
	)

	alloc.ReserveIP(net.ParseIP("198.51.100.2"))
	alloc.ReserveSubnet(mustParseCIDR(t, "198.51.100.0/30"))
	alloc.FreeAllIP()
	alloc.FreeAllSubnets()

	if got := allocIP4(alloc); got != nil {
		t.Fatalf(
			"IP allocation with only banned-containing pool subnet available = %v, want nil",
			got,
		)
	}
	if got := alloc.AllocSubnet4(30); got != nil {
		t.Fatalf(
			"subnet allocation after FreeAll with bans = %v, want nil",
			got,
		)
	}
}

func TestCombinedAllocatorIPv6(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		nil,
		mustParseCIDR(t, "2001:db8::/125"),
		0,
		126,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	ip1 := allocIP6(alloc)
	ip2 := allocIP6(alloc)
	ip3 := allocIP6(alloc)

	if !ip1.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("first IPv6 allocation = %v, want 2001:db8::1", ip1)
	}
	if !ip2.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("second IPv6 allocation = %v, want 2001:db8::2", ip2)
	}
	if !ip3.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("third IPv6 allocation = %v, want 2001:db8::5", ip3)
	}
}

func TestCombinedAllocatorNilParentsAndWrongFamiliesReturnNil(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		nil,
		nil,
		30,
		126,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	if got := allocIP4(alloc); got != nil {
		t.Fatalf("AllocIP4 with nil parents = %v, want nil", got)
	}
	if got := alloc.AllocSubnet6(126); got != nil {
		t.Fatalf("AllocSubnet6 with nil parents = %v, want nil", got)
	}

	ipv4 := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "192.0.2.0/29"),
		nil,
		30,
		126,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if got := allocIP6(ipv4); got != nil {
		t.Fatalf("AllocIP6 with only IPv4 parent = %v, want nil", got)
	}
	if got := ipv4.AllocSubnet4(28); got != nil {
		t.Fatalf("AllocSubnet4 broader than parent = %v, want nil", got)
	}
}

func TestCombinedAllocatorConcurrentIPAllocationsAreUnique(t *testing.T) {
	alloc := subnet.NewCombinedAllocator(
		mustParseCIDR(t, "10.10.0.0/24"),
		nil,
		28,
		0,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	const workers = 64

	var wg sync.WaitGroup
	ips := make(chan string, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip := allocIP4(alloc); ip != nil {
				ips <- ip.String()
			}
		}()
	}
	wg.Wait()
	close(ips)

	seen := make(map[string]struct{})
	for ip := range ips {
		if _, ok := seen[ip]; ok {
			t.Fatalf("duplicate allocation %s", ip)
		}
		seen[ip] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("allocated %d IPs, want %d", len(seen), workers)
	}
}
