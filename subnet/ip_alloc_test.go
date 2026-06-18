package subnet_test

import (
	"net"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return network
}

func allocIP4(alloc subnet.IPAllocator) net.IP {
	ip, _ := alloc.AllocIP4()
	return ip
}

func allocIP6(alloc subnet.IPAllocator) net.IP {
	ip, _ := alloc.AllocIP6()
	return ip
}

func TestIPAllocatorAllocIP4(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)

	ip1, subnet1 := alloc.AllocIP4()
	ip2, subnet2 := alloc.AllocIP4()
	ip3, subnet3 := alloc.AllocIP4()

	if !ip1.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("first allocation = %v, want 192.0.2.1", ip1)
	}
	if subnet1 == nil || subnet1.String() != "192.0.2.0/30" {
		t.Fatalf("first allocation subnet = %v, want 192.0.2.0/30", subnet1)
	}
	if !ip2.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("second allocation = %v, want 192.0.2.2", ip2)
	}
	if subnet2 == nil || subnet2.String() != "192.0.2.0/30" {
		t.Fatalf("second allocation subnet = %v, want 192.0.2.0/30", subnet2)
	}
	if ip3 != nil {
		t.Fatalf("third allocation = %v, want nil", ip3)
	}
	if subnet3 != nil {
		t.Fatalf("third allocation subnet = %v, want nil", subnet3)
	}
}

func TestIPAllocatorAllocIP6(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "2001:db8::/126"), nil)

	ip1, subnet1 := alloc.AllocIP6()
	ip2, subnet2 := alloc.AllocIP6()
	ip3, subnet3 := alloc.AllocIP6()

	if !ip1.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("first allocation = %v, want 2001:db8::1", ip1)
	}
	if subnet1 == nil || subnet1.String() != "2001:db8::/126" {
		t.Fatalf("first allocation subnet = %v, want 2001:db8::/126", subnet1)
	}
	if !ip2.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("second allocation = %v, want 2001:db8::2", ip2)
	}
	if subnet2 == nil || subnet2.String() != "2001:db8::/126" {
		t.Fatalf("second allocation subnet = %v, want 2001:db8::/126", subnet2)
	}
	if ip3 != nil {
		t.Fatalf("third allocation = %v, want nil", ip3)
	}
	if subnet3 != nil {
		t.Fatalf("third allocation subnet = %v, want nil", subnet3)
	}
}

func TestIPAllocatorFilterSkipsRejectedIPs(t *testing.T) {
	rejected := true
	alloc := subnet.NewIPAllocator(
		mustParseCIDR(t, "192.0.2.0/30"),
		func(ip net.IP) bool {
			if rejected && ip.Equal(net.ParseIP("192.0.2.1")) {
				rejected = false
				return false
			}
			return true
		},
	)

	if ip := allocIP4(alloc); !ip.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("first allocation = %v, want 192.0.2.2", ip)
	}
	if ip := allocIP4(alloc); !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("second allocation = %v, want skipped IP 192.0.2.1", ip)
	}
}

func TestIPAllocatorFilterStopsAfterMaxAttempts(t *testing.T) {
	var calls int
	alloc := subnet.NewIPAllocator(
		mustParseCIDR(t, "192.0.0.0/20"),
		func(net.IP) bool {
			calls++
			return false
		},
	)

	if ip := allocIP4(alloc); ip != nil {
		t.Fatalf("allocation with rejecting filter = %v, want nil", ip)
	}
	if calls != 1000 {
		t.Fatalf("filter calls = %d, want 1000", calls)
	}
}

func TestIPAllocatorNeverAllocatesFirstOrLast(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		allocFn func(subnet.IPAllocator) net.IP
		first   net.IP
		last    net.IP
	}{
		{
			name:    "IPv4",
			cidr:    "198.51.100.0/29",
			allocFn: allocIP4,
			first:   net.ParseIP("198.51.100.0"),
			last:    net.ParseIP("198.51.100.7"),
		},
		{
			name:    "IPv6",
			cidr:    "2001:db8:1::/125",
			allocFn: allocIP6,
			first:   net.ParseIP("2001:db8:1::"),
			last:    net.ParseIP("2001:db8:1::7"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc := subnet.NewIPAllocator(mustParseCIDR(t, tt.cidr), nil)

			for {
				ip := tt.allocFn(alloc)
				if ip == nil {
					return
				}
				if ip.Equal(tt.first) || ip.Equal(tt.last) {
					t.Fatalf("allocated reserved edge address %v", ip)
				}
			}
		})
	}
}

func TestIPAllocatorReserveIPNormalizesMapKeys(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)

	alloc.ReserveIP(net.ParseIP("192.0.2.1"))

	ip := allocIP4(alloc)
	if !ip.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("allocation after reservation = %v, want 192.0.2.2", ip)
	}

	alloc.FreeIP(net.IP{192, 0, 2, 1})
	ip = allocIP4(alloc)
	if !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf(
			"allocation after free with 4-byte IP = %v, want 192.0.2.1",
			ip,
		)
	}
}

func TestIPAllocatorReserveIPIsReferenceCounted(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)
	ip := net.ParseIP("192.0.2.1")

	alloc.ReserveIP(ip)
	alloc.ReserveIP(ip)
	alloc.FreeIP(ip)

	got := allocIP4(alloc)
	if !got.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("allocation after one free = %v, want 192.0.2.2", got)
	}

	alloc.FreeIP(ip)
	got = allocIP4(alloc)
	if !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("allocation after second free = %v, want 192.0.2.1", got)
	}
}

func TestIPAllocatorIgnoresUnusableReservations(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)

	alloc.ReserveIP(net.ParseIP("192.0.2.0"))
	alloc.ReserveIP(net.ParseIP("192.0.2.3"))
	alloc.ReserveIP(net.ParseIP("192.0.3.1"))

	got := []net.IP{allocIP4(alloc), allocIP4(alloc), allocIP4(alloc)}
	if !got[0].Equal(net.ParseIP("192.0.2.1")) ||
		!got[1].Equal(net.ParseIP("192.0.2.2")) ||
		got[2] != nil {
		t.Fatalf("allocations = %v, want 192.0.2.1, 192.0.2.2, nil", got)
	}
}

func TestIPAllocatorFreeAllIP(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)

	alloc.ReserveIP(net.ParseIP("192.0.2.1"))
	alloc.ReserveIP(net.ParseIP("192.0.2.2"))
	if ip := allocIP4(alloc); ip != nil {
		t.Fatalf("allocation before FreeAllIP = %v, want nil", ip)
	}

	alloc.FreeAllIP()
	if ip := allocIP4(alloc); !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("allocation after FreeAllIP = %v, want 192.0.2.1", ip)
	}
}

func TestIPAllocatorOwnsNetworkCopy(t *testing.T) {
	network := mustParseCIDR(t, "192.0.2.0/30")
	alloc := subnet.NewIPAllocator(network, nil)

	network.IP[3] = 128
	network.Mask = net.CIDRMask(32, 32)

	if ip := allocIP4(alloc); !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("allocation after source mutation = %v, want 192.0.2.1", ip)
	}
}

func TestIPAllocatorWrongFamilyAndTinySubnetsReturnNil(t *testing.T) {
	ipv4 := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/30"), nil)
	if ip := allocIP6(ipv4); ip != nil {
		t.Fatalf("AllocIP6 from IPv4 network = %v, want nil", ip)
	}

	ipv6 := subnet.NewIPAllocator(mustParseCIDR(t, "2001:db8::/126"), nil)
	if ip := allocIP4(ipv6); ip != nil {
		t.Fatalf("AllocIP4 from IPv6 network = %v, want nil", ip)
	}

	tiny := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/31"), nil)
	if ip := allocIP4(tiny); ip != nil {
		t.Fatalf("AllocIP4 from /31 = %v, want nil", ip)
	}
}

func TestIPAllocatorConcurrentAllocationsAreUnique(t *testing.T) {
	alloc := subnet.NewIPAllocator(mustParseCIDR(t, "192.0.2.0/25"), nil)
	const workers = 32

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
