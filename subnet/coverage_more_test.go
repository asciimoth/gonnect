package subnet_test

import (
	"math/big"
	"net"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestMustCIDRPanicsOnInvalidCIDR(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustCIDR accepted invalid input")
		}
	}()

	_ = subnet.MustCIDR("not-a-cidr")
}

func TestIPArithmeticWrapsAtBounds(t *testing.T) {
	if got := subnet.Next(
		net.IPv4(255, 255, 255, 255),
	); !got.Equal(
		net.IPv4(0, 0, 0, 0),
	) {
		t.Fatalf("Next(max IPv4) = %v, want 0.0.0.0", got)
	}
	if got := subnet.Prev(
		net.IPv4(0, 0, 0, 0),
	); !got.Equal(
		net.IPv4(255, 255, 255, 255),
	) {
		t.Fatalf("Prev(min IPv4) = %v, want 255.255.255.255", got)
	}
}

func TestFromRangeRejectsInvalidRanges(t *testing.T) {
	tests := []struct {
		name  string
		first net.IP
		last  net.IP
	}{
		{
			name:  "invalid first IP",
			first: net.IP{1, 2, 3},
			last:  net.IPv4(192, 0, 2, 1),
		},
		{
			name:  "address family mismatch",
			first: net.IPv4(192, 0, 2, 1),
			last:  net.ParseIP("2001:db8::1"),
		},
		{
			name:  "first after last",
			first: net.IPv4(192, 0, 2, 8),
			last:  net.IPv4(192, 0, 2, 1),
		},
		{
			name:  "non power of two size",
			first: net.IPv4(192, 0, 2, 0),
			last:  net.IPv4(192, 0, 2, 2),
		},
		{
			name:  "not aligned",
			first: net.IPv4(192, 0, 2, 1),
			last:  net.IPv4(192, 0, 2, 2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := subnet.FromRange(tt.first, tt.last); err == nil {
				t.Fatal("FromRange() error = nil, want error")
			}
		})
	}
}

func TestSplitAndIndexRejectInvalidInputs(t *testing.T) {
	maxNetwork := subnet.MustCIDR("192.0.2.1/32")
	if _, _, err := subnet.Split(&maxNetwork); err == nil {
		t.Fatal("Split(/32) error = nil, want error")
	}

	network := subnet.MustCIDR("192.0.2.0/30")
	if _, err := subnet.IPIndex(&network, big.NewInt(-1)); err == nil {
		t.Fatal("IPIndex(negative) error = nil, want error")
	}
	if _, err := subnet.IPIndex(&network, big.NewInt(4)); err == nil {
		t.Fatal("IPIndex(out of range) error = nil, want error")
	}

	invalidIPNetwork := net.IPNet{
		IP:   net.IP{1, 2, 3},
		Mask: net.CIDRMask(24, 32),
	}
	if _, err := subnet.IPIndex(&invalidIPNetwork, big.NewInt(0)); err == nil {
		t.Fatal("IPIndex(invalid IP) error = nil, want error")
	}
}

func TestIPv6SplitExtendNarrowAndIndex(t *testing.T) {
	network := subnet.MustCIDR("2001:db8::/126")

	first, second, err := subnet.Split(&network)
	if err != nil {
		t.Fatalf("Split(IPv6) error = %v", err)
	}
	if first.String() != "2001:db8::/127" {
		t.Fatalf("first split = %s, want 2001:db8::/127", first)
	}
	if second.String() != "2001:db8::2/127" {
		t.Fatalf("second split = %s, want 2001:db8::2/127", second)
	}

	indexed, err := subnet.IPIndex(&network, big.NewInt(3))
	if err != nil {
		t.Fatalf("IPIndex(IPv6) error = %v", err)
	}
	if !indexed.Equal(net.ParseIP("2001:db8::3")) {
		t.Fatalf("IPIndex(IPv6) = %v, want 2001:db8::3", indexed)
	}

	extended, err := subnet.Extend(&network, 2, big.NewInt(1))
	if err != nil {
		t.Fatalf("Extend(IPv6) error = %v", err)
	}
	if extended.String() != "2001:db8::10/124" {
		t.Fatalf("Extend(IPv6) = %s, want 2001:db8::10/124", &extended)
	}

	narrowed, err := subnet.Narrow(&network, 1, big.NewInt(1))
	if err != nil {
		t.Fatalf("Narrow(IPv6) error = %v", err)
	}
	if narrowed.String() != "2001:db8::2/127" {
		t.Fatalf("Narrow(IPv6) = %s, want 2001:db8::2/127", &narrowed)
	}
}

func TestExtendAndNarrowRejectInvalidInputs(t *testing.T) {
	network := subnet.MustCIDR("192.0.2.0/24")

	if _, err := subnet.Extend(&network, -1, big.NewInt(0)); err == nil {
		t.Fatal("Extend(negative bits) error = nil, want error")
	}
	if _, err := subnet.Extend(&network, 1, big.NewInt(-1)); err == nil {
		t.Fatal("Extend(negative num) error = nil, want error")
	}
	if _, err := subnet.Extend(&network, 25, big.NewInt(0)); err == nil {
		t.Fatal("Extend(too broad) error = nil, want error")
	}
	if _, err := subnet.Narrow(&network, -1, big.NewInt(0)); err == nil {
		t.Fatal("Narrow(negative bits) error = nil, want error")
	}
	if _, err := subnet.Narrow(&network, 1, big.NewInt(-1)); err == nil {
		t.Fatal("Narrow(negative num) error = nil, want error")
	}
	if _, err := subnet.Narrow(&network, 9, big.NewInt(0)); err == nil {
		t.Fatal("Narrow(too narrow) error = nil, want error")
	}
	if _, err := subnet.Narrow(&network, 2, big.NewInt(4)); err == nil {
		t.Fatal("Narrow(num out of range) error = nil, want error")
	}
}
