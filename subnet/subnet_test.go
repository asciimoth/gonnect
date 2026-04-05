// nolint
package subnet_test

import (
	"math/big"
	"net"
	"testing"

	"github.com/asciimoth/gonnect/subnet"
)

func TestNext(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want net.IP
	}{
		{
			name: "IPv4 simple increment",
			ip:   net.ParseIP("192.168.1.1"),
			want: net.ParseIP("192.168.1.2"),
		},
		{
			name: "IPv4 carry over",
			ip:   net.ParseIP("192.168.1.255"),
			want: net.ParseIP("192.168.2.0"),
		},
		{
			name: "IPv4 max octet overflow",
			ip:   net.ParseIP("255.255.255.255"),
			want: net.ParseIP("0.0.0.0"),
		},
		{
			name: "IPv6 simple increment",
			ip:   net.ParseIP("::1"),
			want: net.ParseIP("::2"),
		},
		{
			name: "IPv6 carry over",
			ip:   net.ParseIP("::ffff:ffff"),
			want: net.ParseIP("::1:0:0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subnet.Next(tt.ip)
			if !got.Equal(tt.want) {
				t.Errorf("Next(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestPrev(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want net.IP
	}{
		{
			name: "IPv4 simple decrement",
			ip:   net.ParseIP("192.168.1.2"),
			want: net.ParseIP("192.168.1.1"),
		},
		{
			name: "IPv4 borrow from higher octet",
			ip:   net.ParseIP("192.168.2.0"),
			want: net.ParseIP("192.168.1.255"),
		},
		{
			name: "IPv4 min address underflow",
			ip:   net.ParseIP("0.0.0.0"),
			want: net.ParseIP("255.255.255.255"),
		},
		{
			name: "IPv6 simple decrement",
			ip:   net.ParseIP("::2"),
			want: net.ParseIP("::1"),
		},
		{
			name: "IPv6 borrow from higher bytes",
			ip:   net.ParseIP("::1:0:0"),
			want: net.ParseIP("::ffff:ffff"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subnet.Prev(tt.ip)
			if !got.Equal(tt.want) {
				t.Errorf("Prev(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name       string
		parentCIDR string
		childCIDR  string
		want       bool
	}{
		{
			name:       "IPv4 child is subnet of parent",
			parentCIDR: "192.168.0.0/16",
			childCIDR:  "192.168.1.0/24",
			want:       true,
		},
		{
			name:       "IPv4 child equals parent",
			parentCIDR: "192.168.0.0/16",
			childCIDR:  "192.168.0.0/16",
			want:       true,
		},
		{
			name:       "IPv4 child is outside parent",
			parentCIDR: "192.168.0.0/16",
			childCIDR:  "10.0.0.0/8",
			want:       false,
		},
		{
			name:       "IPv4 child is larger than parent",
			parentCIDR: "192.168.1.0/24",
			childCIDR:  "192.168.0.0/16",
			want:       false,
		},
		{
			name:       "IPv6 child is subnet of parent",
			parentCIDR: "2001:db8::/32",
			childCIDR:  "2001:db8:1::/48",
			want:       true,
		},
		{
			name:       "IPv6 child is outside parent",
			parentCIDR: "2001:db8::/32",
			childCIDR:  "fe80::/10",
			want:       false,
		},
		{
			name:       "IPv4 partial overlap",
			parentCIDR: "192.168.0.0/24",
			childCIDR:  "192.168.1.0/24",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, parent, err := net.ParseCIDR(tt.parentCIDR)
			if err != nil {
				t.Fatalf("failed to parse parent CIDR: %v", err)
			}
			_, child, err := net.ParseCIDR(tt.childCIDR)
			if err != nil {
				t.Fatalf("failed to parse child CIDR: %v", err)
			}

			got := subnet.Contains(parent, child)
			if got != tt.want {
				t.Errorf(
					"Contains(%v, %v) = %v, want %v",
					parent,
					child,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestOverlap(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
		want  bool
	}{
		{
			name:  "no overlap - separate networks",
			cidrs: []string{"192.168.1.0/24", "10.0.0.0/8"},
			want:  false,
		},
		{
			name:  "no overlap - adjacent subnets",
			cidrs: []string{"192.168.1.0/24", "192.168.2.0/24"},
			want:  false,
		},
		{
			name:  "overlap - one contains other",
			cidrs: []string{"192.168.0.0/16", "192.168.1.0/24"},
			want:  true,
		},
		{
			name:  "overlap - partial overlap",
			cidrs: []string{"192.168.0.0/23", "192.168.1.0/24"},
			want:  true,
		},
		{
			name:  "overlap - identical networks",
			cidrs: []string{"192.168.1.0/24", "192.168.1.0/24"},
			want:  true,
		},
		{
			name:  "no overlap - three separate networks",
			cidrs: []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
			want:  false,
		},
		{
			name:  "overlap - one of three overlaps",
			cidrs: []string{"192.168.1.0/24", "10.0.0.0/8", "192.168.0.0/16"},
			want:  true,
		},
		{
			name:  "empty list",
			cidrs: []string{},
			want:  false,
		},
		{
			name:  "single network",
			cidrs: []string{"192.168.1.0/24"},
			want:  false,
		},
		{
			name:  "IPv6 no overlap",
			cidrs: []string{"2001:db8::/32", "fe80::/10"},
			want:  false,
		},
		{
			name:  "IPv6 overlap",
			cidrs: []string{"2001:db8::/32", "2001:db8:1::/48"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets := make([]*net.IPNet, 0, len(tt.cidrs))
			for _, cidr := range tt.cidrs {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatalf("failed to parse CIDR %s: %v", cidr, err)
				}
				nets = append(nets, ipNet)
			}

			got := subnet.Overlap(nets)
			if got != tt.want {
				t.Errorf("Overlap(%v) = %v, want %v", tt.cidrs, got, tt.want)
			}
		})
	}
}

func TestCapacity(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want *big.Int
	}{
		{
			name: "/32 - single IPv4",
			cidr: "192.168.1.1/32",
			want: big.NewInt(1),
		},
		{
			name: "/31 - point-to-point IPv4",
			cidr: "192.168.1.0/31",
			want: big.NewInt(2),
		},
		{
			name: "/24 - standard IPv4 subnet",
			cidr: "192.168.1.0/24",
			want: big.NewInt(256),
		},
		{
			name: "/16 - large IPv4 subnet",
			cidr: "192.168.0.0/16",
			want: big.NewInt(65536),
		},
		{
			name: "/0 - entire IPv4 space",
			cidr: "0.0.0.0/0",
			want: new(big.Int).Lsh(big.NewInt(1), 32),
		},
		{
			name: "/128 - single IPv6",
			cidr: "::1/128",
			want: big.NewInt(1),
		},
		{
			name: "/64 - standard IPv6 subnet",
			cidr: "2001:db8::/64",
			want: new(big.Int).Lsh(big.NewInt(1), 64),
		},
		{
			name: "/0 - entire IPv6 space",
			cidr: "::/0",
			want: new(big.Int).Lsh(big.NewInt(1), 128),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			got := subnet.Capacity(ipNet)
			if got.Cmp(tt.want) != 0 {
				t.Errorf("Capacity(%v) = %v, want %v", ipNet, &got, tt.want)
			}
		})
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantFirst net.IP
		wantLast  net.IP
	}{
		{
			name:      "standard /24 IPv4",
			cidr:      "192.168.1.0/24",
			wantFirst: net.ParseIP("192.168.1.0"),
			wantLast:  net.ParseIP("192.168.1.255"),
		},
		{
			name:      "/32 single IPv4",
			cidr:      "192.168.1.1/32",
			wantFirst: net.ParseIP("192.168.1.1"),
			wantLast:  net.ParseIP("192.168.1.1"),
		},
		{
			name:      "/31 point-to-point IPv4",
			cidr:      "192.168.1.0/31",
			wantFirst: net.ParseIP("192.168.1.0"),
			wantLast:  net.ParseIP("192.168.1.1"),
		},
		{
			name:      "/16 IPv4",
			cidr:      "10.0.0.0/16",
			wantFirst: net.ParseIP("10.0.0.0"),
			wantLast:  net.ParseIP("10.0.255.255"),
		},
		{
			name:      "/64 IPv6",
			cidr:      "2001:db8::/64",
			wantFirst: net.ParseIP("2001:db8::"),
			wantLast:  net.ParseIP("2001:db8::ffff:ffff:ffff:ffff"),
		},
		{
			name:      "/128 single IPv6",
			cidr:      "2001:db8::1/128",
			wantFirst: net.ParseIP("2001:db8::1"),
			wantLast:  net.ParseIP("2001:db8::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			gotFirst, gotLast := subnet.Range(ipNet)
			if !gotFirst.Equal(tt.wantFirst) {
				t.Errorf(
					"Range(%v) first = %v, want %v",
					ipNet,
					gotFirst,
					tt.wantFirst,
				)
			}
			if !gotLast.Equal(tt.wantLast) {
				t.Errorf(
					"Range(%v) last = %v, want %v",
					ipNet,
					gotLast,
					tt.wantLast,
				)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		wantFirst  string
		wantSecond string
		wantErr    bool
	}{
		{
			name:       "split /24 into two /25s",
			cidr:       "192.168.1.0/24",
			wantFirst:  "192.168.1.0/25",
			wantSecond: "192.168.1.128/25",
			wantErr:    false,
		},
		{
			name:       "split /31 into two /32s",
			cidr:       "192.168.1.0/31",
			wantFirst:  "192.168.1.0/32",
			wantSecond: "192.168.1.1/32",
			wantErr:    false,
		},
		{
			name:       "split /32 cannot be split",
			cidr:       "192.168.1.1/32",
			wantFirst:  "",
			wantSecond: "",
			wantErr:    true,
		},
		{
			name:       "split IPv6 /64 into two /65s",
			cidr:       "2001:db8::/64",
			wantFirst:  "2001:db8::/65",
			wantSecond: "2001:db8:0:0:8000::/65",
			wantErr:    false,
		},
		{
			name:       "split IPv6 /128 cannot be split",
			cidr:       "2001:db8::1/128",
			wantFirst:  "",
			wantSecond: "",
			wantErr:    true,
		},
		{
			name:       "split /0 IPv4",
			cidr:       "0.0.0.0/0",
			wantFirst:  "0.0.0.0/1",
			wantSecond: "128.0.0.0/1",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			first, second, err := subnet.Split(ipNet)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Split(%v) expected error, got nil", ipNet)
				}
				return
			}

			if err != nil {
				t.Fatalf("Split(%v) unexpected error: %v", ipNet, err)
			}

			_, wantFirstNet, _ := net.ParseCIDR(tt.wantFirst)
			_, wantSecondNet, _ := net.ParseCIDR(tt.wantSecond)

			if !first.IP.Equal(wantFirstNet.IP) ||
				first.Mask.String() != wantFirstNet.Mask.String() {
				t.Errorf(
					"Split(%v) first = %v, want %v",
					ipNet,
					first,
					wantFirstNet,
				)
			}
			if !second.IP.Equal(wantSecondNet.IP) ||
				second.Mask.String() != wantSecondNet.Mask.String() {
				t.Errorf(
					"Split(%v) second = %v, want %v",
					ipNet,
					second,
					wantSecondNet,
				)
			}
		})
	}
}

func TestIPIndex(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		index   *big.Int
		wantIP  string
		wantErr bool
	}{
		{
			name:   "/24 index 0",
			cidr:   "192.168.1.0/24",
			index:  big.NewInt(0),
			wantIP: "192.168.1.0",
		},
		{
			name:   "/24 index 1",
			cidr:   "192.168.1.0/24",
			index:  big.NewInt(1),
			wantIP: "192.168.1.1",
		},
		{
			name:   "/24 index 255",
			cidr:   "192.168.1.0/24",
			index:  big.NewInt(255),
			wantIP: "192.168.1.255",
		},
		{
			name:    "/24 index 256 out of range",
			cidr:    "192.168.1.0/24",
			index:   big.NewInt(256),
			wantIP:  "",
			wantErr: true,
		},
		{
			name:   "/31 index 0",
			cidr:   "192.168.1.0/31",
			index:  big.NewInt(0),
			wantIP: "192.168.1.0",
		},
		{
			name:   "/31 index 1",
			cidr:   "192.168.1.0/31",
			index:  big.NewInt(1),
			wantIP: "192.168.1.1",
		},
		{
			name:   "IPv6 /126 index 0",
			cidr:   "2001:db8::/126",
			index:  big.NewInt(0),
			wantIP: "2001:db8::",
		},
		{
			name:   "IPv6 /126 index 3",
			cidr:   "2001:db8::/126",
			index:  big.NewInt(3),
			wantIP: "2001:db8::3",
		},
		{
			name:    "IPv6 /126 index 4 out of range",
			cidr:    "2001:db8::/126",
			index:   big.NewInt(4),
			wantIP:  "",
			wantErr: true,
		},
		{
			name:   "IPv6 /64 index 0",
			cidr:   "2001:db8::/64",
			index:  big.NewInt(0),
			wantIP: "2001:db8::",
		},
		{
			name:    "negative index",
			cidr:    "192.168.1.0/24",
			index:   big.NewInt(-1),
			wantIP:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			gotIP, err := subnet.IPIndex(ipNet, tt.index)

			if tt.wantErr {
				if err == nil {
					t.Errorf(
						"IPIndex(%v, %v) expected error, got nil",
						ipNet,
						tt.index,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"IPIndex(%v, %v) unexpected error: %v",
					ipNet,
					tt.index,
					err,
				)
			}

			wantIP := net.ParseIP(tt.wantIP)
			if !gotIP.Equal(wantIP) {
				t.Errorf(
					"IPIndex(%v, %v) = %v, want %v",
					ipNet,
					tt.index,
					gotIP,
					wantIP,
				)
			}
		})
	}
}

func TestSubnets(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		prefix    *big.Int
		wantCIDRs []string
		wantErr   bool
	}{
		{
			name:   "/24 into /26s",
			cidr:   "192.168.1.0/24",
			prefix: big.NewInt(26),
			wantCIDRs: []string{
				"192.168.1.0/26",
				"192.168.1.64/26",
				"192.168.1.128/26",
				"192.168.1.192/26",
			},
		},
		{
			name:      "/24 into /25s",
			cidr:      "192.168.1.0/24",
			prefix:    big.NewInt(25),
			wantCIDRs: []string{"192.168.1.0/25", "192.168.1.128/25"},
		},
		{
			name:      "/24 into /24 (same)",
			cidr:      "192.168.1.0/24",
			prefix:    big.NewInt(24),
			wantCIDRs: []string{"192.168.1.0/24"},
		},
		{
			name:    "/24 into /23 (invalid - prefix smaller)",
			cidr:    "192.168.1.0/24",
			prefix:  big.NewInt(23),
			wantErr: true,
		},
		{
			name:    "/32 into /33 (invalid - prefix too large)",
			cidr:    "192.168.1.1/32",
			prefix:  big.NewInt(33),
			wantErr: true,
		},
		{
			name:   "IPv6 /64 into /66s",
			cidr:   "2001:db8::/64",
			prefix: big.NewInt(66),
			wantCIDRs: []string{
				"2001:db8::/66",
				"2001:db8:0:0:4000::/66",
				"2001:db8:0:0:8000::/66",
				"2001:db8:0:0:c000::/66",
			},
		},
		{
			name:    "IPv6 /128 into /129 (invalid - prefix too large)",
			cidr:    "2001:db8::1/128",
			prefix:  big.NewInt(129),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			gotSubnets, err := subnet.Subnets(ipNet, tt.prefix)

			if tt.wantErr {
				if err == nil {
					t.Errorf(
						"Subnets(%v, %v) expected error, got nil",
						ipNet,
						tt.prefix,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"Subnets(%v, %v) unexpected error: %v",
					ipNet,
					tt.prefix,
					err,
				)
			}

			if len(gotSubnets) != len(tt.wantCIDRs) {
				t.Fatalf(
					"Subnets(%v, %v) returned %d subnets, want %d",
					ipNet,
					tt.prefix,
					len(gotSubnets),
					len(tt.wantCIDRs),
				)
			}

			for i, wantCIDR := range tt.wantCIDRs {
				_, wantNet, _ := net.ParseCIDR(wantCIDR)
				if !gotSubnets[i].IP.Equal(wantNet.IP) ||
					gotSubnets[i].Mask.String() != wantNet.Mask.String() {
					t.Errorf(
						"Subnets[%d] = %v, want %v",
						i,
						gotSubnets[i],
						wantNet,
					)
				}
			}
		})
	}
}

func TestExtend(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		bits     int
		num      *big.Int
		wantCIDR string
		wantErr  bool
	}{
		{
			name:     "extend /24 by 1 bit, subnet 0",
			cidr:     "192.168.1.0/24",
			bits:     1,
			num:      big.NewInt(0),
			wantCIDR: "192.168.0.0/23",
		},
		{
			name:     "extend /24 by 1 bit, subnet 1",
			cidr:     "192.168.1.0/24",
			bits:     1,
			num:      big.NewInt(1),
			wantCIDR: "192.168.2.0/23",
		},
		{
			name:     "extend /24 by 2 bits, subnet 0",
			cidr:     "192.168.1.0/24",
			bits:     2,
			num:      big.NewInt(0),
			wantCIDR: "192.168.0.0/22",
		},
		{
			name:     "extend /24 by 2 bits, subnet 3",
			cidr:     "192.168.1.0/24",
			bits:     2,
			num:      big.NewInt(3),
			wantCIDR: "192.168.12.0/22",
		},
		{
			name:     "extend /24 by 8 bits, subnet 0 (to /16)",
			cidr:     "192.168.1.0/24",
			bits:     8,
			num:      big.NewInt(0),
			wantCIDR: "192.168.0.0/16",
		},
		{
			name:     "extend /24 by 8 bits, subnet 1",
			cidr:     "192.168.1.0/24",
			bits:     8,
			num:      big.NewInt(1),
			wantCIDR: "192.169.0.0/16",
		},
		{
			name:     "extend IPv6 /64 by 1 bit, subnet 0",
			cidr:     "2001:db8::/64",
			bits:     1,
			num:      big.NewInt(0),
			wantCIDR: "2001:db8::/63",
		},
		{
			name:     "extend IPv6 /64 by 1 bit, subnet 1",
			cidr:     "2001:db8::/64",
			bits:     1,
			num:      big.NewInt(1),
			wantCIDR: "2001:db8:0:2::/63",
		},
		{
			name:     "extend by 0 bits returns same network",
			cidr:     "192.168.1.0/24",
			bits:     0,
			num:      big.NewInt(0),
			wantCIDR: "192.168.1.0/24",
		},
		{
			name:    "extend beyond /0",
			cidr:    "192.168.1.0/24",
			bits:    25,
			num:     big.NewInt(0),
			wantErr: true,
		},
		{
			name:    "negative num",
			cidr:    "192.168.1.0/24",
			bits:    1,
			num:     big.NewInt(-1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			got, err := subnet.Extend(ipNet, tt.bits, tt.num)

			if tt.wantErr {
				if err == nil {
					t.Errorf(
						"Extend(%v, %d, %v) expected error, got nil",
						ipNet,
						tt.bits,
						tt.num,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"Extend(%v, %d, %v) unexpected error: %v",
					ipNet,
					tt.bits,
					tt.num,
					err,
				)
			}

			_, wantNet, _ := net.ParseCIDR(tt.wantCIDR)
			if !got.IP.Equal(wantNet.IP) ||
				got.Mask.String() != wantNet.Mask.String() {
				t.Errorf(
					"Extend(%v, %d, %v) = %v, want %v",
					ipNet,
					tt.bits,
					tt.num,
					got,
					wantNet,
				)
			}
		})
	}
}

func TestNarrow(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		bits     int
		num      *big.Int
		wantCIDR string
		wantErr  bool
	}{
		{
			name:     "narrow /24 by 1 bit, subnet 0",
			cidr:     "192.168.1.0/24",
			bits:     1,
			num:      big.NewInt(0),
			wantCIDR: "192.168.1.0/25",
		},
		{
			name:     "narrow /24 by 1 bit, subnet 1",
			cidr:     "192.168.1.0/24",
			bits:     1,
			num:      big.NewInt(1),
			wantCIDR: "192.168.1.128/25",
		},
		{
			name:     "narrow /24 by 2 bits, subnet 0",
			cidr:     "192.168.1.0/24",
			bits:     2,
			num:      big.NewInt(0),
			wantCIDR: "192.168.1.0/26",
		},
		{
			name:     "narrow /24 by 2 bits, subnet 3",
			cidr:     "192.168.1.0/24",
			bits:     2,
			num:      big.NewInt(3),
			wantCIDR: "192.168.1.192/26",
		},
		{
			name:     "narrow /24 by 8 bits, subnet 0 (to /32)",
			cidr:     "192.168.1.0/24",
			bits:     8,
			num:      big.NewInt(0),
			wantCIDR: "192.168.1.0/32",
		},
		{
			name:     "narrow /24 by 8 bits, subnet 255",
			cidr:     "192.168.1.0/24",
			bits:     8,
			num:      big.NewInt(255),
			wantCIDR: "192.168.1.255/32",
		},
		{
			name:     "narrow IPv6 /64 by 1 bit, subnet 0",
			cidr:     "2001:db8::/64",
			bits:     1,
			num:      big.NewInt(0),
			wantCIDR: "2001:db8::/65",
		},
		{
			name:     "narrow IPv6 /64 by 1 bit, subnet 1",
			cidr:     "2001:db8::/64",
			bits:     1,
			num:      big.NewInt(1),
			wantCIDR: "2001:db8:0:0:8000::/65",
		},
		{
			name:     "narrow by 0 bits returns same network",
			cidr:     "192.168.1.0/24",
			bits:     0,
			num:      big.NewInt(0),
			wantCIDR: "192.168.1.0/24",
		},
		{
			name:    "narrow beyond /32 IPv4",
			cidr:    "192.168.1.0/24",
			bits:    9,
			num:     big.NewInt(0),
			wantErr: true,
		},
		{
			name:    "narrow beyond /128 IPv6",
			cidr:    "2001:db8::/64",
			bits:    65,
			num:     big.NewInt(0),
			wantErr: true,
		},
		{
			name:    "negative num",
			cidr:    "192.168.1.0/24",
			bits:    1,
			num:     big.NewInt(-1),
			wantErr: true,
		},
		{
			name:    "num out of range",
			cidr:    "192.168.1.0/24",
			bits:    1,
			num:     big.NewInt(2),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("failed to parse CIDR %s: %v", tt.cidr, err)
			}

			got, err := subnet.Narrow(ipNet, tt.bits, tt.num)

			if tt.wantErr {
				if err == nil {
					t.Errorf(
						"Narrow(%v, %d, %v) expected error, got nil",
						ipNet,
						tt.bits,
						tt.num,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"Narrow(%v, %d, %v) unexpected error: %v",
					ipNet,
					tt.bits,
					tt.num,
					err,
				)
			}

			_, wantNet, _ := net.ParseCIDR(tt.wantCIDR)
			if !got.IP.Equal(wantNet.IP) ||
				got.Mask.String() != wantNet.Mask.String() {
				t.Errorf(
					"Narrow(%v, %d, %v) = %v, want %v",
					ipNet,
					tt.bits,
					tt.num,
					got,
					wantNet,
				)
			}
		})
	}
}

func TestFromRange(t *testing.T) {
	tests := []struct {
		name     string
		first    string
		last     string
		wantCIDR string
	}{
		{
			name:     "standard /24 IPv4",
			first:    "192.168.1.0",
			last:     "192.168.1.255",
			wantCIDR: "192.168.1.0/24",
		},
		{
			name:     "single IP /32 IPv4",
			first:    "192.168.1.1",
			last:     "192.168.1.1",
			wantCIDR: "192.168.1.1/32",
		},
		{
			name:     "point-to-point /31 IPv4",
			first:    "192.168.1.0",
			last:     "192.168.1.1",
			wantCIDR: "192.168.1.0/31",
		},
		{
			name:     "/16 IPv4",
			first:    "10.0.0.0",
			last:     "10.0.255.255",
			wantCIDR: "10.0.0.0/16",
		},
		{
			name:     "/64 IPv6",
			first:    "2001:db8::",
			last:     "2001:db8::ffff:ffff:ffff:ffff",
			wantCIDR: "2001:db8::/64",
		},
		{
			name:     "single IP /128 IPv6",
			first:    "2001:db8::1",
			last:     "2001:db8::1",
			wantCIDR: "2001:db8::1/128",
		},
		{
			name:     "invalid range - first > last",
			first:    "192.168.1.255",
			last:     "192.168.1.0",
			wantCIDR: "", // expect error
		},
		{
			name:     "invalid range - not aligned",
			first:    "192.168.1.1",
			last:     "192.168.1.254",
			wantCIDR: "", // expect error - not a valid CIDR range
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := net.ParseIP(tt.first)
			last := net.ParseIP(tt.last)

			ipNet, err := subnet.FromRange(first, last)

			if tt.wantCIDR == "" {
				if err == nil {
					t.Errorf(
						"FROMRange(%s, %s) expected error, got %v",
						tt.first,
						tt.last,
						ipNet,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"FROMRange(%s, %s) unexpected error: %v",
					tt.first,
					tt.last,
					err,
				)
			}

			_, wantNet, _ := net.ParseCIDR(tt.wantCIDR)
			if !ipNet.IP.Equal(wantNet.IP) ||
				ipNet.Mask.String() != wantNet.Mask.String() {
				t.Errorf(
					"FROMRange(%s, %s) = %v, want %v",
					tt.first,
					tt.last,
					ipNet,
					wantNet,
				)
			}
		})
	}
}
