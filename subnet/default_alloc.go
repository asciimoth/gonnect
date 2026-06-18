package subnet

import (
	"math/rand"
	"net"
)

const (
	defaultAllocatorPoolPrefix4 = 24
	defaultAllocatorPoolPrefix6 = 64
)

// DefaultAllocatorConfig holds optional policy inputs for NewDefaultAllocator.
//
// NewDefaultAllocator intentionally does not expose parent networks or pool
// prefix lengths. It always allocates IPv4 space from 10.0.0.0/8 using /24 IP
// pools, and IPv6 space from one random fd00::/48 ULA generated at construction
// time using Rng, with /64 IP pools.
type DefaultAllocatorConfig struct {
	// IPFilter is an optional callback used to reject candidate IP addresses.
	// It has the same locking and reentrancy constraints as NewCombinedAllocator.
	IPFilter IPFilter

	// SubnetFilter is an optional callback used to reject candidate subnets.
	// It has the same locking and reentrancy constraints as NewCombinedAllocator.
	SubnetFilter SubnetFilter

	// BannedIPs are permanent IP blockers merged into the allocator.
	BannedIPs []net.IP

	// BannedSubnets are permanent subnet blockers. They are merged with the
	// built-in defaults for common local, container, VPN, and cluster CIDRs
	// that can collide with the default 10.0.0.0/8 parent or random ULA parent.
	BannedSubnets []*net.IPNet

	// Rng generates the IPv6 ULA parent and selects randomized subnet starts.
	// If nil, a deterministic generator with the same constant seed used by
	// NewCombinedAllocator is used.
	Rng *rand.Rand
}

// NewDefaultAllocator creates a CombinedAllocator with opinionated private
// networking defaults.
//
// The allocator owns 10.0.0.0/8 for IPv4 allocations and a single random
// fdxx:xxxx:xxxx::/48 ULA for IPv6 allocations. The IPv6 parent is generated
// once during construction from config.Rng; the same generator is then passed
// to NewCombinedAllocator for subsequent randomized subnet allocation. A nil
// Rng uses a deterministic constant source, matching NewCombinedAllocator.
//
// IP allocations grow from /24 IPv4 pools and /64 IPv6 pools. Built-in banned
// subnets are merged with config.BannedSubnets and include common 10/8 local,
// container, VPN, and Kubernetes defaults from subnet.go, plus the kind IPv6
// service example that could overlap a random ULA parent. Caller-supplied bans
// are copied by NewCombinedAllocator and remain permanent until the allocator
// is discarded.
func NewDefaultAllocator(config DefaultAllocatorConfig) *CombinedAllocator {
	rng := config.Rng
	if rng == nil {
		rng = rand.New(rand.NewSource(defaultCombinedAllocatorSeed)) // nolint
	}

	bannedSubnets := defaultAllocatorBannedSubnets()
	bannedSubnets = append(bannedSubnets, config.BannedSubnets...)

	return NewCombinedAllocator(
		defaultAllocatorIPv4Parent(),
		randomULA48(rng),
		defaultAllocatorPoolPrefix4,
		defaultAllocatorPoolPrefix6,
		config.IPFilter,
		config.SubnetFilter,
		config.BannedIPs,
		bannedSubnets,
		rng,
	)
}

func defaultAllocatorIPv4Parent() *net.IPNet {
	cidr := MustCIDR("10.0.0.0/8")
	return CopyIPNet(&cidr)
}

func defaultAllocatorBannedSubnets() []*net.IPNet {
	return copyIPNets(
		CIDRCommon10LANs,
		CIDRPodmanDefault,
		CIDROpenVPNBroad,
		CIDRK3s,
		CIDRKubeAdmServices,
		CIDRKindFlannelPods,
		CIDRKindIPv6Services,
	)
}

func copyIPNets(networks ...net.IPNet) []*net.IPNet {
	copies := make([]*net.IPNet, 0, len(networks))
	for i := range networks {
		copies = append(copies, CopyIPNet(&networks[i]))
	}
	return copies
}

func randomULA48(rng *rand.Rand) *net.IPNet {
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
