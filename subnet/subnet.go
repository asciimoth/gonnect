// Package subnet provides utilities for working with IP subnets, including
// well-known CIDR ranges, IP address arithmetic, and network manipulation.
// It supports both IPv4 and IPv6 operations such as splitting, extending,
// narrowing, and enumerating subnets.
package subnet

import (
	"errors"
	"fmt"
	"math/big"
	"net"
)

// Some well-known CIDRs that are likely to collide with local,
// container, VM, VPN, Kubernetes, cloud, or overlay-network usage.
//
// Major sources:
//   - IANA IPv4/IPv6 Special-Purpose Address Registries.
//   - RFC1918 / RFC4193.
//   - Docker, Kubernetes, k3s, Podman, minikube docs.
//   - Common router, VM, VPN, and overlay-network defaults.
var (
	//
	// IPv4 special-use / non-ordinary networks.
	// These are not all "private-use"; many should never be allocated
	// by a normal private-network allocator.
	//

	CIDRIPv4ThisNetwork = MustCIDR(
		"0.0.0.0/8",
	) // "This network"; not usable as ordinary host/network space.
	CIDRIPv4Loopback  = MustCIDR("127.0.0.0/8") // Loopback.
	CIDRIPv4LinkLocal = MustCIDR(
		"169.254.0.0/16",
	) // IPv4 link-local/APIPA.
	CIDRIPv4Multicast = MustCIDR("224.0.0.0/4") // IPv4 multicast.
	CIDRIPv4Reserved  = MustCIDR(
		"240.0.0.0/4",
	) // Reserved by protocol.
	CIDRIPv4LimitedBroadcast = MustCIDR("255.255.255.255/32")
	CIDRIPv4SharedAddress    = MustCIDR(
		"100.64.0.0/10",
	) // Shared Address Space / CGNAT; also used by Tailscale.
	CIDRIPv4Benchmarking = MustCIDR(
		"198.18.0.0/15",
	) // Benchmarking, not RFC1918 private-use.
	CIDRIPv4Documentation1 = MustCIDR("192.0.2.0/24")    // TEST-NET-1.
	CIDRIPv4Documentation2 = MustCIDR("198.51.100.0/24") // TEST-NET-2.
	CIDRIPv4Documentation3 = MustCIDR("203.0.113.0/24")  // TEST-NET-3.

	//
	// Very common home/SOHO router defaults.
	// Most are useful only if your parent is 192.168.0.0/16.
	//

	CIDRRouterDefault1921680 = MustCIDR("192.168.0.0/24")
	CIDRRouterDefault1921681 = MustCIDR("192.168.1.0/24")
	CIDRRouterDefault1921682 = MustCIDR("192.168.2.0/24")
	CIDRRouterDefault1921683 = MustCIDR(
		"192.168.3.0/24",
	) // Huawei and others.
	CIDRRouterDefault1921684 = MustCIDR(
		"192.168.4.0/24",
	) // Zyxel and others.
	CIDRRouterDefault1921688 = MustCIDR(
		"192.168.8.0/24",
	) // Huawei / GL.iNet-style defaults.
	CIDRRouterDefault19216810 = MustCIDR(
		"192.168.10.0/24",
	) // Zyxel/Motorola/etc.; replaces duplicate Zyxel2/Motorola vars.
	CIDRRouterDefault19216831 = MustCIDR(
		"192.168.31.0/24",
	) // Xiaomi/MiWiFi-style default.
	CIDRRouterDefault19216850 = MustCIDR(
		"192.168.50.0/24",
	) // TP-Link/ASUS/Xiaomi-style defaults.
	CIDRRouterDefault19216868 = MustCIDR(
		"192.168.68.0/24",
	) // TP-Link Deco-style default.
	CIDRRouterDefault19216886 = MustCIDR(
		"192.168.86.0/24",
	) // Google/Nest Wifi.
	CIDRRouterDefault19216888 = MustCIDR(
		"192.168.88.0/24",
	) // MikroTik default.
	CIDRRouterDefault192168100 = MustCIDR(
		"192.168.100.0/24",
	) // Cable modem / Huawei-style management LAN.
	CIDRRouterDefault192168178 = MustCIDR("192.168.178.0/24") // FRITZ!Box.
	CIDRRouterDefault192168188 = MustCIDR(
		"192.168.188.0/24",
	) // FRITZ!Box/repeater-style defaults.

	//
	// Common local VM / desktop virtualization / container-host networks.
	//

	CIDRVirtualBoxHostOnly = MustCIDR(
		"192.168.56.0/24",
	) // VirtualBox host-only default.
	CIDRLibvirtDefault = MustCIDR(
		"192.168.122.0/24",
	) // libvirt default NAT network.
	CIDRDockerBridge = MustCIDR(
		"172.17.0.0/16",
	) // Classic docker0 bridge.
	CIDRDockerDesktopMac = MustCIDR(
		"192.168.65.0/24",
	) // Common Docker Desktop internal subnet; treat as heuristic.
	CIDRPodmanDefault = MustCIDR(
		"10.88.0.0/16",
	) // Podman root bridge default.

	// Docker's documented default address pools cover these shapes.
	// If you ever allocate from 172.16.0.0/12, it is often simplest to
	// avoid all of 172.17.0.0/16 through 172.31.0.0/16 or avoid the whole
	// 172.16.0.0/12 parent entirely.
	CIDRDockerPool17217 = MustCIDR("172.17.0.0/16")
	CIDRDockerPool17218 = MustCIDR("172.18.0.0/15")
	CIDRDockerPool17220 = MustCIDR("172.20.0.0/14")
	CIDRDockerPool17224 = MustCIDR("172.24.0.0/14")
	CIDRDockerPool17228 = MustCIDR("172.28.0.0/14")
	CIDRDockerPool192   = MustCIDR(
		"192.168.0.0/16",
	) // Too broad for default banning if parent is 192.168/16.

	//
	// Kubernetes / local cluster / CNI defaults.
	//

	CIDRKubeAdmServices = MustCIDR(
		"10.96.0.0/12",
	) // kubeadm default Service CIDR.
	CIDRK3sPods     = MustCIDR("10.42.0.0/16") // k3s default pod CIDR.
	CIDRK3sServices = MustCIDR("10.43.0.0/16") // k3s default service CIDR.
	CIDRK3s         = MustCIDR(
		"10.42.0.0/15",
	) // Aggregate of k3s pods+services.
	CIDRKindFlannelPods = MustCIDR(
		"10.244.0.0/16",
	) // kind/flannel-style pod CIDR.
	CIDRMinikubeDocker = MustCIDR("192.168.49.0/24")
	CIDRMinikubeVM     = MustCIDR("192.168.59.0/24")
	CIDRMinikubeKVM2   = MustCIDR("192.168.39.0/24")
	CIDRCalicoDefault  = MustCIDR(
		"192.168.0.0/16",
	) // Calico default pool in many manifests; too broad for default banning.

	//
	// VPN / overlay-ish IPv4 defaults.
	//

	CIDROpenVPNDefault = MustCIDR(
		"10.8.0.0/24",
	) // OpenVPN examples commonly use 10.8.0.0/24.
	CIDROpenVPNBroad = MustCIDR(
		"10.8.0.0/16",
	) // Optional broader exclusion.
	CIDRTailscaleCGNAT = MustCIDR(
		"100.64.0.0/10",
	) // Same as Shared Address Space; Tailscale uses this by default.

	//
	// Common cloud defaults.
	// These are useful if your project often runs on developer laptops
	// that VPN into cloud networks. Some are very broad; make them optional.
	//

	CIDRCommon10LANs = MustCIDR(
		"10.0.0.0/15",
	) // Covers very common 10.0.0.0/16 and 10.1.0.0/16 LAN/VNet defaults.
	CIDRAzureDefault = MustCIDR(
		"10.0.0.0/16",
	) // Azure examples/default CLI VNet address space; already covered above.
	CIDRAWSDefaultVPC = MustCIDR("172.31.0.0/16") // AWS default VPC.
	CIDRGCPAutoMode   = MustCIDR(
		"10.128.0.0/9",
	) // GCP auto-mode VPC range; large/aggressive optional exclusion.

	//
	// IPv6 special-use / non-ordinary networks.
	// If your IPv6 parent is a random fdxx:xxxx:xxxx::/48 ULA,
	// most of these do not overlap, except fd00-derived examples.
	//

	CIDRIPv6Unspecified    = MustCIDR("::/128")
	CIDRIPv6Loopback       = MustCIDR("::1/128")
	CIDRIPv6IPv4Mapped     = MustCIDR("::ffff:0:0/96")
	CIDRIPv6NAT64WellKnown = MustCIDR("64:ff9b::/96")
	CIDRIPv6NAT64Local     = MustCIDR("64:ff9b:1::/48")
	CIDRIPv6DiscardOnly    = MustCIDR("100::/64")
	CIDRIPv6Dummy          = MustCIDR("100:0:0:1::/64")
	CIDRIPv6Teredo         = MustCIDR("2001::/32")
	CIDRIPv6Benchmarking   = MustCIDR("2001:2::/48")
	CIDRIPv6Documentation  = MustCIDR("2001:db8::/32")
	CIDRIPv6Documentation2 = MustCIDR("3fff::/20")
	CIDRIPv66to4           = MustCIDR("2002::/16")
	CIDRIPv6SRv6SIDs       = MustCIDR("5f00::/16")
	CIDRIPv6LinkLocal      = MustCIDR("fe80::/10")
	CIDRIPv6Multicast      = MustCIDR("ff00::/8")

	// ULA handling:
	//   fc00::/7 is the whole ULA block.
	//   fd00::/8 is the normal locally-assigned half used for random ULA /48s.
	//   fc00::/8 is not normally used by RFC4193 local generation, but cjdns/
	//   Hyperboria-style overlays use it.
	//
	// Do NOT ban fd00::/8 if your allocator's IPv6 parent is a random ULA /48.
	CIDRIPv6ULA         = MustCIDR("fc00::/7")
	CIDRIPv6ULALocal    = MustCIDR("fd00::/8")
	CIDRHyperboriaCJDNS = MustCIDR(
		"fc00::/8",
	) // cjdns/Hyperboria overlay usage.

	//
	// IPv6 overlay networks that intentionally use unusual global-unicast-looking
	// space. These matter only if your allocator can allocate from broad IPv6
	// parents outside ULA.
	//

	CIDRYggdrasilNetwork = MustCIDR(
		"200::/7",
	) // Yggdrasil; includes 200::/8 node addrs and 300::/8 routed prefixes.
	CIDRMycelium = MustCIDR("400::/7") // Mycelium overlay network.

	//
	// Local Kubernetes IPv6 examples/defaults.
	// These only matter if your ULA parent could overlap them; a random ULA /48
	// almost certainly will not.
	//

	CIDRKindIPv6Services = MustCIDR(
		"fd00:10:96::/112",
	) // kind IPv6 service subnet default.
)

func MustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	if n == nil {
		panic(fmt.Sprintf("failed to parse %s CIDR", s))
	}
	return *n
}

// Next returns the next IP address after ip, wrapping around to all zeros
// if ip is the maximum address (all 0xFF bytes).
func Next(ip net.IP) net.IP {
	// Normalize to 4 bytes for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}

	return next
}

// Prev returns the previous IP address before ip, wrapping around to all 0xFF
// bytes if ip is the minimum address (all zeros).
func Prev(ip net.IP) net.IP {
	// Normalize to 4 bytes for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	prev := make(net.IP, len(ip))
	copy(prev, ip)

	for i := len(prev) - 1; i >= 0; i-- {
		prev[i]--
		if prev[i] != 0xFF {
			break
		}
	}

	return prev
}

// Contains reports whether child is a subnet of parent (or equal to parent).
// It checks that child's network is entirely contained within parent's network.
func Contains(parent, child *net.IPNet) bool {
	parentMaskSize, _ := parent.Mask.Size()
	childMaskSize, _ := child.Mask.Size()

	if childMaskSize < parentMaskSize {
		return false
	}

	return parent.Contains(child.IP)
}

// Overlap reports whether any of the provided networks overlap with each other.
// Returns false for empty list or single network.
func Overlap(nets []*net.IPNet) bool {
	for i := range nets {
		for j := i + 1; j < len(nets); j++ {
			if nets[i].Contains(nets[j].IP) || nets[j].Contains(nets[i].IP) {
				return true
			}
		}
	}
	return false
}

// Capacity returns the total number of IP addresses in the network,
// including the network address and broadcast address.
func Capacity(network *net.IPNet) big.Int {
	ones, bits := network.Mask.Size()
	hosts := big.NewInt(1)
	hosts.Lsh(
		hosts,
		uint(bits-ones), //nolint:gosec // bits-ones is 0-128, safe for shift
	)
	return *hosts
}

// Range returns the first (network) and last (broadcast) IP addresses
// in the network.
func Range(network *net.IPNet) (net.IP, net.IP) {
	first := network.IP.To4()
	if first == nil {
		first = network.IP.To16()
	}
	first = first.To16()

	mask := network.Mask
	ones, bits := mask.Size()

	// Calculate the last address
	hostBits := uint(bits - ones) //nolint:gosec // bits-ones is 0-128, safe
	last := make(net.IP, len(first))
	copy(last, first)

	// Add (2^hostBits - 1) to the first address
	offset := big.NewInt(1)
	offset.Lsh(offset, hostBits)
	offset.Sub(offset, big.NewInt(1))

	ipInt := big.NewInt(0).SetBytes(first)
	ipInt.Add(ipInt, offset)

	lastBytes := ipInt.Bytes()
	// Pad to correct length
	if len(lastBytes) < len(first) {
		padded := make([]byte, len(first))
		copy(padded[len(first)-len(lastBytes):], lastBytes)
		lastBytes = padded
	}
	copy(last, lastBytes[:len(first)])

	// Normalize back to original form
	if network.IP.To4() != nil {
		last = last.To4()
		first = first.To4()
	}

	return first, last
}

// FromRange constructs a network from its first and last IP addresses.
// Returns an error if the range doesn't represent a valid CIDR block
// (i.e., if the range isn't aligned to a power-of-2 boundary).
func FromRange(first, last net.IP) (net.IPNet, error) {
	// Normalize to same format
	f := first.To4()
	if f == nil {
		f = first.To16()
	}
	l := last.To4()
	if l == nil {
		l = last.To16()
	}

	if f == nil || l == nil {
		return net.IPNet{}, &net.ParseError{
			Type: "IP address",
			Text: "invalid IP",
		}
	}

	// Check same address family
	if len(f) != len(l) {
		return net.IPNet{}, &net.ParseError{
			Type: "IP address",
			Text: "address family mismatch",
		}
	}

	fInt := big.NewInt(0).SetBytes(f)
	lInt := big.NewInt(0).SetBytes(l)

	// Check first <= last
	if fInt.Cmp(lInt) > 0 {
		return net.IPNet{}, &net.ParseError{
			Type: "IP range",
			Text: "first > last",
		}
	}

	// Calculate the size of the range
	size := big.NewInt(0).Sub(lInt, fInt)
	size.Add(size, big.NewInt(1))

	// Check if size is a power of 2
	if size.BitLen() == 0 || size.BitLen() > 128 {
		return net.IPNet{}, &net.ParseError{
			Type: "IP range",
			Text: "invalid range size",
		}
	}

	// Check if size is power of 2: (size & (size-1)) == 0
	sizeMinusOne := big.NewInt(0).Sub(size, big.NewInt(1))
	and := big.NewInt(0).And(size, sizeMinusOne)
	if and.Cmp(big.NewInt(0)) != 0 {
		return net.IPNet{}, &net.ParseError{
			Type: "IP range",
			Text: "range size is not a power of 2",
		}
	}

	// Calculate prefix length
	bits := len(f) * 8
	// Size = 2^hostBits, so find which bit is set
	hostBits := 0
	tmp := big.NewInt(0).Set(size)
	for tmp.BitLen() > 1 {
		tmp.Rsh(tmp, 1)
		hostBits++
	}

	prefixLen := bits - hostBits

	// Check if first address is aligned to the prefix
	mask := net.CIDRMask(prefixLen, bits)
	aligned := f.Mask(mask)
	if !aligned.Equal(f) {
		return net.IPNet{}, &net.ParseError{
			Type: "IP range",
			Text: "first address not aligned to prefix",
		}
	}

	return net.IPNet{
		IP:   f,
		Mask: mask,
	}, nil
}

// Split divides a network into two equal halves by incrementing the prefix length by one.
// Returns an error if the network cannot be split further (e.g., /32 for IPv4 or /128 for IPv6).
func Split(network *net.IPNet) (*net.IPNet, *net.IPNet, error) {
	ones, bits := network.Mask.Size()

	// Cannot split if already at maximum prefix length
	if ones == bits {
		return nil, nil, errors.New(
			"cannot split network with maximum prefix length",
		)
	}

	// New prefix length is ones + 1
	newPrefix := ones + 1
	newMask := net.CIDRMask(newPrefix, bits)

	// First half starts at the same IP
	first := &net.IPNet{
		IP:   network.IP.Mask(newMask),
		Mask: newMask,
	}

	// Second half starts at the midpoint
	midpoint := big.NewInt(1)
	midpoint.Lsh(
		midpoint,
		uint(bits-newPrefix), //nolint:gosec // bits-newPrefix is 0-128, safe
	)

	secondIP := big.NewInt(0).SetBytes(network.IP)
	secondIP.Add(secondIP, midpoint)

	secondBytes := secondIP.Bytes()
	if len(secondBytes) < len(network.IP) {
		padded := make([]byte, len(network.IP))
		copy(padded[len(network.IP)-len(secondBytes):], secondBytes)
		secondBytes = padded
	}

	second := &net.IPNet{
		IP:   secondBytes[:len(network.IP)],
		Mask: newMask,
	}

	// Normalize IPv4
	if network.IP.To4() != nil {
		first.IP = first.IP.To4()
		second.IP = second.IP.To4()
	}

	return first, second, nil
}

// IPIndex returns the IP address at the given index within the network.
// Index 0 corresponds to the network address, and the maximum valid index
// is 2^(host_bits) - 1, where host_bits = total_bits - prefix_length.
// Returns an error if the index is negative or out of range.
func IPIndex(network *net.IPNet, i *big.Int) (net.IP, error) {
	// Check for negative index
	if i.Sign() < 0 {
		return nil, errors.New("index cannot be negative")
	}

	ones, bits := network.Mask.Size()
	hostBits := uint(bits - ones) //nolint:gosec // bits-ones is 0-128, safe

	// Calculate capacity: 2^hostBits
	capacity := big.NewInt(1)
	capacity.Lsh(capacity, hostBits)

	// Check if index is out of range
	if i.Cmp(capacity) >= 0 {
		return nil, errors.New("index out of range for network")
	}

	// Get the network base IP
	base := network.IP.To4()
	if base == nil {
		base = network.IP.To16()
	}
	if base == nil {
		return nil, errors.New("invalid IP address")
	}

	// Add index to base IP
	result := big.NewInt(0).SetBytes(base)
	result.Add(result, i)

	resultBytes := result.Bytes()
	if len(resultBytes) < len(base) {
		padded := make([]byte, len(base))
		copy(padded[len(base)-len(resultBytes):], resultBytes)
		resultBytes = padded
	}

	resultIP := net.IP(resultBytes[:len(base)])

	// Normalize to IPv4 if applicable
	if network.IP.To4() != nil {
		resultIP = resultIP.To4()
	}

	return resultIP, nil
}

// Extend creates a supernet of the given network by reducing the prefix length
// by the specified number of bits. The num parameter selects which supernet
// to return (0 for the one containing the original network, 1 for the next, etc.).
// For example, Extend(192.168.1.0/24, 1, 0) returns 192.168.0.0/23,
// and Extend(192.168.1.0/24, 1, 1) returns 192.168.2.0/23.
// Returns an error if bits is negative, num is negative, or the resulting
// prefix length would be less than 0.
func Extend(network *net.IPNet, bits int, num *big.Int) (net.IPNet, error) {
	ones, totalBits := network.Mask.Size()

	// Validate inputs
	if bits < 0 {
		return net.IPNet{}, errors.New("bits cannot be negative")
	}
	if num.Sign() < 0 {
		return net.IPNet{}, errors.New("num cannot be negative")
	}

	newPrefix := ones - bits
	if newPrefix < 0 {
		return net.IPNet{}, errors.New(
			"resulting prefix length would be negative",
		)
	}

	// Calculate the new mask
	newMask := net.CIDRMask(newPrefix, totalBits)

	// Calculate the offset: num * 2^(totalBits - newPrefix)
	//nolint:gosec // totalBits-newPrefix validated to be >= 0
	hostBits := uint(totalBits - newPrefix)
	blockSize := big.NewInt(1)
	blockSize.Lsh(blockSize, hostBits)

	offset := big.NewInt(0).Mul(num, blockSize)

	// Add offset to the network IP
	baseIP := big.NewInt(0).SetBytes(network.IP)
	newIP := big.NewInt(0).Add(baseIP, offset)

	// Apply the new mask to get the network address
	ipBytes := newIP.Bytes()
	if len(ipBytes) < len(network.IP) {
		padded := make([]byte, len(network.IP))
		copy(padded[len(network.IP)-len(ipBytes):], ipBytes)
		ipBytes = padded
	}

	// Ensure we have the right length
	if len(ipBytes) > len(network.IP) {
		ipBytes = ipBytes[len(ipBytes)-len(network.IP):]
	}

	resultIP := net.IP(ipBytes).Mask(newMask)

	// Normalize to IPv4 if applicable
	if network.IP.To4() != nil {
		resultIP = resultIP.To4()
	}

	return net.IPNet{
		IP:   resultIP,
		Mask: newMask,
	}, nil
}

// Narrow creates a subnet of the given network by increasing the prefix length
// by the specified number of bits. The num parameter selects which subnet
// to return (0 for the first subnet, 1 for the second, etc.).
// For example, Narrow(192.168.1.0/24, 1, 0) returns 192.168.1.0/25,
// and Narrow(192.168.1.0/24, 1, 1) returns 192.168.1.128/25.
// Returns an error if bits is negative, num is negative, the resulting
// prefix length would exceed the maximum (32 for IPv4, 128 for IPv6),
// or num is out of range for the specified bits.
func Narrow(network *net.IPNet, bits int, num *big.Int) (net.IPNet, error) {
	ones, totalBits := network.Mask.Size()

	// Validate inputs
	if bits < 0 {
		return net.IPNet{}, errors.New("bits cannot be negative")
	}
	if num.Sign() < 0 {
		return net.IPNet{}, errors.New("num cannot be negative")
	}

	newPrefix := ones + bits
	if newPrefix > totalBits {
		return net.IPNet{}, errors.New(
			"resulting prefix length would exceed maximum",
		)
	}

	// Check that num is within range: must be < 2^bits
	maxNum := big.NewInt(1)
	maxNum.Lsh(maxNum, uint(bits))
	if num.Cmp(maxNum) >= 0 {
		return net.IPNet{}, errors.New("num out of range for specified bits")
	}

	// Calculate the new mask
	newMask := net.CIDRMask(newPrefix, totalBits)

	// Calculate the offset: num * 2^(totalBits - newPrefix)
	//nolint:gosec // totalBits-newPrefix validated >= 0
	hostBits := uint(totalBits - newPrefix)
	blockSize := big.NewInt(1)
	blockSize.Lsh(blockSize, hostBits)

	offset := big.NewInt(0).Mul(num, blockSize)

	// Add offset to the network IP
	baseIP := big.NewInt(0).SetBytes(network.IP)
	newIP := big.NewInt(0).Add(baseIP, offset)

	// Convert back to bytes
	ipBytes := newIP.Bytes()
	if len(ipBytes) < len(network.IP) {
		padded := make([]byte, len(network.IP))
		copy(padded[len(network.IP)-len(ipBytes):], ipBytes)
		ipBytes = padded
	}

	// Ensure we have the right length
	if len(ipBytes) > len(network.IP) {
		ipBytes = ipBytes[len(ipBytes)-len(network.IP):]
	}

	resultIP := net.IP(ipBytes)

	// Normalize to IPv4 if applicable
	if network.IP.To4() != nil {
		resultIP = resultIP.To4()
	}

	return net.IPNet{
		IP:   resultIP,
		Mask: newMask,
	}, nil
}
