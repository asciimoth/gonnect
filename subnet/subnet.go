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

// Some well known CIDRs. May overlap.
// Most info is from [here].
// TODO: Add more well known subnets.
//
// [here]: https://blog.benjojo.co.uk/post/picking-unused-rfc1918-ip-space
var (
	CIDRLocal          = MustCIDR("127.0.0.0/8")
	CIDRCommonDefault1 = MustCIDR("192.168.1.0/24")
	CIDRCommonDefault2 = MustCIDR("192.168.0.0/24")
	CIDRCommonDefault3 = MustCIDR("192.168.2.0/24")
	CIDRFritzBox1      = MustCIDR("192.168.178.0/24")
	CIDRFritzBox2      = MustCIDR("192.168.188.0/24")
	CIDRTpLink1        = MustCIDR("192.168.68.0/24")
	CIDRTpLink2        = MustCIDR("192.168.50.0/24")
	CIDRHuawei1        = MustCIDR("192.168.100.0/24")
	CIDRHuawei2        = MustCIDR("192.168.3.0/24")
	CIDRHuawei3        = MustCIDR("192.168.8.0/24")
	CIDRZyxel1         = MustCIDR("192.168.4.0/24")
	CIDRZyxel2         = MustCIDR("192.168.10.0/24")
	CIDRGoogleWifi     = MustCIDR("192.168.86.0/24")
	CIDRMotorola       = MustCIDR("192.168.10.0/24")

	// From Yggdrasil doc:
	//
	//   Yggdrasil uses the 200::/7 region of the IPv6 network space.
	//   This region was set aside for NSAP-mapped IPv6 addresses in RFC1888,
	//   which was (AFAIK) never used and eventually deprecated in RFC4048
	//   (with further explanation in RFC4548).
	CIDRYggdrasilNetwork = MustCIDR("200::/7")

	// CJDNS use [ULA] address space.
	//
	// [ULA]: https://en.wikipedia.org/wiki/Unique_local_address
	CIDRHyperboria = MustCIDR("FC00::/8")

	CIDRMycelium = MustCIDR("400::/7")
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

// Subnets returns all subnets of the given network with the specified prefix length.
// The prefix must be greater than or equal to the network's current prefix length
// and less than or equal to the maximum (32 for IPv4, 128 for IPv6).
// Returns an error if the prefix is invalid.
func Subnets(network *net.IPNet, prefix *big.Int) ([]*net.IPNet, error) {
	ones, bits := network.Mask.Size()

	// Convert prefix to int
	if !prefix.IsInt64() || prefix.Sign() < 0 {
		return nil, errors.New("invalid prefix length")
	}

	newPrefix := int(prefix.Int64())

	// Validate prefix range
	if newPrefix < ones || newPrefix > bits {
		return nil, errors.New("prefix length out of range")
	}

	// Calculate number of subnets: 2^(newPrefix - ones)
	//nolint:gosec // newPrefix-ones and bits-newPrefix validated to be in range
	subnetBits := uint(newPrefix - ones)
	numSubnets := big.NewInt(1)
	numSubnets.Lsh(numSubnets, subnetBits)

	// Calculate the size of each subnet in terms of host addresses
	hostBits := uint(bits - newPrefix) //nolint:gosec // validated in range
	subnetSize := big.NewInt(1)
	subnetSize.Lsh(subnetSize, hostBits)

	// Generate all subnets
	result := make([]*net.IPNet, 0, numSubnets.Uint64())
	newMask := net.CIDRMask(newPrefix, bits)

	currentIP := big.NewInt(0).SetBytes(network.IP)
	for range numSubnets.Uint64() {
		ipBytes := currentIP.Bytes()
		if len(ipBytes) < len(network.IP) {
			padded := make([]byte, len(network.IP))
			copy(padded[len(network.IP)-len(ipBytes):], ipBytes)
			ipBytes = padded
		}

		subnet := &net.IPNet{
			IP:   make(net.IP, len(ipBytes)),
			Mask: newMask,
		}
		copy(subnet.IP, ipBytes)

		// Normalize to IPv4 if applicable
		if network.IP.To4() != nil {
			subnet.IP = subnet.IP.To4()
		}

		result = append(result, subnet)

		// Move to next subnet
		currentIP.Add(currentIP, subnetSize)
	}

	return result, nil
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
