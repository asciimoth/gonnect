package subnet

import (
	"crypto/rand"
	"math/big"
	"net"
	"slices"
	"sync"
)

// SubnetAllocator manages allocation of IP subnets in thread-safe way to
// track which subnets are in use.
type SubnetAllocator interface {
	// Prefixes returns a list of unique prefix lengths supported by this allocator.
	Prefixes() []int

	// Reserve marks a subnet as reserved. If the subnet is not within any of the
	// available subnets, the call is silently ignored.
	Reserve(subnet *net.IPNet)

	// Alloc returns a free subnet with the provided prefix length and marks it as reserved.
	// It returns nil if:
	//   - The prefix length is not supported (not present in available subnets).
	//   - All subnets with that prefix length are already reserved.
	Alloc(prefix int) *net.IPNet

	// Free removes the reserved mark from a subnet. If the subnet was not reserved,
	// this is a no-op.
	Free(subnet *net.IPNet)

	// FreeAll removes all reserved marks, making all previously allocated subnets
	// available again.
	FreeAll()
}

// subnetAllocator implements SubnetAllocator using a slice of available subnets
// and a map for reservation tracking. Allocations are performed in order of
// the available subnets list, returning the first unreserved match.
type subnetAllocator struct {
	mu        sync.RWMutex
	available []*net.IPNet          // all available subnets provided at creation
	reserved  map[string]*net.IPNet // reserved subnets keyed by CIDR string
	prefixes  []int                 // sorted unique prefix lengths
}

// NewAllocator creates a new SubnetAllocator with the provided available subnets.
// The allocator will only support prefix lengths that are present in the
// available subnets. The available slice is copied internally; modifications
// to the original slice after creation have no effect on the allocator.
func NewAllocator(available []*net.IPNet) SubnetAllocator {
	// Collect unique prefixes
	prefixSet := make(map[int]struct{})
	for _, subnet := range available {
		ones, _ := subnet.Mask.Size()
		prefixSet[ones] = struct{}{}
	}

	prefixes := make([]int, 0, len(prefixSet))
	for p := range prefixSet {
		prefixes = append(prefixes, p)
	}
	slices.Sort(prefixes)

	// Copy available subnets
	avail := make([]*net.IPNet, len(available))
	for i, s := range available {
		avail[i] = copyIPNet(s)
	}

	return &subnetAllocator{
		available: avail,
		reserved:  make(map[string]*net.IPNet),
		prefixes:  prefixes,
	}
}

func (a *subnetAllocator) Prefixes() []int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]int, len(a.prefixes))
	copy(result, a.prefixes)
	return result
}

func (a *subnetAllocator) Reserve(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserve(subnet)
}

func (a *subnetAllocator) Alloc(prefixLen int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Find first available subnet that can contain the requested prefix
	for _, avail := range a.available {
		availPrefix, _ := avail.Mask.Size()
		// Skip if requested prefix is smaller than available (can't fit)
		// Special case: prefixLen 0 means "any", so allocate the whole subnet
		if prefixLen != 0 && prefixLen < availPrefix {
			continue
		}

		// For prefix 0, allocate the entire available subnet
		targetPrefix := prefixLen
		if targetPrefix == 0 {
			targetPrefix = availPrefix
		}

		// Try to find an unreserved subnet at the requested prefix length
		// within this available subnet
		result := a.allocFromSubnet(avail, targetPrefix)
		if result != nil {
			return result
		}
	}

	return nil
}

func (a *subnetAllocator) Free(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := subnet.String()
	delete(a.reserved, key)
}

func (a *subnetAllocator) FreeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserved = make(map[string]*net.IPNet)
}

// allocFromSubnet tries to allocate a subnet with the given prefix length
// from the provided available subnet. Returns nil if all sub-slots are reserved.
func (a *subnetAllocator) allocFromSubnet(
	avail *net.IPNet,
	prefixLen int,
) *net.IPNet {
	availPrefix, _ := avail.Mask.Size()

	// If the available subnet itself is reserved, can't allocate from it
	if a.isReserved(avail) {
		return nil
	}

	// If requesting the same prefix as available, return it
	if prefixLen == availPrefix {
		a.reserve(avail)
		return copyIPNet(avail)
	}

	// Calculate how many subnets of the requested size fit in the available subnet
	diff := prefixLen - availPrefix
	if diff < 0 || diff >= 32 {
		return nil
	}
	numSubnets := 1 << uint(diff)

	// Try each possible subnet slot
	for i := range numSubnets {
		candidate := extendIPNet(avail, prefixLen-availPrefix, i)
		if !a.isReserved(candidate) {
			a.reserve(candidate)
			return candidate
		}
	}

	return nil
}

// extendIPNet creates a subnet by extending the given network to a more specific
// prefix. numBits is how many additional bits to add, and index is which subnet
// to return (0 to 2^numBits-1).
func extendIPNet(base *net.IPNet, numBits int, index int) *net.IPNet {
	ip := make(net.IP, len(base.IP))
	copy(ip, base.IP)

	basePrefix, _ := base.Mask.Size()
	targetPrefix := basePrefix + numBits

	// Add index bits to the IP starting from the bit position after the base prefix
	for i := range numBits {
		if index&(1<<uint(numBits-1-i)) != 0 { //nolint:gosec // numBits is small, safe for shift
			bitPosition := basePrefix + i
			byteIdx := bitPosition / 8
			bitIdx := 7 - (bitPosition % 8)
			ip[byteIdx] |= (1 << uint(bitIdx)) //nolint:gosec // bitIdx is 0-7, safe for shift
		}
	}

	mask := net.CIDRMask(targetPrefix, len(ip)*8)
	return &net.IPNet{IP: ip, Mask: mask}
}

// reserve marks a subnet as reserved (caller must hold write lock).
func (a *subnetAllocator) reserve(subnet *net.IPNet) {
	a.reserved[subnet.String()] = copyIPNet(subnet)
}

// isReserved checks if a subnet is reserved (caller must hold write lock).
func (a *subnetAllocator) isReserved(subnet *net.IPNet) bool {
	_, ok := a.reserved[subnet.String()]
	return ok
}

// copyIPNet creates a deep copy of a net.IPNet.
func copyIPNet(n *net.IPNet) *net.IPNet {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	mask := make(net.IPMask, len(n.Mask))
	copy(mask, n.Mask)
	return &net.IPNet{IP: ip, Mask: mask}
}

// RandomAllocatorConfig holds configuration for NewRandomAllocator.
type RandomAllocatorConfig struct {
	// Filter is an optional callback to validate randomly generated subnets.
	// If Filter returns false, the subnet is rejected and another random
	// subnet will be tried. This is useful for avoiding subnets already
	// in use by the system.
	Filter func(*net.IPNet) bool
}

// randomSubnetAllocator implements SubnetAllocator by randomly generating
// /24 subnets within 10.0.0.0/8. It avoids values 0-24 for the second and
// third octets to reduce collision with common private network ranges.
type randomSubnetAllocator struct {
	mu       sync.RWMutex
	reserved map[string]*net.IPNet // reserved subnets keyed by CIDR string
	filter   func(*net.IPNet) bool // optional filter callback
}

// NewRandomAllocator creates a SubnetAllocator that randomly allocates /24
// subnets within 10.0.0.0/8, avoiding 0-24 values for second and third octets.
// The config parameter is optional; pass nil for default behavior.
func NewRandomAllocator(config *RandomAllocatorConfig) SubnetAllocator {
	var filter func(*net.IPNet) bool
	if config != nil {
		filter = config.Filter
	}

	return &randomSubnetAllocator{
		reserved: make(map[string]*net.IPNet),
		filter:   filter,
	}
}

func (a *randomSubnetAllocator) Prefixes() []int {
	return []int{24}
}

func (a *randomSubnetAllocator) Reserve(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Only reserve if it's a valid /24 IPv4 subnet within our range
	if !isValidRandomSubnet(subnet) {
		return
	}

	a.reserved[subnet.String()] = copyIPNet(subnet)
}

func (a *randomSubnetAllocator) Alloc(prefixLen int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Only support /24
	if prefixLen != 0 && prefixLen != 24 {
		return nil
	}

	// Try to generate a random valid subnet
	// Use a reasonable max attempts to avoid infinite loops
	const maxAttempts = 1000

	for range maxAttempts {
		candidate := generateRandomSubnet()
		if candidate == nil {
			continue
		}

		// Check if already reserved
		if _, ok := a.reserved[candidate.String()]; ok {
			continue
		}

		// Apply filter if provided
		if a.filter != nil && !a.filter(candidate) {
			continue
		}

		// Reserve and return
		a.reserved[candidate.String()] = candidate
		return copyIPNet(candidate)
	}

	return nil
}

func (a *randomSubnetAllocator) Free(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := subnet.String()
	delete(a.reserved, key)
}

func (a *randomSubnetAllocator) FreeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserved = make(map[string]*net.IPNet)
}

// isValidRandomSubnet checks if a subnet is a valid /24 IPv4 subnet
// within the 10.0.0.0/8 range with octets in valid ranges.
func isValidRandomSubnet(subnet *net.IPNet) bool {
	if subnet == nil {
		return false
	}

	// Must be IPv4
	ip4 := subnet.IP.To4()
	if ip4 == nil {
		return false
	}

	// Must be /24
	ones, _ := subnet.Mask.Size()
	if ones != 24 {
		return false
	}

	// Must be within 10.0.0.0/8
	if ip4[0] != 10 {
		return false
	}

	// Second and third octets must be > 24
	if ip4[1] <= 24 || ip4[2] <= 24 {
		return false
	}

	return true
}

// generateRandomSubnet creates a random /24 subnet within 10.0.0.0/8
// with second and third octets in range 25-254.
func generateRandomSubnet() *net.IPNet {
	// Generate random second octet (25-254)
	secondOctet, err := rand.Int(rand.Reader, big.NewInt(230))
	if err != nil {
		return nil
	}
	secondOctet = secondOctet.Add(secondOctet, big.NewInt(25))

	// Generate random third octet (25-254)
	thirdOctet, err := rand.Int(rand.Reader, big.NewInt(230))
	if err != nil {
		return nil
	}
	thirdOctet = thirdOctet.Add(thirdOctet, big.NewInt(25))

	ip := net.IP{10, byte(secondOctet.Uint64()), byte(thirdOctet.Uint64()), 0}
	mask := net.CIDRMask(24, 32)

	return &net.IPNet{IP: ip, Mask: mask}
}

// Ensure interfaces are implemented at compile time
var _ SubnetAllocator = (*subnetAllocator)(nil)
var _ SubnetAllocator = (*randomSubnetAllocator)(nil)
