package subnet

import (
	"math/big"
	"net"
	"sync"
)

// All methods of IPAllocator should be thread-safe.
type IPAllocator interface {
	// Reserve marks an IP as reserved.
	Reserve(ip net.IP)

	// Alloc returns a free IPv4 addr and marks it as reserved.
	// It returns nil if there is no free IPv4 addrs available in this allocator.
	Alloc4() net.IP

	// Alloc returns a free IPv6 addr and marks it as reserved.
	// It returns nil if there is no free IPv6 addrs available in this allocator.
	Alloc6() net.IP

	// Free removes the reserved mark from an IP. If the IP was not reserved,
	// this is a no-op.
	Free(ip net.IP)

	// FreeAll removes all reserved marks, making all previously allocated IPs
	// available again.
	FreeAll()
}

// ipAllocator implements IPAllocator using optional IPv4 and IPv6 subnets.
type ipAllocator struct {
	mu      sync.RWMutex
	subnet4 *net.IPNet // optional IPv4 subnet
	subnet6 *net.IPNet // optional IPv6 subnet
	used4   map[string]struct{}
	used6   map[string]struct{}
	next4   *big.Int // next IPv4 address to try
	next6   *big.Int // next IPv6 address to try
}

// NewIPAllocator creates a new IPAllocator with optional IPv4 and IPv6 subnets.
// Either or both subnets can be nil.
func NewIPAllocator(subnet4, subnet6 *net.IPNet) IPAllocator {
	a := &ipAllocator{
		used4: make(map[string]struct{}),
		used6: make(map[string]struct{}),
	}

	if subnet4 != nil {
		a.subnet4 = copyIPNet(subnet4)
		a.next4 = big.NewInt(0).SetBytes(subnet4.IP.To4())
	}

	if subnet6 != nil {
		a.subnet6 = copyIPNet(subnet6)
		a.next6 = big.NewInt(0).SetBytes(subnet6.IP)
	}

	return a
}

func (a *ipAllocator) Reserve(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		a.used4[ip4.String()] = struct{}{}
	} else {
		a.used6[ip.String()] = struct{}{}
	}
}

func (a *ipAllocator) Alloc4() net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.subnet4 == nil {
		return nil
	}

	ones, bits := a.subnet4.Mask.Size()
	hostBits := bits - ones
	totalHosts := new(
		big.Int,
	).Exp(big.NewInt(2), big.NewInt(int64(hostBits)), nil)

	baseIP := big.NewInt(0).SetBytes(a.subnet4.IP.To4())
	lastIP := big.NewInt(0).
		Add(baseIP, new(big.Int).Sub(totalHosts, big.NewInt(1)))

	for i := big.NewInt(0); i.Cmp(totalHosts) < 0; i.Add(i, big.NewInt(1)) {
		candidate := big.NewInt(0).Add(baseIP, i)
		candidate.Mod(candidate, totalHosts)
		candidate.Add(candidate, baseIP)

		ipBytes := candidate.Bytes()
		ip := make(net.IP, 4)
		// Pad to 4 bytes
		copy(ip[4-len(ipBytes):], ipBytes)

		if ip.Equal(a.subnet4.IP) {
			continue // skip network address (first IP)
		}

		// Calculate last IP bytes
		lastIPBytes := lastIP.Bytes()
		lastIPNet := make(net.IP, 4)
		copy(lastIPNet[4-len(lastIPBytes):], lastIPBytes)

		if ip.Equal(lastIPNet) {
			continue // skip broadcast address (last IP)
		}

		if _, used := a.used4[ip.String()]; !used {
			a.used4[ip.String()] = struct{}{}
			a.next4 = big.NewInt(0).Add(candidate, big.NewInt(1))
			return ip
		}
	}

	return nil
}

func (a *ipAllocator) Alloc6() net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.subnet6 == nil {
		return nil
	}

	ones, bits := a.subnet6.Mask.Size()
	hostBits := bits - ones
	totalHosts := new(
		big.Int,
	).Exp(big.NewInt(2), big.NewInt(int64(hostBits)), nil)

	baseIP := big.NewInt(0).SetBytes(a.subnet6.IP)
	lastIP := big.NewInt(0).
		Add(baseIP, new(big.Int).Sub(totalHosts, big.NewInt(1)))

	for i := big.NewInt(0); i.Cmp(totalHosts) < 0; i.Add(i, big.NewInt(1)) {
		candidate := big.NewInt(0).Add(baseIP, i)
		candidate.Mod(candidate, totalHosts)
		candidate.Add(candidate, baseIP)

		ipBytes := candidate.Bytes()
		ip := make(net.IP, 16)
		// Pad to 16 bytes
		copy(ip[16-len(ipBytes):], ipBytes)

		if ip.Equal(a.subnet6.IP) {
			continue // skip subnet identifier (first IP)
		}

		// Calculate last IP bytes
		lastIPBytes := lastIP.Bytes()
		lastIPNet := make(net.IP, 16)
		copy(lastIPNet[16-len(lastIPBytes):], lastIPBytes)

		if ip.Equal(lastIPNet) {
			continue // skip last IP
		}

		if _, used := a.used6[ip.String()]; !used {
			a.used6[ip.String()] = struct{}{}
			a.next6 = big.NewInt(0).Add(candidate, big.NewInt(1))
			return ip
		}
	}

	return nil
}

func (a *ipAllocator) Free(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		delete(a.used4, ip4.String())
	} else {
		delete(a.used6, ip.String())
	}
}

func (a *ipAllocator) FreeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.used4 = make(map[string]struct{})
	a.used6 = make(map[string]struct{})

	if a.subnet4 != nil {
		a.next4 = big.NewInt(0).SetBytes(a.subnet4.IP.To4())
	}
	if a.subnet6 != nil {
		a.next6 = big.NewInt(0).SetBytes(a.subnet6.IP)
	}
}

// Ensure interface is implemented at compile time
var _ IPAllocator = (*ipAllocator)(nil)
var _ IPAllocator = (*randomIPAllocator)(nil)

// RandomIPAllocatorConfig holds configuration for NewRandomIPAllocator.
type RandomIPAllocatorConfig struct {
	// IPv4Config is optional configuration for the IPv4 SubnetAllocator.
	// If nil, a default random allocator is used.
	IPv4Config *RandomAllocatorConfig
	// IPv6Config is optional configuration for the IPv6 SubnetAllocator.
	// If nil, a default random allocator is used.
	IPv6Config *RandomAllocatorConfig
}

// randomIPAllocator implements IPAllocator using two SubnetAllocators
// (one for IPv4, one for IPv6) that allocate new subnets on demand when
// existing ones are full.
type randomIPAllocator struct {
	mu sync.Mutex

	subAlloc4 SubnetAllocator
	subAlloc6 SubnetAllocator

	// Allocated subnets and their per-subnet IP allocators
	subnets4 []subnetPool
	subnets6 []subnetPool

	// Global reservation tracking across all subnets
	used4 map[string]struct{}
	used6 map[string]struct{}
}

// subnetPool holds a subnet and its associated IP allocator.
type subnetPool struct {
	subnet *net.IPNet
	alloc  IPAllocator
}

// NewRandomIPAllocator creates a new IPAllocator that uses two SubnetAllocators
// to dynamically allocate subnets on demand. When existing subnets are full,
// new subnets are allocated from the underlying SubnetAllocators.
// Config is optional; pass nil for default behavior.
func NewRandomIPAllocator(config *RandomIPAllocatorConfig) IPAllocator {
	a := &randomIPAllocator{
		subnets4: make([]subnetPool, 0),
		subnets6: make([]subnetPool, 0),
		used4:    make(map[string]struct{}),
		used6:    make(map[string]struct{}),
	}

	if config != nil {
		a.subAlloc4 = NewRandomAllocator(config.IPv4Config)
		a.subAlloc6 = NewRandomAllocator(config.IPv6Config)
	} else {
		a.subAlloc4 = NewRandomAllocator(nil)
		a.subAlloc6 = NewRandomAllocator(nil)
	}

	return a
}

func (a *randomIPAllocator) Reserve(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		a.used4[ip4.String()] = struct{}{}
	} else {
		a.used6[ip.String()] = struct{}{}
	}
}

func (a *randomIPAllocator) Alloc4() net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Try to allocate from existing subnets first
	for i := range a.subnets4 {
		ip := a.subnets4[i].alloc.Alloc4()
		if ip != nil {
			// Mark as used globally
			a.used4[ip.String()] = struct{}{}
			return ip
		}
	}

	// No space in existing subnets, allocate a new subnet
	newSubnet := a.subAlloc4.Alloc(0)
	if newSubnet == nil {
		return nil
	}

	// Create IP allocator for this subnet
	pool := subnetPool{
		subnet: newSubnet,
		alloc:  NewIPAllocator(newSubnet, nil),
	}
	a.subnets4 = append(a.subnets4, pool)

	// Try to allocate from the new subnet
	ip := pool.alloc.Alloc4()
	if ip != nil {
		a.used4[ip.String()] = struct{}{}
	}
	return ip
}

func (a *randomIPAllocator) Alloc6() net.IP {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Try to allocate from existing subnets first
	for i := range a.subnets6 {
		ip := a.subnets6[i].alloc.Alloc6()
		if ip != nil {
			// Mark as used globally
			a.used6[ip.String()] = struct{}{}
			return ip
		}
	}

	// No space in existing subnets, allocate a new subnet
	newSubnet := a.subAlloc6.Alloc(0)
	if newSubnet == nil {
		return nil
	}

	// Create IP allocator for this subnet
	pool := subnetPool{
		subnet: newSubnet,
		alloc:  NewIPAllocator(nil, newSubnet),
	}
	a.subnets6 = append(a.subnets6, pool)

	// Try to allocate from the new subnet
	ip := pool.alloc.Alloc6()
	if ip != nil {
		a.used6[ip.String()] = struct{}{}
	}
	return ip
}

func (a *randomIPAllocator) Free(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip4 := ip.To4(); ip4 != nil {
		delete(a.used4, ip4.String())
		// Also free from the subnet-level allocator
		for i := range a.subnets4 {
			a.subnets4[i].alloc.Free(ip)
		}
	} else {
		delete(a.used6, ip.String())
		// Also free from the subnet-level allocator
		for i := range a.subnets6 {
			a.subnets6[i].alloc.Free(ip)
		}
	}
}

func (a *randomIPAllocator) FreeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.used4 = make(map[string]struct{})
	a.used6 = make(map[string]struct{})

	// Free all subnet-level allocators
	for i := range a.subnets4 {
		a.subnets4[i].alloc.FreeAll()
	}
	for i := range a.subnets6 {
		a.subnets6[i].alloc.FreeAll()
	}

	// Clear allocated subnets
	a.subnets4 = make([]subnetPool, 0)
	a.subnets6 = make([]subnetPool, 0)
}
