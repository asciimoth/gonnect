package subnet

import (
	"errors"
	"math/big"
	"net"
	"sort"
	"strconv"
	"sync"
)

// SubnetFilter decides whether a subnet may be allocated.
// It returns true to allow the candidate and false to make the allocator skip
// it and try another subnet.
type SubnetFilter func(*net.IPNet) bool

// SubnetAllocator reserves, allocates, and frees subnets from one owned parent
// network. All methods are safe for concurrent use.
type SubnetAllocator interface {
	// ReserveSubnet marks a subnet as reserved. If subnet was reserved multiple
	// times same count of FreeSubnet calls should be needed to free it.
	//
	// Valid reserved subnets are tracked even when they are outside of the
	// allocator's parent network. Outside reservations can still block future
	// allocations if they overlap the parent, for example when reserving a
	// supernet that contains the parent.
	ReserveSubnet(subnet *net.IPNet)

	// AllocSubnet4 returns a free subnet with the provided prefix length and
	// marks it as reserved.
	// It returns nil if it is not possible to allocate subnet with this prefix.
	AllocSubnet4(prefix int) *net.IPNet

	// AllocSubnet6 returns a free subnet with the provided prefix length and
	// marks it as reserved.
	// It returns nil if it is not possible to allocate subnet with this prefix.
	AllocSubnet6(prefix int) *net.IPNet

	// FreeSubnet decrements reserve counter for provided subnet.
	// If the subnet was not reserved, FreeSubnet is a no-op.
	FreeSubnet(subnet *net.IPNet)

	// FreeAllSubnets removes all reserved marks, making all previously allocated
	// and reserved subnets available again.
	FreeAllSubnets()
}

// NewSubnetAllocator creates a SubnetAllocator that owns a copy of parent.
//
// The allocator only returns subnets inside parent. ReserveSubnet accepts any
// valid IPv4 or IPv6 CIDR and keeps it in the reservation table even when it is
// outside parent, because an outside subnet can still overlap parent by being a
// broader supernet. nil and malformed parents create an empty allocator whose
// allocation methods return nil.
//
// If filter is non-nil, allocation calls evaluate each otherwise available
// candidate with the filter before reserving it. Rejected candidates are skipped
// without being reserved. To avoid unbounded scans when the filter rejects every
// candidate, each allocation call tries at most 1000 filtered candidates before
// returning nil.
//
// Filters are called while the allocator lock is held. They should be fast and
// must not call methods on the same allocator.
func NewSubnetAllocator(
	parent *net.IPNet,
	filter SubnetFilter,
) SubnetAllocator {
	a := &subnetAllocator{
		reserved: make(map[string]*reservedSubnet),
		filter:   filter,
	}

	if parent == nil {
		return a
	}

	ip, mask, bits, ok := normalizeIPNet(parent)
	if !ok {
		return a
	}

	parent = &net.IPNet{IP: ip, Mask: mask}
	first, last := Range(parent)
	a.parent = parent
	a.bits = bits
	a.parentStart = ipToInt(normalizeIPForBits(first, bits))
	a.parentEnd = ipToInt(normalizeIPForBits(last, bits))

	return a
}

type subnetAllocator struct {
	mu          sync.Mutex
	parent      *net.IPNet
	bits        int
	parentStart *big.Int
	parentEnd   *big.Int
	reserved    map[string]*reservedSubnet
	filter      SubnetFilter
}

type reservedSubnet struct {
	network *net.IPNet
	bits    int
	prefix  int
	start   *big.Int
	end     *big.Int
	count   int
}

func (a *subnetAllocator) ReserveSubnet(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserve(subnet)
}

func (a *subnetAllocator) AllocSubnet4(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bits != 32 {
		return nil
	}
	return a.alloc(prefix)
}

func (a *subnetAllocator) AllocSubnet6(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bits != 128 {
		return nil
	}
	return a.alloc(prefix)
}

func (a *subnetAllocator) FreeSubnet(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	normalized := normalizeSubnet(subnet)
	if normalized == nil {
		return
	}

	key := subnetMapKey(normalized.network, normalized.bits, normalized.prefix)
	reserved := a.reserved[key]
	if reserved == nil {
		return
	}
	if reserved.count > 1 {
		reserved.count--
		return
	}
	delete(a.reserved, key)
}

func (a *subnetAllocator) FreeAllSubnets() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserved = make(map[string]*reservedSubnet)
}

// alloc returns the first parent-contained subnet at prefix that does not
// overlap any active reservation. The caller must hold a.mu.
func (a *subnetAllocator) alloc(prefix int) *net.IPNet {
	parentPrefix, ok := a.validPrefix(prefix)
	if !ok || prefix < parentPrefix {
		return nil
	}

	size := subnetSize(a.bits, prefix)
	candidateStart := new(big.Int).Set(a.parentStart)
	candidateEnd := subnetEnd(candidateStart, size)
	blockers := a.sortedBlockers()
	attempts := 0

	for {
		if candidateEnd.Cmp(a.parentEnd) > 0 {
			return nil
		}

		advanced := false
		for _, blocker := range blockers {
			if blocker.end.Cmp(candidateStart) < 0 {
				continue
			}
			if blocker.start.Cmp(candidateEnd) > 0 {
				break
			}

			nextStart := alignUp(
				new(big.Int).Add(blocker.end, big.NewInt(1)),
				size,
			)
			if nextStart.Cmp(candidateStart) <= 0 {
				nextStart = new(big.Int).Add(candidateStart, size)
			}
			candidateStart = nextStart
			candidateEnd = subnetEnd(candidateStart, size)
			advanced = true
			break
		}
		if advanced {
			continue
		}

		network := &net.IPNet{
			IP:   intToIP(candidateStart, a.bits),
			Mask: net.CIDRMask(prefix, a.bits),
		}
		if a.filter != nil {
			attempts++
			if !a.filter(CopyIPNet(network)) {
				if attempts >= maxFilteredAllocationAttempts {
					return nil
				}
				candidateStart = new(big.Int).Add(candidateStart, size)
				candidateEnd = subnetEnd(candidateStart, size)
				continue
			}
		}
		a.reserve(network)
		return CopyIPNet(network)
	}
}

// reserve records subnet as unavailable. It accepts every valid normalized
// IPv4 or IPv6 subnet, including subnets outside the allocator's parent.
// The caller must hold a.mu.
func (a *subnetAllocator) reserve(subnet *net.IPNet) {
	normalized := normalizeSubnet(subnet)
	if normalized == nil {
		return
	}

	key := subnetMapKey(normalized.network, normalized.bits, normalized.prefix)
	if existing := a.reserved[key]; existing != nil {
		existing.count++
		return
	}

	a.reserved[key] = normalized
}

func (a *subnetAllocator) validPrefix(prefix int) (int, bool) {
	if a.parent == nil || prefix < 0 || prefix > a.bits {
		return 0, false
	}
	parentPrefix, bits := a.parent.Mask.Size()
	return parentPrefix, bits == a.bits
}

func (a *subnetAllocator) sortedBlockers() []*reservedSubnet {
	blockers := make([]*reservedSubnet, 0, len(a.reserved))
	for _, reserved := range a.reserved {
		if reserved.bits != a.bits {
			continue
		}
		if reserved.end.Cmp(a.parentStart) < 0 ||
			reserved.start.Cmp(a.parentEnd) > 0 {
			continue
		}
		blockers = append(blockers, reserved)
	}

	sort.Slice(blockers, func(i, j int) bool {
		cmp := blockers[i].start.Cmp(blockers[j].start)
		if cmp != 0 {
			return cmp < 0
		}
		return blockers[i].end.Cmp(blockers[j].end) < 0
	})

	return blockers
}

func normalizeSubnet(subnet *net.IPNet) *reservedSubnet {
	if subnet == nil {
		return nil
	}

	ip, mask, bits, ok := normalizeIPNet(subnet)
	if !ok {
		return nil
	}

	prefix, _ := mask.Size()
	network := &net.IPNet{IP: ip, Mask: mask}
	first, last := Range(network)

	return &reservedSubnet{
		network: network,
		bits:    bits,
		prefix:  prefix,
		start:   ipToInt(normalizeIPForBits(first, bits)),
		end:     ipToInt(normalizeIPForBits(last, bits)),
		count:   1,
	}
}

func subnetMapKey(network *net.IPNet, bits, prefix int) string {
	return strconv.Itoa(
		bits,
	) + "/" + strconv.Itoa(
		prefix,
	) + "/" + ipMapKey(
		network.IP,
	)
}

func ipToInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip)
}

func intToIP(value *big.Int, bits int) net.IP {
	size := bits / 8
	bytes := value.Bytes()
	if len(bytes) > size {
		bytes = bytes[len(bytes)-size:]
	}
	ip := make(net.IP, size)
	copy(ip[size-len(bytes):], bytes)
	return ip
}

func subnetSize(bits, prefix int) *big.Int {
	shift := uint(bits - prefix) //nolint:gosec // prefix is validated.
	return new(
		big.Int,
	).Lsh(big.NewInt(1), shift)
}

func subnetEnd(start, size *big.Int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Add(start, size), big.NewInt(1))
}

func alignUp(value, size *big.Int) *big.Int {
	remainder := new(big.Int).Mod(value, size)
	if remainder.Sign() == 0 {
		return value
	}
	return new(big.Int).Add(value, new(big.Int).Sub(size, remainder))
}

// extendIPNet creates a subnet by extending the given network to a more specific
// prefix. numBits is how many additional bits to add, and index is which subnet
// to return (0 to 2^numBits-1).
func ExtendIPNet(base *net.IPNet, numBits int, index int) (*net.IPNet, error) {
	if base == nil {
		return nil, errors.New("base network cannot be nil")
	}

	ip, _, bits, ok := normalizeIPNet(base)
	if !ok {
		return nil, errors.New("invalid base network")
	}

	basePrefix, _ := base.Mask.Size()
	if numBits < 0 {
		return nil, errors.New("numBits cannot be negative")
	}
	targetPrefix := basePrefix + numBits
	if targetPrefix > bits {
		return nil, errors.New("numBits exceeds address size")
	}
	if index < 0 {
		return nil, errors.New("index cannot be negative")
	}

	indexValue := big.NewInt(int64(index))
	subnetCount := new(
		big.Int,
	).Lsh(big.NewInt(1), uint(numBits))
	//nolint:gosec // numBits is validated.
	if indexValue.Cmp(subnetCount) >= 0 {
		return nil, errors.New("index out of range")
	}

	// Add index bits to the IP starting from the bit position after the base prefix
	for i := range numBits {
		if indexValue.Bit(numBits-1-i) != 0 {
			bitPosition := basePrefix + i
			byteIdx := bitPosition / 8
			bitIdx := 7 - (bitPosition % 8)
			ip[byteIdx] |= (1 << uint(bitIdx)) //nolint:gosec // bitIdx is 0-7, safe for shift
		}
	}

	mask := net.CIDRMask(targetPrefix, bits)
	return &net.IPNet{IP: ip, Mask: mask}, nil
}

// copyIPNet creates a deep copy of a net.IPNet.
func CopyIPNet(n *net.IPNet) *net.IPNet {
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

var _ SubnetAllocator = (*subnetAllocator)(nil)
