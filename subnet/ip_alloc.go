package subnet

import (
	"bytes"
	"net"
	"sync"
)

const maxFilteredAllocationAttempts = 1000

// IPFilter decides whether an IP address may be allocated.
// It returns true to allow the candidate and false to make the allocator skip
// it and try another address.
type IPFilter func(net.IP) bool

// IPAllocator reserves, allocates, and frees IP addresses from owned subnets.
// All methods are safe for concurrent use.
type IPAllocator interface {
	// ReserveIP marks an IP address as reserved. If the same address is
	// reserved multiple times, the same number of FreeIP calls is required
	// before it can be allocated again.
	ReserveIP(ip net.IP)

	// AllocIP4 returns a free IPv4 address, a copy of the subnet it was
	// allocated from, and marks the address as reserved.
	// It returns nil IP and subnet values if this allocator does not own an IPv4
	// subnet or there are no free IPv4 addresses available.
	AllocIP4() (net.IP, *net.IPNet)

	// AllocIP6 returns a free IPv6 address, a copy of the subnet it was
	// allocated from, and marks the address as reserved.
	// It returns nil IP and subnet values if this allocator does not own an IPv6
	// subnet or there are no free IPv6 addresses available.
	AllocIP6() (net.IP, *net.IPNet)

	// FreeIP decrements reserve counter for provided IP.
	// If this IP was not reserved, FreeIP is a no-op.
	FreeIP(ip net.IP)

	// FreeAll removes all reserved marks, making all previously allocated IPs
	// available again.
	FreeAllIP()
}

// NewIPAllocator creates an IPAllocator that owns a copy of network.
//
// The allocator only returns addresses from the provided subnet and never
// returns the first or last address in the range. For IPv4 these are the
// network and broadcast addresses. The same rule is intentionally applied to
// IPv6 so callers can rely on consistent reservation behavior.
//
// nil and malformed networks create an empty allocator whose allocation
// methods return nil IP and subnet values.
//
// If filter is non-nil, allocation calls evaluate each otherwise available
// candidate with the filter before reserving it. Rejected candidates are skipped
// without being reserved. To avoid unbounded scans when the filter rejects every
// candidate, each allocation call tries at most 1000 filtered candidates before
// returning nil.
//
// Filters are called while the allocator lock is held. They should be fast and
// must not call methods on the same allocator.
func NewIPAllocator(network *net.IPNet, filter IPFilter) IPAllocator {
	a := &ipAllocator{
		reserved: make(map[string]int),
		filter:   filter,
	}

	if network == nil {
		return a
	}

	ip, mask, bits, ok := normalizeIPNet(network)
	if !ok {
		return a
	}

	first, last := Range(&net.IPNet{IP: ip, Mask: mask})
	a.network = &net.IPNet{IP: ip, Mask: mask}
	a.bits = bits
	a.first = normalizeIPForBits(first, bits)
	a.last = normalizeIPForBits(last, bits)
	a.next = Next(a.first)

	return a
}

type ipAllocator struct {
	mu       sync.Mutex
	network  *net.IPNet
	bits     int
	first    net.IP
	last     net.IP
	next     net.IP
	reserved map[string]int
	filter   IPFilter
}

func (a *ipAllocator) ReserveIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserve(ip)
}

func (a *ipAllocator) AllocIP4() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bits != 32 {
		return nil, nil
	}
	return a.alloc()
}

func (a *ipAllocator) AllocIP6() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.bits != 128 {
		return nil, nil
	}
	return a.alloc()
}

func (a *ipAllocator) FreeIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	normalized := a.normalizeUsableIP(ip)
	if normalized == nil {
		return
	}

	key := ipMapKey(normalized)
	count := a.reserved[key]
	switch {
	case count > 1:
		a.reserved[key] = count - 1
	case count == 1:
		delete(a.reserved, key)
	}
}

func (a *ipAllocator) FreeAllIP() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserved = make(map[string]int)
	if a.first != nil {
		a.next = Next(a.first)
	}
}

// alloc returns the first currently available usable address, the subnet it was
// allocated from, and reserves the address. The caller must hold a.mu.
func (a *ipAllocator) alloc() (net.IP, *net.IPNet) {
	if a.network == nil || !isBeforeIP(a.first, a.last) {
		return nil, nil
	}

	start := a.next
	if start == nil || !a.isUsable(start) {
		start = Next(a.first)
	}

	attempts := 0
	for candidate := copyIP(start); a.isUsable(candidate); candidate = Next(candidate) {
		if ip := a.tryAlloc(candidate, &attempts); ip != nil {
			return ip, CopyIPNet(a.network)
		}
		if attempts >= maxFilteredAllocationAttempts {
			return nil, nil
		}
	}

	for candidate := Next(a.first); isBeforeIP(candidate, start); candidate = Next(candidate) {
		if !a.isUsable(candidate) {
			break
		}
		if ip := a.tryAlloc(candidate, &attempts); ip != nil {
			return ip, CopyIPNet(a.network)
		}
		if attempts >= maxFilteredAllocationAttempts {
			return nil, nil
		}
	}

	return nil, nil
}

func (a *ipAllocator) tryAlloc(candidate net.IP, attempts *int) net.IP {
	key := ipMapKey(candidate)
	if a.reserved[key] != 0 {
		return nil
	}
	if a.filter != nil {
		(*attempts)++
		if !a.filter(copyIP(candidate)) {
			return nil
		}
	}
	a.reserved[key] = 1
	a.next = Next(candidate)
	return copyIP(candidate)
}

// reserve records ip as unavailable if it belongs to this allocator's subnet.
// Multiple reservations are reference-counted and require the same number of
// FreeIP calls before the address can be allocated again. The caller must hold
// a.mu.
func (a *ipAllocator) reserve(ip net.IP) {
	normalized := a.normalizeUsableIP(ip)
	if normalized == nil {
		return
	}
	a.reserved[ipMapKey(normalized)]++
}

func (a *ipAllocator) normalizeUsableIP(ip net.IP) net.IP {
	normalized := normalizeIPForBits(ip, a.bits)
	if normalized == nil || !a.isUsable(normalized) {
		return nil
	}
	return normalized
}

func (a *ipAllocator) isUsable(ip net.IP) bool {
	return a.network != nil &&
		a.network.Contains(ip) &&
		isBeforeIP(a.first, ip) &&
		isBeforeIP(ip, a.last)
}

func normalizeIPNet(network *net.IPNet) (net.IP, net.IPMask, int, bool) {
	_, bits := network.Mask.Size()
	if bits != 32 && bits != 128 {
		return nil, nil, 0, false
	}

	ip := normalizeIPForBits(network.IP, bits)
	if ip == nil {
		return nil, nil, 0, false
	}

	mask := make(net.IPMask, len(network.Mask))
	copy(mask, network.Mask)

	return ip.Mask(mask), mask, bits, true
}

func normalizeIPForBits(ip net.IP, bits int) net.IP {
	switch bits {
	case 32:
		return copyIP(ip.To4())
	case 128:
		return copyIP(ip.To16())
	default:
		return nil
	}
}

func ipMapKey(ip net.IP) string {
	return string(ip)
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	copied := make(net.IP, len(ip))
	copy(copied, ip)
	return copied
}

func isBeforeIP(left, right net.IP) bool {
	return bytes.Compare(left, right) < 0
}

var _ IPAllocator = (*ipAllocator)(nil)
