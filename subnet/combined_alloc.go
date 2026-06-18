package subnet

import (
	"math/big"
	"math/rand"
	"net"
	"sort"
	"sync"
)

const defaultCombinedAllocatorSeed int64 = 1

// CombinedAllocator allocates both subnets and IP addresses from optional IPv4
// and IPv6 parent networks.
//
// Subnet allocation is close to NewSubnetAllocator: allocated and reserved
// subnets are reference-counted, allocations start at a pseudo-random subnet
// inside the parent and then scan forward with wraparound, and the optional
// subnet filter can reject otherwise-free candidates. In addition, combined
// subnet allocation also treats every reserved, allocated, or banned IP address
// as a one-address blocker, so a subnet containing one of those addresses is
// never returned.
//
// IP allocation is backed by a pool of subnets that were allocated through the
// same subnet allocator state. An IP allocation first tries existing pool
// subnets with free usable addresses. If none can satisfy the request, it
// allocates one more pool subnet using poolPrefix4 or poolPrefix6 and then
// allocates an address from that subnet. The first and last address of every
// pool subnet are skipped, matching NewIPAllocator behavior for both IPv4 and
// IPv6.
//
// ReserveIP accepts any valid IPv4 or IPv6 address, including addresses outside
// the configured parents and outside the current pool. Those reservations still
// block subnet allocations if they fall inside a candidate subnet. ReserveSubnet
// likewise accepts any valid subnet, including outside supernets that overlap a
// parent.
//
// Banned addresses and subnets are permanent blockers installed by the
// constructor. FreeIP, FreeSubnet, FreeAllIP, and FreeAllSubnets do not remove
// bans. IP allocation examines at most 1000 candidate addresses per call.
// Subnet allocation examines at most 1000 candidates that reach the filter,
// matching the simpler subnet allocator's blocker-skipping behavior.
type CombinedAllocator struct {
	mu sync.Mutex

	parents map[int]*combinedParent

	reservedIPs     map[string]*reservedIP
	reservedSubnets map[string]*reservedSubnet

	bannedIPs     map[string]*reservedIP
	bannedSubnets map[string]*reservedSubnet

	poolSubnets map[int][]*combinedPoolSubnet
	poolPrefix4 int
	poolPrefix6 int

	rng          *rand.Rand
	ipFilter     IPFilter
	subnetFilter SubnetFilter
}

type combinedParent struct {
	network *net.IPNet
	bits    int
	start   *big.Int
	end     *big.Int
}

type reservedIP struct {
	ip    net.IP
	bits  int
	value *big.Int
	count int
}

type combinedPoolSubnet struct {
	network *net.IPNet
	bits    int
	prefix  int
	first   net.IP
	last    net.IP
	next    net.IP
}

// NewCombinedAllocator creates an allocator with shared IP and subnet
// reservation state.
//
// ipv4 and ipv6 are optional parent networks. Each valid parent enables
// allocations for that address family; nil or malformed parents simply disable
// that family. poolPrefix4 and poolPrefix6 are the subnet prefix lengths used
// when IP allocation needs to grow its backing subnet pool.
//
// ipFilter and subnetFilter behave like the filters accepted by NewIPAllocator
// and NewSubnetAllocator. bannedIPs and bannedSubnets may be nil. Bans are
// copied, normalized, and treated as permanent reservations.
//
// rng selects the first candidate subnet examined by each subnet allocation,
// including the internal subnet allocations used to grow the IP allocation
// pools. If rng is nil, a deterministic generator with a constant seed is used
// so tests and callers that do not need custom randomness remain reproducible.
// The allocator serializes its own use of rng, but callers must not use the
// same *rand.Rand concurrently elsewhere without their own synchronization.
//
// Filters are called while the allocator lock is held. They should be fast and
// must not call methods on the same allocator.
func NewCombinedAllocator(
	ipv4 *net.IPNet,
	ipv6 *net.IPNet,
	poolPrefix4 int,
	poolPrefix6 int,
	ipFilter IPFilter,
	subnetFilter SubnetFilter,
	bannedIPs []net.IP,
	bannedSubnets []*net.IPNet,
	rng *rand.Rand,
) *CombinedAllocator {
	if rng == nil {
		rng = rand.New(rand.NewSource(defaultCombinedAllocatorSeed)) // nolint
	}

	a := &CombinedAllocator{
		parents:         make(map[int]*combinedParent),
		reservedIPs:     make(map[string]*reservedIP),
		reservedSubnets: make(map[string]*reservedSubnet),
		bannedIPs:       make(map[string]*reservedIP),
		bannedSubnets:   make(map[string]*reservedSubnet),
		poolSubnets:     make(map[int][]*combinedPoolSubnet),
		poolPrefix4:     poolPrefix4,
		poolPrefix6:     poolPrefix6,
		rng:             rng,
		ipFilter:        ipFilter,
		subnetFilter:    subnetFilter,
	}

	a.addParent(ipv4, 32)
	a.addParent(ipv6, 128)

	for _, ip := range bannedIPs {
		if reserved := normalizeAnyIP(ip); reserved != nil {
			a.bannedIPs[ipReservationKey(reserved)] = reserved
		}
	}
	for _, subnet := range bannedSubnets {
		if reserved := normalizeSubnet(subnet); reserved != nil {
			key := subnetMapKey(
				reserved.network,
				reserved.bits,
				reserved.prefix,
			)
			a.bannedSubnets[key] = reserved
		}
	}

	return a
}

func (a *CombinedAllocator) addParent(network *net.IPNet, wantBits int) {
	if network == nil {
		return
	}
	ip, mask, bits, ok := normalizeIPNet(network)
	if !ok || bits != wantBits {
		return
	}
	normalized := &net.IPNet{IP: ip, Mask: mask}
	first, last := Range(normalized)
	a.parents[bits] = &combinedParent{
		network: normalized,
		bits:    bits,
		start:   ipToInt(normalizeIPForBits(first, bits)),
		end:     ipToInt(normalizeIPForBits(last, bits)),
	}
}

func (a *CombinedAllocator) ReserveSubnet(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserveSubnetLocked(subnet)
}

func (a *CombinedAllocator) AllocSubnet4(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.allocSubnetLocked(32, prefix)
}

func (a *CombinedAllocator) AllocSubnet6(prefix int) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.allocSubnetLocked(128, prefix)
}

func (a *CombinedAllocator) FreeSubnet(subnet *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	normalized := normalizeSubnet(subnet)
	if normalized == nil {
		return
	}
	if a.freeReservedSubnetLocked(normalized) {
		a.removePoolSubnetLocked(normalized)
	}
}

func (a *CombinedAllocator) FreeAllSubnets() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reservedSubnets = make(map[string]*reservedSubnet)
	a.poolSubnets = make(map[int][]*combinedPoolSubnet)
}

func (a *CombinedAllocator) ReserveIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reserveIPLocked(ip)
}

func (a *CombinedAllocator) AllocIP4() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.allocIPLocked(32)
}

func (a *CombinedAllocator) AllocIP6() (net.IP, *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.allocIPLocked(128)
}

func (a *CombinedAllocator) FreeIP(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()

	normalized := normalizeAnyIP(ip)
	if normalized == nil {
		return
	}

	key := ipReservationKey(normalized)
	if reserved := a.reservedIPs[key]; reserved != nil {
		if reserved.count > 1 {
			reserved.count--
		} else {
			delete(a.reservedIPs, key)
		}
	}
	a.pruneEmptyPoolSubnetsLocked(normalized.bits)
}

func (a *CombinedAllocator) FreeAllIP() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.reservedIPs = make(map[string]*reservedIP)
	a.pruneEmptyPoolSubnetsLocked(32)
	a.pruneEmptyPoolSubnetsLocked(128)
}

func (a *CombinedAllocator) allocSubnetLocked(bits, prefix int) *net.IPNet {
	parent := a.parents[bits]
	if parent == nil || prefix < 0 || prefix > bits {
		return nil
	}
	parentPrefix, parentBits := parent.network.Mask.Size()
	if parentBits != bits || prefix < parentPrefix {
		return nil
	}

	size := subnetSize(bits, prefix)
	subnetCount := new(big.Int).Div(
		new(big.Int).Add(
			new(big.Int).Sub(parent.end, parent.start),
			big.NewInt(1),
		),
		size,
	)
	if subnetCount.Sign() <= 0 {
		return nil
	}
	firstCandidateStart := new(big.Int).Add(
		parent.start,
		new(big.Int).Mul(randomBigInt(a.rng, subnetCount), size),
	)
	candidateStart := new(big.Int).Set(firstCandidateStart)
	candidateEnd := subnetEnd(candidateStart, size)
	blockers := a.sortedSubnetBlockersLocked(bits, parent)
	attempts := 0
	wrapped := false

	for {
		if candidateEnd.Cmp(parent.end) > 0 {
			if wrapped {
				return nil
			}
			candidateStart = new(big.Int).Set(parent.start)
			candidateEnd = subnetEnd(candidateStart, size)
			wrapped = true
			continue
		}
		if wrapped && candidateStart.Cmp(firstCandidateStart) >= 0 {
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
			IP:   intToIP(candidateStart, bits),
			Mask: net.CIDRMask(prefix, bits),
		}
		if a.subnetFilter != nil {
			attempts++
			if !a.subnetFilter(CopyIPNet(network)) {
				if attempts >= maxFilteredAllocationAttempts {
					return nil
				}
				candidateStart = new(big.Int).Add(candidateStart, size)
				candidateEnd = subnetEnd(candidateStart, size)
				continue
			}
		}

		a.reserveSubnetLocked(network)
		return CopyIPNet(network)
	}
}

func (a *CombinedAllocator) sortedSubnetBlockersLocked(
	bits int,
	parent *combinedParent,
) []*reservedSubnet {
	blockers := make(
		[]*reservedSubnet,
		0,
		len(
			a.reservedSubnets,
		)+len(
			a.bannedSubnets,
		)+len(
			a.reservedIPs,
		)+len(
			a.bannedIPs,
		),
	)
	appendSubnet := func(reserved *reservedSubnet) {
		if reserved.bits != bits {
			return
		}
		if reserved.end.Cmp(parent.start) < 0 ||
			reserved.start.Cmp(parent.end) > 0 {
			return
		}
		blockers = append(blockers, reserved)
	}
	appendIP := func(reserved *reservedIP) {
		if reserved.bits != bits {
			return
		}
		if reserved.value.Cmp(parent.start) < 0 ||
			reserved.value.Cmp(parent.end) > 0 {
			return
		}
		blockers = append(blockers, &reservedSubnet{
			bits:  bits,
			start: reserved.value,
			end:   reserved.value,
		})
	}

	for _, reserved := range a.reservedSubnets {
		appendSubnet(reserved)
	}
	for _, banned := range a.bannedSubnets {
		appendSubnet(banned)
	}
	for _, reserved := range a.reservedIPs {
		appendIP(reserved)
	}
	for _, banned := range a.bannedIPs {
		appendIP(banned)
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

func (a *CombinedAllocator) reserveSubnetLocked(subnet *net.IPNet) {
	normalized := normalizeSubnet(subnet)
	if normalized == nil {
		return
	}

	key := subnetMapKey(normalized.network, normalized.bits, normalized.prefix)
	if existing := a.reservedSubnets[key]; existing != nil {
		existing.count++
		return
	}

	a.reservedSubnets[key] = normalized
}

func (a *CombinedAllocator) freeReservedSubnetLocked(
	normalized *reservedSubnet,
) bool {
	key := subnetMapKey(normalized.network, normalized.bits, normalized.prefix)
	reserved := a.reservedSubnets[key]
	if reserved == nil {
		return false
	}
	if reserved.count > 1 {
		reserved.count--
		return false
	}
	delete(a.reservedSubnets, key)
	return true
}

func (a *CombinedAllocator) allocIPLocked(bits int) (net.IP, *net.IPNet) {
	if a.parents[bits] == nil {
		return nil, nil
	}

	attempts := 0
	if ip, subnet := a.allocIPFromPoolLocked(
		bits,
		&attempts,
	); ip != nil ||
		attempts >= maxFilteredAllocationAttempts {
		return ip, subnet
	}

	prefix := a.poolPrefix4
	if bits == 128 {
		prefix = a.poolPrefix6
	}
	network := a.allocSubnetLocked(bits, prefix)
	if network == nil {
		return nil, nil
	}

	pool := newCombinedPoolSubnet(network)
	if pool == nil {
		a.freeReservedSubnetLocked(normalizeSubnet(network))
		return nil, nil
	}
	a.poolSubnets[bits] = append(a.poolSubnets[bits], pool)

	if ip := a.tryAllocFromPoolSubnetLocked(pool, &attempts); ip != nil {
		return ip, CopyIPNet(pool.network)
	}
	return nil, nil
}

func (a *CombinedAllocator) allocIPFromPoolLocked(
	bits int,
	attempts *int,
) (net.IP, *net.IPNet) {
	for _, pool := range a.poolSubnets[bits] {
		if ip := a.tryAllocFromPoolSubnetLocked(pool, attempts); ip != nil {
			return ip, CopyIPNet(pool.network)
		}
		if *attempts >= maxFilteredAllocationAttempts {
			return nil, nil
		}
	}
	return nil, nil
}

func (a *CombinedAllocator) tryAllocFromPoolSubnetLocked(
	pool *combinedPoolSubnet,
	attempts *int,
) net.IP {
	if pool == nil || !isBeforeIP(pool.first, pool.last) {
		return nil
	}

	start := pool.next
	if start == nil || !pool.isUsable(start) {
		start = Next(pool.first)
	}

	for candidate := copyIP(start); pool.isUsable(candidate); candidate = Next(candidate) {
		if ip := a.tryAllocIPLocked(candidate, attempts); ip != nil {
			pool.next = Next(candidate)
			return ip
		}
		if *attempts >= maxFilteredAllocationAttempts {
			return nil
		}
	}

	for candidate := Next(pool.first); isBeforeIP(candidate, start); candidate = Next(candidate) {
		if !pool.isUsable(candidate) {
			break
		}
		if ip := a.tryAllocIPLocked(candidate, attempts); ip != nil {
			pool.next = Next(candidate)
			return ip
		}
		if *attempts >= maxFilteredAllocationAttempts {
			return nil
		}
	}

	return nil
}

func (a *CombinedAllocator) tryAllocIPLocked(
	candidate net.IP,
	attempts *int,
) net.IP {
	normalized := normalizeAnyIP(candidate)
	if normalized == nil {
		return nil
	}
	if *attempts >= maxFilteredAllocationAttempts {
		return nil
	}
	(*attempts)++

	key := ipReservationKey(normalized)
	if a.reservedIPs[key] != nil || a.bannedIPs[key] != nil {
		return nil
	}
	if a.ipFilter != nil {
		if !a.ipFilter(copyIP(normalized.ip)) {
			return nil
		}
	}

	normalized.count = 1
	a.reservedIPs[key] = normalized
	return copyIP(normalized.ip)
}

func (a *CombinedAllocator) reserveIPLocked(ip net.IP) {
	normalized := normalizeAnyIP(ip)
	if normalized == nil {
		return
	}

	key := ipReservationKey(normalized)
	if existing := a.reservedIPs[key]; existing != nil {
		existing.count++
		return
	}
	a.reservedIPs[key] = normalized
}

func (a *CombinedAllocator) pruneEmptyPoolSubnetsLocked(bits int) {
	pools := a.poolSubnets[bits]
	empty := make([]int, 0, len(pools))
	for i, pool := range pools {
		if !a.poolSubnetHasReservedIPLocked(pool) {
			empty = append(empty, i)
		}
	}
	if len(empty) <= 1 {
		return
	}

	for i := len(empty) - 1; i >= 1; i-- {
		index := empty[i]
		normalized := normalizeSubnet(pools[index].network)
		if normalized != nil {
			a.freeReservedSubnetLocked(normalized)
		}
		pools = append(pools[:index], pools[index+1:]...)
	}
	a.poolSubnets[bits] = pools
}

func (a *CombinedAllocator) poolSubnetHasReservedIPLocked(
	pool *combinedPoolSubnet,
) bool {
	for _, reserved := range a.reservedIPs {
		if reserved.bits == pool.bits && pool.network.Contains(reserved.ip) {
			return true
		}
	}
	return false
}

func (a *CombinedAllocator) removePoolSubnetLocked(normalized *reservedSubnet) {
	pools := a.poolSubnets[normalized.bits]
	for i, pool := range pools {
		if pool.prefix == normalized.prefix &&
			pool.network.IP.Equal(normalized.network.IP) {
			a.poolSubnets[normalized.bits] = append(pools[:i], pools[i+1:]...)
			return
		}
	}
}

func newCombinedPoolSubnet(network *net.IPNet) *combinedPoolSubnet {
	ip, mask, bits, ok := normalizeIPNet(network)
	if !ok {
		return nil
	}

	normalized := &net.IPNet{IP: ip, Mask: mask}
	prefix, _ := mask.Size()
	first, last := Range(normalized)
	first = normalizeIPForBits(first, bits)
	last = normalizeIPForBits(last, bits)

	return &combinedPoolSubnet{
		network: normalized,
		bits:    bits,
		prefix:  prefix,
		first:   first,
		last:    last,
		next:    Next(first),
	}
}

func randomBigInt(rng *rand.Rand, limit *big.Int) *big.Int {
	if limit.Sign() <= 0 {
		return big.NewInt(0)
	}
	if limit.IsInt64() {
		return big.NewInt(rng.Int63n(limit.Int64()))
	}

	bytes := make([]byte, len(limit.Bytes()))
	for {
		for i := range bytes {
			bytes[i] = byte(rng.Intn(256))
		}
		candidate := new(big.Int).SetBytes(bytes)
		if candidate.Cmp(limit) < 0 {
			return candidate
		}
	}
}

func (p *combinedPoolSubnet) isUsable(ip net.IP) bool {
	return p.network.Contains(ip) && isBeforeIP(p.first, ip) &&
		isBeforeIP(ip, p.last)
}

func normalizeAnyIP(ip net.IP) *reservedIP {
	if normalized := normalizeIPForBits(ip, 32); normalized != nil {
		return &reservedIP{
			ip:    normalized,
			bits:  32,
			value: ipToInt(normalized),
			count: 1,
		}
	}
	if normalized := normalizeIPForBits(ip, 128); normalized != nil {
		return &reservedIP{
			ip:    normalized,
			bits:  128,
			value: ipToInt(normalized),
			count: 1,
		}
	}
	return nil
}

func ipReservationKey(reserved *reservedIP) string {
	return subnetMapKey(
		&net.IPNet{
			IP:   reserved.ip,
			Mask: net.CIDRMask(reserved.bits, reserved.bits),
		},
		reserved.bits,
		reserved.bits,
	)
}

var _ IPAllocator = (*CombinedAllocator)(nil)
var _ SubnetAllocator = (*CombinedAllocator)(nil)
