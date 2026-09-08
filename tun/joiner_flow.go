package tun

import (
	"encoding/binary"
	"time"
)

const (
	// DefaultJoinerFlowTimeout is the inactivity timeout used by shared-address
	// routing when JoinerOptions.FlowTimeout is zero or negative.
	DefaultJoinerFlowTimeout = 2 * time.Minute

	// DefaultJoinerMaxFlowEntries is the maximum combined number of flow and
	// fragment routes used when JoinerOptions.MaxFlowEntries is not positive.
	DefaultJoinerMaxFlowEntries = 64 * 1024
)

const (
	joinerProtocolICMPv4 = 1
	joinerProtocolTCP    = 6
	joinerProtocolUDP    = 17
	joinerProtocolICMPv6 = 58
)

// JoinerOptions controls optional Joiner routing behavior.
type JoinerOptions struct {
	// SharedAddressRouting enables transport-flow routing before the existing
	// address route. It lets independent nested Tuns use the same local IP
	// address when their TCP, UDP, or ICMP echo tuples differ.
	//
	// An identical tuple collision keeps the first owner until that route is
	// detached, expires, or is evicted. Joiner records the collision in
	// JoinerRoutingStats. This mode does not translate ports, so it cannot give
	// complete isolation to identical flows from independent network stacks.
	SharedAddressRouting bool

	// FlowTimeout sets the inactivity timeout for flow and fragment routes.
	// A zero or negative value selects DefaultJoinerFlowTimeout.
	FlowTimeout time.Duration

	// MaxFlowEntries sets one hard limit for the combined flow and fragment
	// route table. Least-recently-used entries are evicted at the limit. A zero
	// or negative value selects DefaultJoinerMaxFlowEntries.
	MaxFlowEntries int
}

// JoinerRoutingStats is a snapshot of shared-address routing diagnostics.
// Counters increase for the lifetime of a Joiner. Active values report the
// current table sizes after expired routes are removed.
type JoinerRoutingStats struct {
	// ActiveFlows and ActiveFragments are current route table sizes.
	ActiveFlows     int
	ActiveFragments int

	// FlowRoutes and FragmentRoutes count writes that used dynamic routes.
	FlowRoutes     uint64
	FragmentRoutes uint64

	// AddressFallbacks, DefaultFallbacks, and DroppedFallbacks count writes
	// that could not use a dynamic route.
	AddressFallbacks uint64
	DefaultFallbacks uint64
	DroppedFallbacks uint64

	// FlowCollisions counts identical tuples from different nested Tuns.
	FlowCollisions uint64

	// ExpiredRoutes and EvictedRoutes count removed dynamic routes.
	ExpiredRoutes uint64
	EvictedRoutes uint64
}

// RoutingStats returns shared-address routing counters and current table
// sizes. All fields remain zero when shared-address routing is disabled.
func (j *Joiner) RoutingStats() JoinerRoutingStats {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.flowRouting && !j.closed {
		j.expireDynamicRoutesLocked(j.now())
	}
	stats := j.routeStats
	stats.ActiveFlows = len(j.flows)
	stats.ActiveFragments = len(j.fragments)
	return stats
}

func normalizeJoinerOptions(options JoinerOptions) (time.Duration, int) {
	timeout := options.FlowTimeout
	if timeout <= 0 {
		timeout = DefaultJoinerFlowTimeout
	}
	limit := options.MaxFlowEntries
	if limit <= 0 {
		limit = DefaultJoinerMaxFlowEntries
	}
	return timeout, limit
}

type joinerFlowKey struct {
	source      [16]byte
	destination [16]byte
	sourcePort  uint16
	destPort    uint16
	identifier  uint16
	version     uint8
	protocol    uint8
	subtype     uint8
}

type joinerFragmentKey struct {
	source      [16]byte
	destination [16]byte
	id          uint32
	version     uint8
	protocol    uint8
}

type joinerDynamicRouteKind uint8

const (
	joinerDynamicFlow joinerDynamicRouteKind = iota
	joinerDynamicFragment
)

type joinerDynamicRoute struct {
	owner       *joinerNested
	expires     time.Time
	kind        joinerDynamicRouteKind
	flowKey     joinerFlowKey
	fragmentKey joinerFragmentKey
	previous    *joinerDynamicRoute
	next        *joinerDynamicRoute
}

type joinerPacket struct {
	data             []byte
	source           [16]byte
	destination      [16]byte
	fragmentID       uint32
	transportOffset  int
	version          uint8
	protocol         uint8
	fragmentProtocol uint8
	fragmentOffset   uint16
	moreFragments    bool
	fragmented       bool
}

func (j *Joiner) routeSharedAddressLocked(
	buf []byte,
	offset int,
	now time.Time,
) *joinerNested {
	packet, parsed := parseJoinerPacket(buf, offset)

	if parsed && packet.fragmented && packet.fragmentOffset != 0 {
		key := packet.joinerFragmentKey()
		if route := j.fragments[key]; route != nil {
			j.touchDynamicRouteLocked(route, now)
			j.routeStats.FragmentRoutes++
			return route.owner
		}
	}

	if parsed {
		if key, ok := joinerInboundFlowKey(packet); ok {
			if route := j.flows[key]; route != nil {
				j.touchDynamicRouteLocked(route, now)
				j.rememberInboundFragmentLocked(packet, route.owner, now)
				j.routeStats.FlowRoutes++
				return route.owner
			}
		}
	}

	owner := j.defaultTun
	var addressOwner *joinerNested
	if parsed {
		addressOwner = j.parsedDestinationRouteLocked(packet)
	} else {
		addressOwner = j.packetDestinationRouteLocked(buf, offset)
	}
	if addressOwner != nil {
		owner = addressOwner
		j.routeStats.AddressFallbacks++
		j.rememberInboundFragmentLocked(packet, owner, now)
		return owner
	}
	if owner != nil {
		j.routeStats.DefaultFallbacks++
		j.rememberInboundFragmentLocked(packet, owner, now)
	} else {
		j.routeStats.DroppedFallbacks++
	}
	return owner
}

func (j *Joiner) rememberFlowLocked(
	key joinerFlowKey,
	owner *joinerNested,
	now time.Time,
) {
	if route := j.flows[key]; route != nil {
		if route.owner != owner {
			j.routeStats.FlowCollisions++
			return
		}
		j.touchDynamicRouteLocked(route, now)
		return
	}
	route := j.newDynamicRouteLocked()
	*route = joinerDynamicRoute{
		owner:   owner,
		expires: now.Add(j.flowTimeout),
		kind:    joinerDynamicFlow,
		flowKey: key,
	}
	j.addDynamicRouteLocked(route)
	j.flows[key] = route
}

func (j *Joiner) rememberInboundFragmentLocked(
	packet joinerPacket,
	owner *joinerNested,
	now time.Time,
) {
	if owner == nil || !packet.fragmented || packet.fragmentOffset != 0 ||
		!packet.moreFragments {
		return
	}
	key := packet.joinerFragmentKey()
	if route := j.fragments[key]; route != nil {
		route.owner = owner
		j.touchDynamicRouteLocked(route, now)
		return
	}
	route := j.newDynamicRouteLocked()
	*route = joinerDynamicRoute{
		owner:       owner,
		expires:     now.Add(j.flowTimeout),
		kind:        joinerDynamicFragment,
		fragmentKey: key,
	}
	j.addDynamicRouteLocked(route)
	j.fragments[key] = route
}

func (j *Joiner) addDynamicRouteLocked(route *joinerDynamicRoute) {
	if j.dynamicTail == nil {
		j.dynamicHead = route
	} else {
		j.dynamicTail.next = route
		route.previous = j.dynamicTail
	}
	j.dynamicTail = route
	j.dynamicSize++
}

func (j *Joiner) newDynamicRouteLocked() *joinerDynamicRoute {
	for j.dynamicSize >= j.flowLimit && j.dynamicHead != nil {
		j.removeDynamicRouteLocked(j.dynamicHead)
		j.routeStats.EvictedRoutes++
	}
	if j.dynamicFree == nil {
		return new(joinerDynamicRoute)
	}
	route := j.dynamicFree
	j.dynamicFree = route.next
	return route
}

func (j *Joiner) touchDynamicRouteLocked(
	route *joinerDynamicRoute,
	now time.Time,
) {
	route.expires = now.Add(j.flowTimeout)
	if route == j.dynamicTail {
		return
	}
	if route.previous == nil {
		j.dynamicHead = route.next
	} else {
		route.previous.next = route.next
	}
	if route.next != nil {
		route.next.previous = route.previous
	}
	route.previous = j.dynamicTail
	route.next = nil
	j.dynamicTail.next = route
	j.dynamicTail = route
}

func (j *Joiner) expireDynamicRoutesLocked(now time.Time) {
	for j.dynamicHead != nil {
		route := j.dynamicHead
		if now.Before(route.expires) {
			return
		}
		j.removeDynamicRouteLocked(route)
		j.routeStats.ExpiredRoutes++
	}
}

func (j *Joiner) removeDynamicRouteLocked(route *joinerDynamicRoute) {
	switch route.kind {
	case joinerDynamicFlow:
		delete(j.flows, route.flowKey)
	case joinerDynamicFragment:
		delete(j.fragments, route.fragmentKey)
	}
	if route.previous == nil {
		j.dynamicHead = route.next
	} else {
		route.previous.next = route.next
	}
	if route.next == nil {
		j.dynamicTail = route.previous
	} else {
		route.next.previous = route.previous
	}
	j.dynamicSize--
	*route = joinerDynamicRoute{next: j.dynamicFree}
	j.dynamicFree = route
}

func (j *Joiner) removeDynamicRoutesForOwnerLocked(owner *joinerNested) {
	for route := j.dynamicHead; route != nil; {
		next := route.next
		if route.owner == owner {
			j.removeDynamicRouteLocked(route)
		}
		route = next
	}
}

func (j *Joiner) clearDynamicRoutesLocked() {
	j.flows = nil
	j.fragments = nil
	j.dynamicHead = nil
	j.dynamicTail = nil
	j.dynamicFree = nil
	j.dynamicSize = 0
}

func (packet joinerPacket) joinerFragmentKey() joinerFragmentKey {
	return joinerFragmentKey{
		source:      packet.source,
		destination: packet.destination,
		id:          packet.fragmentID,
		version:     packet.version,
		protocol:    packet.fragmentProtocol,
	}
}

func joinerReverseFlowKey(packet joinerPacket) (joinerFlowKey, bool) {
	key, ok := joinerDirectFlowKey(packet)
	if !ok {
		return joinerFlowKey{}, false
	}
	key.source, key.destination = key.destination, key.source
	key.sourcePort, key.destPort = key.destPort, key.sourcePort
	if peerType, ok := joinerICMPEchoPeerType(key.protocol, key.subtype); ok {
		key.subtype = peerType
	}
	return key, true
}

func joinerInboundFlowKey(packet joinerPacket) (joinerFlowKey, bool) {
	if key, ok := joinerDirectFlowKey(packet); ok {
		return key, true
	}
	if packet.protocol != joinerProtocolICMPv4 &&
		packet.protocol != joinerProtocolICMPv6 {
		return joinerFlowKey{}, false
	}
	if packet.transportOffset < 0 ||
		packet.transportOffset+8 > len(packet.data) {
		return joinerFlowKey{}, false
	}
	typeValue := packet.data[packet.transportOffset]
	if !joinerICMPErrorType(packet.protocol, typeValue) {
		return joinerFlowKey{}, false
	}
	quoted, ok := parseJoinerPacket(
		packet.data[packet.transportOffset+8:],
		0,
	)
	if !ok {
		return joinerFlowKey{}, false
	}
	return joinerReverseFlowKey(quoted)
}

func joinerDirectFlowKey(packet joinerPacket) (joinerFlowKey, bool) {
	if packet.fragmentOffset != 0 || packet.transportOffset < 0 {
		return joinerFlowKey{}, false
	}
	key := joinerFlowKey{
		source:      packet.source,
		destination: packet.destination,
		version:     packet.version,
		protocol:    packet.protocol,
	}
	switch packet.protocol {
	case joinerProtocolTCP, joinerProtocolUDP:
		if packet.transportOffset+4 > len(packet.data) {
			return joinerFlowKey{}, false
		}
		key.sourcePort = binary.BigEndian.Uint16(
			packet.data[packet.transportOffset:],
		)
		key.destPort = binary.BigEndian.Uint16(
			packet.data[packet.transportOffset+2:],
		)
		return key, true
	case joinerProtocolICMPv4, joinerProtocolICMPv6:
		if packet.transportOffset+8 > len(packet.data) {
			return joinerFlowKey{}, false
		}
		typeValue := packet.data[packet.transportOffset]
		if _, ok := joinerICMPEchoPeerType(packet.protocol, typeValue); !ok {
			return joinerFlowKey{}, false
		}
		key.subtype = typeValue
		key.identifier = binary.BigEndian.Uint16(
			packet.data[packet.transportOffset+4:],
		)
		return key, true
	default:
		return joinerFlowKey{}, false
	}
}

func joinerICMPEchoPeerType(protocol, typeValue uint8) (uint8, bool) {
	switch {
	case protocol == joinerProtocolICMPv4 && typeValue == 8:
		return 0, true
	case protocol == joinerProtocolICMPv4 && typeValue == 0:
		return 8, true
	case protocol == joinerProtocolICMPv6 && typeValue == 128:
		return 129, true
	case protocol == joinerProtocolICMPv6 && typeValue == 129:
		return 128, true
	default:
		return 0, false
	}
}

func joinerICMPErrorType(protocol, typeValue uint8) bool {
	if protocol == joinerProtocolICMPv6 {
		return typeValue < 128
	}
	if protocol != joinerProtocolICMPv4 {
		return false
	}
	switch typeValue {
	case 3, 4, 5, 11, 12:
		return true
	default:
		return false
	}
}

func parseJoinerPacket(buf []byte, offset int) (joinerPacket, bool) {
	if offset < 0 || offset >= len(buf) {
		return joinerPacket{}, false
	}
	data := buf[offset:]
	switch data[0] >> 4 {
	case 4:
		return parseJoinerIPv4Packet(data)
	case 6:
		return parseJoinerIPv6Packet(data)
	default:
		return joinerPacket{}, false
	}
}

func parseJoinerIPv4Packet(data []byte) (joinerPacket, bool) {
	if len(data) < 20 {
		return joinerPacket{}, false
	}
	headerLength := int(data[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(data) {
		return joinerPacket{}, false
	}
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength != 0 && totalLength < headerLength {
		return joinerPacket{}, false
	}
	if totalLength >= headerLength && totalLength < len(data) {
		data = data[:totalLength]
	}
	packet := joinerPacket{
		data:             data,
		fragmentID:       uint32(binary.BigEndian.Uint16(data[4:6])),
		transportOffset:  headerLength,
		version:          4,
		protocol:         data[9],
		fragmentProtocol: data[9],
	}
	copy(packet.source[:4], data[12:16])
	copy(packet.destination[:4], data[16:20])
	fragment := binary.BigEndian.Uint16(data[6:8])
	packet.fragmentOffset = fragment & 0x1fff
	packet.moreFragments = fragment&0x2000 != 0
	packet.fragmented = packet.fragmentOffset != 0 || packet.moreFragments
	return packet, true
}

func parseJoinerIPv6Packet(data []byte) (joinerPacket, bool) {
	if len(data) < 40 {
		return joinerPacket{}, false
	}
	payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	if payloadLength != 0 && 40+payloadLength < len(data) {
		data = data[:40+payloadLength]
	}
	packet := joinerPacket{
		data:            data,
		transportOffset: 40,
		version:         6,
	}
	copy(packet.source[:], data[8:24])
	copy(packet.destination[:], data[24:40])

	nextHeader := data[6]
	for range 16 {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, and Destination Options.
			if packet.transportOffset+2 > len(data) {
				return joinerPacket{}, false
			}
			headerLength := (int(data[packet.transportOffset+1]) + 1) * 8
			if packet.transportOffset+headerLength > len(data) {
				return joinerPacket{}, false
			}
			nextHeader = data[packet.transportOffset]
			packet.transportOffset += headerLength
		case 44: // Fragment.
			if packet.transportOffset+8 > len(data) {
				return joinerPacket{}, false
			}
			fragmentNext := data[packet.transportOffset]
			fragment := binary.BigEndian.Uint16(
				data[packet.transportOffset+2:],
			)
			packet.fragmented = true
			packet.fragmentProtocol = fragmentNext
			packet.fragmentOffset = (fragment & 0xfff8) >> 3
			packet.moreFragments = fragment&1 != 0
			packet.fragmentID = binary.BigEndian.Uint32(
				data[packet.transportOffset+4:],
			)
			packet.transportOffset += 8
			nextHeader = fragmentNext
			if packet.fragmentOffset != 0 {
				packet.protocol = nextHeader
				return packet, true
			}
		case 51: // Authentication Header.
			if packet.transportOffset+2 > len(data) {
				return joinerPacket{}, false
			}
			headerLength := (int(data[packet.transportOffset+1]) + 2) * 4
			if packet.transportOffset+headerLength > len(data) {
				return joinerPacket{}, false
			}
			nextHeader = data[packet.transportOffset]
			packet.transportOffset += headerLength
		default:
			packet.protocol = nextHeader
			if !packet.fragmented {
				packet.fragmentProtocol = nextHeader
			}
			return packet, true
		}
	}
	return joinerPacket{}, false
}
