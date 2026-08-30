package tun

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asciimoth/gonnect"
)

var _ interface {
	Tun
	gonnect.Wrapper
} = (*Firewall)(nil)

// Firewall filters IP packets that pass through a Tun.
//
// Read receives packets that leave the local IP stack. It silently drops
// packets that match an outgoing Exclude rule and records allowed flows. Write
// receives packets that enter the local IP stack. It silently drops packets
// that do not match an incoming Include rule, unless they are a response to a
// recorded outgoing flow.
//
// The wrapper parses IPv4, IPv6, TCP, UDP, ICMP, and IPv6 extension headers.
// Unknown IP protocols use the names "ip4:<protocol-number>" and
// "ip6:<protocol-number>". A generic "ip:<protocol-number>" rule matches both
// families. Rules with Network set to "ip" match every parsed IP protocol.
// Keep this interface private so that Firewall does not expose an embedded Tun
// field as part of its public API.
//
//nolint:iface // The identical method set is intentional for API encapsulation.
type firewallTun interface {
	Tun
}

type Firewall struct {
	firewallTun
	config      atomic.Pointer[gonnect.FirewallConfig]
	responsesMu sync.Mutex
	responses   map[firewallFlow]int64
	recorded    uint64
}

// NewFirewall creates a packet-filtering wrapper. It optimizes and clones cfg
// before it returns. A nil config allows all outgoing traffic and denies
// unsolicited incoming traffic.
func NewFirewall(t Tun, cfg *gonnect.FirewallConfig) *Firewall {
	firewall := &Firewall{firewallTun: t}
	firewall.config.Store(cfg.Optimize())
	return firewall
}

// GetWrapped returns the wrapped Tun.
func (f *Firewall) GetWrapped() any { return f.firewallTun }

// GetTun returns the wrapped Tun.
func (f *Firewall) GetTun() Tun { return f.firewallTun }

// File always returns nil. File access would bypass the firewall.
func (f *Firewall) File() *os.File { return nil }

// IsNative always returns false. Direct native access would bypass filtering.
func (f *Firewall) IsNative() bool { return false }

// SetConfig atomically installs an optimized clone of cfg. Existing response
// cache entries remain valid until their original expiration time.
func (f *Firewall) SetConfig(cfg *gonnect.FirewallConfig) {
	f.config.Store(cfg.Optimize())
}

// SetCfg is an alias for SetConfig.
func (f *Firewall) SetCfg(cfg *gonnect.FirewallConfig) { f.SetConfig(cfg) }

// GetConfig returns an independent copy of the active policy. The returned
// config retains the shared DNSCache.
func (f *Firewall) GetConfig() *gonnect.FirewallConfig {
	return f.config.Load().Clone()
}

// GetCfg is an alias for GetConfig.
func (f *Firewall) GetCfg() *gonnect.FirewallConfig { return f.GetConfig() }

// Read filters outgoing packets and returns only packets that are allowed.
func (f *Firewall) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if offset < 0 {
		return 0, errTunInvalidOffset
	}
	for {
		n, err := f.firewallTun.Read(bufs, sizes, offset)
		if n < 0 {
			n = 0
		}
		n = min(n, len(bufs), len(sizes))
		kept, filterErr := f.filterOutgoingRead(bufs, sizes, offset, n)
		if filterErr != nil {
			return kept, filterErr
		}
		if kept != 0 || err != nil {
			return kept, err
		}
	}
}

func (f *Firewall) filterOutgoingRead(
	bufs [][]byte,
	sizes []int,
	offset, n int,
) (int, error) {
	kept := 0
	for i := range n {
		packet, ok := firewallTunPacket(bufs[i], sizes[i], offset)
		if !ok {
			continue
		}
		flow, ok := parseFirewallPacket(packet)
		if !ok || f.blocksOutgoing(flow) {
			continue
		}
		f.recordResponse(flow.reverse())
		if kept != i {
			if offset > len(bufs[kept]) ||
				len(packet) > len(bufs[kept])-offset {
				return kept, io.ErrShortBuffer
			}
			copy(bufs[kept][offset:], packet)
		}
		sizes[kept] = len(packet)
		kept++
	}
	return kept, nil
}

// Write filters incoming packets. Denied packets are treated as consumed so a
// caller does not retry them indefinitely.
func (f *Firewall) Write(bufs [][]byte, offset int) (int, error) {
	if err := validatePacketOffset(bufs, offset); err != nil {
		return 0, err
	}
	firstDenied := -1
	var allowed [][]byte
	var indexes []int
	for i, buf := range bufs {
		flow, ok := parseFirewallPacket(buf[offset:])
		if !ok || !f.allowsIncoming(buf[offset:], flow) {
			if firstDenied < 0 {
				firstDenied = i
			}
			continue
		}
		if firstDenied < 0 {
			continue
		}
		if allowed == nil {
			allowed = make([][]byte, firstDenied, len(bufs)-1)
			copy(allowed, bufs[:firstDenied])
			indexes = make([]int, firstDenied, len(bufs)-1)
			for j := range firstDenied {
				indexes[j] = j
			}
		}
		allowed = append(allowed, buf)
		indexes = append(indexes, i)
	}
	if firstDenied < 0 {
		return f.firewallTun.Write(bufs, offset)
	}
	if allowed == nil {
		if firstDenied == 0 {
			return len(bufs), nil
		}
		written, err := f.firewallTun.Write(bufs[:firstDenied], offset)
		if written < 0 {
			written = 0
		}
		if written >= firstDenied {
			return len(bufs), err
		}
		return written, err
	}
	written, err := f.firewallTun.Write(allowed, offset)
	if written >= len(allowed) && err == nil {
		return len(bufs), nil
	}
	if written < 0 {
		written = 0
	}
	if written >= len(indexes) {
		return len(bufs), err
	}
	return indexes[written], err
}

type firewallFlow struct {
	version uint8
	proto   uint8
	src     netip.Addr
	dst     netip.Addr
	srcPort uint16
	dstPort uint16
}

func (flow firewallFlow) reverse() firewallFlow {
	return firewallFlow{
		version: flow.version,
		proto:   flow.proto,
		src:     flow.dst,
		dst:     flow.src,
		srcPort: flow.dstPort,
		dstPort: flow.srcPort,
	}
}

func (flow firewallFlow) network() string {
	family := strconv.Itoa(int(flow.version))
	switch flow.proto {
	case 6:
		return "tcp" + family
	case 17:
		return "udp" + family
	case 1:
		return "icmp4"
	case 58:
		return "icmp6"
	default:
		return "ip" + family + ":" + strconv.Itoa(int(flow.proto))
	}
}

func (flow firewallFlow) outgoingAddress() string {
	return net.JoinHostPort(flow.dst.String(), strconv.Itoa(int(flow.dstPort)))
}

func (flow firewallFlow) incomingAddress() string {
	return net.JoinHostPort(flow.src.String(), strconv.Itoa(int(flow.dstPort)))
}

func (f *Firewall) blocksOutgoing(flow firewallFlow) bool {
	return f.config.Load().BlocksOutgoingIP(
		flow.proto,
		netip.AddrPortFrom(flow.dst, flow.dstPort),
	)
}

func (f *Firewall) allowsIncoming(packet []byte, flow firewallFlow) bool {
	if f.hasResponse(flow) || f.relatedICMPResponse(packet, flow) {
		return true
	}
	return f.config.Load().AllowsIncomingIP(
		flow.proto,
		netip.AddrPortFrom(flow.src, flow.srcPort),
		netip.AddrPortFrom(flow.dst, flow.dstPort),
	)
}

func (f *Firewall) recordResponse(flow firewallFlow) {
	now := time.Now()
	expires := now.Add(f.responseTTL()).UnixNano()
	f.responsesMu.Lock()
	if f.responses == nil {
		f.responses = make(map[firewallFlow]int64)
	}
	f.responses[flow] = expires
	f.recorded++
	if f.recorded%256 == 0 {
		f.deleteExpiredResponsesLocked(now.UnixNano())
	}
	f.responsesMu.Unlock()
}

func (f *Firewall) hasResponse(flow firewallFlow) bool {
	now := time.Now().UnixNano()
	f.responsesMu.Lock()
	expires, ok := f.responses[flow]
	if !ok {
		f.responsesMu.Unlock()
		return false
	}
	if expires >= now {
		f.responsesMu.Unlock()
		return true
	}
	delete(f.responses, flow)
	f.responsesMu.Unlock()
	return false
}

func (f *Firewall) deleteExpiredResponsesLocked(now int64) {
	for flow, expires := range f.responses {
		if expires < now {
			delete(f.responses, flow)
		}
	}
}

func (f *Firewall) responseTTL() time.Duration {
	ttl := f.config.Load().ResponseTTL
	if ttl <= 0 {
		return 2 * time.Minute
	}
	return ttl
}

func (f *Firewall) relatedICMPResponse(
	packet []byte,
	flow firewallFlow,
) bool {
	var embedded []byte
	switch {
	case flow.version == 4 && flow.proto == 1:
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen+8 > len(packet) || !isIPv4ICMPError(packet[headerLen]) {
			return false
		}
		embedded = packet[headerLen+8:]
	case flow.version == 6 && flow.proto == 58:
		offset, _, ok := ipv6TransportOffset(packet)
		if !ok || offset+8 > len(packet) || packet[offset] >= 128 {
			return false
		}
		embedded = packet[offset+8:]
	default:
		return false
	}
	original, ok := parseFirewallPacket(embedded)
	return ok && f.hasResponse(original.reverse())
}

func isIPv4ICMPError(kind byte) bool {
	switch kind {
	case 3, 4, 5, 11, 12:
		return true
	default:
		return false
	}
}

func firewallTunPacket(buf []byte, size, offset int) ([]byte, bool) {
	if size < 0 || offset < 0 || offset > len(buf) || size > len(buf)-offset {
		return nil, false
	}
	return buf[offset : offset+size], true
}

func parseFirewallPacket(packet []byte) (firewallFlow, bool) {
	if len(packet) == 0 {
		return firewallFlow{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		return parseFirewallIPv4(packet)
	case 6:
		return parseFirewallIPv6(packet)
	default:
		return firewallFlow{}, false
	}
}

func parseFirewallIPv4(packet []byte) (firewallFlow, bool) {
	if len(packet) < 20 {
		return firewallFlow{}, false
	}
	headerLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLen < 20 || headerLen > len(packet) || totalLen < headerLen ||
		totalLen > len(packet) {
		return firewallFlow{}, false
	}
	src, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return firewallFlow{}, false
	}
	dst, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return firewallFlow{}, false
	}
	flow := firewallFlow{
		version: 4,
		proto:   packet[9],
		src:     src.Unmap(),
		dst:     dst.Unmap(),
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x1fff == 0 {
		flow.srcPort, flow.dstPort = firewallTransportPorts(
			flow.proto,
			packet[headerLen:totalLen],
		)
	}
	return flow, true
}

func parseFirewallIPv6(packet []byte) (firewallFlow, bool) {
	if len(packet) < 40 {
		return firewallFlow{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen != 0 && 40+payloadLen > len(packet) {
		return firewallFlow{}, false
	}
	src, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return firewallFlow{}, false
	}
	dst, ok := netip.AddrFromSlice(packet[24:40])
	if !ok {
		return firewallFlow{}, false
	}
	offset, proto, ok := ipv6TransportOffset(packet)
	if !ok {
		return firewallFlow{}, false
	}
	flow := firewallFlow{
		version: 6,
		proto:   proto,
		src:     src,
		dst:     dst,
	}
	flow.srcPort, flow.dstPort = firewallTransportPorts(proto, packet[offset:])
	return flow, true
}

func ipv6TransportOffset(packet []byte) (int, uint8, bool) {
	if len(packet) < 40 {
		return 0, 0, false
	}
	next := packet[6]
	offset := 40
	for {
		switch next {
		case 0, 43, 60:
			if offset+2 > len(packet) {
				return 0, 0, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length < 8 || offset+length > len(packet) {
				return 0, 0, false
			}
			next = packet[offset]
			offset += length
		case 44:
			if offset+8 > len(packet) {
				return 0, 0, false
			}
			fragmentOffset := binary.BigEndian.Uint16(
				packet[offset+2:offset+4],
			) >> 3
			next = packet[offset]
			offset += 8
			if fragmentOffset != 0 {
				// A non-initial fragment does not contain transport headers.
				// Keep the IP protocol but force zero transport ports.
				return len(packet), next, true
			}
		case 51:
			if offset+2 > len(packet) {
				return 0, 0, false
			}
			length := (int(packet[offset+1]) + 2) * 4
			if length < 8 || offset+length > len(packet) {
				return 0, 0, false
			}
			next = packet[offset]
			offset += length
		default:
			return offset, next, offset <= len(packet)
		}
	}
}

func firewallTransportPorts(proto uint8, payload []byte) (uint16, uint16) {
	if (proto != 6 && proto != 17) || len(payload) < 4 {
		return 0, 0
	}
	return binary.BigEndian.Uint16(payload[:2]),
		binary.BigEndian.Uint16(payload[2:4])
}
