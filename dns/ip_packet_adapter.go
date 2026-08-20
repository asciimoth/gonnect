package dns

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ipProtocolUDP = 17

	ipv6NextHeaderHopByHop     = 0
	ipv6NextHeaderRouting      = 43
	ipv6NextHeaderFragment     = 44
	ipv6NextHeaderAH           = 51
	ipv6NextHeaderDestination  = 60
	ipv6NextHeaderMobility     = 135
	ipv6NextHeaderHostIdentity = 139
	ipv6NextHeaderShim6        = 140

	dnsPort = 53
)

// IPPacketCallback receives raw IP packets containing DNS UDP responses.
type IPPacketCallback func([]byte)

// IPPacketAdapter adapts raw IP UDP DNS packets to a DNS Interface.
//
// It accepts complete, unfragmented IPv4 or IPv6 UDP packets addressed to port
// 53, forwards DNS requests to the configured upstream, and emits matching raw
// IP UDP DNS response packets through the callback.
type IPPacketAdapter struct {
	upstream Interface
	callback IPPacketCallback
	timeout  time.Duration
	limit    packetLimiter

	done   chan struct{}
	closed atomic.Bool

	cbMu sync.RWMutex
}

// NewIPPacketAdapter creates an adapter backed by upstream.
func NewIPPacketAdapter(
	upstream Interface,
	callback IPPacketCallback,
) *IPPacketAdapter {
	return NewIPPacketAdapterWithOptions(upstream, callback, PacketOptions{})
}

// NewIPPacketAdapterWithOptions creates an adapter backed by upstream.
func NewIPPacketAdapterWithOptions(
	upstream Interface,
	callback IPPacketCallback,
	opts PacketOptions,
) *IPPacketAdapter {
	opts = normalizePacketOptions(opts)
	done := make(chan struct{})
	return &IPPacketAdapter{
		upstream: upstream,
		callback: callback,
		timeout:  opts.RequestTimeout,
		limit:    newPacketLimiter(opts.MaxConcurrentRequests),
		done:     done,
	}
}

// FeedPacket feeds one raw IP packet into the adapter.
func (a *IPPacketAdapter) FeedPacket(pkt []byte) { a.feedPacket(pkt) }

// Close stops accepting packets and prevents future response callbacks.
func (a *IPPacketAdapter) Close() error {
	if a == nil {
		return nil
	}
	if a.closed.CompareAndSwap(false, true) {
		close(a.done)
	}
	return nil
}

func (a *IPPacketAdapter) feedPacket(pkt []byte) {
	if a == nil || a.closed.Load() {
		return
	}
	req, ok := parseDNSIPPacket(pkt)
	if !ok {
		return
	}
	msg, err := Unpack(req.payload)
	if err != nil || msg.Response {
		return
	}
	ctx, cancel := a.queryContext()
	if !a.limit.acquire(ctx) {
		cancel()
		return
	}
	go a.handleRequest(ctx, cancel, req, msg)
}

func (a *IPPacketAdapter) handleRequest(
	ctx context.Context,
	cancel context.CancelFunc,
	req ipPacketRequest,
	msg *Message,
) {
	defer a.limit.release()
	defer cancel()
	if a.closed.Load() {
		return
	}
	clientID := msg.ID
	resp := a.query(ctx, msg)
	if resp == nil || a.closed.Load() {
		return
	}
	resp.ID = clientID
	pkt, ok := buildDNSIPResponse(req, resp)
	if !ok {
		return
	}
	a.emit(pkt)
}

func (a *IPPacketAdapter) query(ctx context.Context, msg *Message) *Message {
	if a.upstream == nil {
		resp := responseFor(msg)
		resp.RCode = RCodeServerFailure
		return resp
	}
	resp, err := Query(ctx, a.upstream, msg)
	if err == nil {
		return resp
	}
	if ctx.Err() != nil {
		return nil
	}
	resp = responseFor(msg)
	resp.RCode = RCodeServerFailure
	return resp
}

func (a *IPPacketAdapter) queryContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	if a != nil && a.timeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, a.timeout)
		ctx = ctxWithTimeout
		return a.closeAwareContext(ctx, cancel)
	}
	ctx, cancel := context.WithCancel(ctx)
	return a.closeAwareContext(ctx, cancel)
}

func (a *IPPacketAdapter) closeAwareContext(
	ctx context.Context,
	cancel context.CancelFunc,
) (context.Context, context.CancelFunc) {
	if a == nil || a.done == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (a *IPPacketAdapter) emit(pkt []byte) {
	if a.callback == nil {
		return
	}
	a.cbMu.RLock()
	defer a.cbMu.RUnlock()
	if a.closed.Load() {
		return
	}
	a.callback(pkt)
}

type ipPacketRequest struct {
	version int

	src4 [4]byte
	dst4 [4]byte
	src6 [16]byte
	dst6 [16]byte

	srcPort uint16
	dstPort uint16
	payload []byte
}

func parseDNSIPPacket(pkt []byte) (ipPacketRequest, bool) {
	if len(pkt) < 1 {
		return ipPacketRequest{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseDNSIPv4Packet(pkt)
	case 6:
		return parseDNSIPv6Packet(pkt)
	default:
		return ipPacketRequest{}, false
	}
}

func parseDNSIPv4Packet(pkt []byte) (ipPacketRequest, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return ipPacketRequest{}, false
	}
	headerLen := int(pkt[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(pkt) {
		return ipPacketRequest{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < headerLen || totalLen > len(pkt) {
		return ipPacketRequest{}, false
	}
	flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
	if flagsFrag&0x3fff != 0 || pkt[9] != ipProtocolUDP {
		return ipPacketRequest{}, false
	}
	req, ok := parseDNSUDP(pkt, headerLen, totalLen)
	if !ok {
		return ipPacketRequest{}, false
	}
	udp := udpSegment(pkt, headerLen, totalLen)
	if udp == nil || !validUDPChecksumIPv4(pkt[12:16], pkt[16:20], udp) {
		return ipPacketRequest{}, false
	}
	req.version = 4
	copy(req.src4[:], pkt[12:16])
	copy(req.dst4[:], pkt[16:20])
	return req, true
}

func parseDNSIPv6Packet(pkt []byte) (ipPacketRequest, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return ipPacketRequest{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	totalLen := 40 + payloadLen
	if totalLen > len(pkt) {
		return ipPacketRequest{}, false
	}
	next := pkt[6]
	off := 40
	for {
		switch next {
		case ipProtocolUDP:
			req, ok := parseDNSUDP(pkt, off, totalLen)
			if !ok {
				return ipPacketRequest{}, false
			}
			udp := udpSegment(pkt, off, totalLen)
			if udp == nil || !validUDPChecksumIPv6(pkt[8:24], pkt[24:40], udp) {
				return ipPacketRequest{}, false
			}
			req.version = 6
			copy(req.src6[:], pkt[8:24])
			copy(req.dst6[:], pkt[24:40])
			return req, true
		case ipv6NextHeaderFragment:
			return ipPacketRequest{}, false
		case ipv6NextHeaderHopByHop,
			ipv6NextHeaderRouting,
			ipv6NextHeaderDestination,
			ipv6NextHeaderMobility,
			ipv6NextHeaderHostIdentity,
			ipv6NextHeaderShim6:
			if off+2 > totalLen {
				return ipPacketRequest{}, false
			}
			headerLen := (int(pkt[off+1]) + 1) * 8
			if headerLen == 0 || off+headerLen > totalLen {
				return ipPacketRequest{}, false
			}
			next = pkt[off]
			off += headerLen
		case ipv6NextHeaderAH:
			if off+2 > totalLen {
				return ipPacketRequest{}, false
			}
			headerLen := (int(pkt[off+1]) + 2) * 4
			if headerLen == 0 || off+headerLen > totalLen {
				return ipPacketRequest{}, false
			}
			next = pkt[off]
			off += headerLen
		default:
			return ipPacketRequest{}, false
		}
	}
}

func parseDNSUDP(
	pkt []byte,
	off int,
	totalLen int,
) (ipPacketRequest, bool) {
	if off+8 > totalLen {
		return ipPacketRequest{}, false
	}
	udp := pkt[off:totalLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return ipPacketRequest{}, false
	}
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if dstPort != dnsPort {
		return ipPacketRequest{}, false
	}
	return ipPacketRequest{
		srcPort: binary.BigEndian.Uint16(udp[0:2]),
		dstPort: dstPort,
		payload: append([]byte(nil), udp[8:udpLen]...),
	}, true
}

func udpSegment(pkt []byte, off int, totalLen int) []byte {
	if off+8 > totalLen {
		return nil
	}
	udp := pkt[off:totalLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil
	}
	return udp[:udpLen]
}

func buildDNSIPResponse(req ipPacketRequest, msg *Message) ([]byte, bool) {
	payload, err := Pack(msg)
	if err != nil {
		return nil, false
	}
	udpLen := 8 + len(payload)
	if udpLen > 1<<16-1 {
		return nil, false
	}
	switch req.version {
	case 4:
		return buildDNSIPv4Response(req, payload, udpLen)
	case 6:
		return buildDNSIPv6Response(req, payload, udpLen)
	default:
		return nil, false
	}
}

func buildDNSIPv4Response(
	req ipPacketRequest,
	payload []byte,
	udpLen int,
) ([]byte, bool) {
	totalLen := 20 + udpLen
	if totalLen > 1<<16-1 {
		return nil, false
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	totalLen16 := uint16(totalLen) //nolint:gosec // totalLen is bounded above.
	binary.BigEndian.PutUint16(pkt[2:4], totalLen16)
	pkt[8] = 64
	pkt[9] = ipProtocolUDP
	copy(pkt[12:16], req.dst4[:])
	copy(pkt[16:20], req.src4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	udp := pkt[20:]
	writeUDPResponse(udp, req, payload, udpLen)
	sum := udpChecksumIPv4(pkt[12:16], pkt[16:20], udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt, true
}

func buildDNSIPv6Response(
	req ipPacketRequest,
	payload []byte,
	udpLen int,
) ([]byte, bool) {
	if udpLen > 1<<16-1 {
		return nil, false
	}
	pkt := make([]byte, 40+udpLen)
	pkt[0] = 0x60
	udpLen16 := uint16(udpLen) //nolint:gosec // udpLen is bounded above.
	binary.BigEndian.PutUint16(pkt[4:6], udpLen16)
	pkt[6] = ipProtocolUDP
	pkt[7] = 64
	copy(pkt[8:24], req.dst6[:])
	copy(pkt[24:40], req.src6[:])

	udp := pkt[40:]
	writeUDPResponse(udp, req, payload, udpLen)
	sum := udpChecksumIPv6(pkt[8:24], pkt[24:40], udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt, true
}

func writeUDPResponse(
	udp []byte,
	req ipPacketRequest,
	payload []byte,
	udpLen int,
) {
	binary.BigEndian.PutUint16(udp[0:2], req.dstPort)
	binary.BigEndian.PutUint16(udp[2:4], req.srcPort)
	udpLen16 := uint16(udpLen) //nolint:gosec // udpLen is bounded by callers.
	binary.BigEndian.PutUint16(udp[4:6], udpLen16)
	copy(udp[8:], payload)
}

func udpChecksumIPv4(src, dst, udp []byte) uint16 {
	return nonZeroChecksum(ipv4UDPPseudoHeader(src, dst, udp), udp)
}

func validUDPChecksumIPv4(src, dst, udp []byte) bool {
	if len(udp) < 8 {
		return false
	}
	if binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return true
	}
	return checksumIPv4UDP(src, dst, udp) == 0
}

func udpChecksumIPv6(src, dst, udp []byte) uint16 {
	return nonZeroChecksum(ipv6UDPPseudoHeader(src, dst, udp), udp)
}

func validUDPChecksumIPv6(src, dst, udp []byte) bool {
	if len(udp) < 8 || binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return false
	}
	return checksum(ipv6UDPPseudoHeader(src, dst, udp), udp) == 0
}

func checksumIPv4UDP(src, dst, udp []byte) uint16 {
	return checksum(ipv4UDPPseudoHeader(src, dst, udp), udp)
}

func ipv4UDPPseudoHeader(src, dst, udp []byte) []byte {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = ipProtocolUDP
	// UDP packets are bounded to uint16 before checksums are calculated.
	udpLen := uint16(len(udp)) //nolint:gosec
	binary.BigEndian.PutUint16(pseudo[10:12], udpLen)
	return pseudo
}

func ipv6UDPPseudoHeader(src, dst, udp []byte) []byte {
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	// UDP packets are bounded to uint16 before checksums are calculated.
	udpLen := uint32(len(udp)) //nolint:gosec
	binary.BigEndian.PutUint32(pseudo[32:36], udpLen)
	pseudo[39] = ipProtocolUDP
	return pseudo
}

func nonZeroChecksum(parts ...[]byte) uint16 {
	sum := checksum(parts...)
	if sum == 0 {
		return 0xffff
	}
	return sum
}

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for len(part) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(part[:2]))
			part = part[2:]
		}
		if len(part) == 1 {
			sum += uint32(part[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum) //nolint:gosec // sum is folded to 16 bits above.
}
