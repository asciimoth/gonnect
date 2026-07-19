//nolint:testpackage // These tests exercise raw packet helpers kept internal.
package dns

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestIPPacketAdapterIPv4DNSRequest(t *testing.T) {
	upstream := newStaticDNS()
	t.Cleanup(func() {
		if err := upstream.Close(); err != nil {
			t.Fatalf("upstream Close() error = %v", err)
		}
	})

	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- append([]byte(nil), pkt...)
	})
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Fatalf("adapter Close() error = %v", err)
		}
	})

	req := aQuery("localhost.")
	raw := testIPv4DNSPacket(
		t,
		[4]byte{10, 0, 0, 2},
		[4]byte{10, 0, 0, 53},
		dnsPort,
		req,
	)
	adapter.FeedPacket(raw)

	resp := recvIPPacket(t, responses)
	src, dst, srcPort, dstPort, msg := parseIPv4DNSResponse(t, resp)
	if src != [4]byte{10, 0, 0, 53} || dst != [4]byte{10, 0, 0, 2} {
		t.Fatalf("IPv4 response src/dst = %v/%v", src, dst)
	}
	if srcPort != dnsPort || dstPort != 53000 {
		t.Fatalf("UDP response ports = %d/%d, want 53/53000", srcPort, dstPort)
	}
	if !msg.Response || msg.ID != req.ID || len(msg.Answers) != 1 {
		t.Fatalf("DNS response = %#v", msg)
	}
}

func TestIPPacketAdapterIPv6DNSRequest(t *testing.T) {
	upstream := newStaticDNS()
	t.Cleanup(func() {
		if err := upstream.Close(); err != nil {
			t.Fatalf("upstream Close() error = %v", err)
		}
	})

	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- append([]byte(nil), pkt...)
	})
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Fatalf("adapter Close() error = %v", err)
		}
	})

	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1}
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x53}
	req := aQuery("localhost.")
	raw := testIPv6DNSPacket(t, src, dst, 53001, dnsPort, req)
	adapter.FeedPacket(raw)

	resp := recvIPPacket(t, responses)
	gotSrc, gotDst, srcPort, dstPort, msg := parseIPv6DNSResponse(t, resp)
	if gotSrc != dst || gotDst != src {
		t.Fatalf("IPv6 response src/dst = %v/%v", gotSrc, gotDst)
	}
	if srcPort != dnsPort || dstPort != 53001 {
		t.Fatalf("UDP response ports = %d/%d, want 53/53001", srcPort, dstPort)
	}
	if !msg.Response || msg.ID != req.ID || len(msg.Answers) != 1 {
		t.Fatalf("DNS response = %#v", msg)
	}
}

func TestIPPacketAdapterIPv6DNSRequestWithExtensionHeader(t *testing.T) {
	upstream := newStaticDNS()
	t.Cleanup(func() {
		if err := upstream.Close(); err != nil {
			t.Fatalf("upstream Close() error = %v", err)
		}
	})

	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- append([]byte(nil), pkt...)
	})
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Fatalf("adapter Close() error = %v", err)
		}
	})

	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1}
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x53}
	req := aQuery("localhost.")
	raw := testIPv6DNSPacketWithDestinationOptions(
		t,
		src,
		dst,
		53002,
		dnsPort,
		req,
	)
	adapter.FeedPacket(raw)

	resp := recvIPPacket(t, responses)
	gotSrc, gotDst, srcPort, dstPort, msg := parseIPv6DNSResponse(t, resp)
	if gotSrc != dst || gotDst != src {
		t.Fatalf("IPv6 response src/dst = %v/%v", gotSrc, gotDst)
	}
	if srcPort != dnsPort || dstPort != 53002 {
		t.Fatalf("UDP response ports = %d/%d, want 53/53002", srcPort, dstPort)
	}
	if !msg.Response || msg.ID != req.ID || len(msg.Answers) != 1 {
		t.Fatalf("DNS response = %#v", msg)
	}
}

func TestIPPacketAdapterIgnoresNonDNSPackets(t *testing.T) {
	upstream := &manualDNS{requests: make(chan Request, 1)}
	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- pkt
	})
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Fatalf("adapter Close() error = %v", err)
		}
	})

	src := [4]byte{10, 0, 0, 2}
	dst := [4]byte{10, 0, 0, 53}
	req := aQuery("localhost.")
	adapter.FeedPacket(testIPv4DNSPacket(t, src, dst, dnsPort+1, req))

	fragment := testIPv4DNSPacket(t, src, dst, dnsPort, req)
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	adapter.FeedPacket(fragment)

	dnsResp := req.Copy()
	dnsResp.Response = true
	adapter.FeedPacket(testIPv4DNSPacket(t, src, dst, dnsPort, dnsResp))

	assertNoDNSRequest(t, upstream.requests)
	assertNoIPPacket(t, responses)
}

func TestIPPacketAdapterRejectsBadUDPChecksums(t *testing.T) {
	upstream := &manualDNS{requests: make(chan Request, 2)}
	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- pkt
	})
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Fatalf("adapter Close() error = %v", err)
		}
	})

	req := aQuery("localhost.")
	ipv4 := testIPv4DNSPacket(
		t,
		[4]byte{10, 0, 0, 2},
		[4]byte{10, 0, 0, 53},
		dnsPort,
		req,
	)
	ipv4[26] ^= 0xff
	adapter.FeedPacket(ipv4)

	ipv6 := testIPv6DNSPacket(
		t,
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x53},
		53003,
		dnsPort,
		req,
	)
	ipv6[46] = 0
	ipv6[47] = 0
	adapter.FeedPacket(ipv6)

	assertNoDNSRequest(t, upstream.requests)
	assertNoIPPacket(t, responses)
}

func TestIPPacketAdapterCloseSuppressesLateResponses(t *testing.T) {
	upstream := &manualDNS{requests: make(chan Request, 1)}
	responses := make(chan []byte, 1)
	adapter := NewIPPacketAdapter(upstream, func(pkt []byte) {
		responses <- pkt
	})

	req := aQuery("localhost.")
	raw := testIPv4DNSPacket(
		t,
		[4]byte{10, 0, 0, 2},
		[4]byte{10, 0, 0, 53},
		dnsPort,
		req,
	)
	adapter.FeedPacket(raw)

	var upstreamReq Request
	select {
	case upstreamReq = <-upstream.requests:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive DNS request")
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	resp := responseFor(upstreamReq.Message)
	resp.Answers = staticAnswers(upstreamReq.Message.Questions[0])
	upstreamReq.Reply <- Response{Message: resp}
	assertNoIPPacket(t, responses)

	adapter.FeedPacket(raw)
	assertNoDNSRequest(t, upstream.requests)
}

type manualDNS struct {
	requests chan Request
}

func (d *manualDNS) Requests() chan<- Request { return d.requests }
func (d *manualDNS) Close() error             { return nil }

const testIPv4SourcePort = 53000

func testIPv4DNSPacket(
	t *testing.T,
	src [4]byte,
	dst [4]byte,
	dstPort uint16,
	msg *Message,
) []byte {
	t.Helper()
	payload := testDNSPayload(t, msg)
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	if totalLen > 1<<16-1 {
		t.Fatalf("test IPv4 packet too large: %d", totalLen)
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	totalLen16 := uint16(totalLen) //nolint:gosec // totalLen is bounded above.
	binary.BigEndian.PutUint16(pkt[2:4], totalLen16)
	pkt[8] = 64
	pkt[9] = ipProtocolUDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], testIPv4SourcePort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	udpLen16 := uint16(udpLen) //nolint:gosec // udpLen is bounded above.
	binary.BigEndian.PutUint16(udp[4:6], udpLen16)
	copy(udp[8:], payload)
	sum := udpChecksumIPv4(pkt[12:16], pkt[16:20], udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt
}

func testIPv6DNSPacket(
	t *testing.T,
	src [16]byte,
	dst [16]byte,
	srcPort uint16,
	dstPort uint16,
	msg *Message,
) []byte {
	t.Helper()
	payload := testDNSPayload(t, msg)
	udpLen := 8 + len(payload)
	if udpLen > 1<<16-1 {
		t.Fatalf("test IPv6 UDP packet too large: %d", udpLen)
	}
	pkt := make([]byte, 40+udpLen)
	pkt[0] = 0x60
	udpLen16 := uint16(udpLen) //nolint:gosec // udpLen is bounded above.
	binary.BigEndian.PutUint16(pkt[4:6], udpLen16)
	pkt[6] = ipProtocolUDP
	pkt[7] = 64
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	udp := pkt[40:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], udpLen16)
	copy(udp[8:], payload)
	sum := udpChecksumIPv6(pkt[8:24], pkt[24:40], udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt
}

func testIPv6DNSPacketWithDestinationOptions(
	t *testing.T,
	src [16]byte,
	dst [16]byte,
	srcPort uint16,
	dstPort uint16,
	msg *Message,
) []byte {
	t.Helper()
	payload := testDNSPayload(t, msg)
	udpLen := 8 + len(payload)
	extLen := 8
	if udpLen > 1<<16-1-extLen {
		t.Fatalf("test IPv6 UDP packet too large: %d", udpLen)
	}
	pkt := make([]byte, 40+extLen+udpLen)
	pkt[0] = 0x60
	payloadLen16 := uint16(extLen + udpLen) //nolint:gosec // bounded above.
	binary.BigEndian.PutUint16(pkt[4:6], payloadLen16)
	pkt[6] = ipv6NextHeaderDestination
	pkt[7] = 64
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	ext := pkt[40 : 40+extLen]
	ext[0] = ipProtocolUDP
	ext[1] = 0

	udp := pkt[40+extLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	udpLen16 := uint16(udpLen) //nolint:gosec // udpLen is bounded above.
	binary.BigEndian.PutUint16(udp[4:6], udpLen16)
	copy(udp[8:], payload)
	sum := udpChecksumIPv6(pkt[8:24], pkt[24:40], udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt
}

func testDNSPayload(t *testing.T, msg *Message) []byte {
	t.Helper()
	payload, err := Pack(msg)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func recvIPPacket(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IP packet response")
		return nil
	}
}

func assertNoIPPacket(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case pkt := <-ch:
		t.Fatalf("unexpected IP packet response: %x", pkt)
	case <-time.After(50 * time.Millisecond):
	}
}

func assertNoDNSRequest(t *testing.T, ch <-chan Request) {
	t.Helper()
	select {
	case req := <-ch:
		t.Fatalf("unexpected DNS request: %#v", req.Message)
	case <-time.After(50 * time.Millisecond):
	}
}

func parseIPv4DNSResponse(
	t *testing.T,
	pkt []byte,
) ([4]byte, [4]byte, uint16, uint16, *Message) {
	t.Helper()
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		t.Fatalf("not an IPv4 UDP packet: %x", pkt)
	}
	headerLen := int(pkt[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if headerLen < 20 || totalLen > len(pkt) || totalLen < headerLen+8 {
		t.Fatalf(
			"invalid IPv4 lengths: header=%d total=%d len=%d",
			headerLen,
			totalLen,
			len(pkt),
		)
	}
	if pkt[9] != ipProtocolUDP {
		t.Fatalf("IPv4 protocol = %d, want UDP", pkt[9])
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	if !validUDPChecksumIPv4(
		src[:],
		dst[:],
		udpSegment(pkt, headerLen, totalLen),
	) {
		t.Fatal("invalid IPv4 UDP checksum")
	}
	srcPort, dstPort, msg := parseUDPMessage(t, pkt[headerLen:totalLen])
	return src, dst, srcPort, dstPort, msg
}

func parseIPv6DNSResponse(
	t *testing.T,
	pkt []byte,
) ([16]byte, [16]byte, uint16, uint16, *Message) {
	t.Helper()
	if len(pkt) < 48 || pkt[0]>>4 != 6 {
		t.Fatalf("not an IPv6 UDP packet: %x", pkt)
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	totalLen := 40 + payloadLen
	if totalLen > len(pkt) || payloadLen < 8 {
		t.Fatalf(
			"invalid IPv6 lengths: payload=%d len=%d",
			payloadLen,
			len(pkt),
		)
	}
	if pkt[6] != ipProtocolUDP {
		t.Fatalf("IPv6 next header = %d, want UDP", pkt[6])
	}
	var src, dst [16]byte
	copy(src[:], pkt[8:24])
	copy(dst[:], pkt[24:40])
	if !validUDPChecksumIPv6(src[:], dst[:], udpSegment(pkt, 40, totalLen)) {
		t.Fatal("invalid IPv6 UDP checksum")
	}
	srcPort, dstPort, msg := parseUDPMessage(t, pkt[40:totalLen])
	return src, dst, srcPort, dstPort, msg
}

func parseUDPMessage(t *testing.T, udp []byte) (uint16, uint16, *Message) {
	t.Helper()
	if len(udp) < 8 {
		t.Fatalf("short UDP packet: %d", len(udp))
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		t.Fatalf("invalid UDP length: %d of %d", udpLen, len(udp))
	}
	msg, err := Unpack(udp[8:udpLen])
	if err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint16(udp[0:2]),
		binary.BigEndian.Uint16(udp[2:4]),
		msg
}
