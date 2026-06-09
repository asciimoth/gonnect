// nolint
package sockowner

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestFlowTupleFromOutgoingIPv4UDPPacket(t *testing.T) {
	packet := ipv4Packet(
		ipProtoUDP,
		net.IPv4(10, 0, 0, 2),
		net.IPv4(203, 0, 113, 7),
		udpHeader(12345, 53),
	)

	flow, err := FlowTupleFromOutgoingIPPacket(packet)
	if err != nil {
		t.Fatalf("FlowTupleFromOutgoingIPPacket() error = %v", err)
	}

	assertFlowTuple(t, flow, FlowTuple{
		Proto:      "udp",
		LocalIP:    net.IPv4(10, 0, 0, 2).To4(),
		LocalPort:  12345,
		RemoteIP:   net.IPv4(203, 0, 113, 7).To4(),
		RemotePort: 53,
	})
}

func TestFlowTupleFromIncomingIPv4TCPPacket(t *testing.T) {
	packet := ipv4Packet(
		ipProtoTCP,
		net.IPv4(203, 0, 113, 7),
		net.IPv4(10, 0, 0, 2),
		tcpHeader(443, 12345, 20),
	)

	flow, err := FlowTupleFromIncomingIPPacket(packet)
	if err != nil {
		t.Fatalf("FlowTupleFromIncomingIPPacket() error = %v", err)
	}

	assertFlowTuple(t, flow, FlowTuple{
		Proto:      "tcp",
		LocalIP:    net.IPv4(10, 0, 0, 2).To4(),
		LocalPort:  12345,
		RemoteIP:   net.IPv4(203, 0, 113, 7).To4(),
		RemotePort: 443,
	})
}

func TestFlowTupleFromIPv6PacketWithDestinationOptions(t *testing.T) {
	extHeader := make([]byte, 8)
	extHeader[0] = ipProtoTCP
	extHeader[1] = 0

	transport := tcpHeader(54321, 443, 20)
	payload := append(extHeader, transport...)

	packet := ipv6Packet(
		ipv6ExtDestinationOptions,
		net.ParseIP("fd00::1"),
		net.ParseIP("2001:db8::1"),
		payload,
	)

	flow, err := FlowTupleFromOutgoingIPPacket(packet)
	if err != nil {
		t.Fatalf("FlowTupleFromOutgoingIPPacket() error = %v", err)
	}

	assertFlowTuple(t, flow, FlowTuple{
		Proto:      "tcp",
		LocalIP:    net.ParseIP("fd00::1").To16(),
		LocalPort:  54321,
		RemoteIP:   net.ParseIP("2001:db8::1").To16(),
		RemotePort: 443,
	})
}

func TestFlowTupleFromIPv4NonFirstFragment(t *testing.T) {
	packet := ipv4Packet(
		ipProtoUDP,
		net.IPv4(10, 0, 0, 2),
		net.IPv4(203, 0, 113, 7),
		[]byte{1, 2, 3, 4, 5, 6, 7, 8},
	)
	binary.BigEndian.PutUint16(packet[6:8], 1)

	_, err := FlowTupleFromOutgoingIPPacket(packet)
	if !errors.Is(err, ErrNonFirstFragment) {
		t.Fatalf(
			"FlowTupleFromOutgoingIPPacket() error = %v, want %v",
			err,
			ErrNonFirstFragment,
		)
	}
}

func TestFlowTupleFromIPv6NonFirstFragment(t *testing.T) {
	fragHeader := make([]byte, 8)
	fragHeader[0] = ipProtoUDP
	binary.BigEndian.PutUint16(fragHeader[2:4], 8)

	packet := ipv6Packet(
		ipv6ExtFragment,
		net.ParseIP("fd00::1"),
		net.ParseIP("2001:db8::1"),
		fragHeader,
	)

	_, err := FlowTupleFromOutgoingIPPacket(packet)
	if !errors.Is(err, ErrNonFirstFragment) {
		t.Fatalf(
			"FlowTupleFromOutgoingIPPacket() error = %v, want %v",
			err,
			ErrNonFirstFragment,
		)
	}
}

func TestFlowTupleFromIPPacketMalformedTransportHeaders(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		wantErr error
	}{
		{
			name: "short UDP header",
			packet: ipv4Packet(
				ipProtoUDP,
				net.IPv4(10, 0, 0, 2),
				net.IPv4(203, 0, 113, 7),
				[]byte{0x30, 0x39, 0x00, 0x35},
			),
			wantErr: ErrShortPacket,
		},
		{
			name: "short TCP header",
			packet: ipv4Packet(
				ipProtoTCP,
				net.IPv4(10, 0, 0, 2),
				net.IPv4(203, 0, 113, 7),
				[]byte{0x30, 0x39, 0x01, 0xbb},
			),
			wantErr: ErrShortPacket,
		},
		{
			name: "invalid TCP data offset",
			packet: ipv4Packet(
				ipProtoTCP,
				net.IPv4(10, 0, 0, 2),
				net.IPv4(203, 0, 113, 7),
				tcpHeader(12345, 443, 16),
			),
			wantErr: ErrMalformedPacket,
		},
		{
			name: "truncated TCP options",
			packet: ipv4Packet(
				ipProtoTCP,
				net.IPv4(10, 0, 0, 2),
				net.IPv4(203, 0, 113, 7),
				tcpHeader(12345, 443, 24)[:20],
			),
			wantErr: ErrShortPacket,
		},
		{
			name: "unsupported protocol with short payload",
			packet: ipv4Packet(
				1,
				net.IPv4(10, 0, 0, 2),
				net.IPv4(203, 0, 113, 7),
				nil,
			),
			wantErr: ErrProtocol,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FlowTupleFromOutgoingIPPacket(tt.packet)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"FlowTupleFromOutgoingIPPacket() error = %v, want %v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func assertFlowTuple(t *testing.T, got, want FlowTuple) {
	t.Helper()

	if got.Proto != want.Proto {
		t.Fatalf("Proto = %q, want %q", got.Proto, want.Proto)
	}
	if !got.LocalIP.Equal(want.LocalIP) {
		t.Fatalf("LocalIP = %v, want %v", got.LocalIP, want.LocalIP)
	}
	if got.LocalPort != want.LocalPort {
		t.Fatalf("LocalPort = %d, want %d", got.LocalPort, want.LocalPort)
	}
	if !got.RemoteIP.Equal(want.RemoteIP) {
		t.Fatalf("RemoteIP = %v, want %v", got.RemoteIP, want.RemoteIP)
	}
	if got.RemotePort != want.RemotePort {
		t.Fatalf("RemotePort = %d, want %d", got.RemotePort, want.RemotePort)
	}
}

func ipv4Packet(proto uint8, srcIP, dstIP net.IP, payload []byte) []byte {
	headerLen := 20
	packet := make([]byte, headerLen+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())
	copy(packet[headerLen:], payload)
	return packet
}

func ipv6Packet(proto uint8, srcIP, dstIP net.IP, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = proto
	packet[7] = 64
	copy(packet[8:24], srcIP.To16())
	copy(packet[24:40], dstIP.To16())
	copy(packet[40:], payload)
	return packet
}

func udpHeader(srcPort, dstPort uint16) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(header)))
	return header
}

func tcpHeader(srcPort, dstPort uint16, headerLen int) []byte {
	header := make([]byte, max(headerLen, 20))
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	header[12] = byte(headerLen/4) << 4
	return header
}
