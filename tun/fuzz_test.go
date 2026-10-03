package tun //nolint:testpackage // Fuzzes internal packet parsers.

import "testing"

func FuzzPacketInputs(f *testing.F) {
	f.Add([]byte{})
	f.Add(fuzzTunIPv4Packet())
	f.Add(fuzzTunIPv6Packet())
	f.Add(append([]byte{0, 0, 0, 0}, fuzzTunIPv4Packet()...))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		offset := 0
		if len(data) != 0 {
			offset = int(data[0]) % len(data)
		}
		packet, ok := parseJoinerPacket(data, offset)
		if ok {
			if packet.transportOffset < 0 ||
				packet.transportOffset > len(packet.data) {
				t.Fatalf(
					"joiner transport offset %d outside %d bytes",
					packet.transportOffset,
					len(packet.data),
				)
			}
			_, _ = joinerDirectFlowKey(packet)
			_, _ = joinerInboundFlowKey(packet)
			_, _ = joinerReverseFlowKey(packet)
		}
		_, _ = parseFirewallPacket(data)
		_, _, _ = ipv6TransportOffset(data)
		_, _ = firewallTunPacket(data, len(data)-offset, offset)
	})
}

func fuzzTunIPv4Packet() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[3] = byte(len(packet))
	packet[9] = 17
	copy(packet[12:20], []byte{192, 0, 2, 1, 198, 51, 100, 2})
	copy(packet[20:24], []byte{0x12, 0x34, 0, 53})
	return packet
}

func fuzzTunIPv6Packet() []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[5] = 8
	packet[6] = 17
	packet[23] = 1
	packet[39] = 2
	copy(packet[40:44], []byte{0x12, 0x34, 0, 53})
	return packet
}
