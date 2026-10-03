package sockowner //nolint:testpackage // Uses protocol constants in packet seeds.

import "testing"

func FuzzIPPacketInputs(f *testing.F) {
	f.Add([]byte{})
	f.Add(fuzzSockownerIPv4Packet())
	f.Add(fuzzSockownerIPv6Packet())

	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 64<<10 {
			t.Skip()
		}
		outgoing, outgoingErr := FlowTupleFromOutgoingIPPacket(packet)
		incoming, incomingErr := FlowTupleFromIncomingIPPacket(packet)
		if (outgoingErr == nil) != (incomingErr == nil) {
			t.Fatalf(
				"packet validity depends on direction: outgoing %v, incoming %v",
				outgoingErr,
				incomingErr,
			)
		}
		if outgoingErr == nil {
			if !outgoing.LocalIP.Equal(incoming.RemoteIP) ||
				!outgoing.RemoteIP.Equal(incoming.LocalIP) ||
				outgoing.LocalPort != incoming.RemotePort ||
				outgoing.RemotePort != incoming.LocalPort {
				t.Fatalf(
					"incoming tuple is not the reverse of outgoing: %#v, %#v",
					outgoing,
					incoming,
				)
			}
		}
	})
}

func fuzzSockownerIPv4Packet() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[3] = byte(len(packet))
	packet[9] = ipProtoUDP
	copy(packet[12:20], []byte{192, 0, 2, 1, 198, 51, 100, 2})
	copy(packet[20:24], []byte{0x12, 0x34, 0, 53})
	return packet
}

func fuzzSockownerIPv6Packet() []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[5] = 8
	packet[6] = ipProtoUDP
	packet[23] = 1
	packet[39] = 2
	copy(packet[40:44], []byte{0x12, 0x34, 0, 53})
	return packet
}
