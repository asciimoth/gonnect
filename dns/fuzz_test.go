package dns //nolint:testpackage // Fuzzes internal IP packet parsing.

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func FuzzWireAndIPPacketInputs(f *testing.F) {
	query, err := Pack(&Message{
		ID: 1,
		Questions: []Question{{
			Name:  "example.test.",
			Type:  TypeA,
			Class: ClassIN,
		}},
	})
	if err != nil {
		f.Fatalf("make seed query: %v", err)
	}
	f.Add(uint8(0), query)
	f.Add(uint8(0), []byte{})
	f.Add(uint8(1), fuzzDNSIPv4Packet(query))
	f.Add(uint8(1), fuzzDNSIPv6Packet(query))
	f.Add(uint8(2), []byte("example.test."))
	f.Add(uint8(3), append([]byte{byte(TypeTXT)}, []byte("text")...))

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}

		switch kind % 4 {
		case 0:
			message, unpackErr := Unpack(data)
			if unpackErr != nil {
				return
			}
			packed, packErr := Pack(message)
			if packErr != nil {
				t.Fatalf("Pack after successful Unpack: %v", packErr)
			}
			roundTrip, roundTripErr := Unpack(packed)
			if roundTripErr != nil {
				t.Fatalf("Unpack after round trip: %v", roundTripErr)
			}
			if !reflect.DeepEqual(roundTrip, message) {
				t.Fatalf(
					"DNS round trip changed message: got %#v, want %#v",
					roundTrip,
					message,
				)
			}
		case 1:
			request, ok := parseDNSIPPacket(data)
			if !ok {
				return
			}
			if request.dstPort != dnsPort {
				t.Fatalf(
					"parsed destination port = %d, want %d",
					request.dstPort,
					dnsPort,
				)
			}
			if !bytes.Contains(data, request.payload) &&
				len(request.payload) != 0 {
				t.Fatal("parsed payload is not present in the packet")
			}
			_, _ = Unpack(request.payload)
		case 2:
			fuzzDNSPackRoundTrip(t, &Message{
				ID: uint16(kind),
				Questions: []Question{{
					Name:  string(data),
					Type:  TypeA,
					Class: ClassIN,
				}},
			})
		case 3:
			if len(data) == 0 {
				return
			}
			types := [...]uint16{
				TypeA, TypeAAAA, TypeCNAME, TypeNS, TypePTR,
				TypeMX, TypeSRV, TypeTXT, 65000,
			}
			fuzzDNSPackRoundTrip(t, &Message{
				ID: uint16(kind),
				Answers: []Resource{{
					Name:  "fuzz.test.",
					Type:  types[int(data[0])%len(types)],
					Class: ClassIN,
					Data:  data[1:],
				}},
			})
		}
	})
}

func fuzzDNSPackRoundTrip(t *testing.T, message *Message) {
	t.Helper()
	packet, err := Pack(message)
	if err != nil {
		return
	}
	if _, err := Unpack(packet); err != nil {
		t.Fatalf("Unpack after successful Pack: %v", err)
	}
}

func fuzzDNSIPv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	// #nosec G115 -- Seed DNS packets are smaller than the wire limit.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = ipProtocolUDP
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{192, 0, 2, 53})
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], 53000)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	// #nosec G115 -- Seed DNS packets are smaller than the wire limit.
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	binary.BigEndian.PutUint16(
		udp[6:8],
		udpChecksumIPv4(packet[12:16], packet[16:20], udp),
	)
	return packet
}

func fuzzDNSIPv6Packet(payload []byte) []byte {
	packet := make([]byte, 40+8+len(payload))
	packet[0] = 0x60
	// #nosec G115 -- Seed DNS packets are smaller than the wire limit.
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	packet[6] = ipProtocolUDP
	packet[7] = 64
	packet[23] = 1
	packet[39] = 2
	udp := packet[40:]
	binary.BigEndian.PutUint16(udp[0:2], 53000)
	binary.BigEndian.PutUint16(udp[2:4], dnsPort)
	// #nosec G115 -- Seed DNS packets are smaller than the wire limit.
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(
		udp[6:8],
		udpChecksumIPv6(packet[8:24], packet[24:40], udp),
	)
	return packet
}
