package routing //nolint:testpackage // Fuzzes internal bytecode and packet parsers.

import (
	"testing"

	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func FuzzRoutingInputs(f *testing.F) {
	f.Add(uint8(0), []byte("TRUE\nSLOT 1\n"))
	f.Add(uint8(0), []byte("NET4\nPORT 443\nAND\nSLOT 1\n"))
	f.Add(uint8(0), []byte("TRUE\nBACKEND secure\n"))
	f.Add(uint8(0), []byte("SNIFF HTTP HOST:example.test\nDROP\n"))
	f.Add(uint8(0), []byte("TRUE\nREMAP DST PORT 8443\n"))
	f.Add(uint8(1), []byte{OP_TRUE, OP_SLOT, 1})
	f.Add(uint8(2), fuzzRoutingIPv4Packet())
	f.Add(uint8(2), fuzzRoutingIPv6Packet())

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > 16<<10 {
			t.Skip()
		}
		switch kind % 3 {
		case 0:
			program := string(data)
			_, _ = NewBytecodeRules(program, program, program, program, program)
			_, _ = NewBytecodeRulesProgram(program)
			_, _ = NewSplitBytecodeRules(&sysnetdebug.System{}, program)
			_, _ = NewDNSBytecodeRules(program)
			_, _ = NewSnifferBytecodeRules(nil, program)
			_, _ = NewRemapperBytecodeRules(program)
		case 1:
			_, _ = NewBytecodeRouterCfg(BytecodeRules{DialTCP: data})
			_, _ = NewBytecodeDNSRouteFunc(DNSBytecodeRules{Route: data})
			_, _ = NewBytecodeSnifferControls(
				SnifferBytecodeRules{Control: data},
			)
			_, _ = NewBytecodeRemapRules(RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{Predicate: data}},
			})
		case 2:
			offset := 0
			if len(data) != 0 {
				offset = int(data[0]) % len(data)
			}
			packet, ok := parseIPPacket(data, offset)
			if ok && (packet.total <= 0 || packet.total > len(data)-offset) {
				t.Fatalf(
					"parsed total length %d is outside %d bytes",
					packet.total,
					len(data)-offset,
				)
			}
		}
	})
}

func fuzzRoutingIPv4Packet() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	packet[9] = 17
	packet[12] = 192
	packet[13] = 0
	packet[14] = 2
	packet[15] = 1
	packet[16] = 198
	packet[17] = 51
	packet[18] = 100
	packet[19] = 2
	packet[20] = 0x12
	packet[21] = 0x34
	packet[22] = 0
	packet[23] = 53
	return packet
}

func fuzzRoutingIPv6Packet() []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[5] = 8
	packet[6] = 17
	packet[23] = 1
	packet[39] = 2
	packet[40] = 0x12
	packet[41] = 0x34
	packet[43] = 53
	return packet
}
