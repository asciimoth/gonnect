//nolint:testpackage // These benchmarks measure unexported routing hot paths.
package tun

import (
	"os"
	"testing"
	"time"
)

var joinerBenchmarkOwner *joinerNested

func BenchmarkJoinerAddressRoute(b *testing.B) {
	owner := &joinerNested{}
	packet := testIPv4Transport(
		[4]byte{198, 51, 100, 20},
		[4]byte{192, 0, 2, 10},
		joinerProtocolTCP,
		443,
		41001,
	)
	j := &Joiner{
		defaultTun: owner,
		routes4:    map[uint32]*joinerNested{0xc000020a: owner},
		routes6:    make(map[[16]byte]*joinerNested),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		joinerBenchmarkOwner = j.route(packet, 0)
	}
}

func BenchmarkJoinerAddressLearn(b *testing.B) {
	owner := &joinerNested{}
	packet := testIPv4Transport(
		[4]byte{192, 0, 2, 10},
		[4]byte{198, 51, 100, 20},
		joinerProtocolTCP,
		41001,
		443,
	)
	j := &Joiner{
		nested:  map[Tun]*joinerNested{nil: owner},
		routes4: make(map[uint32]*joinerNested),
		routes6: make(map[[16]byte]*joinerNested),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		j.rememberRoute(packet, owner)
	}
}

func BenchmarkJoinerFlowRoute(b *testing.B) {
	owner := &joinerNested{}
	outbound := testIPv4Transport(
		[4]byte{192, 0, 2, 10},
		[4]byte{198, 51, 100, 20},
		joinerProtocolTCP,
		41001,
		443,
	)
	inbound := testIPv4Transport(
		[4]byte{198, 51, 100, 20},
		[4]byte{192, 0, 2, 10},
		joinerProtocolTCP,
		443,
		41001,
	)
	j := newJoinerBenchmarkFlowTable(owner)
	j.rememberRoute(outbound, owner)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		joinerBenchmarkOwner = j.route(inbound, 0)
	}
}

func BenchmarkJoinerFlowLearnExisting(b *testing.B) {
	owner := &joinerNested{}
	packet := testIPv4Transport(
		[4]byte{192, 0, 2, 10},
		[4]byte{198, 51, 100, 20},
		joinerProtocolTCP,
		41001,
		443,
	)
	j := newJoinerBenchmarkFlowTable(owner)
	j.rememberRoute(packet, owner)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		j.rememberRoute(packet, owner)
	}
}

func BenchmarkJoinerFlowLearnChurn(b *testing.B) {
	owner := &joinerNested{}
	packet := testIPv4Transport(
		[4]byte{192, 0, 2, 10},
		[4]byte{198, 51, 100, 20},
		joinerProtocolTCP,
		1,
		443,
	)
	j := newJoinerBenchmarkFlowTable(owner)
	j.flowLimit = 256

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		packet[20] = byte(i >> 8)
		packet[21] = byte(i)
		j.rememberRoute(packet, owner)
	}
}

func BenchmarkJoinerWriteBatch(b *testing.B) {
	tests := []struct {
		name string
		size int
	}{
		{name: "1_packet", size: 1},
		{name: "64_packets", size: 64},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			device := joinerBenchmarkTun{}
			owner := &joinerNested{t: device, up: true}
			packet := make([]byte, joinerOffset+24)
			copy(packet[joinerOffset:], testIPv4Transport(
				[4]byte{198, 51, 100, 20},
				[4]byte{192, 0, 2, 10},
				joinerProtocolTCP,
				443,
				41001,
			))
			packets := make([][]byte, test.size)
			for i := range packets {
				packets[i] = packet
			}
			j := &Joiner{
				defaultTun: owner,
				routes4:    map[uint32]*joinerNested{0xc000020a: owner},
				routes6:    make(map[[16]byte]*joinerNested),
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := j.Write(packets, joinerOffset); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJoinerWriteMixedBatch(b *testing.B) {
	device := joinerBenchmarkTun{}
	first := &joinerNested{t: device, up: true}
	second := &joinerNested{t: device, up: true}
	firstPacket := make([]byte, joinerOffset+24)
	secondPacket := make([]byte, joinerOffset+24)
	copy(firstPacket[joinerOffset:], testIPv4Transport(
		[4]byte{198, 51, 100, 20},
		[4]byte{192, 0, 2, 10},
		joinerProtocolTCP,
		443,
		41001,
	))
	copy(secondPacket[joinerOffset:], testIPv4Transport(
		[4]byte{198, 51, 100, 20},
		[4]byte{192, 0, 2, 11},
		joinerProtocolTCP,
		443,
		41002,
	))
	packets := make([][]byte, 64)
	for i := range packets {
		if i%2 == 0 {
			packets[i] = firstPacket
		} else {
			packets[i] = secondPacket
		}
	}
	j := &Joiner{
		defaultTun: first,
		routes4: map[uint32]*joinerNested{
			0xc000020a: first,
			0xc000020b: second,
		},
		routes6: make(map[[16]byte]*joinerNested),
	}

	// Populate the reusable target batch before allocation measurement starts.
	if _, err := j.Write(packets, joinerOffset); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := j.Write(packets, joinerOffset); err != nil {
			b.Fatal(err)
		}
	}
}

type joinerBenchmarkTun struct{}

func (joinerBenchmarkTun) File() *os.File { return nil }

func (joinerBenchmarkTun) IsNative() bool { return false }
func (joinerBenchmarkTun) MWO() int       { return 0 }
func (joinerBenchmarkTun) MRO() int       { return 0 }

func (joinerBenchmarkTun) MTU() (int, error) { return 1500, nil }

func (joinerBenchmarkTun) Name() (string, error) { return "benchmark", nil }
func (joinerBenchmarkTun) Events() <-chan Event  { return nil }

func (joinerBenchmarkTun) BatchSize() int { return joinerDefaultBatch }
func (joinerBenchmarkTun) Close() error   { return nil }

func (joinerBenchmarkTun) Read(
	[][]byte,
	[]int,
	int,
) (int, error) {
	return 0, nil
}
func (joinerBenchmarkTun) Write(bufs [][]byte, _ int) (int, error) {
	return len(bufs), nil
}

func newJoinerBenchmarkFlowTable(owner *joinerNested) *Joiner {
	now := time.Unix(1_000, 0)
	return &Joiner{
		defaultTun:  owner,
		nested:      map[Tun]*joinerNested{nil: owner},
		routes4:     make(map[uint32]*joinerNested),
		routes6:     make(map[[16]byte]*joinerNested),
		flowRouting: true,
		flowTimeout: DefaultJoinerFlowTimeout,
		flowLimit:   DefaultJoinerMaxFlowEntries,
		flows:       make(map[joinerFlowKey]*joinerDynamicRoute),
		fragments:   make(map[joinerFragmentKey]*joinerDynamicRoute),
		now:         func() time.Time { return now },
	}
}
