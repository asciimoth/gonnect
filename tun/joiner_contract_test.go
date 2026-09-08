package tun_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

const contractTimeout = 2 * time.Second

// TestJoinerSharedAddressBehaviorContract specifies behavior through exported
// APIs only. Keep these subtests independent from the flow-table implementation.
func TestJoinerSharedAddressBehaviorContract(t *testing.T) {
	t.Run("legacy constructor keeps address routing", func(t *testing.T) {
		joiner := contractJoiner(t, tun.JoinerOptions{})
		first := newContractTun()
		second := newContractTun()
		contractAttachPair(t, joiner, first, second)

		local := [4]byte{192, 0, 2, 10}
		remote := [4]byte{198, 51, 100, 20}
		firstFlow := contractIPv4Transport(local, remote, 6, 41001, 443)
		secondFlow := contractIPv4Transport(local, remote, 6, 41002, 443)
		contractLearn(t, joiner, first, firstFlow)
		contractLearn(t, joiner, second, secondFlow)

		firstReply := contractIPv4Transport(remote, local, 6, 443, 41001)
		contractWrite(t, joiner, firstReply)
		contractRequirePackets(t, second, firstReply)
		contractRequireNoPacket(t, first)
		if stats := joiner.RoutingStats(); stats != (tun.JoinerRoutingStats{}) {
			t.Fatalf("RoutingStats() = %+v, want zero in legacy mode", stats)
		}
	})

	t.Run("shared IPv4 and IPv6 flows stay isolated", func(t *testing.T) {
		joiner := contractJoiner(t, tun.JoinerOptions{
			SharedAddressRouting: true,
		})
		first := newContractTun()
		second := newContractTun()
		contractAttachPair(t, joiner, first, second)

		local4 := [4]byte{192, 0, 2, 10}
		remote4 := [4]byte{198, 51, 100, 20}
		local6 := [16]byte{
			0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
		}
		remote6 := [16]byte{
			0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20,
		}

		first4 := contractIPv4Transport(local4, remote4, 6, 41001, 443)
		second4 := contractIPv4Transport(local4, remote4, 6, 41002, 443)
		first6 := contractIPv6Transport(local6, remote6, 17, 51820, 41641)
		second6 := contractIPv6Transport(local6, remote6, 6, 42002, 443)
		contractLearn(t, joiner, first, first4, first6)
		contractLearn(t, joiner, second, second4, second6)

		first4Reply := contractIPv4Transport(remote4, local4, 6, 443, 41001)
		second4Reply := contractIPv4Transport(remote4, local4, 6, 443, 41002)
		first6Reply := contractIPv6Transport(remote6, local6, 17, 41641, 51820)
		second6Reply := contractIPv6Transport(remote6, local6, 6, 443, 42002)
		contractWrite(
			t,
			joiner,
			second6Reply,
			first4Reply,
			second4Reply,
			first6Reply,
		)
		contractRequirePackets(t, first, first4Reply, first6Reply)
		contractRequirePackets(t, second, second6Reply, second4Reply)

		stats := joiner.RoutingStats()
		if stats.FlowRoutes != 4 || stats.ActiveFlows != 4 {
			t.Fatalf("RoutingStats() = %+v, want four isolated flows", stats)
		}
	})

	t.Run("first collision owner wins until detach", func(t *testing.T) {
		joiner := contractJoiner(t, tun.JoinerOptions{
			SharedAddressRouting: true,
		})
		first := newContractTun()
		second := newContractTun()
		contractAttachPair(t, joiner, first, second)

		local := [4]byte{192, 0, 2, 10}
		remote := [4]byte{198, 51, 100, 20}
		flow := contractIPv4Transport(local, remote, 6, 41001, 443)
		reply := contractIPv4Transport(remote, local, 6, 443, 41001)
		contractLearn(t, joiner, first, flow)
		contractLearn(t, joiner, second, flow)

		contractWrite(t, joiner, reply)
		contractRequirePackets(t, first, reply)
		contractRequireNoPacket(t, second)
		stats := joiner.RoutingStats()
		if stats.FlowCollisions != 1 || stats.ActiveFlows != 1 {
			t.Fatalf("collision stats = %+v, want first-owner collision", stats)
		}

		if err := joiner.Detach(first); err != nil {
			t.Fatalf("Detach(first) error = %v", err)
		}
		if stats := joiner.RoutingStats(); stats.ActiveFlows != 0 {
			t.Fatalf("stats after detach = %+v, want no active flow", stats)
		}
		// The second Tun owns the compatibility address route because it sent
		// the latest outbound packet. It receives the packet after detach.
		contractWrite(t, joiner, reply)
		contractRequirePackets(t, second, reply)
	})

	t.Run(
		"flow refresh and expiry expose address fallback",
		func(t *testing.T) {
			joiner := contractJoiner(t, tun.JoinerOptions{
				SharedAddressRouting: true,
				FlowTimeout:          25 * time.Millisecond,
			})
			addressOwner := newContractTun()
			flowOwner := newContractTun()
			contractAttachPair(t, joiner, addressOwner, flowOwner)

			local := [4]byte{192, 0, 2, 10}
			remote := [4]byte{198, 51, 100, 20}
			flow := contractIPv4Transport(local, remote, 17, 51820, 41641)
			reply := contractIPv4Transport(remote, local, 17, 41641, 51820)
			contractLearn(t, joiner, flowOwner, flow)
			contractLearn(
				t,
				joiner,
				addressOwner,
				contractIPv4Protocol(local, remote, 99, nil),
			)

			contractWrite(t, joiner, reply)
			contractRequirePackets(t, flowOwner, reply)
			time.Sleep(100 * time.Millisecond)
			contractWrite(t, joiner, reply)
			contractRequirePackets(t, addressOwner, reply)

			stats := joiner.RoutingStats()
			if stats.FlowRoutes != 1 || stats.AddressFallbacks != 1 ||
				stats.ExpiredRoutes != 1 || stats.ActiveFlows != 0 {
				t.Fatalf(
					"expiry stats = %+v, want flow then address fallback",
					stats,
				)
			}
		},
	)

	t.Run(
		"fallback diagnostics distinguish default and drop",
		func(t *testing.T) {
			joiner := contractJoiner(t, tun.JoinerOptions{
				SharedAddressRouting: true,
			})
			malformed := []byte{0xf0}
			contractWrite(t, joiner, malformed)

			defaultTun := newContractTun()
			if err := joiner.AttachDefault(defaultTun); err != nil {
				t.Fatalf("AttachDefault() error = %v", err)
			}
			contractWrite(t, joiner, malformed)
			contractRequirePackets(t, defaultTun, malformed)

			stats := joiner.RoutingStats()
			if stats.DroppedFallbacks != 1 || stats.DefaultFallbacks != 1 {
				t.Fatalf(
					"fallback stats = %+v, want one drop and one default",
					stats,
				)
			}
		},
	)

	t.Run(
		"entry limit evicts the least recently used flow",
		func(t *testing.T) {
			joiner := contractJoiner(t, tun.JoinerOptions{
				SharedAddressRouting: true,
				MaxFlowEntries:       2,
			})
			addressOwner := newContractTun()
			flowOwner := newContractTun()
			contractAttachPair(t, joiner, addressOwner, flowOwner)

			local := [4]byte{192, 0, 2, 10}
			remote := [4]byte{198, 51, 100, 20}
			first := contractIPv4Transport(local, remote, 6, 41001, 443)
			second := contractIPv4Transport(local, remote, 6, 41002, 443)
			third := contractIPv4Transport(local, remote, 6, 41003, 443)
			firstReply := contractIPv4Transport(remote, local, 6, 443, 41001)
			secondReply := contractIPv4Transport(remote, local, 6, 443, 41002)
			thirdReply := contractIPv4Transport(remote, local, 6, 443, 41003)
			contractLearn(t, joiner, flowOwner, first, second)

			// A matching inbound packet refreshes the first flow. The second flow
			// is now the least recently used route.
			contractWrite(t, joiner, firstReply)
			contractRequirePackets(t, flowOwner, firstReply)
			contractLearn(t, joiner, flowOwner, third)
			contractLearn(
				t,
				joiner,
				addressOwner,
				contractIPv4Protocol(local, remote, 99, nil),
			)

			contractWrite(t, joiner, secondReply, firstReply, thirdReply)
			contractRequirePackets(t, addressOwner, secondReply)
			contractRequirePackets(t, flowOwner, firstReply, thirdReply)
			stats := joiner.RoutingStats()
			if stats.EvictedRoutes != 1 || stats.ActiveFlows != 2 ||
				stats.AddressFallbacks != 1 || stats.FlowRoutes != 3 {
				t.Fatalf("LRU stats = %+v, want one refreshed survivor", stats)
			}
		},
	)
}

// contractTun is a controllable Tun used by the public behavior tests. It does
// not expose or use any Joiner implementation state.
type contractTun struct {
	outbound chan [][]byte
	inbound  chan []byte
	events   chan tun.Event
	closed   chan struct{}
	once     sync.Once
}

func newContractTun() *contractTun {
	return &contractTun{
		outbound: make(chan [][]byte, 16),
		inbound:  make(chan []byte, 256),
		events:   make(chan tun.Event),
		closed:   make(chan struct{}),
	}
}

func (device *contractTun) File() *os.File { return nil }

func (device *contractTun) IsNative() bool { return false }

func (device *contractTun) MWO() int { return 0 }

func (device *contractTun) MRO() int { return 0 }

func (device *contractTun) MTU() (int, error) { return 1500, nil }

func (device *contractTun) Name() (string, error) { return "contract", nil }

func (device *contractTun) Events() <-chan tun.Event { return device.events }

func (device *contractTun) BatchSize() int { return 16 }

func (device *contractTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative read offset")
	}
	select {
	case <-device.closed:
		return 0, os.ErrClosed
	case packets := <-device.outbound:
		count := min(len(packets), len(bufs), len(sizes))
		for index := range count {
			if offset > len(bufs[index]) ||
				len(packets[index]) > len(bufs[index])-offset {
				return index, io.ErrShortBuffer
			}
			copy(bufs[index][offset:], packets[index])
			sizes[index] = len(packets[index])
		}
		return count, nil
	}
}

func (device *contractTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative write offset")
	}
	for index, buf := range bufs {
		if offset > len(buf) {
			return index, io.ErrShortBuffer
		}
		packet := bytes.Clone(buf[offset:])
		select {
		case <-device.closed:
			return index, os.ErrClosed
		case device.inbound <- packet:
		}
	}
	return len(bufs), nil
}

func (device *contractTun) Close() error {
	device.once.Do(func() {
		close(device.closed)
		close(device.events)
	})
	return nil
}

func (device *contractTun) inject(packets ...[]byte) error {
	clones := make([][]byte, len(packets))
	for index := range packets {
		clones[index] = bytes.Clone(packets[index])
	}
	select {
	case <-device.closed:
		return os.ErrClosed
	case device.outbound <- clones:
		return nil
	}
}

func contractJoiner(t *testing.T, options tun.JoinerOptions) *tun.Joiner {
	t.Helper()
	var joiner *tun.Joiner
	if options == (tun.JoinerOptions{}) {
		joiner = tun.NewJoiner(nil, nil)
	} else {
		joiner = tun.NewJoinerWithOptions(nil, nil, options)
	}
	t.Cleanup(func() {
		if err := joiner.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return joiner
}

func contractAttachPair(
	t *testing.T,
	joiner *tun.Joiner,
	first, second tun.Tun,
) {
	t.Helper()
	if err := joiner.AttachDefault(first); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	if err := joiner.AttachSecondary(second); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
}

func contractLearn(
	t *testing.T,
	joiner *tun.Joiner,
	owner *contractTun,
	packets ...[]byte,
) {
	t.Helper()
	if err := owner.inject(packets...); err != nil {
		t.Fatalf("inject() error = %v", err)
	}
	got := contractRead(t, joiner, len(packets))
	if !reflect.DeepEqual(got, packets) {
		t.Fatalf("Joiner.Read() packets = %v, want %v", got, packets)
	}
}

func contractRead(t *testing.T, joiner *tun.Joiner, count int) [][]byte {
	t.Helper()
	type result struct {
		packets [][]byte
		err     error
	}
	results := make(chan result, 1)
	go func() {
		bufs := make([][]byte, count)
		sizes := make([]int, count)
		for index := range bufs {
			bufs[index] = make([]byte, joiner.MRO()+2048)
		}
		read, err := joiner.Read(bufs, sizes, joiner.MRO())
		packets := make([][]byte, read)
		for index := range read {
			start := joiner.MRO()
			packets[index] = bytes.Clone(
				bufs[index][start : start+sizes[index]],
			)
		}
		results <- result{packets: packets, err: err}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("Joiner.Read() error = %v", result.err)
		}
		return result.packets
	case <-time.After(contractTimeout):
		t.Fatal("Joiner.Read() timed out")
		return nil
	}
}

func contractWrite(t *testing.T, joiner *tun.Joiner, packets ...[]byte) {
	t.Helper()
	bufs := make([][]byte, len(packets))
	for index := range packets {
		bufs[index] = make([]byte, joiner.MWO()+len(packets[index]))
		copy(bufs[index][joiner.MWO():], packets[index])
	}
	written, err := joiner.Write(bufs, joiner.MWO())
	if err != nil || written != len(packets) {
		t.Fatalf(
			"Joiner.Write() = %d, %v; want %d, nil",
			written,
			err,
			len(packets),
		)
	}
}

func contractRequirePackets(
	t *testing.T,
	device *contractTun,
	want ...[]byte,
) {
	t.Helper()
	got := make([][]byte, 0, len(want))
	for range want {
		select {
		case packet := <-device.inbound:
			got = append(got, packet)
		case <-time.After(contractTimeout):
			t.Fatalf("received packets = %v, want %v", got, want)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("received packets = %v, want %v", got, want)
	}
}

func contractRequireNoPacket(t *testing.T, device *contractTun) {
	t.Helper()
	select {
	case packet := <-device.inbound:
		t.Fatalf("received unexpected packet %v", packet)
	case <-time.After(20 * time.Millisecond):
	}
}

func contractIPv4Transport(
	source, destination [4]byte,
	protocol byte,
	sourcePort, destinationPort uint16,
) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload, sourcePort)
	binary.BigEndian.PutUint16(payload[2:], destinationPort)
	return contractIPv4Protocol(source, destination, protocol, payload)
}

func contractIPv4Protocol(
	source, destination [4]byte,
	protocol byte,
	payload []byte,
) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = protocol
	contractPutLength(packet[2:], len(packet))
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	copy(packet[20:], payload)
	return packet
}

func contractIPv6Transport(
	source, destination [16]byte,
	protocol byte,
	sourcePort, destinationPort uint16,
) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload, sourcePort)
	binary.BigEndian.PutUint16(payload[2:], destinationPort)
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	contractPutLength(packet[4:], len(payload))
	packet[6] = protocol
	packet[7] = 64
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	copy(packet[40:], payload)
	return packet
}

//nolint:gosec // Contract packets are always smaller than 65536 bytes.
func contractPutLength(destination []byte, length int) {
	binary.BigEndian.PutUint16(destination, uint16(length))
}
