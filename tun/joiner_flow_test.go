//nolint:testpackage // These tests control the internal clock and packet parser.
package tun

import (
	"encoding/binary"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestJoinerSharedAddressRoutingIsOptIn(t *testing.T) {
	j := NewJoiner(nil, testDebugPool(t))
	defer closeJoiner(t, j)

	first := newMockTun(4, 1500, 0, 0)
	second := newMockTun(4, 1500, 0, 0)
	attachJoinerPair(t, j, first, second)

	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	firstFlow := testIPv4Transport(local, remote, joinerProtocolTCP, 41001, 443)
	secondFlow := testIPv4Transport(
		local, remote, joinerProtocolTCP, 41002, 443,
	)
	learnJoinerBatch(t, j, first, firstFlow)
	learnJoinerBatch(t, j, second, secondFlow)

	reply := testIPv4Transport(remote, local, joinerProtocolTCP, 443, 41001)
	writeJoinerBatch(t, j, reply)
	if got := second.waitForWrittenPackets(1, time.Second); !reflect.DeepEqual(
		got,
		[][]byte{reply},
	) {
		t.Fatalf(
			"legacy address route packets = %v, want %v",
			got,
			[][]byte{reply},
		)
	}
	if stats := j.RoutingStats(); stats != (JoinerRoutingStats{}) {
		t.Fatalf("legacy RoutingStats() = %+v, want zero", stats)
	}
}

func TestJoinerSharedAddressConcurrentIPv4TCPFlows(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	first := newMockTun(64, 1500, 0, 0)
	second := newMockTun(64, 1500, 0, 0)
	attachJoinerPair(t, j, first, second)

	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	const flowCount = 32
	firstOutbound := make([][]byte, flowCount)
	secondOutbound := make([][]byte, flowCount)
	firstReplies := make([][]byte, flowCount)
	secondReplies := make([][]byte, flowCount)
	firstPort := uint16(40000)
	secondPort := uint16(50000)
	for i := range flowCount {
		firstOutbound[i] = testIPv4Transport(
			local, remote, joinerProtocolTCP, firstPort, 443,
		)
		secondOutbound[i] = testIPv4Transport(
			local, remote, joinerProtocolTCP, secondPort, 443,
		)
		firstReplies[i] = testIPv4Transport(
			remote, local, joinerProtocolTCP, 443, firstPort,
		)
		secondReplies[i] = testIPv4Transport(
			remote, local, joinerProtocolTCP, 443, secondPort,
		)
		firstPort++
		secondPort++
	}

	// Both read goroutines learn routes at the same time. Their common address
	// route can change in any order, but their flow routes must stay separate.
	first.enqueueRead(mockReadResult{packets: firstOutbound})
	second.enqueueRead(mockReadResult{packets: secondOutbound})
	wantRead := append(append([][]byte{}, firstOutbound...), secondOutbound...)
	readJoinerPacketsUnordered(t, j, wantRead)

	// Use mixed-owner batches from concurrent writers to probe both batch
	// splitting and the routing lock.
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for shard := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			packets := make([][]byte, 0, flowCount)
			for i := shard; i < flowCount; i += 2 {
				packets = append(packets, firstReplies[i], secondReplies[i])
			}
			bufs := make([][]byte, len(packets))
			for i := range packets {
				bufs[i] = withOffset(j.MWO(), packets[i])
			}
			if n, err := j.Write(bufs, j.MWO()); err != nil {
				errors <- err
			} else if n != len(bufs) {
				errors <- errWriteNoProgress
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent Write() error = %v", err)
	}

	gotFirst := first.waitForWrittenPackets(flowCount, time.Second)
	gotSecond := second.waitForWrittenPackets(flowCount, time.Second)
	if !packetMultisetEqual(gotFirst, firstReplies) {
		t.Fatalf(
			"first flow replies = %v, want unordered %v",
			gotFirst,
			firstReplies,
		)
	}
	if !packetMultisetEqual(gotSecond, secondReplies) {
		t.Fatalf(
			"second flow replies = %v, want unordered %v",
			gotSecond,
			secondReplies,
		)
	}
	stats := j.RoutingStats()
	if stats.FlowRoutes != flowCount*2 || stats.ActiveFlows != flowCount*2 {
		t.Fatalf(
			"RoutingStats() = %+v, want %d flow routes and entries",
			stats,
			flowCount*2,
		)
	}
}

func TestJoinerSharedAddressContinuousTrafficCannotStealFlow(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	application := newMockTun(8, 1500, 0, 0)
	transport := newMockTun(8, 1500, 0, 0)
	attachJoinerPair(t, j, application, transport)

	local := [4]byte{192, 0, 2, 10}
	web := [4]byte{198, 51, 100, 80}
	overlay := [4]byte{203, 0, 113, 30}
	appFlow := testIPv4Transport(local, web, joinerProtocolTCP, 41001, 443)
	appReply := testIPv4Transport(web, local, joinerProtocolTCP, 443, 41001)
	learnJoinerBatch(t, j, application, appFlow)

	const iterations = 48
	overlayPort := uint16(52000)
	for range iterations {
		// Each overlay packet replaces the common address owner. It must not
		// replace the unrelated application flow owner.
		overlayPacket := testIPv4Transport(
			local,
			overlay,
			joinerProtocolUDP,
			overlayPort,
			41641,
		)
		learnJoinerBatch(t, j, transport, overlayPacket)
		writeJoinerBatch(t, j, appReply)
		overlayPort++
	}
	got := application.waitForWrittenPackets(iterations, time.Second)
	if len(got) != iterations {
		t.Fatalf("application replies = %d, want %d", len(got), iterations)
	}
	if got := transport.waitForWrittenPackets(
		1,
		30*time.Millisecond,
	); len(
		got,
	) != 0 {
		t.Fatalf("transport received %d unrelated replies, want 0", len(got))
	}
}

func TestJoinerSharedAddressIPv6ExtensionsAndMixedProtocols(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	first := newMockTun(8, 1500, 0, 0)
	second := newMockTun(8, 1500, 0, 0)
	attachJoinerPair(t, j, first, second)

	local := [16]byte{0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
	remote := [16]byte{0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20}
	tcp := testIPv6TransportWithHopByHop(
		local, remote, joinerProtocolTCP, 41001, 443,
	)
	udp := testIPv6Transport(local, remote, joinerProtocolUDP, 51820, 41641)
	secondTCP := testIPv6Transport(
		local,
		remote,
		joinerProtocolTCP,
		41002,
		443,
	)
	learnJoinerBatch(t, j, first, tcp)
	learnJoinerBatch(t, j, second, udp, secondTCP)

	tcpReply := testIPv6TransportWithHopByHop(
		remote, local, joinerProtocolTCP, 443, 41001,
	)
	udpReply := testIPv6Transport(
		remote,
		local,
		joinerProtocolUDP,
		41641,
		51820,
	)
	secondTCPReply := testIPv6Transport(
		remote,
		local,
		joinerProtocolTCP,
		443,
		41002,
	)
	writeJoinerBatch(t, j, udpReply, tcpReply, secondTCPReply)
	if got := first.waitForWrittenPackets(1, time.Second); !reflect.DeepEqual(
		got,
		[][]byte{tcpReply},
	) {
		t.Fatalf("IPv6 TCP replies = %v, want %v", got, [][]byte{tcpReply})
	}
	if got := second.waitForWrittenPackets(2, time.Second); !reflect.DeepEqual(
		got,
		[][]byte{udpReply, secondTCPReply},
	) {
		t.Fatalf(
			"IPv6 second-owner replies = %v, want %v",
			got,
			[][]byte{udpReply, secondTCPReply},
		)
	}
}

func TestJoinerSharedAddressIdenticalFlowKeepsFirstOwner(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	first := newMockTun(4, 1500, 0, 0)
	second := newMockTun(4, 1500, 0, 0)
	attachJoinerPair(t, j, first, second)
	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	flow := testIPv4Transport(local, remote, joinerProtocolTCP, 41001, 443)
	learnJoinerBatch(t, j, first, flow)
	learnJoinerBatch(t, j, second, flow)

	reply := testIPv4Transport(remote, local, joinerProtocolTCP, 443, 41001)
	writeJoinerBatch(t, j, reply)
	if got := first.waitForWrittenPackets(1, time.Second); !reflect.DeepEqual(
		got,
		[][]byte{reply},
	) {
		t.Fatalf("first owner packets = %v, want %v", got, [][]byte{reply})
	}
	if got := second.waitForWrittenPackets(
		1,
		30*time.Millisecond,
	); len(
		got,
	) != 0 {
		t.Fatalf("colliding owner packets = %v, want none", got)
	}
	stats := j.RoutingStats()
	if stats.FlowCollisions != 1 || stats.ActiveFlows != 1 {
		t.Fatalf(
			"RoutingStats() = %+v, want one collision and active flow",
			stats,
		)
	}
}

func TestJoinerSharedAddressFlowRefreshExpiryAndFallback(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{FlowTimeout: 10 * time.Second})
	defer closeJoiner(t, j)

	now := time.Unix(1000, 0)
	j.now = func() time.Time { return now }
	addressOwner := newMockTun(4, 1500, 0, 0)
	flowOwner := newMockTun(4, 1500, 0, 0)
	attachJoinerPair(t, j, addressOwner, flowOwner)

	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	flow := testIPv4Transport(local, remote, joinerProtocolTCP, 41001, 443)
	reply := testIPv4Transport(remote, local, joinerProtocolTCP, 443, 41001)
	learnJoinerBatch(t, j, flowOwner, flow)
	// An unsupported protocol moves only the address fallback to the other Tun.
	learnJoinerBatch(
		t,
		j,
		addressOwner,
		testIPv4Protocol(local, remote, 99, nil),
	)

	now = now.Add(9 * time.Second)
	writeJoinerBatch(t, j, reply)
	now = now.Add(9 * time.Second)
	writeJoinerBatch(t, j, reply)
	now = now.Add(11 * time.Second)
	writeJoinerBatch(t, j, reply)

	if got := flowOwner.waitForWrittenPackets(2, time.Second); len(got) != 2 {
		t.Fatalf("flow owner packets = %d, want 2", len(got))
	}
	if got := addressOwner.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{reply},
	) {
		t.Fatalf("fallback packets = %v, want %v", got, [][]byte{reply})
	}
	stats := j.RoutingStats()
	if stats.FlowRoutes != 2 || stats.ExpiredRoutes != 1 ||
		stats.AddressFallbacks != 1 || stats.ActiveFlows != 0 {
		t.Fatalf(
			"RoutingStats() = %+v, want refresh, expiry, and fallback",
			stats,
		)
	}
}

func TestJoinerSharedAddressBoundedLRUEviction(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{MaxFlowEntries: 2})
	defer closeJoiner(t, j)

	addressOwner := newMockTun(8, 1500, 0, 0)
	flowOwner := newMockTun(8, 1500, 0, 0)
	attachJoinerPair(t, j, addressOwner, flowOwner)
	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	for _, port := range []uint16{41001, 41002} {
		learnJoinerBatch(t, j, flowOwner, testIPv4Transport(
			local, remote, joinerProtocolTCP, port, 443,
		))
	}
	learnJoinerBatch(
		t,
		j,
		addressOwner,
		testIPv4Protocol(local, remote, 99, nil),
	)
	learnJoinerBatch(t, j, flowOwner, testIPv4Transport(
		local, remote, joinerProtocolTCP, 41003, 443,
	))
	// Restore the other Tun as the address fallback after the last flow learn.
	learnJoinerBatch(
		t,
		j,
		addressOwner,
		testIPv4Protocol(local, remote, 99, nil),
	)

	oldestReply := testIPv4Transport(
		remote,
		local,
		joinerProtocolTCP,
		443,
		41001,
	)
	secondReply := testIPv4Transport(
		remote,
		local,
		joinerProtocolTCP,
		443,
		41002,
	)
	newestReply := testIPv4Transport(
		remote,
		local,
		joinerProtocolTCP,
		443,
		41003,
	)
	writeJoinerBatch(t, j, oldestReply, secondReply, newestReply)
	if got := addressOwner.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{oldestReply},
	) {
		t.Fatalf(
			"evicted flow fallback = %v, want %v",
			got,
			[][]byte{oldestReply},
		)
	}
	if got := flowOwner.waitForWrittenPackets(
		2,
		time.Second,
	); !packetMultisetEqual(
		got,
		[][]byte{secondReply, newestReply},
	) {
		t.Fatalf("retained flow packets = %v", got)
	}
	stats := j.RoutingStats()
	if stats.EvictedRoutes != 1 || stats.ActiveFlows != 2 {
		t.Fatalf("RoutingStats() = %+v, want one LRU eviction", stats)
	}
}

func TestJoinerSharedAddressDetachAndReattachRemovesFlowState(t *testing.T) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	defaultTun := newMockTun(4, 1500, 0, 0)
	oldOwner := newMockTun(4, 1500, 0, 0)
	attachJoinerPair(t, j, defaultTun, oldOwner)
	local := [4]byte{192, 0, 2, 10}
	remote := [4]byte{198, 51, 100, 20}
	flow := testIPv4Transport(local, remote, joinerProtocolUDP, 51820, 41641)
	reply := testIPv4Transport(remote, local, joinerProtocolUDP, 41641, 51820)
	learnJoinerBatch(t, j, oldOwner, flow)

	if err := j.Detach(oldOwner); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	if stats := j.RoutingStats(); stats.ActiveFlows != 0 {
		t.Fatalf("stats after detach = %+v, want no active flow", stats)
	}
	writeJoinerBatch(t, j, reply)
	if got := defaultTun.waitForWrittenPackets(1, time.Second); len(got) != 1 {
		t.Fatalf("default packets after detach = %d, want 1", len(got))
	}

	replacement := newMockTun(4, 1500, 0, 0)
	if err := j.AttachSecondary(replacement); err != nil {
		t.Fatalf("AttachSecondary(replacement) error = %v", err)
	}
	learnJoinerBatch(t, j, replacement, flow)
	writeJoinerBatch(t, j, reply)
	if got := replacement.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{reply},
	) {
		t.Fatalf("replacement packets = %v, want %v", got, [][]byte{reply})
	}
}

func TestJoinerSharedAddressRoutesICMPEchoAndQuotedErrors(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		j := newSharedAddressJoiner(t, JoinerOptions{})
		defer closeJoiner(t, j)
		first := newMockTun(8, 1500, 0, 0)
		second := newMockTun(8, 1500, 0, 0)
		attachJoinerPair(t, j, first, second)
		local := [4]byte{192, 0, 2, 10}
		remote := [4]byte{198, 51, 100, 20}
		router := [4]byte{203, 0, 113, 1}

		echoFirst := testIPv4ICMPEcho(local, remote, 8, 100)
		echoSecond := testIPv4ICMPEcho(local, remote, 8, 200)
		tcp := testIPv4Transport(local, remote, joinerProtocolTCP, 41001, 443)
		udp := testIPv4Transport(local, remote, joinerProtocolUDP, 51820, 41641)
		learnJoinerBatch(t, j, first, echoFirst, tcp)
		learnJoinerBatch(t, j, second, echoSecond, udp)

		firstEchoReply := testIPv4ICMPEcho(remote, local, 0, 100)
		secondEchoReply := testIPv4ICMPEcho(remote, local, 0, 200)
		tcpError := testIPv4ICMPError(router, local, 3, tcp)
		udpError := testIPv4ICMPError(router, local, 11, udp)
		writeJoinerBatch(
			t,
			j,
			secondEchoReply,
			tcpError,
			firstEchoReply,
			udpError,
		)
		wantFirst := [][]byte{tcpError, firstEchoReply}
		wantSecond := [][]byte{secondEchoReply, udpError}
		if got := first.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			wantFirst,
		) {
			t.Fatalf("first ICMP packets = %v, want %v", got, wantFirst)
		}
		if got := second.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			wantSecond,
		) {
			t.Fatalf("second ICMP packets = %v, want %v", got, wantSecond)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		j := newSharedAddressJoiner(t, JoinerOptions{})
		defer closeJoiner(t, j)
		first := newMockTun(8, 1500, 0, 0)
		second := newMockTun(8, 1500, 0, 0)
		attachJoinerPair(t, j, first, second)
		local := [16]byte{
			0x20,
			1,
			0xd,
			0xb8,
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			10,
		}
		remote := [16]byte{
			0x20,
			1,
			0xd,
			0xb8,
			0,
			2,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			20,
		}
		router := [16]byte{
			0x20,
			1,
			0xd,
			0xb8,
			0,
			3,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			1,
		}

		echoFirst := testIPv6ICMPEcho(local, remote, 128, 100)
		echoSecond := testIPv6ICMPEcho(local, remote, 128, 200)
		tcp := testIPv6Transport(local, remote, joinerProtocolTCP, 41001, 443)
		udp := testIPv6Transport(local, remote, joinerProtocolUDP, 51820, 41641)
		learnJoinerBatch(t, j, first, echoFirst, tcp)
		learnJoinerBatch(t, j, second, echoSecond, udp)

		firstEchoReply := testIPv6ICMPEcho(remote, local, 129, 100)
		secondEchoReply := testIPv6ICMPEcho(remote, local, 129, 200)
		tcpError := testIPv6ICMPError(router, local, 1, tcp)
		udpError := testIPv6ICMPError(router, local, 3, udp)
		writeJoinerBatch(
			t,
			j,
			udpError,
			firstEchoReply,
			tcpError,
			secondEchoReply,
		)
		if got := first.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{firstEchoReply, tcpError},
		) {
			t.Fatalf("first ICMPv6 packets = %v", got)
		}
		if got := second.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{udpError, secondEchoReply},
		) {
			t.Fatalf("second ICMPv6 packets = %v", got)
		}
	})
}

func TestJoinerSharedAddressRoutesIPv4AndIPv6Fragments(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		j := newSharedAddressJoiner(t, JoinerOptions{})
		defer closeJoiner(t, j)
		first := newMockTun(8, 1500, 0, 0)
		second := newMockTun(8, 1500, 0, 0)
		attachJoinerPair(t, j, first, second)
		local := [4]byte{192, 0, 2, 10}
		remote := [4]byte{198, 51, 100, 20}
		learnJoinerBatch(t, j, first, testIPv4Transport(
			local, remote, joinerProtocolTCP, 41001, 443,
		))
		learnJoinerBatch(t, j, second, testIPv4Transport(
			local, remote, joinerProtocolUDP, 51820, 41641,
		))

		firstHead := testIPv4FirstFragment(
			remote, local, joinerProtocolTCP, 443, 41001, 101,
		)
		firstTail := testIPv4LaterFragment(
			remote,
			local,
			joinerProtocolTCP,
			101,
			1,
		)
		secondHead := testIPv4FirstFragment(
			remote, local, joinerProtocolUDP, 41641, 51820, 202,
		)
		secondTail := testIPv4LaterFragment(
			remote,
			local,
			joinerProtocolUDP,
			202,
			1,
		)
		unknownTail := testIPv4LaterFragment(
			remote,
			local,
			joinerProtocolTCP,
			303,
			1,
		)
		writeJoinerBatch(
			t,
			j,
			firstHead,
			secondHead,
			secondTail,
			firstTail,
			unknownTail,
		)
		if got := first.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{firstHead, firstTail},
		) {
			t.Fatalf("first IPv4 fragments = %v", got)
		}
		if got := second.waitForWrittenPackets(
			3,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{secondHead, secondTail, unknownTail},
		) {
			t.Fatalf("second IPv4 fragments = %v", got)
		}
		stats := j.RoutingStats()
		if stats.FlowRoutes != 2 || stats.FragmentRoutes != 2 ||
			stats.AddressFallbacks != 1 {
			t.Fatalf("IPv4 RoutingStats() = %+v", stats)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		j := newSharedAddressJoiner(t, JoinerOptions{})
		defer closeJoiner(t, j)
		first := newMockTun(8, 1500, 0, 0)
		second := newMockTun(8, 1500, 0, 0)
		attachJoinerPair(t, j, first, second)
		local := [16]byte{
			0x20,
			1,
			0xd,
			0xb8,
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			10,
		}
		remote := [16]byte{
			0x20,
			1,
			0xd,
			0xb8,
			0,
			2,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			20,
		}
		learnJoinerBatch(t, j, first, testIPv6Transport(
			local, remote, joinerProtocolTCP, 41001, 443,
		))
		learnJoinerBatch(t, j, second, testIPv6Transport(
			local, remote, joinerProtocolUDP, 51820, 41641,
		))

		firstHead := testIPv6FirstFragment(
			remote, local, joinerProtocolTCP, 443, 41001, 101,
		)
		firstTail := testIPv6LaterFragment(
			remote,
			local,
			joinerProtocolTCP,
			101,
			1,
		)
		secondHead := testIPv6FirstFragment(
			remote, local, joinerProtocolUDP, 41641, 51820, 202,
		)
		secondTail := testIPv6LaterFragment(
			remote,
			local,
			joinerProtocolUDP,
			202,
			1,
		)
		writeJoinerBatch(t, j, secondHead, firstHead, firstTail, secondTail)
		if got := first.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{firstHead, firstTail},
		) {
			t.Fatalf("first IPv6 fragments = %v", got)
		}
		if got := second.waitForWrittenPackets(
			2,
			time.Second,
		); !packetMultisetEqual(
			got,
			[][]byte{secondHead, secondTail},
		) {
			t.Fatalf("second IPv6 fragments = %v", got)
		}
	})
}

func TestJoinerSharedAddressFallbackDiagnosticsAndMalformedPackets(
	t *testing.T,
) {
	j := newSharedAddressJoiner(t, JoinerOptions{})
	defer closeJoiner(t, j)

	// No route and no default causes a successful drop, including for malformed
	// IPv4, truncated IPv6 extensions, and an invalid packet version.
	writeJoinerBatch(t, j, []byte{0x45}, []byte{0x60, 0}, []byte{0xf0})
	defaultTun := newMockTun(4, 1500, 0, 0)
	if err := j.AttachDefault(defaultTun); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	unknown := testIPv4Protocol(
		[4]byte{198, 51, 100, 1},
		[4]byte{192, 0, 2, 99},
		99,
		nil,
	)
	writeJoinerBatch(t, j, unknown)
	if got := defaultTun.waitForWrittenPackets(
		1,
		time.Second,
	); !reflect.DeepEqual(
		got,
		[][]byte{unknown},
	) {
		t.Fatalf("default fallback packets = %v", got)
	}
	stats := j.RoutingStats()
	if stats.DroppedFallbacks != 3 || stats.DefaultFallbacks != 1 {
		t.Fatalf(
			"RoutingStats() = %+v, want drop and default diagnostics",
			stats,
		)
	}
}

func TestJoinerOptionsDefaults(t *testing.T) {
	j := NewJoinerWithOptions(nil, nil, JoinerOptions{
		SharedAddressRouting: true,
		FlowTimeout:          -time.Second,
		MaxFlowEntries:       -1,
	})
	defer closeJoiner(t, j)
	if j.flowTimeout != DefaultJoinerFlowTimeout {
		t.Fatalf(
			"flow timeout = %v, want %v",
			j.flowTimeout,
			DefaultJoinerFlowTimeout,
		)
	}
	if j.flowLimit != DefaultJoinerMaxFlowEntries {
		t.Fatalf(
			"flow limit = %d, want %d",
			j.flowLimit,
			DefaultJoinerMaxFlowEntries,
		)
	}
}

func TestJoinerFlowPacketParserEdgeCases(t *testing.T) {
	local4 := [4]byte{192, 0, 2, 10}
	remote4 := [4]byte{198, 51, 100, 20}
	plain4 := testIPv4Transport(
		local4,
		remote4,
		joinerProtocolTCP,
		41001,
		443,
	)
	withOptions := make([]byte, len(plain4)+4)
	copy(withOptions[:20], plain4[:20])
	copy(withOptions[24:], plain4[20:])
	withOptions[0] = 0x46
	binary.BigEndian.PutUint16(
		withOptions[2:],
		testUint16Length(len(withOptions)),
	)
	parsed4, ok := parseJoinerPacket(withOptions, 0)
	if !ok || parsed4.transportOffset != 24 {
		t.Fatalf(
			"IPv4 options parse = %+v, %v; want transport offset 24",
			parsed4,
			ok,
		)
	}
	if key, ok := joinerReverseFlowKey(parsed4); !ok ||
		key.sourcePort != 443 || key.destPort != 41001 {
		t.Fatalf("IPv4 options reverse key = %+v, %v", key, ok)
	}

	local6 := [16]byte{
		0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
	}
	remote6 := [16]byte{
		0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20,
	}
	udp := testIPv6Transport(
		local6,
		remote6,
		joinerProtocolUDP,
		51820,
		41641,
	)
	// Parse Routing, Destination Options, and Authentication headers before
	// the UDP header. The AH length field value 1 gives a 12-byte header.
	extensions := make([]byte, 28+len(udp[40:]))
	extensions[0] = 60
	extensions[8] = 51
	extensions[16] = joinerProtocolUDP
	extensions[17] = 1
	copy(extensions[28:], udp[40:])
	withExtensions := testIPv6Protocol(local6, remote6, 43, extensions)
	parsed6, ok := parseJoinerPacket(withExtensions, 0)
	if !ok || parsed6.protocol != joinerProtocolUDP ||
		parsed6.transportOffset != 68 {
		t.Fatalf(
			"IPv6 extension parse = %+v, %v; want UDP offset 68",
			parsed6,
			ok,
		)
	}

	badIPv4IHL := append([]byte{0x44}, make([]byte, 19)...)
	longIPv4IHL := append([]byte{0x46}, make([]byte, 19)...)
	badIPv4Length := append([]byte(nil), plain4...)
	binary.BigEndian.PutUint16(badIPv4Length[2:], 19)
	truncatedIPv6Option := testIPv6Protocol(local6, remote6, 0, nil)
	truncatedIPv6AH := testIPv6Protocol(local6, remote6, 51, []byte{0})
	tooManyExtensions := testIPv6Protocol(
		local6,
		remote6,
		0,
		make([]byte, 17*8),
	)
	for offset := 40; offset < len(tooManyExtensions); offset += 8 {
		tooManyExtensions[offset] = 0
	}

	invalidPackets := []struct {
		name   string
		packet []byte
		offset int
	}{
		{name: "negative offset", packet: plain4, offset: -1},
		{name: "empty", packet: nil},
		{name: "invalid version", packet: []byte{0xf0}},
		{name: "short IPv4", packet: []byte{0x45}},
		{name: "small IPv4 IHL", packet: badIPv4IHL},
		{name: "large IPv4 IHL", packet: longIPv4IHL},
		{name: "small IPv4 total length", packet: badIPv4Length},
		{name: "short IPv6", packet: []byte{0x60}},
		{name: "truncated IPv6 option", packet: truncatedIPv6Option},
		{name: "truncated IPv6 AH", packet: truncatedIPv6AH},
		{name: "too many IPv6 extensions", packet: tooManyExtensions},
	}
	for _, test := range invalidPackets {
		t.Run(test.name, func(t *testing.T) {
			if packet, ok := parseJoinerPacket(test.packet, test.offset); ok {
				t.Fatalf("parseJoinerPacket() = %+v, true; want false", packet)
			}
		})
	}

	if joinerICMPErrorType(joinerProtocolTCP, 3) ||
		joinerICMPErrorType(joinerProtocolICMPv4, 0) {
		t.Fatal("non-error ICMP types were classified as errors")
	}
	if _, ok := joinerICMPEchoPeerType(joinerProtocolICMPv4, 99); ok {
		t.Fatal("unknown ICMP echo type has a peer type")
	}
}

func newSharedAddressJoiner(t *testing.T, options JoinerOptions) *Joiner {
	t.Helper()
	options.SharedAddressRouting = true
	return NewJoinerWithOptions(nil, testDebugPool(t), options)
}

func closeJoiner(t *testing.T, j *Joiner) {
	t.Helper()
	if err := j.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func attachJoinerPair(t *testing.T, j *Joiner, first, second Tun) {
	t.Helper()
	if err := j.AttachDefault(first); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	if err := j.AttachSecondary(second); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}
}

func learnJoinerBatch(
	t *testing.T,
	j *Joiner,
	owner *mockTun,
	packets ...[]byte,
) {
	t.Helper()
	owner.enqueueRead(mockReadResult{packets: packets})
	got := readJoinerPackets(t, j, len(packets))
	if !reflect.DeepEqual(got, packets) {
		t.Fatalf("learned packets = %v, want %v", got, packets)
	}
}

func writeJoinerBatch(t *testing.T, j *Joiner, packets ...[]byte) {
	t.Helper()
	bufs := make([][]byte, len(packets))
	for i := range packets {
		bufs[i] = withOffset(j.MWO(), packets[i])
	}
	if n, err := j.Write(bufs, j.MWO()); err != nil || n != len(bufs) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(bufs))
	}
}

func testIPv4Transport(
	source, destination [4]byte,
	protocol uint8,
	sourcePort, destinationPort uint16,
) []byte {
	payloadLength := 8
	switch protocol {
	case joinerProtocolTCP:
		payloadLength = 20
	case joinerProtocolUDP:
		payloadLength = 8
	}
	payload := make([]byte, payloadLength)
	binary.BigEndian.PutUint16(payload, sourcePort)
	binary.BigEndian.PutUint16(payload[2:], destinationPort)
	switch protocol {
	case joinerProtocolTCP:
		payload[12] = 5 << 4
	case joinerProtocolUDP:
		binary.BigEndian.PutUint16(payload[4:], testUint16Length(payloadLength))
	}
	return testIPv4Protocol(source, destination, protocol, payload)
}

func testIPv4Protocol(
	source, destination [4]byte,
	protocol uint8,
	payload []byte,
) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = protocol
	binary.BigEndian.PutUint16(packet[2:], testUint16Length(len(packet)))
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	copy(packet[20:], payload)
	return packet
}

func testIPv6Transport(
	source, destination [16]byte,
	protocol uint8,
	sourcePort, destinationPort uint16,
) []byte {
	payloadLength := 8
	switch protocol {
	case joinerProtocolTCP:
		payloadLength = 20
	case joinerProtocolUDP:
		payloadLength = 8
	}
	payload := make([]byte, payloadLength)
	binary.BigEndian.PutUint16(payload, sourcePort)
	binary.BigEndian.PutUint16(payload[2:], destinationPort)
	switch protocol {
	case joinerProtocolTCP:
		payload[12] = 5 << 4
	case joinerProtocolUDP:
		binary.BigEndian.PutUint16(payload[4:], testUint16Length(payloadLength))
	}
	return testIPv6Protocol(source, destination, protocol, payload)
}

func testIPv6Protocol(
	source, destination [16]byte,
	protocol uint8,
	payload []byte,
) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], testUint16Length(len(payload)))
	packet[6] = protocol
	packet[7] = 64
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	copy(packet[40:], payload)
	return packet
}

func testIPv6TransportWithHopByHop(
	source, destination [16]byte,
	protocol uint8,
	sourcePort, destinationPort uint16,
) []byte {
	plain := testIPv6Transport(
		source, destination, protocol, sourcePort, destinationPort,
	)
	packet := make([]byte, len(plain)+8)
	copy(packet[:40], plain[:40])
	packet[6] = 0
	binary.BigEndian.PutUint16(packet[4:], testUint16Length(len(packet)-40))
	packet[40] = protocol
	copy(packet[48:], plain[40:])
	return packet
}

func testIPv4ICMPEcho(
	source, destination [4]byte,
	typeValue uint8,
	identifier uint16,
) []byte {
	payload := make([]byte, 8)
	payload[0] = typeValue
	binary.BigEndian.PutUint16(payload[4:], identifier)
	return testIPv4Protocol(source, destination, joinerProtocolICMPv4, payload)
}

func testIPv6ICMPEcho(
	source, destination [16]byte,
	typeValue uint8,
	identifier uint16,
) []byte {
	payload := make([]byte, 8)
	payload[0] = typeValue
	binary.BigEndian.PutUint16(payload[4:], identifier)
	return testIPv6Protocol(source, destination, joinerProtocolICMPv6, payload)
}

func testIPv4ICMPError(
	source, destination [4]byte,
	typeValue uint8,
	quoted []byte,
) []byte {
	payload := make([]byte, 8+len(quoted))
	payload[0] = typeValue
	copy(payload[8:], quoted)
	return testIPv4Protocol(source, destination, joinerProtocolICMPv4, payload)
}

func testIPv6ICMPError(
	source, destination [16]byte,
	typeValue uint8,
	quoted []byte,
) []byte {
	payload := make([]byte, 8+len(quoted))
	payload[0] = typeValue
	copy(payload[8:], quoted)
	return testIPv6Protocol(source, destination, joinerProtocolICMPv6, payload)
}

func testIPv4FirstFragment(
	source, destination [4]byte,
	protocol uint8,
	sourcePort, destinationPort uint16,
	identifier uint16,
) []byte {
	packet := testIPv4Transport(
		source, destination, protocol, sourcePort, destinationPort,
	)
	binary.BigEndian.PutUint16(packet[4:], identifier)
	binary.BigEndian.PutUint16(packet[6:], 0x2000)
	return packet
}

func testIPv4LaterFragment(
	source, destination [4]byte,
	protocol uint8,
	identifier, offset uint16,
) []byte {
	packet := testIPv4Protocol(source, destination, protocol, make([]byte, 8))
	binary.BigEndian.PutUint16(packet[4:], identifier)
	binary.BigEndian.PutUint16(packet[6:], offset&0x1fff)
	return packet
}

func testIPv6FirstFragment(
	source, destination [16]byte,
	protocol uint8,
	sourcePort, destinationPort uint16,
	identifier uint32,
) []byte {
	plain := testIPv6Transport(
		source, destination, protocol, sourcePort, destinationPort,
	)
	return testIPv6Fragment(
		source,
		destination,
		protocol,
		identifier,
		1,
		plain[40:],
	)
}

func testIPv6LaterFragment(
	source, destination [16]byte,
	protocol uint8,
	identifier uint32,
	offset uint16,
) []byte {
	return testIPv6Fragment(
		source, destination, protocol, identifier, offset<<3, make([]byte, 8),
	)
}

func testIPv6Fragment(
	source, destination [16]byte,
	protocol uint8,
	identifier uint32,
	fragmentField uint16,
	payload []byte,
) []byte {
	fragment := make([]byte, 8+len(payload))
	fragment[0] = protocol
	binary.BigEndian.PutUint16(fragment[2:], fragmentField)
	binary.BigEndian.PutUint32(fragment[4:], identifier)
	copy(fragment[8:], payload)
	return testIPv6Protocol(source, destination, 44, fragment)
}

//nolint:gosec // The test builders control every length.
func testUint16Length(length int) uint16 {
	// All test packets are much smaller than the maximum IPv4 or IPv6 packet.
	return uint16(length)
}
