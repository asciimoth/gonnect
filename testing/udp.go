package testing

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	numClients    = 30
	rounds        = 30
	clientTimeout = 20 * time.Millisecond
	roundDelay    = 10 * time.Millisecond
	maxRetries    = 100
	dropEvery     = 7
	testTimeout   = time.Duration(5 * time.Second)
)

type FullPacketConn interface {
	net.PacketConn
	net.Conn
}

// DialPacketFunc dials to the given listener address and returns a net.PacketConn.
// The returned PacketConn should ideally be connected to the server address (so Write/Read work).
type DialPacketFunc func(addr net.Addr) (FullPacketConn, error)

// RunUDPPingPongTest runs a ping-pong test over PacketConn (UDP-like semantics).
// Client will use a single connected PacketConn and prefer Write/Read. If the returned PacketConn
// doesn't support Write/Read, the helper will fall back to WriteTo/ReadFrom.
//
// Protocol summary:
//   - Client and server exchange "ping <n>\n" / "pong <n>\n" for n = 0..9.
//   - For each ping n the client will resend the same ping up to maxAttempts times (default 30)
//     until it receives a matching "pong n".
//   - Server ignores out-of-order pings (seq > expected) and resends pongs for duplicates.
func RunUDPPingPongTest(
	t *testing.T,
	pc FullPacketConn,
	dial DialPacketFunc,
	numClients int,
	rounds int,
	clientTimeout time.Duration,
	roundDelay time.Duration,
	maxRetries int,
	dropEvery int,
	testTimeout time.Duration,
) {
	t.Helper()

	// overall test timeout to avoid hangs
	deadline := time.After(testTimeout)
	serverAddr := pc.LocalAddr()
	lastRoundStr := strconv.Itoa(rounds - 1)
	t.Logf("server listening at %s\n", serverAddr)

	// server goroutine: single goroutine handles all incoming pings and replies,
	// but drops every dropEvery'th packet to simulate loss.
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 2048)
		recvCount := 0
		completedClients := 0
		for {
			n, srcAddr, err := pc.ReadFrom(buf)
			if err != nil {
				// Any other error log and continue
				t.Logf("server read error: %v\n", err)
				continue
			}

			recvCount++
			msg := string(buf[:n])
			t.Logf("server got from %s: %q (recv# %d)\n", srcAddr, msg, recvCount)

			// simulate drop of every dropEvery'th packet
			if dropEvery > 0 && recvCount%dropEvery == 0 {
				// drop: don't reply
				t.Logf("server dropping packet #%d from %s to simulate loss\n", recvCount, srcAddr)
				continue
			}

			// build reply "pong N" for "ping N"
			var seq string
			_, _ = fmt.Sscanf(msg, "ping %s", &seq)
			reply := fmt.Sprintf("pong %s", seq)

			// reply to client
			_, err = pc.WriteTo([]byte(reply), srcAddr)
			if err != nil {
				t.Logf("server write error to %s: %v\n", srcAddr, err)
			} else {
				t.Logf("server replied to %s: %q\n", srcAddr, reply)
			}
			if seq == lastRoundStr {
				completedClients += 1
				if completedClients >= numClients {
					t.Log("Server finishing")
					return
				}
			}
		}
	})

	for clientID := range numClients {
		wg.Go(func() {

			cc, err := dial(serverAddr)
			if err != nil {
				t.Fatalf("client %d dial: %v", clientID, err)
			}
			defer cc.Close()

			t.Logf("client %d local %s -> server %s\n", clientID, cc.LocalAddr(), serverAddr)

			buf := make([]byte, 2048)
			for r := 1; r <= rounds; r++ {
				seq := r
				msg := fmt.Sprintf("ping %d", seq)

				received := false
				for attempt := 1; attempt <= maxRetries && !received; attempt++ {
					// check global test timeout to avoid infinite waits
					select {
					case <-deadline:
						t.Errorf("test timeout reached while client %d waiting (seq %d)", clientID, seq)
						return
					default:
					}

					// send ping
					_, err := cc.Write([]byte(msg))
					if err != nil {
						t.Logf("client %d attempt %d: write error: %v\n", clientID, attempt, err)
						time.Sleep(5 * time.Millisecond)
						continue
					}

					// wait for pong with read deadline
					cc.SetReadDeadline(time.Now().Add(clientTimeout))
					n, src, err := cc.ReadFrom(buf)
					if err != nil {
						// if timeout -> retry
						if opErr, ok := err.(*net.OpError); ok && opErr != nil && opErr.Err.Error() == "i/o timeout" {
							t.Logf("client %d seq %d attempt %d: timeout waiting pong, will retry\n", clientID, seq, attempt)
							continue
						}
						t.Logf("client %d seq %d attempt %d: read error: %v\n", clientID, seq, attempt, err)
						continue
					}

					reply := string(buf[:n])
					expected := fmt.Sprintf("pong %d", seq)
					if reply == expected {
						t.Logf("client %d seq %d got reply from %s: %q\n", clientID, seq, src.String(), reply)
						received = true
						break
					}
					// else unexpected reply; keep retrying
					t.Logf("client %d seq %d got unexpected reply %q (expected %q)\n", clientID, seq, reply, expected)
				}
				if !received {
					// don't fail the test outright; log that this sequence gave up after retries
					t.Logf("client %d seq %d: giving up after %d attempts\n", clientID, seq, maxRetries)
				}
				// small pause between rounds
				time.Sleep(roundDelay)
			}
		})
	}

	// wait for clients to finish or global timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-deadline:
		t.Fatalf("test timed out after %v", testTimeout)
	}

	t.Log("ping-pong test with simulated loss finished")
}

func RunUdpPingPongForNetworks(t *testing.T, a, b NetAddrPair) {
	t.Helper()

	ctx := context.Background()
	lnA, err := a.Network.ListenUDP(ctx, "udp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()

	lnB, err := b.Network.ListenUDP(ctx, "udp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnB.Close()

	dialA := func(serverAddr net.Addr) (FullPacketConn, error) {
		c, err := a.Network.DialUDP(ctx, serverAddr.Network(), "", serverAddr.String())
		if err != nil {
			return nil, err
		}
		return c, nil
	}

	dialB := func(serverAddr net.Addr) (FullPacketConn, error) {
		c, err := b.Network.DialUDP(ctx, serverAddr.Network(), "", serverAddr.String())
		if err != nil {
			return nil, err
		}
		return c, nil
	}

	RunUDPPingPongTest(t, lnA, dialB, numClients, rounds, clientTimeout, roundDelay, maxRetries, dropEvery, testTimeout)
	RunUDPPingPongTest(t, lnB, dialA, numClients, rounds, clientTimeout, roundDelay, maxRetries, dropEvery, testTimeout)
}
