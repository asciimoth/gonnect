package testing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type DialFunc func(addr net.Addr) (net.Conn, error)

// RunTCPPingPongTest runs a ping-pong TCP test using the provided listener and dial function.
//
// Protocol:
//   - Client sends "ping 0\n"
//   - Server reads "ping 0" and writes "pong 0\n"
//   - Client reads "pong 0" and writes "ping 1\n"
//   - ... repeat up to "ping 9" / "pong 9"
//   - After receiving "pong 9" client closes connection
//   - Server then performs one more Read and the test asserts that the error equals io.EOF
//
// Notes:
//   - The function fails the test (t.Fatalf) on any mismatch, corruption, or unexpected error.
//   - The listener is NOT closed by this helper (caller should close when appropriate).
func RunTCPPingPongTest(t *testing.T, ln net.Listener, dial DialFunc) {
	t.Helper()

	numClients := runtime.NumCPU()*2 + 1

	addr := ln.Addr()

	// channels for collecting per-connection server results and client results
	serverResults := make(chan error, numClients)
	clientResults := make(chan error, numClients)

	// --- server side: accept numClients connections and handle each in its own goroutine ---
	go func() {
		for c := range numClients {
			conn, err := ln.Accept()
			if err != nil {
				// if accept fails, report and continue trying to accept remaining connections
				serverResults <- fmt.Errorf("accept #%d: %w", c, err)
				continue
			}

			// handle connection in goroutine so Accept loop can continue
			go func(conn net.Conn, idx int) {
				defer conn.Close()

				if _, ok := conn.(gonnect.TCPConn); !ok {
					serverResults <- fmt.Errorf("server #%d: expecting tcp, got: %t", idx, conn)
					return
				}

				r := bufio.NewReader(conn)
				w := bufio.NewWriter(conn)

				// process 10 pings
				for i := range 10 {
					line, err := r.ReadString('\n')
					if err != nil {
						serverResults <- fmt.Errorf("server #%d read #%d: %w", idx, i, err)
						return
					}
					line = strings.TrimSpace(line)
					expectPing := fmt.Sprintf("ping %d", i)
					if line != expectPing {
						serverResults <- fmt.Errorf("server #%d: expected %q, got %q", idx, expectPing, line)
						return
					}

					_, err = fmt.Fprintf(w, "pong %d\n", i)
					if err != nil {
						serverResults <- fmt.Errorf("server #%d write #%d: %w", idx, i, err)
						return
					}
					if err := w.Flush(); err != nil {
						serverResults <- fmt.Errorf("server #%d flush #%d: %w", idx, i, err)
						return
					}
				}

				// After responding to "ping 9", client should close. Expect io.EOF on next read.
				_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 1)
				n, err := conn.Read(buf)
				if err == nil {
					serverResults <- fmt.Errorf("server #%d: expected EOF after client close, but Read returned %d bytes: %q", idx, n, string(buf[:n]))
					return
				}
				if err != io.EOF {
					serverResults <- fmt.Errorf("server #%d: expected io.EOF after client close, got: %T %v", idx, err, err)
					return
				}

				serverResults <- nil
			}(conn, c)
		}
	}()

	// --- client side: spawn numClients clients concurrently ---
	for c := range numClients {
		go func(idx int) {
			conn, err := dial(addr)
			if err != nil {
				clientResults <- fmt.Errorf("client #%d dial: %w", idx, err)
				return
			}
			// ensure connection closed by this goroutine
			defer conn.Close()

			if _, ok := conn.(gonnect.TCPConn); !ok {
				clientResults <- fmt.Errorf("client #%d: expecting tcp, got: %t", idx, conn)
				return
			}

			cr := bufio.NewReader(conn)
			cw := bufio.NewWriter(conn)

			for i := range 10 {
				_, err := fmt.Fprintf(cw, "ping %d\n", i)
				if err != nil {
					clientResults <- fmt.Errorf("client #%d write ping %d: %w", idx, i, err)
					return
				}
				if err := cw.Flush(); err != nil {
					clientResults <- fmt.Errorf("client #%d flush ping %d: %w", idx, i, err)
					return
				}

				line, err := cr.ReadString('\n')
				if err != nil {
					clientResults <- fmt.Errorf("client #%d read pong %d: %w", idx, i, err)
					return
				}
				line = strings.TrimSpace(line)
				expectPong := fmt.Sprintf("pong %d", i)
				if line != expectPong {
					clientResults <- fmt.Errorf("client #%d: expected %q, got %q", idx, expectPong, line)
					return
				}

				// after receiving pong 9, close and finish
				if i == 9 {
					if err := conn.Close(); err != nil {
						clientResults <- fmt.Errorf("client #%d close: %w", idx, err)
						return
					}
					break
				}
			}

			clientResults <- nil
		}(c)
	}

	// wait for all clients to finish (or timeout)
	clientTimeout := time.After(10 * time.Second)
	for i := range numClients {
		select {
		case cerr := <-clientResults:
			if cerr != nil {
				t.Fatalf("client reported error: %v", cerr)
			}
		case <-clientTimeout:
			t.Fatalf("timeout waiting for client %d to finish", i)
		}
	}

	// wait for all server handlers to finish (or timeout)
	serverTimeout := time.After(10 * time.Second)
	for i := range numClients {
		select {
		case serr := <-serverResults:
			if serr != nil {
				t.Fatalf("server reported error: %v", serr)
			}
		case <-serverTimeout:
			t.Fatalf("timeout waiting for server handler %d to finish", i)
		}
	}
}

type NetAddrPair struct {
	Network gonnect.Network
	Addr    string
}

func RunTcpPingPongForNetworks(t *testing.T, a, b NetAddrPair) {
	t.Helper()

	ctx := context.Background()

	lnA, err := a.Network.Listen(ctx, "tcp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()

	lnB, err := b.Network.Listen(ctx, "tcp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()

	dialA := func(addr net.Addr) (net.Conn, error) {
		return a.Network.Dial(ctx, addr.Network(), addr.String())
	}

	dialB := func(addr net.Addr) (net.Conn, error) {
		return b.Network.Dial(ctx, addr.Network(), addr.String())
	}

	RunTCPPingPongTest(t, lnA, dialB)
	RunTCPPingPongTest(t, lnB, dialA)
}
