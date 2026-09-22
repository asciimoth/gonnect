//nolint:testpackage // Internal transport tests require unexported helpers.
package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const dotParallelTestTimeout = 2 * time.Second

type dotPeerHandler func(net.Conn, *Message) error

type dotPeerResult struct {
	address string
	err     error
}

type dotQueryResult struct {
	msg *Message
	err error
}

func TestClientDoTQueriesBootstrapAddressesInParallel(t *testing.T) {
	cert, _ := testTLSCert(t, "dns.test")
	requests := make(chan string, 2)
	releaseFast := make(chan struct{})
	var releaseFastOnce sync.Once
	peerDone := make(chan dotPeerResult, 2)

	handlers := map[string]dotPeerHandler{
		"127.0.0.1:853": func(conn net.Conn, _ *Message) error {
			requests <- "127.0.0.1:853"
			// This peer does not respond. It must be canceled after the other
			// peer returns a valid response.
			_, err := conn.Read(make([]byte, 1))
			return err
		},
		"127.0.0.2:853": func(conn net.Conn, req *Message) error {
			requests <- "127.0.0.2:853"
			<-releaseFast
			return writeDoTTestResponse(conn, req, 2, false)
		},
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := newParallelDoTTestClient(
		bootstrap,
		cert,
		handlers,
		peerDone,
	)
	defer func() { _ = client.Close() }()
	// Release the successful peer before cleanup closes the client if an
	// assertion stops this test early.
	defer releaseFastOnce.Do(func() { close(releaseFast) })

	queryDone := startDoTTestQuery(client)
	seen := map[string]bool{}
	for range 2 {
		address := receiveDoTTestValue(t, requests, "parallel DoT request")
		seen[address] = true
	}
	if !seen["127.0.0.1:853"] || !seen["127.0.0.2:853"] {
		t.Fatalf(
			"requested addresses = %v, want both bootstrap addresses",
			seen,
		)
	}
	releaseFastOnce.Do(func() { close(releaseFast) })

	result := receiveDoTTestValue(t, queryDone, "DoT query result")
	if result.err != nil {
		t.Fatalf("DoT query error = %v", result.err)
	}
	if got := responseAddressMarker(result.msg); got != 2 {
		t.Fatalf("response address marker = %d, want 2", got)
	}

	peers := receiveDoTTestPeers(t, peerDone)
	if peers["127.0.0.2:853"] != nil {
		t.Fatalf("successful peer error = %v", peers["127.0.0.2:853"])
	}
	if peers["127.0.0.1:853"] == nil {
		t.Fatal("slow peer was not canceled")
	}
}

func TestClientDoTReturnsLastErrorAfterAllAddressesFail(t *testing.T) {
	errFirst := errors.New("first DoT address failed")
	errLast := errors.New("last DoT address failed")
	started := make(chan string, 2)
	firstGate := make(chan struct{})
	lastGate := make(chan struct{})
	var closeFirst sync.Once
	var closeLast sync.Once
	defer closeFirst.Do(func() { close(firstGate) })
	defer closeLast.Do(func() { close(lastGate) })

	dial := func(
		ctx context.Context,
		_, address string,
	) (net.Conn, error) {
		started <- address
		var gate <-chan struct{}
		var dialErr error
		switch address {
		case "127.0.0.1:853":
			gate, dialErr = firstGate, errFirst
		case "127.0.0.2:853":
			gate, dialErr = lastGate, errLast
		default:
			return nil, fmt.Errorf("unexpected address %q", address)
		}
		select {
		case <-gate:
			return nil, dialErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := NewClientWithOptions(
		dial,
		bootstrap,
		nil,
		ClientOptions{RequestTimeout: time.Hour},
		"dot://dns.test:853",
	)
	defer func() { _ = client.Close() }()

	queryDone := startDoTTestQuery(client)
	seen := map[string]bool{}
	for range 2 {
		seen[receiveDoTTestValue(t, started, "DoT dial")] = true
	}
	if !seen["127.0.0.1:853"] || !seen["127.0.0.2:853"] {
		t.Fatalf("dialed addresses = %v, want both bootstrap addresses", seen)
	}

	closeFirst.Do(func() { close(firstGate) })
	select {
	case result := <-queryDone:
		t.Fatalf("query returned before all attempts failed: %v", result.err)
	case <-time.After(25 * time.Millisecond):
	}
	closeLast.Do(func() { close(lastGate) })
	result := receiveDoTTestValue(t, queryDone, "failed DoT query result")
	if !errors.Is(result.err, errLast) {
		t.Fatalf("query error = %v, want final error %v", result.err, errLast)
	}
}

func TestClientDoTMismatchedResponseCannotWinParallelExchange(t *testing.T) {
	cert, _ := testTLSCert(t, "dns.test")
	mismatchWritten := make(chan struct{})
	var mismatchWrittenOnce sync.Once
	defer mismatchWrittenOnce.Do(func() { close(mismatchWritten) })
	peerDone := make(chan dotPeerResult, 2)
	handlers := map[string]dotPeerHandler{
		"127.0.0.1:853": func(conn net.Conn, req *Message) error {
			err := writeDoTTestResponse(conn, req, 1, true)
			mismatchWrittenOnce.Do(func() { close(mismatchWritten) })
			return err
		},
		"127.0.0.2:853": func(conn net.Conn, req *Message) error {
			<-mismatchWritten
			return writeDoTTestResponse(conn, req, 2, false)
		},
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := newParallelDoTTestClient(
		bootstrap,
		cert,
		handlers,
		peerDone,
	)
	defer func() { _ = client.Close() }()

	resp, err := Query(context.Background(), client, aQuery("localhost."))
	if err != nil {
		t.Fatalf("DoT query error = %v", err)
	}
	if got := responseAddressMarker(resp); got != 2 {
		t.Fatalf("response address marker = %d, want valid peer marker 2", got)
	}
	_ = receiveDoTTestPeers(t, peerDone)
}

func TestClientCloseCancelsAllParallelDoTRequests(t *testing.T) {
	cert, _ := testTLSCert(t, "dns.test")
	requests := make(chan string, 2)
	peerDone := make(chan dotPeerResult, 2)
	handlers := map[string]dotPeerHandler{}
	for _, address := range []string{"127.0.0.1:853", "127.0.0.2:853"} {
		handlers[address] = func(conn net.Conn, _ *Message) error {
			requests <- address
			_, err := conn.Read(make([]byte, 1))
			return err
		}
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := newParallelDoTTestClient(
		bootstrap,
		cert,
		handlers,
		peerDone,
	)
	defer func() { _ = client.Close() }()

	queryDone := startDoTTestQuery(client)
	for range 2 {
		_ = receiveDoTTestValue(t, requests, "blocked DoT request")
	}
	mustCloseQuickly(t, client, "parallel DoT client")

	result := receiveDoTTestValue(t, queryDone, "canceled DoT query result")
	if result.err == nil {
		t.Fatal("in-flight DoT query succeeded after client close")
	}
	peers := receiveDoTTestPeers(t, peerDone)
	for address, err := range peers {
		if err == nil {
			t.Fatalf("peer %s did not observe connection cancellation", address)
		}
	}
	assertQueryAfterCloseReturns(t, client)
}

func TestClientDoTResponseCanRaceWithClose(t *testing.T) {
	cert, _ := testTLSCert(t, "dns.test")
	requests := make(chan struct{}, 2)
	startRace := make(chan struct{})
	peerDone := make(chan dotPeerResult, 2)
	handlers := map[string]dotPeerHandler{
		"127.0.0.1:853": func(conn net.Conn, req *Message) error {
			requests <- struct{}{}
			<-startRace
			return writeDoTTestResponse(conn, req, 1, false)
		},
		"127.0.0.2:853": func(conn net.Conn, _ *Message) error {
			requests <- struct{}{}
			_, err := conn.Read(make([]byte, 1))
			return err
		},
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := newParallelDoTTestClient(
		bootstrap,
		cert,
		handlers,
		peerDone,
	)
	defer func() { _ = client.Close() }()

	queryDone := startDoTTestQuery(client)
	for range 2 {
		_ = receiveDoTTestValue(t, requests, "DoT request before close race")
	}
	closeDone := make(chan error, 1)
	go func() {
		<-startRace
		closeDone <- client.Close()
	}()
	close(startRace)

	closeErr := receiveDoTTestValue(t, closeDone, "client close race")
	if closeErr != nil {
		t.Fatalf("client close error = %v", closeErr)
	}
	// The response and Close are simultaneous. Either query result is valid,
	// but the query and both peer exchanges must always stop.
	result := receiveDoTTestValue(t, queryDone, "DoT close race query")
	if result.err == nil && responseAddressMarker(result.msg) != 1 {
		t.Fatalf(
			"successful raced response = %#v, want peer 1 response",
			result.msg,
		)
	}
	_ = receiveDoTTestPeers(t, peerDone)
	assertQueryAfterCloseReturns(t, client)
}

func TestClientCloseCancelsManyParallelDoTQueries(t *testing.T) {
	const queryCount = 16
	const addressCount = 2
	started := make(chan struct{}, queryCount*addressCount)
	stopped := make(chan struct{}, queryCount*addressCount)
	dial := func(
		ctx context.Context,
		_, _ string,
	) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return nil, ctx.Err()
	}

	bootstrap := newBootstrapDNS("127.0.0.1", "127.0.0.2")
	defer func() { _ = bootstrap.Close() }()
	client := NewClientWithOptions(
		dial,
		bootstrap,
		nil,
		ClientOptions{RequestTimeout: time.Hour},
		"dot://dns.test:853",
	)
	defer func() { _ = client.Close() }()

	queryDone := make(chan error, queryCount)
	for range queryCount {
		go func() {
			_, err := Query(context.Background(), client, aQuery("localhost."))
			queryDone <- err
		}()
	}
	for range queryCount * addressCount {
		_ = receiveDoTTestValue(t, started, "concurrent DoT dial")
	}

	mustCloseQuickly(t, client, "client with concurrent DoT queries")
	for range queryCount * addressCount {
		_ = receiveDoTTestValue(t, stopped, "canceled concurrent DoT dial")
	}
	for range queryCount {
		err := receiveDoTTestValue(t, queryDone, "concurrent DoT query")
		if err == nil {
			t.Fatal("concurrent DoT query succeeded after client close")
		}
	}
	assertQueryAfterCloseReturns(t, client)
}

func TestClientTCPAndDoTConnectionsUseTimeout(t *testing.T) {
	const clientTimeout = 40 * time.Millisecond
	for _, scheme := range []string{"tcp", "dot"} {
		t.Run(scheme, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			deadlines := make(chan time.Time, 1)
			peerDone := make(chan error, 1)
			if scheme == "tcp" {
				go func() {
					_, err := readDoTTestMessage(serverConn)
					if err == nil {
						_, err = serverConn.Read(make([]byte, 1))
					}
					peerDone <- err
				}()
			}

			dial := func(context.Context, string, string) (net.Conn, error) {
				return &deadlineRecordingConn{
					Conn:      clientConn,
					deadlines: deadlines,
				}, nil
			}
			client := NewClientWithOptions(
				dial,
				nil,
				nil,
				ClientOptions{RequestTimeout: clientTimeout},
				scheme+"://127.0.0.1:853",
			)
			if scheme == "dot" {
				client.TLSConfig = &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // In-memory peer.
					MinVersion:         tls.VersionTLS12,
				}
			}
			defer func() { _ = client.Close() }()

			started := time.Now()
			if _, err := Query(
				context.Background(),
				client,
				aQuery("localhost."),
			); err == nil {
				t.Fatal("query without a server response succeeded")
			}
			deadline := receiveDoTTestValue(t, deadlines, "stream deadline")
			assertDoTTestDeadline(t, deadline, started, clientTimeout)
			if scheme == "tcp" {
				peerErr := receiveDoTTestValue(t, peerDone, "TCP peer stop")
				if peerErr == nil {
					t.Fatal("TCP peer did not observe the timed-out connection")
				}
			}
		})
	}
}

func TestClientUDPToTCPFallbackUsesTimeout(t *testing.T) {
	const clientTimeout = 40 * time.Millisecond
	tcpDeadlines := make(chan time.Time, 1)
	peerDone := make(chan error, 2)
	dialedNetworks := make(chan string, 2)
	dial := func(
		_ context.Context,
		network, _ string,
	) (net.Conn, error) {
		dialedNetworks <- network
		clientConn, serverConn := net.Pipe()
		switch network {
		case "udp":
			go func() {
				peerDone <- serveDoTTestTruncatedUDP(serverConn)
			}()
			return clientConn, nil
		case "tcp":
			go func() {
				defer func() { _ = serverConn.Close() }()
				_, err := readDoTTestMessage(serverConn)
				if err == nil {
					_, err = serverConn.Read(make([]byte, 1))
				}
				peerDone <- err
			}()
			return &deadlineRecordingConn{
				Conn:      clientConn,
				deadlines: tcpDeadlines,
			}, nil
		default:
			_ = clientConn.Close()
			_ = serverConn.Close()
			return nil, fmt.Errorf("unexpected network %q", network)
		}
	}

	client := NewClientWithOptions(
		dial,
		nil,
		nil,
		ClientOptions{RequestTimeout: clientTimeout},
		"udp://127.0.0.1:853",
	)
	defer func() { _ = client.Close() }()
	started := time.Now()
	if _, err := Query(
		context.Background(),
		client,
		aQuery("localhost."),
	); err == nil {
		t.Fatal("UDP fallback query without a TCP response succeeded")
	}
	if got := receiveDoTTestValue(t, dialedNetworks, "UDP dial"); got != "udp" {
		t.Fatalf("first network = %q, want udp", got)
	}
	fallbackNetwork := receiveDoTTestValue(
		t,
		dialedNetworks,
		"TCP fallback dial",
	)
	if fallbackNetwork != "tcp" {
		t.Fatalf("fallback network = %q, want tcp", fallbackNetwork)
	}
	deadline := receiveDoTTestValue(t, tcpDeadlines, "TCP fallback deadline")
	assertDoTTestDeadline(t, deadline, started, clientTimeout)
	for range 2 {
		_ = receiveDoTTestValue(t, peerDone, "UDP fallback peer stop")
	}
}

func TestClientReturnsConnectionDeadlineError(t *testing.T) {
	wantErr := errors.New("cannot set connection deadline")
	for _, scheme := range []string{"tcp", "dot"} {
		t.Run(scheme, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = serverConn.Close() }()
			dial := func(context.Context, string, string) (net.Conn, error) {
				return &deadlineErrorConn{Conn: clientConn, err: wantErr}, nil
			}
			client := NewClient(dial, nil, nil, scheme+"://127.0.0.1:853")
			defer func() { _ = client.Close() }()

			_, err := Query(context.Background(), client, aQuery("localhost."))
			if !errors.Is(err, wantErr) {
				t.Fatalf("query error = %v, want %v", err, wantErr)
			}
		})
	}
}

func newParallelDoTTestClient(
	bootstrap Interface,
	cert tls.Certificate,
	handlers map[string]dotPeerHandler,
	peerDone chan<- dotPeerResult,
) *Client {
	dial := func(
		ctx context.Context,
		_, address string,
	) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		handler, ok := handlers[address]
		if !ok {
			return nil, fmt.Errorf("unexpected address %q", address)
		}
		clientConn, serverConn := net.Pipe()
		go serveDoTTestPeer(serverConn, address, cert, handler, peerDone)
		return clientConn, nil
	}
	client := NewClientWithOptions(
		dial,
		bootstrap,
		nil,
		ClientOptions{RequestTimeout: time.Hour},
		"dot://dns.test:853",
	)
	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Test-only in-memory TLS peer.
		MinVersion:         tls.VersionTLS12,
	}
	return client
}

func serveDoTTestPeer(
	conn net.Conn,
	address string,
	cert tls.Certificate,
	handler dotPeerHandler,
	done chan<- dotPeerResult,
) {
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	request, err := readDoTTestMessage(tlsConn)
	if err == nil {
		err = handler(tlsConn, request)
	}
	done <- dotPeerResult{address: address, err: err}
}

func readDoTTestMessage(conn net.Conn) (*Message, error) {
	var sizeBytes [2]byte
	if _, err := io.ReadFull(conn, sizeBytes[:]); err != nil {
		return nil, err
	}
	pkt := make([]byte, binary.BigEndian.Uint16(sizeBytes[:]))
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return Unpack(pkt)
}

func writeDoTTestResponse(
	conn net.Conn,
	request *Message,
	addressMarker byte,
	mismatchID bool,
) error {
	resp := responseFor(request)
	if mismatchID {
		resp.ID++
	}
	resp.Answers = []Resource{{
		Name:  request.Questions[0].Name,
		Type:  TypeA,
		Class: ClassIN,
		TTL:   1,
		Data:  []byte{127, 0, 0, addressMarker},
	}}
	pkt, err := Pack(resp)
	if err != nil {
		return err
	}
	var sizeBytes [2]byte
	// #nosec G115 -- A test response is smaller than the DNS message limit.
	binary.BigEndian.PutUint16(sizeBytes[:], uint16(len(pkt)))
	if _, err = conn.Write(sizeBytes[:]); err != nil {
		return err
	}
	_, err = conn.Write(pkt)
	return err
}

func responseAddressMarker(msg *Message) byte {
	if msg == nil || len(msg.Answers) != 1 || len(msg.Answers[0].Data) != 4 {
		return 0
	}
	return msg.Answers[0].Data[3]
}

func startDoTTestQuery(client *Client) <-chan dotQueryResult {
	done := make(chan dotQueryResult, 1)
	go func() {
		msg, err := Query(context.Background(), client, aQuery("localhost."))
		done <- dotQueryResult{msg: msg, err: err}
	}()
	return done
}

func receiveDoTTestPeers(
	t *testing.T,
	done <-chan dotPeerResult,
) map[string]error {
	t.Helper()
	peers := make(map[string]error, 2)
	for range 2 {
		result := receiveDoTTestValue(t, done, "DoT peer completion")
		peers[result.address] = result.err
	}
	return peers
}

func receiveDoTTestValue[T any](t *testing.T, ch <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(dotParallelTestTimeout):
		t.Fatalf("timed out waiting for %s", name)
		var zero T
		return zero
	}
}

type deadlineRecordingConn struct {
	net.Conn
	deadlines chan<- time.Time
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.deadlines <- deadline
	return c.Conn.SetDeadline(deadline)
}

type deadlineErrorConn struct {
	net.Conn
	err error
}

func (c *deadlineErrorConn) SetDeadline(time.Time) error {
	return c.err
}

func serveDoTTestTruncatedUDP(conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, maxDNSMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	request, err := Unpack(buf[:n])
	if err != nil {
		return err
	}
	resp := responseFor(request)
	resp.Truncated = true
	pkt, err := Pack(resp)
	if err != nil {
		return err
	}
	_, err = conn.Write(pkt)
	return err
}

func assertDoTTestDeadline(
	t *testing.T,
	deadline time.Time,
	started time.Time,
	timeout time.Duration,
) {
	t.Helper()
	if deadline.IsZero() {
		t.Fatal("connection deadline is zero")
	}
	if latest := started.Add(2 * timeout); deadline.After(latest) {
		t.Fatalf(
			"connection deadline = %v, want no later than %v",
			deadline,
			latest,
		)
	}
}
