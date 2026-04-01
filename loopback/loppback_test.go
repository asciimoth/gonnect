// nolint
package loopback_test

import (
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/loopback"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestNativeNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return loopback.NewLoopbackNetwok()
	})
}

func TestNativeNetworkTcpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: loopback.NewLoopbackNetwok(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkHTTP(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: loopback.NewLoopbackNetwok(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestNativeNetworkUdpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: loopback.NewLoopbackNetwok(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestLoopbackTCPListenerDeadline(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Test SetDeadline with past time (should timeout immediately)
	listener.SetDeadline(time.Now().Add(-1 * time.Second))
	_, err = listener.AcceptTCP()
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("expected *net.OpError, got %T", err)
	}
	if opErr.Err.Error() != "i/o timeout" {
		t.Fatalf("expected 'i/o timeout', got %v", opErr.Err)
	}

	// Test SetDeadline with future time (should not timeout)
	listener2, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener2.Close()

	listener2.SetDeadline(time.Now().Add(100 * time.Millisecond))

	// Dial a connection in a goroutine
	go func() {
		time.Sleep(10 * time.Millisecond)
		conn, err := network.DialTCP(
			t.Context(),
			"tcp",
			"",
			listener2.Addr().String(),
		)
		if err != nil {
			t.Logf("dial failed: %v", err)
			return
		}
		defer conn.Close()
	}()

	conn, err := listener2.AcceptTCP()
	if err != nil {
		t.Fatalf("expected successful accept, got: %v", err)
	}
	conn.Close()

	// Test SetDeadline with zero time (disable deadline)
	listener3, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener3.Close()

	listener3.SetDeadline(time.Time{})
}

func TestLoopbackTCPConnReadDeadline(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Dial client
	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Accept server
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer server.Close()

	// Test read deadline on server - should timeout
	server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes read, got %d", n)
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("expected *net.OpError, got %T", err)
	}
	if opErr.Err.Error() != "i/o timeout" {
		t.Fatalf("expected 'i/o timeout', got %v", opErr.Err)
	}
	if opErr.Op != "read" {
		t.Fatalf("expected op 'read', got %v", opErr.Op)
	}

	// Test disabling read deadline with zero time (no error)
	err = server.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetReadDeadline(zero) failed: %v", err)
	}
}

func TestLoopbackTCPConnReadDeadlineSuccess(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Dial client
	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Accept server
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer server.Close()

	// Set a future deadline and write/read should succeed
	server.SetReadDeadline(time.Now().Add(1 * time.Second))

	writeDone := make(chan error, 1)
	readDone := make(chan struct {
		n   int
		err error
	}, 1)

	go func() {
		_, err := client.Write([]byte("hello"))
		writeDone <- err
	}()

	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		readDone <- struct {
			n   int
			err error
		}{n, err}
	}()

	// Check write result
	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	// Check read result
	result := <-readDone
	if result.err != nil {
		t.Fatalf("server read failed: %v", result.err)
	}
}

func TestLoopbackTCPConnWriteDeadline(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Dial client
	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Accept server
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer server.Close()

	// Use channels to synchronize write and read
	writeDone := make(chan struct {
		n   int
		err error
	}, 1)
	readDone := make(chan struct {
		n   int
		err error
	}, 1)

	// Test write deadline - normal write should succeed
	client.SetWriteDeadline(time.Now().Add(1 * time.Second))

	go func() {
		n, err := client.Write([]byte("test data"))
		writeDone <- struct {
			n   int
			err error
		}{n, err}
	}()

	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		readDone <- struct {
			n   int
			err error
		}{n, err}
	}()

	// Check write result
	writeResult := <-writeDone
	if writeResult.err != nil {
		t.Fatalf("expected successful write, got: %v", writeResult.err)
	}
	if writeResult.n != 9 {
		t.Fatalf("expected 9 bytes written, got %d", writeResult.n)
	}

	// Check read result to verify data was sent
	readResult := <-readDone
	if readResult.err != nil {
		t.Fatalf("server read failed: %v", readResult.err)
	}

	// Test disabling write deadline with zero time (no error)
	err = client.SetWriteDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetWriteDeadline(zero) failed: %v", err)
	}
}

func TestLoopbackTCPConnWriteDeadlineTimeout(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Dial client
	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Accept server
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer server.Close()

	// Close server read side to cause write to block
	server.Close()

	// Test write deadline - should timeout since server is closed
	client.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = client.Write(
		make([]byte, 1024*1024),
	) // Large write to potentially block
	if err == nil {
		t.Fatal("expected timeout or closed error, got nil")
	}
}

func TestLoopbackTCPConnSetDeadline(t *testing.T) {
	network := loopback.NewLoopbackNetwok()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Dial client
	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Accept server
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}
	defer server.Close()

	// Test SetDeadline affects both read and write
	client.SetDeadline(time.Now().Add(-1 * time.Second))

	// Test read times out
	buf := make([]byte, 1024)
	_, err = client.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error on read, got nil")
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("expected *net.OpError, got %T", err)
	}
	if opErr.Op != "read" {
		t.Fatalf("expected op 'read', got %v", opErr.Op)
	}

	// Test write times out
	_, err = client.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected timeout error on write, got nil")
	}
	opErr, ok = err.(*net.OpError)
	if !ok {
		t.Fatalf("expected *net.OpError, got %T", err)
	}
	if opErr.Op != "write" {
		t.Fatalf("expected op 'write', got %v", opErr.Op)
	}

	// Test disabling deadline with zero time
	client.SetDeadline(time.Time{})
}
