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

func TestLoopbackNetwork_Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		return loopback.NewLoopbackNetwok()
	}, "127.0.0.1:0")
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

func TestPipeTCP(t *testing.T) {
	client, server := loopback.PipeTCP()
	defer client.Close()
	defer server.Close()

	// Verify addresses are set
	if client.LocalAddr().String() != "pipe:client" {
		t.Fatalf(
			"expected client local addr 'pipe:client', got %v",
			client.LocalAddr(),
		)
	}
	if client.RemoteAddr().String() != "pipe:server" {
		t.Fatalf(
			"expected client remote addr 'pipe:server', got %v",
			client.RemoteAddr(),
		)
	}
	if server.LocalAddr().String() != "pipe:server" {
		t.Fatalf(
			"expected server local addr 'pipe:server', got %v",
			server.LocalAddr(),
		)
	}
	if server.RemoteAddr().String() != "pipe:client" {
		t.Fatalf(
			"expected server remote addr 'pipe:client', got %v",
			server.RemoteAddr(),
		)
	}

	// Test bidirectional communication using goroutines to avoid blocking
	writeData := []byte("hello, pipe!")
	readBuf := make([]byte, 1024)

	// Start reader first to avoid blocking
	readDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := server.Read(readBuf)
		readDone <- struct {
			n   int
			err error
		}{n, err}
	}()

	// Write from client
	n, err := client.Write(writeData)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(writeData) {
		t.Fatalf("expected %d bytes written, got %d", len(writeData), n)
	}

	// Wait for read to complete
	result := <-readDone
	if result.err != nil {
		t.Fatalf("server read failed: %v", result.err)
	}
	if result.n != len(writeData) {
		t.Fatalf("expected %d bytes read, got %d", len(writeData), result.n)
	}
	if string(readBuf[:result.n]) != string(writeData) {
		t.Fatalf(
			"expected %q, got %q",
			string(writeData),
			string(readBuf[:result.n]),
		)
	}

	// Test reverse direction
	writeData = []byte("response")
	readDone2 := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := client.Read(readBuf)
		readDone2 <- struct {
			n   int
			err error
		}{n, err}
	}()

	n, err = server.Write(writeData)
	if err != nil {
		t.Fatalf("server write failed: %v", err)
	}

	result2 := <-readDone2
	if result2.err != nil {
		t.Fatalf("client read failed: %v", result2.err)
	}
	if string(readBuf[:result2.n]) != string(writeData) {
		t.Fatalf(
			"expected %q, got %q",
			string(writeData),
			string(readBuf[:result2.n]),
		)
	}
}

func TestPipeTCPClose(t *testing.T) {
	client, server := loopback.PipeTCP()

	// Close client
	client.Close()

	// Server should get EOF on read
	buf := make([]byte, 1024)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected EOF error, got nil")
	}

	server.Close()
}

func TestPipeTCPDeadline(t *testing.T) {
	client, server := loopback.PipeTCP()
	defer client.Close()
	defer server.Close()

	// Test read deadline
	server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1024)
	_, err := server.Read(buf)
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

	// Test write deadline (write to closed pipe)
	client.Close()
	client2, _ := loopback.PipeTCP()
	client2.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = client2.Write(make([]byte, 1024*1024))
	if err == nil {
		t.Fatal("expected error on write to closed pipe, got nil")
	}
	client2.Close()
}

func TestPipeUDP(t *testing.T) {
	conn1, conn2 := loopback.PipeUDP()
	defer conn1.Close()
	defer conn2.Close()

	// Verify addresses are set
	if conn1.LocalAddr().String() != "pipe:conn1" {
		t.Fatalf(
			"expected conn1 local addr 'pipe:conn1', got %v",
			conn1.LocalAddr(),
		)
	}
	if conn1.RemoteAddr().String() != "pipe:conn2" {
		t.Fatalf(
			"expected conn1 remote addr 'pipe:conn2', got %v",
			conn1.RemoteAddr(),
		)
	}
	if conn2.LocalAddr().String() != "pipe:conn2" {
		t.Fatalf(
			"expected conn2 local addr 'pipe:conn2', got %v",
			conn2.LocalAddr(),
		)
	}
	if conn2.RemoteAddr().String() != "pipe:conn1" {
		t.Fatalf(
			"expected conn2 remote addr 'pipe:conn1', got %v",
			conn2.RemoteAddr(),
		)
	}

	// Test conn1 -> conn2
	writeData := []byte("hello from conn1!")
	n, err := conn1.WriteTo(writeData, conn2.LocalAddr())
	if err != nil {
		t.Fatalf("conn1 WriteTo failed: %v", err)
	}
	if n != len(writeData) {
		t.Fatalf("expected %d bytes written, got %d", len(writeData), n)
	}

	readBuf := make([]byte, 1024)
	n, addr, err := conn2.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("conn2 ReadFrom failed: %v", err)
	}
	if n != len(writeData) {
		t.Fatalf("expected %d bytes read, got %d", len(writeData), n)
	}
	if string(readBuf[:n]) != string(writeData) {
		t.Fatalf("expected %q, got %q", string(writeData), string(readBuf[:n]))
	}
	if addr.String() != conn1.LocalAddr().String() {
		t.Fatalf("expected src addr %v, got %v", conn1.LocalAddr(), addr)
	}

	// Test conn2 -> conn1
	writeData = []byte("response from conn2")
	n, err = conn2.WriteTo(writeData, conn1.LocalAddr())
	if err != nil {
		t.Fatalf("conn2 WriteTo failed: %v", err)
	}

	n, addr, err = conn1.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("conn1 ReadFrom failed: %v", err)
	}
	if string(readBuf[:n]) != string(writeData) {
		t.Fatalf("expected %q, got %q", string(writeData), string(readBuf[:n]))
	}
	if addr.String() != conn2.LocalAddr().String() {
		t.Fatalf("expected src addr %v, got %v", conn2.LocalAddr(), addr)
	}
}

func TestPipeUDPClose(t *testing.T) {
	conn1, conn2 := loopback.PipeUDP()

	// Close conn1
	conn1.Close()

	// conn2 should get error when trying to write to closed conn1
	_, err := conn2.WriteTo([]byte("test"), conn1.LocalAddr())
	if err == nil {
		t.Fatal("expected error on write to closed conn, got nil")
	}

	conn2.Close()
}

func TestPipeUDPDeadline(t *testing.T) {
	conn1, conn2 := loopback.PipeUDP()
	defer conn1.Close()
	defer conn2.Close()

	// Test read deadline
	conn1.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1024)
	_, _, err := conn1.ReadFrom(buf)
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

	// Test write deadline
	conn1.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	conn2.Close()
	_, err = conn1.WriteTo([]byte("test"), conn2.LocalAddr())
	if err == nil {
		t.Fatal("expected error on write to closed conn, got nil")
	}
}
