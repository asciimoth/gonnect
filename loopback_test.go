// nolint
package gonnect_test

import (
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestLoopbackNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return gonnect.NewLoopbackNetwork()
	})
}

func TestLoopbackNetworkTcpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NewLoopbackNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestLoopbackNetworkHTTP(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NewLoopbackNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestLoopbackNetworkUdpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NewLoopbackNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestLoopbackNetworkAllowAnyHost(t *testing.T) {
	t.Parallel()

	network := gonnect.NewLoopbackNetwork()
	if listener, err := network.ListenTCP(
		t.Context(),
		"tcp",
		"example.com:0",
	); err == nil {
		_ = listener.Close()
		t.Fatal("ListenTCP() unexpectedly accepted a hostname before opt-in")
	}

	network.AllowAnyHost = true
	listener, err := network.ListenTCP(t.Context(), "tcp", "example.com:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer listener.Close()
	if host, _, err := net.SplitHostPort(listener.Addr().String()); err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	} else if host != "127.0.0.1" {
		t.Fatalf("listener host = %q, want 127.0.0.1", host)
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("ok"))
		acceptErr <- err
	}()

	client, err := network.DialTCP(
		t.Context(),
		"tcp",
		"192.0.2.10:0",
		net.JoinHostPort("service.internal", port),
	)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 2)
	if n, err := client.Read(buf); err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("Read() = %d, %q, %v; want %q, nil", n, buf[:n], err, "ok")
	}
	if err := <-acceptErr; err != nil {
		t.Fatalf("server write error = %v", err)
	}
}

func TestLoopbackNetworkAllowAnyHostUDP(t *testing.T) {
	t.Parallel()

	network := gonnect.NewLoopbackNetwork()
	network.AllowAnyHost = true

	server, err := network.ListenUDP(t.Context(), "udp4", "example.com:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer server.Close()
	_, port, err := net.SplitHostPort(server.LocalAddr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	client, err := network.DialUDP(
		t.Context(),
		"udp4",
		"198.51.100.10:0",
		net.JoinHostPort("service.internal", port),
	)
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 2)
	n, _, err := server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("ReadFrom() = %d, %q, %v; want %q, nil", n, buf[:n], err, "ok")
	}
}

func TestLoopbackNetworkInterfaceMulticastAddrs(t *testing.T) {
	t.Parallel()

	network := gonnect.NewLoopbackNetwork()
	addrs, err := network.InterfaceMulticastAddrs()
	if err != nil {
		t.Fatalf("InterfaceMulticastAddrs() error = %v", err)
	}
	want := []string{"224.0.0.1", "ff02::1"}
	if len(addrs) != len(want) {
		t.Fatalf(
			"InterfaceMulticastAddrs() len = %d, want %d",
			len(addrs),
			len(want),
		)
	}
	for i, wantAddr := range want {
		if addrs[i].String() != wantAddr {
			t.Fatalf(
				"InterfaceMulticastAddrs()[%d] = %q, want %q",
				i,
				addrs[i],
				wantAddr,
			)
		}
		ipAddr, ok := addrs[i].(*net.IPAddr)
		if !ok {
			t.Fatalf(
				"InterfaceMulticastAddrs()[%d] type = %T, want *net.IPAddr",
				i,
				addrs[i],
			)
		}
		if !ipAddr.IP.IsMulticast() {
			t.Fatalf(
				"InterfaceMulticastAddrs()[%d] = %q, want multicast IP",
				i,
				addrs[i],
			)
		}
	}

	ifs, err := network.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error = %v", err)
	}
	if len(ifs) != 1 {
		t.Fatalf("Interfaces() len = %d, want 1", len(ifs))
	}
	if ifs[0].Flags()&net.FlagMulticast == 0 {
		t.Fatal("loopback interface missing multicast flag")
	}
	ifaceAddrs, err := ifs[0].MulticastAddrs()
	if err != nil {
		t.Fatalf("lo MulticastAddrs() error = %v", err)
	}
	if len(ifaceAddrs) != len(addrs) {
		t.Fatalf(
			"lo MulticastAddrs() len = %d, want %d",
			len(ifaceAddrs),
			len(addrs),
		)
	}
	for i := range addrs {
		if ifaceAddrs[i].String() != addrs[i].String() {
			t.Fatalf(
				"lo MulticastAddrs()[%d] = %q, want %q",
				i,
				ifaceAddrs[i],
				addrs[i],
			)
		}
	}
}

func TestLoopbackNetworkMulticastUDP(t *testing.T) {
	t.Parallel()

	network := gonnect.NewLoopbackNetwork()
	ifs, err := network.InterfacesByName("lo")
	if err != nil {
		t.Fatalf("InterfacesByName() error = %v", err)
	}
	if len(ifs) != 1 {
		t.Fatalf("InterfacesByName() len = %d, want 1", len(ifs))
	}
	if flags := ifs[0].Flags(); flags&net.FlagUp == 0 ||
		flags&net.FlagRunning == 0 ||
		flags&net.FlagMulticast == 0 ||
		flags&net.FlagPointToPoint != 0 {
		t.Fatalf(
			"loopback flags = %v, want up/running/multicast and not point-to-point",
			flags,
		)
	}
	addrs, err := ifs[0].Addrs()
	if err != nil {
		t.Fatalf("lo Addrs() error = %v", err)
	}
	var hasLinkLocal bool
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.IsLinkLocalUnicast() {
			hasLinkLocal = true
		}
	}
	if !hasLinkLocal {
		t.Fatal("lo Addrs() missing IPv6 link-local address")
	}

	c1, err := network.ListenMulticastUDP(
		t.Context(),
		"udp6",
		"[::]:0",
		gonnect.MulticastOptions{
			ReuseAddr:    true,
			ReusePort:    true,
			ControlFlags: gonnect.ControlDst | gonnect.ControlInterface,
		},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP(c1) error = %v", err)
	}
	defer c1.Close()

	port := c1.LocalAddr().(*net.UDPAddr).Port
	c2, err := network.ListenMulticastUDP(
		t.Context(),
		"udp6",
		net.JoinHostPort("::", strconv.Itoa(port)),
		gonnect.MulticastOptions{
			ReuseAddr:    true,
			ReusePort:    true,
			ControlFlags: gonnect.ControlDst | gonnect.ControlInterface,
		},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP(c2) error = %v", err)
	}
	defer c2.Close()

	group := &net.IPAddr{IP: net.ParseIP("ff02::114")}
	if err := c1.JoinGroup(ifs[0], group); err != nil {
		t.Fatalf("c1 JoinGroup() error = %v", err)
	}
	if err := c2.JoinGroup(ifs[0], group); err != nil {
		t.Fatalf("c2 JoinGroup() error = %v", err)
	}

	msg := []byte("multicast ping")
	dst := &net.UDPAddr{IP: group.IP, Port: port, Zone: ifs[0].Name()}
	if _, err := c1.WriteToControl(msg, gonnect.ControlMessage{
		IfIndex: ifs[0].Index(),
		IfName:  ifs[0].Name(),
	}, dst); err != nil {
		t.Fatalf("WriteToControl() error = %v", err)
	}

	buf := make([]byte, 64)
	if err := c2.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, cm, from, err := c2.ReadFromControl(buf)
	if err != nil {
		t.Fatalf("ReadFromControl() error = %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("ReadFromControl() payload = %q, want %q", buf[:n], msg)
	}
	if cm.IfIndex != ifs[0].Index() || cm.IfName != ifs[0].Name() {
		t.Fatalf(
			"control interface = %d/%q, want %d/%q",
			cm.IfIndex,
			cm.IfName,
			ifs[0].Index(),
			ifs[0].Name(),
		)
	}
	if cm.Dst == nil || cm.Dst.String() != dst.String() {
		t.Fatalf("control dst = %v, want %v", cm.Dst, dst)
	}
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("from type = %T, want *net.UDPAddr", from)
	}
	if !fromUDP.IP.IsLinkLocalUnicast() || fromUDP.Zone != ifs[0].Name() {
		t.Fatalf(
			"from = %v, want link-local source with zone %q",
			fromUDP,
			ifs[0].Name(),
		)
	}
}

func TestLoopbackNetwork_Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		return gonnect.NewLoopbackNetwork()
	}, "127.0.0.1:0")
}

func TestLoopbackTCPListenerDeadline(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()
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
	network := gonnect.NewLoopbackNetwork()
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
	network := gonnect.NewLoopbackNetwork()
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
	network := gonnect.NewLoopbackNetwork()
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
	network := gonnect.NewLoopbackNetwork()
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

func TestLoopbackTCPConcurrentWriteFirst(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()
	listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept: %v", err)
			return
		}
		accepted <- conn
	}()

	client, err := network.Dial(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := client.Write([]byte("hello")); err != nil {
			t.Errorf("client write failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := server.Write([]byte("world")); err != nil {
			t.Errorf("server write failed: %v", err)
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("simultaneous write-first traffic blocked")
	}
}

func TestLoopbackTCPConnSetDeadline(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()
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
	client, server := gonnect.PipeTCP()
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
	client, server := gonnect.PipeTCP()

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
	client, server := gonnect.PipeTCP()
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
	client2, _ := gonnect.PipeTCP()
	client2.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = client2.Write(make([]byte, 1024*1024))
	if err == nil {
		t.Fatal("expected error on write to closed pipe, got nil")
	}
	client2.Close()
}

func TestPipeUDP(t *testing.T) {
	conn1, conn2 := gonnect.PipeUDP()
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
	conn1, conn2 := gonnect.PipeUDP()

	// Close conn1
	conn1.Close()

	// conn2 should get error when trying to write to closed conn1
	_, err := conn2.WriteTo([]byte("test"), conn1.LocalAddr())
	if err == nil {
		t.Fatal("expected error on write to closed conn, got nil")
	}

	conn2.Close()
}

func TestLoopbackUDPGenericAddrWritePaths(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()

	tests := []struct {
		name string
		send func(t *testing.T, conn net.PacketConn, addr *net.UDPAddr)
	}{
		{
			name: "WriteToUDP",
			send: func(t *testing.T, conn net.PacketConn, addr *net.UDPAddr) {
				udpConn, ok := conn.(interface {
					WriteToUDP([]byte, *net.UDPAddr) (int, error)
				})
				if !ok {
					t.Fatalf(
						"packet conn does not support WriteToUDP: %T",
						conn,
					)
				}
				if _, err := udpConn.WriteToUDP(
					[]byte("ping"),
					addr,
				); err != nil {
					t.Fatalf("WriteToUDP failed: %v", err)
				}
			},
		},
		{
			name: "WriteMsgUDP",
			send: func(t *testing.T, conn net.PacketConn, addr *net.UDPAddr) {
				udpConn, ok := conn.(interface {
					WriteMsgUDP([]byte, []byte, *net.UDPAddr) (int, int, error)
				})
				if !ok {
					t.Fatalf(
						"packet conn does not support WriteMsgUDP: %T",
						conn,
					)
				}
				if _, _, err := udpConn.WriteMsgUDP(
					[]byte("ping"),
					nil,
					addr,
				); err != nil {
					t.Fatalf("WriteMsgUDP failed: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver, err := network.ListenUDP(
				t.Context(),
				"udp4",
				"127.0.0.1:0",
			)
			if err != nil {
				t.Fatalf("failed to create receiver: %v", err)
			}
			defer receiver.Close()

			sender, err := network.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to create sender: %v", err)
			}
			defer sender.Close()

			dst, err := net.ResolveUDPAddr("udp", receiver.LocalAddr().String())
			if err != nil {
				t.Fatalf("failed to resolve generic UDP addr: %v", err)
			}
			if dst.Network() != "udp" {
				t.Fatalf("expected generic udp address, got %q", dst.Network())
			}

			tt.send(t, sender, dst)

			buf := make([]byte, 16)
			n, addr, err := receiver.ReadFrom(buf)
			if err != nil {
				t.Fatalf("receiver ReadFrom failed: %v", err)
			}
			if got := string(buf[:n]); got != "ping" {
				t.Fatalf("expected payload %q, got %q", "ping", got)
			}
			if addr.String() != sender.LocalAddr().String() {
				t.Fatalf(
					"expected src addr %q, got %q",
					sender.LocalAddr(),
					addr,
				)
			}
		})
	}
}

func TestLoopbackClosedErrorsMatchNetErrClosed(t *testing.T) {
	t.Run("udp read/write", func(t *testing.T) {
		conn1, conn2 := gonnect.PipeUDP()
		defer conn2.Close()

		if err := conn1.Close(); err != nil {
			t.Fatalf("conn1 close failed: %v", err)
		}

		buf := make([]byte, 1)
		if _, _, err := conn1.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom error = %v, want errors.Is(net.ErrClosed)", err)
		}
		if _, err := conn1.WriteTo(
			[]byte("x"),
			conn2.LocalAddr(),
		); !errors.Is(
			err,
			net.ErrClosed,
		) {
			t.Fatalf("WriteTo error = %v, want errors.Is(net.ErrClosed)", err)
		}
		if _, err := conn2.WriteTo(
			[]byte("x"),
			conn1.LocalAddr(),
		); !errors.Is(
			err,
			net.ErrClosed,
		) {
			t.Fatalf(
				"peer WriteTo error = %v, want errors.Is(net.ErrClosed)",
				err,
			)
		}
	})

	t.Run("tcp accept", func(t *testing.T) {
		network := gonnect.NewLoopbackNetwork()
		listener, err := network.ListenTCP(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("listener close failed: %v", err)
		}
		_, err = listener.AcceptTCP()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("AcceptTCP error = %v, want errors.Is(net.ErrClosed)", err)
		}
	})
}

func TestPipeUDPDeadline(t *testing.T) {
	conn1, conn2 := gonnect.PipeUDP()
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

func TestLoopbackUDPConcurrentCloseAndWrite(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()

	receiver, err := network.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create receiver: %v", err)
	}
	sender, err := network.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		receiver.Close()
		t.Fatalf("failed to create sender: %v", err)
	}
	defer sender.Close()

	var sawErr atomic.Bool
	var wg sync.WaitGroup

	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := sender.WriteTo(
					[]byte("ping"),
					receiver.LocalAddr(),
				)
				if err != nil {
					sawErr.Store(true)
					return
				}
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver close failed: %v", err)
	}

	wg.Wait()
	if !sawErr.Load() {
		t.Fatal("expected at least one write to fail after receiver close")
	}
}

func TestLoopbackUDPDownWhileWriting(t *testing.T) {
	network := gonnect.NewLoopbackNetwork()

	receiver, err := network.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create receiver: %v", err)
	}
	sender, err := network.ListenUDP(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		receiver.Close()
		t.Fatalf("failed to create sender: %v", err)
	}

	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := sender.WriteTo(
					[]byte("ping"),
					receiver.LocalAddr(),
				); err != nil {
					return
				}
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)

	if err := network.Down(); err != nil {
		t.Fatalf("network down failed: %v", err)
	}

	wg.Wait()
}
