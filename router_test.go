// nolint
package gonnect_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestRouter_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		r := gonnect.NewRouter()
		if err := r.Attach(1, &gonnect.RejectNetwork{}); err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		return r
	})
}

func TestRouter_Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		r := gonnect.NewRouter()
		if err := r.Attach(1, gonnect.NativeConfig{}.Build()); err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		return r
	}, "127.0.0.1:0")
}

func TestRouterDefaultTCPRoute(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	if err := r.Attach(1, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	ln, err := r.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan gonnect.TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- c
	}()

	client, err := r.DialTCP(ctx, "tcp", "", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer client.Close()

	var server gonnect.TCPConn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-errs:
		t.Fatalf("AcceptTCP() error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for AcceptTCP()")
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	buf := make([]byte, 4)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("server Read() error = %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("server read %q, want ping", buf)
	}
}

func TestRouterReplaceBackendClosesSlotObjects(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	if err := r.Attach(1, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	ln, err := r.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()

	client, err := r.Dial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	if err := r.Attach(1, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("reattach error = %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = client.Read([]byte{0})
	if err == nil {
		t.Fatal("client Read() succeeded after backend replacement")
	}
	if _, err := ln.Accept(); err == nil {
		t.Fatal("old listener accepted after backend replacement")
	}
}

func TestRouterUDPListenRoutesEachPacketAndReattaches(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	cfg := &testRouterCfg{udpSlotByPort: map[string]int{
		"30001": 1,
		"30002": 2,
		"30003": 2,
	}}
	r.SetCfg(cfg)

	backend1 := gonnect.NewLoopbackNetwok()
	backend2 := gonnect.NewLoopbackNetwok()
	if err := r.Attach(1, backend1); err != nil {
		t.Fatalf("Attach(1) error = %v", err)
	}
	if err := r.Attach(2, backend2); err != nil {
		t.Fatalf("Attach(2) error = %v", err)
	}

	frontend, err := r.ListenUDP(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer frontend.Close()
	addr := frontend.LocalAddr().String()

	client1 := dialUDPFrom(t, backend1, "127.0.0.1:30001", addr)
	defer client1.Close()
	client2 := dialUDPFrom(t, backend2, "127.0.0.1:30002", addr)
	defer client2.Close()

	writeUDP(t, client1, "one")
	src1 := readFrontendUDP(t, frontend, "one")
	writeUDP(t, client2, "two")
	src2 := readFrontendUDP(t, frontend, "two")

	writeFrontendUDP(t, frontend, "reply-one", src1)
	readUDP(t, client1, "reply-one")
	writeFrontendUDP(t, frontend, "reply-two", src2)
	readUDP(t, client2, "reply-two")

	if err := r.Detach(2); err != nil {
		t.Fatalf("Detach(2) error = %v", err)
	}
	if _, err := client2.Write([]byte("after-detach")); err == nil {
		t.Fatal("client Write() to detached backend listener succeeded")
	}
	if _, err := frontend.WriteTo([]byte("closed"), src2); err == nil {
		t.Fatal("WriteTo() to detached slot succeeded")
	}

	backend2b := gonnect.NewLoopbackNetwok()
	if err := r.Attach(2, backend2b); err != nil {
		t.Fatalf("reattach slot 2 error = %v", err)
	}
	client3 := dialUDPFrom(t, backend2b, "127.0.0.1:30003", addr)
	defer client3.Close()

	writeUDP(t, client3, "three")
	src3 := readFrontendUDP(t, frontend, "three")
	writeFrontendUDP(t, frontend, "reply-three", src3)
	readUDP(t, client3, "reply-three")
}

func TestRouterUDPConnCompatibilityMethods(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	r.SetCfg(&testRouterCfg{udpSlotByPort: map[string]int{"30100": 1}})
	backend := gonnect.NewLoopbackNetwok()
	if err := r.Attach(1, backend); err != nil {
		t.Fatalf("Attach(1) error = %v", err)
	}

	frontend, err := r.ListenUDP(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer frontend.Close()
	if frontend.RemoteAddr() != nil {
		t.Fatalf("RemoteAddr() = %v, want nil", frontend.RemoteAddr())
	}
	if _, err := frontend.Write([]byte("unconnected")); err == nil {
		t.Fatal("Write() on unconnected UDP listener succeeded")
	}
	if err := frontend.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := frontend.SetWriteDeadline(
		time.Now().Add(time.Second),
	); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}

	client := dialUDPFrom(
		t,
		backend,
		"127.0.0.1:30100",
		frontend.LocalAddr().String(),
	)
	defer client.Close()

	writeUDP(t, client, "read")
	buf := make([]byte, 64)
	n, err := frontend.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf[:n]) != "read" {
		t.Fatalf("Read() = %q, want read", buf[:n])
	}

	writeUDP(t, client, "udp")
	n, udpAddr, err := frontend.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP() error = %v", err)
	}
	if string(buf[:n]) != "udp" {
		t.Fatalf("ReadFromUDP() = %q, want udp", buf[:n])
	}

	writeUDP(t, client, "addrport")
	n, addrPort, err := frontend.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ReadFromUDPAddrPort() error = %v", err)
	}
	if string(buf[:n]) != "addrport" {
		t.Fatalf("ReadFromUDPAddrPort() = %q, want addrport", buf[:n])
	}

	writeUDP(t, client, "msg")
	n, _, _, msgAddr, err := frontend.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDP() error = %v", err)
	}
	if string(buf[:n]) != "msg" {
		t.Fatalf("ReadMsgUDP() = %q, want msg", buf[:n])
	}

	writeUDP(t, client, "msgaddrport")
	n, _, _, msgAddrPort, err := frontend.ReadMsgUDPAddrPort(buf, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDPAddrPort() error = %v", err)
	}
	if string(buf[:n]) != "msgaddrport" {
		t.Fatalf("ReadMsgUDPAddrPort() = %q, want msgaddrport", buf[:n])
	}

	if _, err := frontend.WriteToUDP([]byte("to-udp"), udpAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
	readUDP(t, client, "to-udp")

	if _, err := frontend.WriteToUDPAddrPort(
		[]byte("to-addrport"),
		addrPort,
	); err != nil {
		t.Fatalf("WriteToUDPAddrPort() error = %v", err)
	}
	readUDP(t, client, "to-addrport")

	if _, _, err := frontend.WriteMsgUDP(
		[]byte("msg-udp"),
		nil,
		msgAddr,
	); err != nil {
		t.Fatalf("WriteMsgUDP() error = %v", err)
	}
	readUDP(t, client, "msg-udp")

	if _, _, err := frontend.WriteMsgUDPAddrPort(
		[]byte("msg-addrport"),
		nil,
		msgAddrPort,
	); err != nil {
		t.Fatalf("WriteMsgUDPAddrPort() error = %v", err)
	}
	readUDP(t, client, "msg-addrport")

	missing := netip.MustParseAddrPort("127.0.0.1:39999")
	if _, err := frontend.WriteToUDPAddrPort(
		[]byte("missing"),
		missing,
	); err == nil {
		t.Fatal("WriteToUDPAddrPort() to missing routed backend succeeded")
	}
}

func TestRouterRejectsMissingAndInvalidSlotsLikeRejectNetwork(t *testing.T) {
	ctx := context.Background()
	reject := &gonnect.RejectNetwork{}
	r := gonnect.NewRouter()
	r.SetCfg(testRouterCfg{tcpSlot: 2, udpSlot: 17})

	_, got := r.DialTCP(ctx, "tcp", "", "127.0.0.1:80")
	_, want := reject.DialTCP(ctx, "tcp", "", "127.0.0.1:80")
	if got == nil || got.Error() != want.Error() {
		t.Fatalf("DialTCP() error = %v, want %v", got, want)
	}

	_, got = r.ListenTCP(ctx, "tcp", "127.0.0.1:80")
	_, want = reject.ListenTCP(ctx, "tcp", "127.0.0.1:80")
	if got == nil || got.Error() != want.Error() {
		t.Fatalf("ListenTCP() error = %v, want %v", got, want)
	}

	_, got = r.DialUDP(ctx, "udp", "", "127.0.0.1:80")
	_, want = reject.DialUDP(ctx, "udp", "", "127.0.0.1:80")
	if got == nil || got.Error() != want.Error() {
		t.Fatalf("DialUDP() error = %v, want %v", got, want)
	}
}

func TestRouterLookupRoutesThroughConfig(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	r.SetCfg(testRouterCfg{lookupSlot: 2})
	if err := r.Attach(1, &gonnect.RejectNetwork{}); err != nil {
		t.Fatalf("Attach(1) error = %v", err)
	}
	if err := r.Attach(2, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(2) error = %v", err)
	}

	addrs, err := r.LookupHost(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupHost() error = %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "127.0.0.1" {
		t.Fatalf("LookupHost() = %v, want loopback results", addrs)
	}

	r.SetCfg(testRouterCfg{lookupSlot: 1})
	if _, err := r.LookupHost(ctx, "localhost"); err == nil {
		t.Fatal("LookupHost() succeeded through rejecting slot")
	}
}

func TestRouterResolverOverridesLookupAndPreResolvesDial(t *testing.T) {
	ctx := context.Background()
	r := gonnect.NewRouter()
	cfg := &recordingRouterCfg{testRouterCfg: testRouterCfg{lookupSlot: 16}}
	r.SetCfg(cfg)
	r.SetResolver(&routerTestResolver{
		hosts: map[string][]net.IP{
			"service.test": {net.ParseIP("127.0.0.1")},
			"localhost":    {net.ParseIP("127.0.0.1")},
		},
		ports: map[string]int{"svc": 0},
	})

	addrs, err := r.LookupHost(ctx, "service.test")
	if err != nil {
		t.Fatalf("LookupHost() with resolver error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Fatalf("LookupHost() = %v, want resolver result", addrs)
	}

	if err := r.Attach(1, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(1) error = %v", err)
	}
	ln, err := r.ListenTCP(ctx, "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%s) error = %v", ln.Addr(), err)
	}
	r.SetResolver(&routerTestResolver{
		hosts: map[string][]net.IP{
			"service.test": {net.ParseIP("127.0.0.1")},
		},
		ports: map[string]int{"svc": mustAtoi(t, port)},
	})

	accepted := make(chan gonnect.TCPConn, 1)
	go func() {
		c, _ := ln.AcceptTCP()
		accepted <- c
	}()

	client, err := r.DialTCP(ctx, "tcp", "", "service.test:svc")
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	cfg.mu.Lock()
	raddr := cfg.lastRaddr
	cfg.mu.Unlock()
	if strings.Contains(raddr, "service.test") ||
		strings.Contains(raddr, "svc") {
		t.Fatalf("RouterCfg saw unresolved raddr %q", raddr)
	}

	r.SetResolver(nil)
	if _, err := r.LookupHost(ctx, "service.test"); err == nil {
		t.Fatal("LookupHost() succeeded after resolver removal")
	}
}

func TestRouterSubscribeCloser(t *testing.T) {
	r := gonnect.NewRouter()
	closer := &routerTestCloser{}
	unsubscribe, err := r.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	unsubscribe()
	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closed {
		t.Fatal("unsubscribed closer was closed")
	}

	late := &routerTestCloser{}
	unsubscribe, err = r.SubscribeCloser(late)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SubscribeCloser() error = %v, want net.ErrClosed", err)
	}
	if unsubscribe != nil {
		t.Fatal("SubscribeCloser() returned unsubscribe after error")
	}
	if !late.closed {
		t.Fatal("late closer was not closed")
	}
}

type testRouterCfg struct {
	tcpSlot       int
	udpSlot       int
	lookupSlot    int
	udpSlotByPort map[string]int
}

func (c testRouterCfg) DialTCP(network, laddr, raddr string) int {
	if c.tcpSlot == 0 {
		return 1
	}
	return c.tcpSlot
}

func (c testRouterCfg) ListenTCP(network, laddr string) int {
	if c.tcpSlot == 0 {
		return 1
	}
	return c.tcpSlot
}

func (c testRouterCfg) DialUDP(network, laddr, raddr string) int {
	if c.udpSlot == 0 {
		return 1
	}
	return c.udpSlot
}

func (c testRouterCfg) RouteUDP(network string, laddr, raddr net.Addr) int {
	_, port, err := net.SplitHostPort(raddr.String())
	if err == nil {
		if slot := c.udpSlotByPort[port]; slot != 0 {
			return slot
		}
	}
	if c.udpSlot == 0 {
		return 1
	}
	return c.udpSlot
}

func (c testRouterCfg) Lookup(network, address string) int {
	if c.lookupSlot == 0 {
		return 1
	}
	return c.lookupSlot
}

type recordingRouterCfg struct {
	testRouterCfg
	mu        sync.Mutex
	lastRaddr string
}

func (c *recordingRouterCfg) DialTCP(network, laddr, raddr string) int {
	c.mu.Lock()
	c.lastRaddr = raddr
	c.mu.Unlock()
	return c.testRouterCfg.DialTCP(network, laddr, raddr)
}

type routerTestResolver struct {
	gonnect.RejectNetwork
	hosts map[string][]net.IP
	ports map[string]int
}

func (r *routerTestResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	ips := r.hosts[host]
	if len(ips) == 0 {
		return nil, gonnect.NoSuchHost(host, "testrouterdns")
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

func (r *routerTestResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	ips := r.hosts[host]
	if len(ips) == 0 {
		return nil, gonnect.NoSuchHost(host, "testrouterdns")
	}
	return append([]net.IP(nil), ips...), nil
}

func (r *routerTestResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	port, ok := r.ports[service]
	if !ok {
		return 0, gonnect.NoSuchHost(service, "testrouterdns")
	}
	return port, nil
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	i, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("Atoi(%q) error = %v", s, err)
	}
	return i
}

func dialUDPFrom(
	t *testing.T,
	n gonnect.Network,
	laddr, raddr string,
) gonnect.UDPConn {
	t.Helper()
	c, err := n.DialUDP(context.Background(), "udp", laddr, raddr)
	if err != nil {
		t.Fatalf("DialUDP(%s -> %s) error = %v", laddr, raddr, err)
	}
	return c
}

func writeUDP(t *testing.T, c gonnect.UDPConn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("Write(%q) error = %v", msg, err)
	}
}

func writeFrontendUDP(
	t *testing.T,
	c gonnect.UDPConn,
	msg string,
	addr net.Addr,
) {
	t.Helper()
	if _, err := c.WriteTo([]byte(msg), addr); err != nil {
		t.Fatalf("WriteTo(%q, %s) error = %v", msg, addr, err)
	}
}

func readFrontendUDP(
	t *testing.T,
	c gonnect.UDPConn,
	want string,
) net.Addr {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 64)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if string(buf[:n]) != want {
		t.Fatalf("ReadFrom() = %q, want %q", buf[:n], want)
	}
	return addr
}

func readUDP(t *testing.T, c gonnect.UDPConn, want string) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if strings.TrimSpace(string(buf[:n])) != want {
		t.Fatalf("Read() = %q, want %q", buf[:n], want)
	}
}

type routerTestCloser struct {
	closed bool
}

func (c *routerTestCloser) Close() error {
	c.closed = true
	return nil
}
