// nolint
package gonnect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestCallbacksRunMethods(t *testing.T) {
	var calls int
	var nilCallbacks *Callbacks
	nilCallbacks.RunBeforeClose()
	conn, err := nilCallbacks.RunOnAccept(&fakeConn{})
	if err != nil || conn == nil {
		t.Fatalf("nil RunOnAccept = %v, %v", conn, err)
	}
	tcpConn, err := nilCallbacks.RunOnAcceptTCP(&callbackTestTCPConn{})
	if err != nil || tcpConn == nil {
		t.Fatalf("nil RunOnAcceptTCP = %v, %v", tcpConn, err)
	}

	cbErr := errors.New("callback error")
	cb := &Callbacks{
		BeforeClose: func() { calls++ },
		OnAccept: func(net.Conn) (net.Conn, error) {
			return nil, cbErr
		},
		OnAcceptTCP: func(TCPConn) (TCPConn, error) {
			return nil, cbErr
		},
	}
	cb.RunBeforeClose()
	if calls != 1 {
		t.Fatalf("BeforeClose calls = %d, want 1", calls)
	}
	if _, err := cb.RunOnAccept(&fakeConn{}); !errors.Is(err, cbErr) {
		t.Fatalf("RunOnAccept error = %v, want %v", err, cbErr)
	}
	if _, err := cb.RunOnAcceptTCP(
		&callbackTestTCPConn{},
	); !errors.Is(
		err,
		cbErr,
	) {
		t.Fatalf("RunOnAcceptTCP error = %v, want %v", err, cbErr)
	}
}

func TestCallbackPacketWrappers(t *testing.T) {
	pc := &fakePacketConn{}
	var calls int
	wrapped := PacketConnWithCallbacks(pc, &Callbacks{
		BeforeClose: func() { calls++ },
	})
	if GetWrapped(wrapped) != pc {
		t.Fatalf(
			"PacketConnWithCallbacks wrapped = %T, want fake packet conn",
			GetWrapped(wrapped),
		)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("packet Close error = %v", err)
	}
	if calls != 1 || pc.closed != 1 {
		t.Fatalf("packet close calls = %d/%d, want 1/1", calls, pc.closed)
	}

	npc := &fakeNetPacketConn{}
	calls = 0
	netWrapped := NetPacketConnWithCallbacks(npc, &Callbacks{
		BeforeClose: func() { calls++ },
	})
	if GetWrapped(netWrapped) != npc {
		t.Fatalf(
			"NetPacketConnWithCallbacks wrapped = %T, want fake net packet conn",
			GetWrapped(netWrapped),
		)
	}
	if err := netWrapped.Close(); err != nil {
		t.Fatalf("net packet Close error = %v", err)
	}
	if calls != 1 || npc.closed != 1 {
		t.Fatalf("net packet close calls = %d/%d, want 1/1", calls, npc.closed)
	}
}

func TestCallbackWrapperAccessors(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	wrappedConn := ConnWithCallbacks(c1, &Callbacks{})
	if GetWrapped(wrappedConn) != c1 {
		t.Fatalf(
			"callback conn wrapped = %T, want original conn",
			GetWrapped(wrappedConn),
		)
	}

	ln := newCallbackTestListener()
	wrappedListener := ListenerWithCallbacks(ln, &Callbacks{})
	if GetWrapped(wrappedListener) != ln {
		t.Fatalf(
			"callback listener wrapped = %T, want original listener",
			GetWrapped(wrappedListener),
		)
	}

	tcpLn := newCallbackTestTCPListener()
	wrappedTCPListener := TCPListenerWithCallbacks(tcpLn, &Callbacks{})
	if GetWrapped(wrappedTCPListener) != tcpLn {
		t.Fatalf(
			"callback TCP listener wrapped = %T, want original listener",
			GetWrapped(wrappedTCPListener),
		)
	}

	tcpConn := TCPConnWithCallbacks(&callbackTestTCPConn{}, &Callbacks{})
	if GetWrapped(tcpConn) == nil {
		t.Fatal("callback TCP conn GetWrapped returned nil")
	}
	if tcpConn.(*CallbackTCPConn).callbacks() == nil {
		t.Fatal("callback TCP conn callbacks returned nil")
	}

	udpConn := UDPConnWithCallbacks(&fakeUDPConn{}, &Callbacks{})
	if GetWrapped(udpConn) == nil {
		t.Fatal("callback UDP conn GetWrapped returned nil")
	}
	if udpConn.(*CallbackUDPConn).callbacks() == nil {
		t.Fatal("callback UDP conn callbacks returned nil")
	}
	packetConn := PacketConnWithCallbacks(&fakePacketConn{}, &Callbacks{})
	if packetConn.(*CallbackPacketConn).callbacks() == nil {
		t.Fatal("callback packet conn callbacks returned nil")
	}
	netPacketConn := NetPacketConnWithCallbacks(
		&fakeNetPacketConn{},
		&Callbacks{},
	)
	if netPacketConn.(*CallbackNetPacketConn).callbacks() == nil {
		t.Fatal("callback net packet conn callbacks returned nil")
	}

	full := UDPConnWithCallbacks(&fakeFullUDPConn{}, &Callbacks{})
	if GetWrapped(full) == nil {
		t.Fatal("callback full UDP conn GetWrapped returned nil")
	}
	if full.(*callbackFullUDPConn).callbacks() == nil {
		t.Fatal("callback full UDP conn callbacks returned nil")
	}
}

func TestCallbackWrapperBranchVariants(t *testing.T) {
	var called int
	cb := &Callbacks{BeforeClose: func() { called++ }}

	wrappedConn := ConnWithCallbacks(&fakeFullUDPConn{}, cb)
	if _, ok := wrappedConn.(*callbackFullUDPConn); !ok {
		t.Fatalf(
			"ConnWithCallbacks full UDP = %T, want callbackFullUDPConn",
			wrappedConn,
		)
	}
	if again := ConnWithCallbacks(wrappedConn, cb); again != wrappedConn {
		t.Fatal("ConnWithCallbacks rewrapped callback wrapper")
	}
	_ = wrappedConn.Close()
	if called != 2 {
		t.Fatalf("full UDP close callbacks = %d, want 2", called)
	}

	wrappedPacket := PacketConnWithCallbacks(&fakeFullUDPConn{}, nil)
	if _, ok := wrappedPacket.(*callbackFullUDPConn); !ok {
		t.Fatalf(
			"PacketConnWithCallbacks full UDP = %T, want callbackFullUDPConn",
			wrappedPacket,
		)
	}
	if again := PacketConnWithCallbacks(
		wrappedPacket,
		cb,
	); again != wrappedPacket {
		t.Fatal("PacketConnWithCallbacks rewrapped callback wrapper")
	}

	wrappedUDP := UDPConnWithCallbacks(&fakeFullUDPConn{}, nil)
	if _, ok := wrappedUDP.(*callbackFullUDPConn); !ok {
		t.Fatalf(
			"UDPConnWithCallbacks full UDP = %T, want callbackFullUDPConn",
			wrappedUDP,
		)
	}
	if again := UDPConnWithCallbacks(wrappedUDP, cb); again != wrappedUDP {
		t.Fatal("UDPConnWithCallbacks rewrapped callback wrapper")
	}

	wrappedNetPacket := NetPacketConnWithCallbacks(&fakeUDPConn{}, nil)
	if _, ok := wrappedNetPacket.(*CallbackUDPConn); !ok {
		t.Fatalf(
			"NetPacketConnWithCallbacks UDP = %T, want CallbackUDPConn",
			wrappedNetPacket,
		)
	}
	if again := NetPacketConnWithCallbacks(
		wrappedNetPacket,
		cb,
	); again != wrappedNetPacket {
		t.Fatal("NetPacketConnWithCallbacks rewrapped callback wrapper")
	}
}

func TestCallbackSetNilAndErrorBranches(t *testing.T) {
	var nilSet *callbackSet
	nilSet.add(
		&Callbacks{BeforeClose: func() { t.Fatal("nil set called callback") }},
	)
	nilSet.runBeforeClose()
	if conn, err := nilSet.runOnAccept(&fakeConn{}); err != nil || conn == nil {
		t.Fatalf("nil runOnAccept = %v, %v, want conn nil", conn, err)
	}
	if conn, err := nilSet.runOnAcceptTCP(
		&callbackTestTCPConn{},
	); err != nil ||
		conn == nil {
		t.Fatalf("nil runOnAcceptTCP = %v, %v, want conn nil", conn, err)
	}

	acceptErr := errors.New("accept callback error")
	conn := &fakeConn{}
	set := newCallbackSet(&Callbacks{
		OnAccept: func(net.Conn) (net.Conn, error) { return conn, acceptErr },
	})
	if got, err := set.runOnAccept(
		conn,
	); !errors.Is(err, acceptErr) || got != nil ||
		conn.closed != 1 {
		t.Fatalf(
			"runOnAccept error branch = %v, %v, closed=%d",
			got,
			err,
			conn.closed,
		)
	}

	tcpConn := &callbackTestTCPConn{}
	set = newCallbackSet(&Callbacks{
		OnAcceptTCP: func(TCPConn) (TCPConn, error) { return tcpConn, acceptErr },
	})
	if got, err := set.runOnAcceptTCP(
		tcpConn,
	); !errors.Is(err, acceptErr) || got != nil ||
		tcpConn.closeCount.Load() != 1 {
		t.Fatalf(
			"runOnAcceptTCP error branch = %v, %v, closed=%d",
			got,
			err,
			tcpConn.closeCount.Load(),
		)
	}
}

func TestInterfacesAndWrapperHelpers(t *testing.T) {
	if got := WrapNativeInterfaces(nil); got != nil {
		t.Fatalf("WrapNativeInterfaces(nil) = %#v, want nil", got)
	}
	native := WrapNativeInterfaces([]net.Interface{{
		Index:        7,
		MTU:          1500,
		Name:         "test0",
		HardwareAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6},
		Flags:        net.FlagUp,
	}})
	if len(native) != 1 {
		t.Fatalf("native interfaces len = %d, want 1", len(native))
	}
	if native[0].ID() != "native:test0:7" ||
		native[0].Index() != 7 ||
		native[0].Name() != "test0" ||
		native[0].MTU() != 1500 ||
		!reflect.DeepEqual(
			native[0].HardwareAddr(),
			net.HardwareAddr{1, 2, 3, 4, 5, 6},
		) ||
		native[0].Flags() != net.FlagUp {
		t.Fatalf("native interface accessors returned unexpected values")
	}

	lit := &LiteralInterface{
		IDVal:           "literal",
		IndexVal:        3,
		NameVal:         "lit0",
		MTUVal:          1400,
		HardwareAddrVal: net.HardwareAddr{6, 5, 4, 3, 2, 1},
		FlagsVal:        net.FlagBroadcast,
	}
	if lit.ID() != "literal" || lit.Index() != 3 || lit.Name() != "lit0" ||
		lit.MTU() != 1400 || lit.Flags() != net.FlagBroadcast ||
		!reflect.DeepEqual(
			lit.HardwareAddr(),
			net.HardwareAddr{6, 5, 4, 3, 2, 1},
		) {
		t.Fatalf("literal interface accessors returned unexpected values")
	}
	if addrs, err := lit.Addrs(); err != nil || len(addrs) != 0 {
		t.Fatalf(
			"literal Addrs = %v, %v, want empty nil-error slice",
			addrs,
			err,
		)
	}
	if addrs, err := lit.MulticastAddrs(); err != nil || len(addrs) != 0 {
		t.Fatalf(
			"literal MulticastAddrs = %v, %v, want empty nil-error slice",
			addrs,
			err,
		)
	}
	ifaces, err := net.Interfaces()
	if err == nil && len(ifaces) > 0 {
		ni := &NativeInterface{Iface: ifaces[0]}
		if _, err := ni.Addrs(); err != nil {
			t.Fatalf("NativeInterface Addrs error = %v", err)
		}
		if _, err := nativeNetInterface(ni); err != nil {
			t.Fatalf("nativeNetInterface native error = %v", err)
		}
	}

	w := &testWrapper{wrapped: "value"}
	if GetWrapped(w) != "value" {
		t.Fatalf("GetWrapped(wrapper) failed")
	}
	if GetWrapped(nil) != nil || GetWrapped(struct{}{}) != nil {
		t.Fatalf("GetWrapped should return nil for nil/non-wrapper values")
	}
}

func TestHelperWrapperRecursion(t *testing.T) {
	mp := &multipathConn{Conn: &fakeConn{}, val: true}
	got, err := MultipathTCP(mp)
	if err != nil || !got {
		t.Fatalf("MultipathTCP direct = %v, %v, want true nil", got, err)
	}
	got, err = MultipathTCP(&connWrapper{Conn: &fakeConn{}, wrapped: mp})
	if err != nil || !got {
		t.Fatalf("MultipathTCP wrapped = %v, %v, want true nil", got, err)
	}
	got, err = MultipathTCP(&fakeConn{})
	if err != nil || got {
		t.Fatalf("MultipathTCP unsupported = %v, %v, want false nil", got, err)
	}

	sysErr := errors.New("syscall error")
	if _, err := SyscallConn(
		&syscallConnProvider{err: sysErr},
	); !errors.Is(
		err,
		sysErr,
	) {
		t.Fatalf("SyscallConn error = %v, want %v", err, sysErr)
	}
	if rc, err := SyscallConn(
		&testWrapper{wrapped: &syscallConnProvider{}},
	); err != nil ||
		rc != nil {
		t.Fatalf("SyscallConn wrapped = %v, %v, want nil nil", rc, err)
	}
	if rc, err := SyscallConn(nil); err != nil || rc != nil {
		t.Fatalf("SyscallConn nil = %v, %v, want nil nil", rc, err)
	}

	fileErr := errors.New("file error")
	if _, err := File(&fileProvider{err: fileErr}); !errors.Is(err, fileErr) {
		t.Fatalf("File error = %v, want %v", err, fileErr)
	}
	if f, err := File(
		&testWrapper{wrapped: &fileProvider{}},
	); err != nil ||
		f != nil {
		t.Fatalf("File wrapped = %v, %v, want nil nil", f, err)
	}
	if f, err := File(nil); err != nil || f != nil {
		t.Fatalf("File nil = %v, %v, want nil nil", f, err)
	}

	if err := joinNetErrors(errors.New("a"), nil); err == nil {
		t.Fatal("joinNetErrors returned nil for single error")
	}
	if err := joinNetErrors(nil, errors.New("b")); err == nil {
		t.Fatal("joinNetErrors returned nil for second error")
	}
	if err := joinNetErrors(errors.New("a"), errors.New("b")); err == nil {
		t.Fatal("joinNetErrors returned nil for two errors")
	}
	if err := joinNetErrors(net.ErrClosed, nil); err != nil {
		t.Fatalf("joinNetErrors(net.ErrClosed) = %v, want nil", err)
	}
}

func TestNetworkAndCloseHelpers(t *testing.T) {
	if NetworkFromConn(
		&fakeConn{local: &NetAddr{Net: "local", Addr: "l"}},
	) != "local" {
		t.Fatalf("NetworkFromConn should prefer local addr")
	}
	if NetworkFromConn(
		&fakeConn{remote: &NetAddr{Net: "remote", Addr: "r"}},
	) != "remote" {
		t.Fatalf("NetworkFromConn should use remote addr when local is nil")
	}
	if NetworkFromConn(&fakePacketConn{}) != "udp" {
		t.Fatalf("NetworkFromConn packet conn should default to udp")
	}
	if NetworkFromConn(&fakeConn{}) != "tcp" {
		t.Fatalf("NetworkFromConn conn should default to tcp")
	}

	a := &fakeCloser{}
	b := &fakeCloser{err: errors.New("ignored")}
	CloseAll([]io.Closer{a, b})
	if a.closed != 1 || b.closed != 1 {
		t.Fatalf("CloseAll close counts = %d/%d, want 1/1", a.closed, b.closed)
	}

	ch := make(chan int, 3)
	ch <- 1
	ch <- 2
	Drain(ch)
	if len(ch) != 0 {
		t.Fatalf("Drain left %d items, want 0", len(ch))
	}
}

func TestDefaultInterfaceBranches(t *testing.T) {
	ctx := context.Background()
	dialErr := errors.New("dial error")
	if _, err := DefaultInterface(
		ctx,
		&defaultIfaceNetwork{dialErr: dialErr},
	); !errors.Is(
		err,
		dialErr,
	) {
		t.Fatalf("DefaultInterface dial error = %v, want %v", err, dialErr)
	}

	if _, err := DefaultInterface(ctx, &defaultIfaceNetwork{
		conn: &fakeConn{local: &NetAddr{Net: "tcp", Addr: "not udp"}},
	}); !errors.Is(err, ErrNoDefaultInterface) {
		t.Fatalf(
			"DefaultInterface non-UDP local error = %v, want ErrNoDefaultInterface",
			err,
		)
	}

	ifaceErr := errors.New("interfaces error")
	if _, err := DefaultInterface(ctx, &defaultIfaceNetwork{
		conn: &fakeConn{
			local: &net.UDPAddr{IP: net.ParseIP("10.0.0.4"), Port: 12},
		},
		ifacesErr: ifaceErr,
	}); !errors.Is(err, ifaceErr) {
		t.Fatalf(
			"DefaultInterface interfaces error = %v, want %v",
			err,
			ifaceErr,
		)
	}

	got, err := DefaultInterface(ctx, &defaultIfaceNetwork{
		conn: &fakeConn{
			local: &net.UDPAddr{IP: net.ParseIP("10.0.0.4"), Port: 12},
		},
		ifaces: []NetworkInterface{&LiteralInterface{
			IDVal: "match",
			AddrsVal: []net.Addr{&net.IPNet{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(24, 32),
			}},
		}},
	})
	if err != nil || got.ID() != "match" {
		t.Fatalf("DefaultInterface match = %v, %v, want match nil", got, err)
	}
}

func TestErrorAndTCPListenerHelpers(t *testing.T) {
	dns := DnsReqErr("example.test", "127.0.0.1:53").(*net.DNSError)
	if dns.Name != "example.test" || dns.Server != "127.0.0.1:53" ||
		dns.IsNotFound || !dns.IsTemporary {
		t.Fatalf("DnsReqErr returned unexpected DNSError: %#v", dns)
	}

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP error = %v", err)
	}
	defer ln.Close()
	wrapped := &NetTCPListener{TCPListener: ln}
	accepted := make(chan TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := wrapped.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial error = %v", err)
	}
	defer client.Close()
	select {
	case err := <-errs:
		t.Fatalf("AcceptTCP error = %v", err)
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP timed out")
	}
}

func TestPipeAndPacketHelpers(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- PipeConn(a, b) }()
	_ = a.Close()
	_ = b.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("PipeConn closed pipes = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("PipeConn timed out")
	}

	src := &scriptedPacketConn{
		packets: []packetScriptItem{{
			data: []byte("abc"),
			addr: &NetAddr{Net: "udp", Addr: "127.0.0.1:1"},
		}},
		err: io.EOF,
	}
	dst := &recordingPacketConn{}
	n, err := CopyPacket(dst, src, 64, nil)
	if !errors.Is(err, io.EOF) || n != 3 {
		t.Fatalf("CopyPacket = %d, %v, want 3 EOF", n, err)
	}
	if len(dst.writes) != 1 || string(dst.writes[0]) != "abc" {
		t.Fatalf("CopyPacket writes = %q, want abc", dst.writes)
	}

	inc := &scriptedPacketConn{err: net.ErrClosed}
	out := &scriptedPacketConn{err: net.ErrClosed}
	if err := PipePacketConn(inc, out, 64, nil); err != nil {
		t.Fatalf("PipePacketConn closed packet conns = %v, want nil", err)
	}

	writeErr := errors.New("write packet error")
	if n, err := CopyPacket(
		&recordingPacketConn{err: writeErr},
		&scriptedPacketConn{
			packets: []packetScriptItem{{
				data: []byte("x"),
				addr: &NetAddr{Net: "udp", Addr: "127.0.0.1:1"},
			}},
		},
		8,
		nil,
	); !errors.Is(err, writeErr) ||
		n != 0 {
		t.Fatalf("CopyPacket write error = %d, %v, want 0 writeErr", n, err)
	}
}

func TestRejectNetworkExtraBranches(t *testing.T) {
	ctx := context.Background()
	n := &RejectNetwork{}
	if n.IsNative() {
		t.Fatal("RejectNetwork IsNative() = true, want false")
	}
	if ifs, err := n.Interfaces(); err != nil || len(ifs) != 0 {
		t.Fatalf("Interfaces = %v, %v, want empty nil-error slice", ifs, err)
	}
	if addrs, err := n.InterfaceAddrs(); err != nil || len(addrs) != 0 {
		t.Fatalf(
			"InterfaceAddrs = %v, %v, want empty nil-error slice",
			addrs,
			err,
		)
	}
	if addrs, err := n.InterfaceMulticastAddrs(); err != nil ||
		len(addrs) != 0 {
		t.Fatalf(
			"InterfaceMulticastAddrs = %v, %v, want empty nil-error slice",
			addrs,
			err,
		)
	}
	if _, err := n.ListenPacketConfig(
		ctx,
		nil,
		"udp",
		"127.0.0.1:1",
	); err == nil {
		t.Fatal("ListenPacketConfig returned nil error")
	}
	if _, err := n.ListenUDPConfig(ctx, nil, "udp", "127.0.0.1:1"); err == nil {
		t.Fatal("ListenUDPConfig returned nil error")
	}
	if _, err := n.ListenMulticastUDP(
		ctx,
		"udp",
		"224.0.0.1:1",
		MulticastOptions{},
	); err == nil {
		t.Fatal("ListenMulticastUDP returned nil error")
	}
	if _, err := n.LookupIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("LookupIP returned nil error")
	}
	if _, err := n.LookupIPAddr(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupIPAddr returned nil error")
	}
	if _, err := n.LookupNetIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("LookupNetIP returned nil error")
	}
	if _, err := n.LookupAddr(ctx, "192.0.2.1"); err == nil {
		t.Fatal("LookupAddr returned nil error")
	}
	if _, err := n.LookupCNAME(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupCNAME returned nil error")
	}
	if _, err := n.LookupPort(ctx, "tcp", "unknown-service"); err == nil {
		t.Fatal("LookupPort returned nil error")
	}
	if _, err := n.LookupNS(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupNS returned nil error")
	}
}

func TestResolverCfgAndGoDebugHelpers(t *testing.T) {
	if (&DnsServer{}).net() != "udp" {
		t.Fatal("empty DNS server network should default to udp")
	}
	if (&DnsServer{Net: "tcp"}).net() != "tcp" {
		t.Fatal("explicit DNS server network was not preserved")
	}
	if got := (&DnsServer{Addr: "1.1.1.1"}).addr(); got != "1.1.1.1:53" {
		t.Fatalf("DNS server addr without port = %q, want 1.1.1.1:53", got)
	}
	if got := (&DnsServer{Addr: "1.1.1.1:dns"}).addr(); got != "1.1.1.1:53" {
		t.Fatalf("DNS server dns service addr = %q, want 1.1.1.1:53", got)
	}
	if got := (&DnsServer{Addr: "1.1.1.1:5353"}).addr(); got != "1.1.1.1:5353" {
		t.Fatalf("DNS server explicit port addr = %q, want 1.1.1.1:5353", got)
	}

	var dialNetwork, dialAddress string
	dialErr := errors.New("dial blocked")
	resolver := ResolverCfg{
		Server: &DnsServer{Net: "tcp", Addr: "9.9.9.9:dns"},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialNetwork = network
			dialAddress = address
			return nil, dialErr
		},
	}.Build()
	if _, err := resolver.Dial(
		context.Background(),
		"udp",
		"ignored:53",
	); !errors.Is(
		err,
		dialErr,
	) {
		t.Fatalf("resolver Dial error = %v, want %v", err, dialErr)
	}
	if dialNetwork != "tcp" || dialAddress != "9.9.9.9:53" {
		t.Fatalf(
			"resolver Dial target = %s/%s, want tcp/9.9.9.9:53",
			dialNetwork,
			dialAddress,
		)
	}
	dialNetwork, dialAddress = "", ""
	resolver = ResolverCfg{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialNetwork = network
			dialAddress = address
			return nil, dialErr
		},
	}.Build()
	if _, err := resolver.Dial(
		context.Background(),
		"udp",
		"1.1.1.1:53",
	); !errors.Is(
		err,
		dialErr,
	) {
		t.Fatalf(
			"resolver Dial without server error = %v, want %v",
			err,
			dialErr,
		)
	}
	if dialNetwork != "udp" || dialAddress != "1.1.1.1:53" {
		t.Fatalf(
			"resolver Dial without server target = %s/%s",
			dialNetwork,
			dialAddress,
		)
	}
	if port, err := LookupPortOffline("udp", "ntp"); err != nil || port != 123 {
		t.Fatalf("LookupPortOffline udp/ntp = %d, %v, want 123 nil", port, err)
	}
	if _, err := LookupPortOffline(
		"tcp",
		"definitely-unknown-service",
	); err == nil {
		t.Fatal("LookupPortOffline unknown service returned nil error")
	}

	t.Setenv("GODEBUG", "")
	UnfuckGoDns()
	if got := os.Getenv("GODEBUG"); got != "netedns0=0" {
		t.Fatalf("GODEBUG empty result = %q, want netedns0=0", got)
	}
	t.Setenv("GODEBUG", "x=1")
	UnfuckGoDns()
	if got := os.Getenv("GODEBUG"); got != "x=1,netedns0=0" {
		t.Fatalf("GODEBUG append result = %q, want x=1,netedns0=0", got)
	}
	t.Setenv("GODEBUG", "netedns0=1")
	UnfuckGoDns()
	if got := os.Getenv("GODEBUG"); got != "netedns0=1" {
		t.Fatalf("GODEBUG existing result = %q, want netedns0=1", got)
	}
}

func TestNativeFilteredBranches(t *testing.T) {
	ctx := context.Background()
	n := NativeConfig{
		Filter: func(string, string) bool { return true },
	}.Build()
	if !n.IsNative() {
		t.Fatal("NativeNetwork IsNative() = false, want true")
	}

	if _, err := n.LookupIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("filtered LookupIP returned nil error")
	}
	if _, err := n.LookupIPAddr(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupIPAddr returned nil error")
	}
	if _, err := n.LookupNetIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("filtered LookupNetIP returned nil error")
	}
	if _, err := n.LookupHost(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupHost returned nil error")
	}
	if _, err := n.LookupAddr(ctx, "192.0.2.1"); err == nil {
		t.Fatal("filtered LookupAddr returned nil error")
	}
	if _, err := n.LookupCNAME(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupCNAME returned nil error")
	}
	if _, err := n.LookupPort(ctx, "tcp", "http"); err == nil {
		t.Fatal("filtered LookupPort returned nil error")
	}
	if _, err := n.LookupTXT(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupTXT returned nil error")
	}
	if _, err := n.LookupMX(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupMX returned nil error")
	}
	if _, err := n.LookupNS(ctx, "example.invalid"); err == nil {
		t.Fatal("filtered LookupNS returned nil error")
	}
	if _, _, err := n.LookupSRV(
		ctx,
		"svc",
		"tcp",
		"example.invalid",
	); err == nil {
		t.Fatal("filtered LookupSRV returned nil error")
	}
	if _, _, err := n.LookupNetAddr(
		ctx,
		"tcp",
		"example.invalid:80",
	); err == nil {
		t.Fatal("filtered LookupNetAddr returned nil error")
	}
	if _, err := n.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("filtered Dial returned nil error")
	}
	if _, err := n.Listen(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("filtered Listen returned nil error")
	}

	if err := (&NativeNetwork{}).doFilter(
		"tcp",
		"127.0.0.1:1",
		actionDial,
	); err != nil {
		t.Fatalf("nil filter doFilter = %v, want nil", err)
	}
	if got := (nativeAddr{network: "tcp", address: "host:1"}); got.Network() != "tcp" ||
		got.String() != "host:1" {
		t.Fatalf(
			"nativeAddr accessors returned %q/%q",
			got.Network(),
			got.String(),
		)
	}
	if nativePickIP(nil, 4) != nil {
		t.Fatal("nativePickIP(nil) should return nil")
	}
	if DefaultNetwork(nil) == nil {
		t.Fatal("DefaultNetwork returned nil")
	}
	if _, err := n.ListenMulticastUDP(
		ctx,
		"udp4",
		"",
		MulticastOptions{},
	); err == nil {
		t.Fatal("filtered ListenMulticastUDP udp4 returned nil error")
	}
	if flags := nativeIPv6ControlFlags(
		ControlDst | ControlInterface,
	); flags == 0 {
		t.Fatal("nativeIPv6ControlFlags returned zero for both flags")
	}
	if cm := controlMessageFromNative(nil); cm != (ControlMessage{}) {
		t.Fatalf("controlMessageFromNative(nil) = %#v, want zero", cm)
	}
	if native := controlMessageToNative(ControlMessage{}); native != nil {
		t.Fatalf("controlMessageToNative(empty) = %#v, want nil", native)
	}
	if native := controlMessageToNative(
		ControlMessage{IfIndex: 123},
	); native == nil ||
		native.IfIndex != 123 {
		t.Fatalf(
			"controlMessageToNative(IfIndex) = %#v, want index 123",
			native,
		)
	}
	if got := addrIP(
		&net.IPAddr{IP: net.ParseIP("192.0.2.1")},
	); !got.Equal(
		net.ParseIP("192.0.2.1"),
	) {
		t.Fatalf("addrIP(IPAddr) = %v", got)
	}
	if got := addrIP(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.2")},
	); !got.Equal(
		net.ParseIP("192.0.2.2"),
	) {
		t.Fatalf("addrIP(UDPAddr) = %v", got)
	}
	if got := addrIP(
		&net.IPNet{IP: net.ParseIP("192.0.2.3")},
	); !got.Equal(
		net.ParseIP("192.0.2.3"),
	) {
		t.Fatalf("addrIP(IPNet) = %v", got)
	}
	if got := addrIP(
		&NetAddr{Net: "ip", Addr: "192.0.2.4%eth0"},
	); !got.Equal(
		net.ParseIP("192.0.2.4"),
	) {
		t.Fatalf("addrIP(zone addr) = %v", got)
	}
	if _, err := nativeNetInterface(&LiteralInterface{}); err == nil {
		t.Fatal("nativeNetInterface empty literal returned nil error")
	}
	if got := nativeFamilyFromNetwork("tcp6"); got != "ip6" {
		t.Fatalf("nativeFamilyFromNetwork tcp6 = %q, want ip6", got)
	}
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}
	if got := nativePickIP(ips, 4); !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("nativePickIP prefer 4 = %v", got)
	}
	if got := nativePickIP(ips, 6); !got.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("nativePickIP prefer 6 = %v", got)
	}
	if got := nativePickIP(ips, 0); !got.Equal(ips[0]) {
		t.Fatalf("nativePickIP no preference = %v", got)
	}
}

func TestNativeUnprivilegedBranches(t *testing.T) {
	ctx := context.Background()
	n := NativeConfig{
		ResolverCfg: &ResolverCfg{DontPreferGo: true},
		ListenCfg:   &net.ListenConfig{},
		PreferIP:    4,
	}.Build()

	if _, err := n.InterfaceAddrs(); err != nil {
		t.Fatalf("InterfaceAddrs error = %v", err)
	}
	if _, err := n.InterfaceMulticastAddrs(); err != nil {
		t.Fatalf("InterfaceMulticastAddrs error = %v", err)
	}
	ifs, err := n.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces error = %v", err)
	}
	if len(ifs) > 0 {
		if _, err := n.InterfacesByIndex(ifs[0].Index()); err != nil {
			t.Fatalf("InterfacesByIndex error = %v", err)
		}
		if _, err := n.InterfacesByName(ifs[0].Name()); err != nil {
			t.Fatalf("InterfacesByName error = %v", err)
		}
	}

	if hosts, err := n.LookupHost(
		ctx,
		"localhost",
	); err != nil ||
		len(hosts) == 0 {
		t.Fatalf("LookupHost(localhost) = %v, %v", hosts, err)
	}
	if ips, err := n.LookupIP(
		ctx,
		"ip",
		"localhost",
	); err != nil ||
		len(ips) == 0 {
		t.Fatalf("LookupIP(localhost) = %v, %v", ips, err)
	}
	if addrs, err := n.LookupIPAddr(
		ctx,
		"localhost",
	); err != nil ||
		len(addrs) == 0 {
		t.Fatalf("LookupIPAddr(localhost) = %v, %v", addrs, err)
	}
	if ips, err := n.LookupNetIP(
		ctx,
		"ip",
		"localhost",
	); err != nil ||
		len(ips) == 0 {
		t.Fatalf("LookupNetIP(localhost) = %v, %v", ips, err)
	}
	if names, err := n.LookupAddr(
		ctx,
		"127.0.0.1",
	); err != nil ||
		len(names) == 0 {
		t.Fatalf("LookupAddr(127.0.0.1) = %v, %v", names, err)
	}
	_, _ = n.LookupCNAME(ctx, "localhost")
	if port, err := n.LookupPort(ctx, "tcp", "http"); err != nil || port != 80 {
		t.Fatalf("LookupPort(http) = %d, %v", port, err)
	}
	if _, err := n.LookupNS(ctx, "localhost"); err == nil {
		t.Fatal("LookupNS(localhost) returned nil error")
	}

	packet, err := n.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	_ = packet.Close()
	packet, err = n.ListenPacketConfig(ctx, nil, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacketConfig error = %v", err)
	}
	_ = packet.Close()
	udp, err := n.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP error = %v", err)
	}
	defer udp.Close()
	udpCfg, err := n.ListenUDPConfig(ctx, nil, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDPConfig error = %v", err)
	}
	_ = udpCfg.Close()

	dialedUDP, err := n.DialUDP(
		ctx,
		"udp4",
		"127.0.0.1:0",
		udp.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("DialUDP error = %v", err)
	}
	_ = dialedUDP.Close()

	tcpLn, err := n.ListenTCP(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP error = %v", err)
	}
	defer tcpLn.Close()
	accepted := make(chan TCPConn, 1)
	go func() {
		conn, _ := tcpLn.AcceptTCP()
		accepted <- conn
	}()
	tcpConn, err := n.DialTCP(ctx, "tcp4", "127.0.0.1:0", tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP error = %v", err)
	}
	_ = tcpConn.Close()
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("native AcceptTCP timed out")
	}
}

func TestLoopbackLookupAndStateBranches(t *testing.T) {
	ctx := context.Background()
	ln := NewLoopbackNetwok()
	if ln.IsNative() {
		t.Fatal("LoopbackNetwork IsNative() = true, want false")
	}
	if up, err := ln.IsUp(); err != nil || !up {
		t.Fatalf("initial IsUp = %v, %v, want true nil", up, err)
	}
	if addrs, err := ln.InterfaceAddrs(); err != nil || len(addrs) == 0 {
		t.Fatalf(
			"InterfaceAddrs = %v, %v, want non-empty nil-error slice",
			addrs,
			err,
		)
	}
	if _, err := ln.InterfacesByIndex(2); err == nil {
		t.Fatal("InterfacesByIndex(2) returned nil error")
	}
	if ifs, err := ln.InterfacesByIndex(1); err != nil || len(ifs) != 1 {
		t.Fatalf("InterfacesByIndex(1) = %v, %v, want one nil", ifs, err)
	}
	if _, err := ln.InterfacesByName("bad0"); err == nil {
		t.Fatal("InterfacesByName(bad0) returned nil error")
	}

	if txt, err := ln.LookupTXT(ctx, "localhost"); err != nil || len(txt) != 0 {
		t.Fatalf("LookupTXT(localhost) = %v, %v, want empty nil", txt, err)
	}
	if _, err := ln.LookupTXT(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupTXT(non-local) returned nil error")
	}
	if names, err := ln.LookupAddr(
		ctx,
		"127.0.0.1",
	); err != nil || len(names) != 1 ||
		names[0] != "localhost" {
		t.Fatalf("LookupAddr(local) = %v, %v, want localhost nil", names, err)
	}
	if _, err := ln.LookupAddr(ctx, "192.0.2.1"); err == nil {
		t.Fatal("LookupAddr(non-local) returned nil error")
	}
	if _, err := ln.LookupCNAME(ctx, "localhost"); err == nil {
		t.Fatal("LookupCNAME returned nil error")
	}
	if port, err := ln.LookupPort(
		ctx,
		"tcp",
		"http",
	); err != nil ||
		port != 80 {
		t.Fatalf("LookupPort(http) = %d, %v, want 80 nil", port, err)
	}
	if ips, err := ln.LookupIP(
		ctx,
		"ip4",
		"localhost",
	); err != nil || len(ips) != 1 ||
		ips[0].To4() == nil {
		t.Fatalf("LookupIP(ip4 localhost) = %v, %v, want IPv4 nil", ips, err)
	}
	if ips, err := ln.LookupIP(
		ctx,
		"ip6",
		"localhost",
	); err != nil || len(ips) != 1 ||
		ips[0].To4() != nil {
		t.Fatalf("LookupIP(ip6 localhost) = %v, %v, want IPv6 nil", ips, err)
	}
	if ips, err := ln.LookupIP(
		ctx,
		"ip",
		"localhost",
	); err != nil ||
		len(ips) != 2 {
		t.Fatalf("LookupIP(ip localhost) = %v, %v, want two nil", ips, err)
	}
	if _, err := ln.LookupIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("LookupIP(non-local) returned nil error")
	}
	if ips, err := ln.LookupNetIP(
		ctx,
		"ip4",
		"localhost",
	); err != nil || len(ips) != 1 ||
		!ips[0].Is4() {
		t.Fatalf("LookupNetIP(ip4 localhost) = %v, %v, want IPv4 nil", ips, err)
	}
	if ips, err := ln.LookupNetIP(
		ctx,
		"ip6",
		"localhost",
	); err != nil ||
		len(ips) != 1 {
		t.Fatalf("LookupNetIP(ip6 localhost) = %v, %v, want one nil", ips, err)
	}
	if ips, err := ln.LookupNetIP(
		ctx,
		"ip",
		"localhost",
	); err != nil ||
		len(ips) != 2 {
		t.Fatalf("LookupNetIP(ip localhost) = %v, %v, want two nil", ips, err)
	}
	if _, err := ln.LookupNetIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("LookupNetIP(non-local) returned nil error")
	}
	if _, err := ln.LookupNS(ctx, "localhost"); err == nil {
		t.Fatal("LookupNS returned nil error")
	}
	if addrs, err := ln.LookupIPAddr(
		ctx,
		"localhost",
	); err != nil ||
		len(addrs) != 2 {
		t.Fatalf(
			"LookupIPAddr(localhost) = %v, %v, want two addrs nil",
			addrs,
			err,
		)
	}
	if _, err := ln.LookupIPAddr(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupIPAddr(non-local) returned nil error")
	}

	if err := ln.Down(); err != nil {
		t.Fatalf("Down error = %v", err)
	}
	if up, err := ln.IsUp(); err != nil || up {
		t.Fatalf("IsUp after Down = %v, %v, want false nil", up, err)
	}
	if _, err := ln.LookupPort(ctx, "tcp", "http"); err == nil {
		t.Fatal("LookupPort while down returned nil error")
	}
	if _, err := ln.LookupMX(ctx, "localhost"); err == nil {
		t.Fatal("LookupMX while down returned nil error")
	}
	if _, _, err := ln.LookupSRV(ctx, "svc", "tcp", "localhost"); err == nil {
		t.Fatal("LookupSRV while down returned nil error")
	}
	if err := ln.Up(); err != nil {
		t.Fatalf("Up error = %v", err)
	}
	if up, err := ln.IsUp(); err != nil || !up {
		t.Fatalf("IsUp after Up = %v, %v, want true nil", up, err)
	}
}

func TestLoopbackHelperBranches(t *testing.T) {
	var pa loopbackPortAllocator
	if !pa.isVoid() {
		t.Fatal("new allocator should be void")
	}
	port := uint16(8080)
	if got, err := pa.alloc(&port); err != nil || got != port {
		t.Fatalf("alloc explicit port = %d, %v, want %d nil", got, err, port)
	}
	if pa.isVoid() {
		t.Fatal("allocator with reserved port should not be void")
	}
	pa.free(port)
	if !pa.isVoid() {
		t.Fatal("allocator after free should be void")
	}
	pa.allocated = 16382
	if _, err := pa.alloc(nil); err == nil {
		t.Fatal("exhausted allocator returned nil error")
	}

	if got := loopbackHostToFamily("192.0.2.1"); got != "ip4" {
		t.Fatalf("loopbackHostToFamily IPv4 = %q, want ip4", got)
	}
	if got := loopbackHostToFamily("2001:db8::1"); got != "ip6" {
		t.Fatalf("loopbackHostToFamily IPv6 = %q, want ip6", got)
	}
	if _, err := normalizeLoopbackHost("tcp4", "::1"); err == nil {
		t.Fatal("normalizeLoopbackHost mismatched IPv6/tcp4 returned nil error")
	}
	if _, err := normalizeLoopbackHosts(
		"tcp4",
		"127.0.0.1",
		"::1",
	); err == nil {
		t.Fatal("normalizeLoopbackHosts mismatched families returned nil error")
	}
	if host := replaceNonLocalHostWithLocalhost(
		"example.invalid",
		true,
	); host != "localhost" {
		t.Fatalf("replaceNonLocalHostWithLocalhost = %q, want localhost", host)
	}
	if _, _, err := loopbackListenPrep(
		"tcp",
		"example.invalid:80",
		false,
	); err == nil {
		t.Fatal(
			"loopbackListenPrep non-local without AllowAnyHost returned nil error",
		)
	}
	if host, port, err := loopbackListenPrep(
		"tcp",
		"example.invalid:http",
		true,
	); err != nil || host != "127.0.0.1" || port == nil ||
		*port != 80 {
		t.Fatalf(
			"loopbackListenPrep AllowAnyHost = %q, %v, %v, want 127.0.0.1 80 nil",
			host,
			port,
			err,
		)
	}
	if _, _, _, err := loopbackDialPrep(
		"tcp",
		"example.invalid:0",
		"localhost:http",
		false,
	); err == nil {
		t.Fatal(
			"loopbackDialPrep non-local without AllowAnyHost returned nil error",
		)
	}
	if host, lport, rport, err := loopbackDialPrep(
		"tcp",
		"example.invalid:http",
		"localhost:http",
		true,
	); err != nil || host != "127.0.0.1" || lport == nil || *lport != 80 ||
		rport != 80 {
		t.Fatalf(
			"loopbackDialPrep AllowAnyHost = %q, %v, %d, %v",
			host,
			lport,
			rport,
			err,
		)
	}
	if timerForDeadline(time.Time{}) != nil {
		t.Fatal("timerForDeadline zero returned non-nil channel")
	}
	select {
	case <-timerForDeadline(time.Now().Add(-time.Millisecond)):
	case <-time.After(time.Second):
		t.Fatal("expired deadline timer did not fire")
	}
}

func TestLoopbackConfigAndMulticastHelpers(t *testing.T) {
	ctx := context.Background()
	ln := NewLoopbackNetwok()
	pc, err := ln.ListenPacketConfig(ctx, nil, "udp4", "localhost:0")
	if err != nil {
		t.Fatalf("ListenPacketConfig error = %v", err)
	}
	_ = pc.Close()
	uc, err := ln.ListenUDPConfig(ctx, nil, "udp4", "localhost:0")
	if err != nil {
		t.Fatalf("ListenUDPConfig error = %v", err)
	}
	_ = uc.Close()

	group := &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 5353, Zone: "lo"}
	if ip, port, zone, err := multicastDestination(
		group,
	); err != nil || !ip.Equal(group.IP) || port != 5353 ||
		zone != "lo" {
		t.Fatalf("multicastDestination UDP = %v/%d/%q/%v", ip, port, zone, err)
	}
	if ip, port, zone, err := multicastDestination(
		&net.IPAddr{IP: group.IP, Zone: "lo"},
	); err != nil || !ip.Equal(group.IP) || port != 0 ||
		zone != "lo" {
		t.Fatalf("multicastDestination IP = %v/%d/%q/%v", ip, port, zone, err)
	}
	if ip, port, zone, err := multicastDestination(
		&NetAddr{Net: "udp6", Addr: "[ff02::1%lo]:domain"},
	); err != nil || !ip.Equal(group.IP) || port != 53 ||
		zone != "lo" {
		t.Fatalf(
			"multicastDestination string = %v/%d/%q/%v",
			ip,
			port,
			zone,
			err,
		)
	}
	if _, _, _, err := multicastDestination(
		&net.UDPAddr{IP: net.IPv4(224, 0, 0, 1), Port: 1},
	); err == nil {
		t.Fatal("multicastDestination IPv4 multicast returned nil error")
	}
	if got, err := loopbackMulticastKey(
		&LiteralInterface{IndexVal: 1, NameVal: loopbackMulticastIfName},
		group,
		5353,
	); err != nil ||
		got == "" {
		t.Fatalf("loopbackMulticastKey = %q, %v", got, err)
	}
	if _, err := loopbackMulticastKey(
		&LiteralInterface{IndexVal: 2, NameVal: "bad0"},
		group,
		5353,
	); err == nil {
		t.Fatal("loopbackMulticastKey bad interface returned nil error")
	}
	masked := maskControlMessage(ControlMessage{
		Dst:     group,
		IfIndex: 1,
		IfName:  "lo",
	}, ControlDst)
	if masked.Dst == nil || masked.IfIndex != 0 || masked.IfName != "" {
		t.Fatalf("maskControlMessage ControlDst = %#v", masked)
	}
}

func TestLoopbackMulticastConnBehavior(t *testing.T) {
	ctx := context.Background()
	ln := NewLoopbackNetwok()
	group := &net.UDPAddr{
		IP:   net.ParseIP("ff02::1"),
		Port: 0,
		Zone: loopbackMulticastIfName,
	}

	recv, err := ln.ListenMulticastUDP(ctx, "udp", "", MulticastOptions{
		ControlFlags: ControlDst | ControlInterface,
	})
	if err != nil {
		t.Fatalf("ListenMulticastUDP recv error = %v", err)
	}
	defer recv.Close()
	send, err := ln.ListenMulticastUDP(
		ctx,
		"udp6",
		"[::]:0",
		MulticastOptions{},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP send error = %v", err)
	}
	defer send.Close()

	if err := recv.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline error = %v", err)
	}
	if err := recv.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline error = %v", err)
	}
	if err := send.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline error = %v", err)
	}
	if err := recv.JoinGroup(nil, group); err != nil {
		t.Fatalf("JoinGroup error = %v", err)
	}

	dst := &net.UDPAddr{
		IP:   group.IP,
		Port: recv.LocalAddr().(*net.UDPAddr).Port,
		Zone: loopbackMulticastIfName,
	}
	if n, err := send.WriteToControl(
		[]byte("hello"),
		ControlMessage{IfName: loopbackMulticastIfName},
		dst,
	); err != nil ||
		n != 5 {
		t.Fatalf("WriteToControl = %d, %v, want 5 nil", n, err)
	}
	buf := make([]byte, 16)
	n, cm, from, err := recv.ReadFromControl(buf)
	if err != nil || string(buf[:n]) != "hello" || cm.Dst == nil ||
		cm.IfIndex != 1 ||
		cm.IfName != loopbackMulticastIfName ||
		from == nil {
		t.Fatalf(
			"ReadFromControl = %d %q %#v %v %v",
			n,
			string(buf[:n]),
			cm,
			from,
			err,
		)
	}

	if err := recv.SetControlMessage(ControlInterface, false); err != nil {
		t.Fatalf("SetControlMessage off error = %v", err)
	}
	if n, err := send.WriteTo([]byte("two"), dst); err != nil || n != 3 {
		t.Fatalf("WriteTo = %d, %v, want 3 nil", n, err)
	}
	n, from, err = recv.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "two" || from == nil {
		t.Fatalf("ReadFrom = %d %q %v %v", n, string(buf[:n]), from, err)
	}

	if err := recv.LeaveGroup(nil, group); err != nil {
		t.Fatalf("LeaveGroup error = %v", err)
	}
	if _, err := send.WriteTo([]byte("lost"), dst); err == nil {
		t.Fatal("WriteTo after LeaveGroup returned nil error")
	}

	if err := recv.SetReadDeadline(
		time.Now().Add(-time.Millisecond),
	); err != nil {
		t.Fatalf("expired SetReadDeadline error = %v", err)
	}
	if _, _, _, err := recv.ReadFromControl(buf); err == nil {
		t.Fatal("ReadFromControl expired deadline returned nil error")
	}
	_ = recv.Close()
	if err := recv.JoinGroup(nil, group); err == nil {
		t.Fatal("JoinGroup closed conn returned nil error")
	}
	if err := recv.LeaveGroup(nil, group); err == nil {
		t.Fatal("LeaveGroup closed conn returned nil error")
	}
	if _, err := recv.WriteTo([]byte("closed"), dst); err == nil {
		t.Fatal("WriteTo closed conn returned nil error")
	}
	if _, _, err := recv.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom closed conn returned nil error")
	}

	if _, err := ln.ListenMulticastUDP(
		ctx,
		"udp4",
		"",
		MulticastOptions{},
	); err == nil {
		t.Fatal("ListenMulticastUDP udp4 returned nil error")
	}
	if err := ln.Down(); err != nil {
		t.Fatalf("Loopback Down error = %v", err)
	}
	if _, err := ln.ListenMulticastUDP(
		ctx,
		"udp",
		"",
		MulticastOptions{},
	); err == nil {
		t.Fatal("ListenMulticastUDP while down returned nil error")
	}
}

func TestLoopbackPipeTCPExtraMethods(t *testing.T) {
	client, server := PipeTCP()
	defer client.Close()
	defer server.Close()

	if client.LocalAddr() == nil || client.RemoteAddr() == nil {
		t.Fatal("PipeTCP client addrs should be set")
	}
	if err := client.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive error = %v", err)
	}
	if err := client.SetKeepAliveConfig(net.KeepAliveConfig{}); err != nil {
		t.Fatalf("SetKeepAliveConfig error = %v", err)
	}
	if err := client.SetKeepAlivePeriod(time.Millisecond); err != nil {
		t.Fatalf("SetKeepAlivePeriod error = %v", err)
	}
	if err := client.SetLinger(0); err != nil {
		t.Fatalf("SetLinger error = %v", err)
	}
	if err := client.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay error = %v", err)
	}

	readFromDone := make(chan struct{})
	go func() {
		_, _ = client.ReadFrom(bytes.NewBufferString("hello"))
		_ = client.Close()
		close(readFromDone)
	}()
	var out bytes.Buffer
	n, err := server.WriteTo(&out)
	<-readFromDone
	if err != nil || n != 5 || out.String() != "hello" {
		t.Fatalf(
			"WriteTo after ReadFrom = %d, %q, %v, want 5 hello nil",
			n,
			out.String(),
			err,
		)
	}

	if err := client.CloseRead(); err != nil {
		t.Fatalf("CloseRead error = %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite error = %v", err)
	}
}

func TestLoopbackPipeUDPExtraMethods(t *testing.T) {
	ctx := context.Background()
	n := NewLoopbackNetwok()
	c2, err := n.ListenUDP(ctx, "udp4", "localhost:0")
	if err != nil {
		t.Fatalf("ListenUDP error = %v", err)
	}
	c1, err := n.DialUDP(ctx, "udp4", "localhost:0", c2.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP error = %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	if c1.LocalAddr() == nil || c1.RemoteAddr() == nil {
		t.Fatal("PipeUDP addrs should be set")
	}
	if err := c1.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline error = %v", err)
	}
	dst := netip.MustParseAddrPort(c2.LocalAddr().String())
	if n, err := c1.WriteToUDPAddrPort(
		[]byte("one"),
		dst,
	); err != nil ||
		n != 3 {
		t.Fatalf("WriteToUDPAddrPort = %d, %v, want 3 nil", n, err)
	}
	buf := make([]byte, 8)
	if n, addr, err := c2.ReadFromUDPAddrPort(
		buf,
	); err != nil || n != 3 ||
		!addr.Addr().Is4() {
		t.Fatalf("ReadFromUDPAddrPort = %d, %v, %v", n, addr, err)
	}

	if n, _, err := c1.WriteMsgUDPAddrPort(
		[]byte("two"),
		nil,
		dst,
	); err != nil ||
		n != 3 {
		t.Fatalf("WriteMsgUDPAddrPort = %d, %v, want 3 nil", n, err)
	}
	if n, _, _, addr, err := c2.ReadMsgUDPAddrPort(
		buf,
		nil,
	); err != nil || n != 3 ||
		!addr.Addr().Is4() {
		t.Fatalf("ReadMsgUDPAddrPort = %d, %v, %v", n, addr, err)
	}

	dstUDP, err := net.ResolveUDPAddr("udp4", c2.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr error = %v", err)
	}
	if n, _, err := c1.WriteMsgUDP(
		[]byte("tri"),
		nil,
		dstUDP,
	); err != nil ||
		n != 3 {
		t.Fatalf("WriteMsgUDP = %d, %v, want 3 nil", n, err)
	}
	if n, _, _, addr, err := c2.ReadMsgUDP(
		buf,
		nil,
	); err != nil || n != 3 ||
		addr == nil {
		t.Fatalf("ReadMsgUDP = %d, %v, %v", n, addr, err)
	}
}

func TestRouterAccessorsAndDelegatingBranches(t *testing.T) {
	ctx := context.Background()
	r := NewRouter()
	if r.IsNative() {
		t.Fatal("Router IsNative() = true, want false")
	}
	if up, err := r.IsUp(); err != nil || !up {
		t.Fatalf("initial Router IsUp = %v, %v, want true nil", up, err)
	}
	cfg := staticRouterCfg{slot: 1}
	r.SetCfg(cfg)
	if r.GetCfg() != cfg {
		t.Fatal("GetCfg did not return installed config")
	}
	reject := &RejectNetwork{}
	r.SetResolver(reject)
	if r.GetResolver() != reject {
		t.Fatal("GetResolver did not return installed resolver")
	}
	if _, err := r.LookupIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("resolver-backed LookupIP returned nil error")
	}
	if _, err := r.LookupIPAddr(ctx, "example.invalid"); err == nil {
		t.Fatal("resolver-backed LookupIPAddr returned nil error")
	}
	if _, err := r.LookupNetIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("resolver-backed LookupNetIP returned nil error")
	}
	if _, err := r.LookupAddr(ctx, "192.0.2.1"); err == nil {
		t.Fatal("resolver-backed LookupAddr returned nil error")
	}
	if _, err := r.LookupCNAME(ctx, "example.invalid"); err == nil {
		t.Fatal("resolver-backed LookupCNAME returned nil error")
	}
	if _, err := r.LookupPort(ctx, "tcp", "unknown-service"); err == nil {
		t.Fatal("resolver-backed LookupPort returned nil error")
	}
	if _, err := r.LookupNS(ctx, "example.invalid"); err == nil {
		t.Fatal("resolver-backed LookupNS returned nil error")
	}

	r.SetResolver(nil)
	if err := r.Attach(1, NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach loopback error = %v", err)
	}
	if ips, err := r.LookupIP(
		ctx,
		"ip4",
		"localhost",
	); err != nil ||
		len(ips) != 1 {
		t.Fatalf("Router LookupIP via backend = %v, %v, want one nil", ips, err)
	}
	if addrs, err := r.LookupIPAddr(
		ctx,
		"localhost",
	); err != nil ||
		len(addrs) != 2 {
		t.Fatalf(
			"Router LookupIPAddr via backend = %v, %v, want two nil",
			addrs,
			err,
		)
	}
	if ips, err := r.LookupNetIP(
		ctx,
		"ip4",
		"localhost",
	); err != nil ||
		len(ips) != 1 {
		t.Fatalf(
			"Router LookupNetIP via backend = %v, %v, want one nil",
			ips,
			err,
		)
	}
	if names, err := r.LookupAddr(
		ctx,
		"127.0.0.1",
	); err != nil ||
		len(names) != 1 {
		t.Fatalf(
			"Router LookupAddr via backend = %v, %v, want one nil",
			names,
			err,
		)
	}
	if _, err := r.LookupCNAME(ctx, "localhost"); err == nil {
		t.Fatal("Router LookupCNAME via backend returned nil error")
	}
	if port, err := r.LookupPort(ctx, "tcp", "http"); err != nil || port != 80 {
		t.Fatalf(
			"Router LookupPort via backend = %d, %v, want 80 nil",
			port,
			err,
		)
	}
	if txt, err := r.LookupTXT(ctx, "localhost"); err != nil || len(txt) != 0 {
		t.Fatalf(
			"Router LookupTXT via backend = %v, %v, want empty nil",
			txt,
			err,
		)
	}
	if _, err := r.LookupMX(ctx, "localhost"); err == nil {
		t.Fatal("Router LookupMX via backend returned nil error")
	}
	if _, err := r.LookupNS(ctx, "localhost"); err == nil {
		t.Fatal("Router LookupNS via backend returned nil error")
	}
	if _, _, err := r.LookupSRV(ctx, "svc", "tcp", "localhost"); err == nil {
		t.Fatal("Router LookupSRV via backend returned nil error")
	}
	if _, err := r.Interfaces(); err != nil {
		t.Fatalf("Router Interfaces error = %v", err)
	}
	if _, err := r.InterfaceAddrs(); err != nil {
		t.Fatalf("Router InterfaceAddrs error = %v", err)
	}
	if _, err := r.InterfaceMulticastAddrs(); err != nil {
		t.Fatalf("Router InterfaceMulticastAddrs error = %v", err)
	}
	if _, err := r.ListenPacketConfig(
		ctx,
		nil,
		"udp",
		"localhost:0",
	); err != nil {
		t.Fatalf("Router ListenPacketConfig error = %v", err)
	}
	if c, err := r.ListenUDPConfig(ctx, nil, "udp", "localhost:0"); err != nil {
		t.Fatalf("Router ListenUDPConfig error = %v", err)
	} else {
		_ = c.Close()
	}
	if _, err := r.ListenMulticastUDP(
		ctx,
		"udp",
		"224.0.0.1:1",
		MulticastOptions{},
	); !errors.Is(
		err,
		ErrUnsupported,
	) {
		t.Fatalf(
			"Router ListenMulticastUDP error = %v, want ErrUnsupported",
			err,
		)
	}
	if err := r.Down(); err != nil {
		t.Fatalf("Router Down error = %v", err)
	}
	if up, err := r.IsUp(); err != nil || up {
		t.Fatalf("Router IsUp after Down = %v, %v, want false nil", up, err)
	}
	if _, err := r.Interfaces(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Router Interfaces while down = %v, want net.ErrClosed", err)
	}
	if err := r.Up(); err != nil {
		t.Fatalf("Router Up error = %v", err)
	}
	if up, err := r.IsUp(); err != nil || !up {
		t.Fatalf("Router IsUp after Up = %v, %v, want true nil", up, err)
	}
	if err := r.Attach(0, reject); err == nil {
		t.Fatal("Attach invalid slot returned nil error")
	}
	if err := routerSlotError(99); err == nil {
		t.Fatal("routerSlotError returned nil")
	}
	if err := routerTimeout("dial", "tcp"); err == nil {
		t.Fatal("routerTimeout returned nil")
	}
	if got := routerPickResolvedHost(
		"tcp4",
		[]string{"::1", "127.0.0.1"},
	); got != "127.0.0.1" {
		t.Fatalf("routerPickResolvedHost tcp4 = %q, want 127.0.0.1", got)
	}
	if got := routerPickResolvedHost(
		"tcp6",
		[]string{"127.0.0.1", "::1"},
	); got != "::1" {
		t.Fatalf("routerPickResolvedHost tcp6 = %q, want ::1", got)
	}
}

func TestDetachedNetworkAccessorsAndDelegatingBranches(t *testing.T) {
	ctx := context.Background()
	base := &RejectNetwork{}
	n := DetachNetwork(base)
	if n.GetWrapped() != base {
		t.Fatal("DetachedNetwork GetWrapped did not return wrapped network")
	}
	if n.IsNative() {
		t.Fatal("DetachedNetwork IsNative() = true, want false")
	}
	if up, err := n.IsUp(); err != nil || !up {
		t.Fatalf(
			"initial DetachedNetwork IsUp = %v, %v, want true nil",
			up,
			err,
		)
	}
	if _, err := n.DialUDP(ctx, "udp", "", "127.0.0.1:1"); err == nil {
		t.Fatal("DetachedNetwork DialUDP returned nil error")
	}
	if _, err := n.ListenPacketConfig(
		ctx,
		nil,
		"udp",
		"127.0.0.1:1",
	); err == nil {
		t.Fatal("DetachedNetwork ListenPacketConfig returned nil error")
	}
	if _, err := n.ListenUDPConfig(ctx, nil, "udp", "127.0.0.1:1"); err == nil {
		t.Fatal("DetachedNetwork ListenUDPConfig returned nil error")
	}
	if _, err := n.ListenMulticastUDP(
		ctx,
		"udp",
		"224.0.0.1:1",
		MulticastOptions{},
	); err == nil {
		t.Fatal("DetachedNetwork ListenMulticastUDP returned nil error")
	}
	if _, err := n.LookupIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("DetachedNetwork LookupIP returned nil error")
	}
	if _, err := n.LookupIPAddr(ctx, "example.invalid"); err == nil {
		t.Fatal("DetachedNetwork LookupIPAddr returned nil error")
	}
	if _, err := n.LookupNetIP(ctx, "ip", "example.invalid"); err == nil {
		t.Fatal("DetachedNetwork LookupNetIP returned nil error")
	}
	if _, err := n.LookupAddr(ctx, "192.0.2.1"); err == nil {
		t.Fatal("DetachedNetwork LookupAddr returned nil error")
	}
	if _, err := n.LookupCNAME(ctx, "example.invalid"); err == nil {
		t.Fatal("DetachedNetwork LookupCNAME returned nil error")
	}
	if _, err := n.LookupPort(ctx, "tcp", "unknown-service"); err == nil {
		t.Fatal("DetachedNetwork LookupPort returned nil error")
	}
	if _, err := n.LookupNS(ctx, "example.invalid"); err == nil {
		t.Fatal("DetachedNetwork LookupNS returned nil error")
	}
	if _, err := n.Interfaces(); err != nil {
		t.Fatalf("DetachedNetwork Interfaces error = %v", err)
	}
	if _, err := n.InterfaceAddrs(); err != nil {
		t.Fatalf("DetachedNetwork InterfaceAddrs error = %v", err)
	}
	if _, err := n.InterfaceMulticastAddrs(); err != nil {
		t.Fatalf("DetachedNetwork InterfaceMulticastAddrs error = %v", err)
	}

	if err := n.Down(); err != nil {
		t.Fatalf("DetachedNetwork Down error = %v", err)
	}
	if up, err := n.IsUp(); err != nil || up {
		t.Fatalf(
			"DetachedNetwork IsUp after Down = %v, %v, want false nil",
			up,
			err,
		)
	}
	if _, err := n.LookupHost(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf(
			"DetachedNetwork LookupHost while down = %v, want net.ErrClosed",
			err,
		)
	}
	if err := n.Up(); err != nil {
		t.Fatalf("DetachedNetwork Up error = %v", err)
	}
	if up, err := n.IsUp(); err != nil || !up {
		t.Fatalf(
			"DetachedNetwork IsUp after Up = %v, %v, want true nil",
			up,
			err,
		)
	}
}

func TestDetachedNetworkTrackingBranches(t *testing.T) {
	n := DetachNetwork(&RejectNetwork{})
	unsub, err := n.SubscribeCloser(&fakeCloser{})
	if err != nil {
		t.Fatalf("SubscribeCloser error = %v", err)
	}
	unsub()
	unsub()

	tcpConn := &callbackTestTCPConn{}
	trackedTCP, err := n.trackTCPConn(n.gen, tcpConn)
	if err != nil {
		t.Fatalf("trackTCPConn error = %v", err)
	}
	if trackedTCP == tcpConn {
		t.Fatal("trackTCPConn did not wrap connection")
	}
	_ = trackedTCP.Close()

	udpConn := &fakeUDPConn{}
	trackedUDP, err := n.trackUDPConn(n.gen, udpConn)
	if err != nil {
		t.Fatalf("trackUDPConn error = %v", err)
	}
	_ = trackedUDP.Close()

	mcast := &fakeMulticastPacketConn{}
	trackedMcast, err := n.trackMulticastPacketConn(n.gen, mcast)
	if err != nil {
		t.Fatalf("trackMulticastPacketConn error = %v", err)
	}
	_ = trackedMcast.Close()
	_ = trackedMcast.Close()
	if mcast.closed != 2 {
		t.Fatalf(
			"detached multicast underlying closes = %d, want 2",
			mcast.closed,
		)
	}

	tcpListener := newCallbackTestTCPListener()
	trackedListener, err := n.trackTCPListener(n.gen, tcpListener)
	if err != nil {
		t.Fatalf("trackTCPListener error = %v", err)
	}
	_ = trackedListener.Close()

	accepted, err := n.acceptTCPConnCallback(&callbackTestTCPConn{})
	if err != nil {
		t.Fatalf("acceptTCPConnCallback error = %v", err)
	}
	_ = accepted.Close()

	if err := n.Down(); err != nil {
		t.Fatalf("Down error = %v", err)
	}
	closed := &fakeCloser{}
	unsubClosed, err := n.SubscribeCloser(closed)
	if err != nil || unsubClosed == nil || closed.closed != 0 {
		t.Fatalf(
			"SubscribeCloser while down = closed %d, unsub nil %t, err %v",
			closed.closed,
			unsubClosed == nil,
			err,
		)
	}
	unsubClosed()
	if _, err := n.trackTCPConn(
		n.gen,
		&callbackTestTCPConn{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("trackTCPConn while down = %v, want net.ErrClosed", err)
	}
	if _, err := n.trackMulticastPacketConn(
		n.gen,
		&fakeMulticastPacketConn{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf(
			"trackMulticastPacketConn while down = %v, want net.ErrClosed",
			err,
		)
	}
	if _, err := n.trackTCPListener(
		n.gen,
		newCallbackTestTCPListener(),
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("trackTCPListener while down = %v, want net.ErrClosed", err)
	}
	if _, err := n.acceptTCPConnCallback(
		&callbackTestTCPConn{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf(
			"acceptTCPConnCallback while down = %v, want net.ErrClosed",
			err,
		)
	}
}

type testWrapper struct {
	wrapped any
}

func (w *testWrapper) GetWrapped() any { return w.wrapped }

type connWrapper struct {
	net.Conn
	wrapped any
}

func (w *connWrapper) GetWrapped() any { return w.wrapped }

type multipathConn struct {
	net.Conn
	val bool
	err error
}

func (c *multipathConn) MultipathTCP() (bool, error) { return c.val, c.err }

type syscallConnProvider struct {
	err error
}

func (p *syscallConnProvider) SyscallConn() (syscall.RawConn, error) {
	return nil, p.err
}

type fileProvider struct {
	err error
}

func (p *fileProvider) File() (*os.File, error) { return nil, p.err }

type fakeConn struct {
	local  net.Addr
	remote net.Addr
	closed int
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *fakeConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *fakeConn) Close() error                     { c.closed++; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return c.local }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeNetPacketConn struct {
	closed int
}

func (c *fakeNetPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *fakeNetPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *fakeNetPacketConn) Close() error                     { c.closed++; return nil }
func (c *fakeNetPacketConn) LocalAddr() net.Addr              { return nil }
func (c *fakeNetPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeNetPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeNetPacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakePacketConn struct {
	fakeNetPacketConn
}

func (c *fakePacketConn) Read(
	[]byte,
) (int, error) {
	return 0, net.ErrClosed
}
func (c *fakePacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakePacketConn) RemoteAddr() net.Addr        { return nil }

type fakeUDPConn struct {
	fakePacketConn
}

func (c *fakeUDPConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}
func (c *fakeUDPConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (c *fakeUDPConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	return len(b), nil
}

func (c *fakeUDPConn) WriteToUDPAddrPort(
	b []byte,
	_ netip.AddrPort,
) (int, error) {
	return len(b), nil
}

func (c *fakeUDPConn) ReadMsgUDP(
	[]byte,
	[]byte,
) (int, int, int, *net.UDPAddr, error) {
	return 0, 0, 0, nil, net.ErrClosed
}

func (c *fakeUDPConn) ReadMsgUDPAddrPort(
	[]byte,
	[]byte,
) (int, int, int, netip.AddrPort, error) {
	return 0, 0, 0, netip.AddrPort{}, net.ErrClosed
}

func (c *fakeUDPConn) WriteMsgUDP(
	b []byte,
	_ []byte,
	_ *net.UDPAddr,
) (int, int, error) {
	return len(b), 0, nil
}

func (c *fakeUDPConn) WriteMsgUDPAddrPort(
	b []byte,
	_ []byte,
	_ netip.AddrPort,
) (int, int, error) {
	return len(b), 0, nil
}

type fakeFullUDPConn struct {
	fakeUDPConn
}

func (c *fakeFullUDPConn) SetReadBuffer(int) error  { return nil }
func (c *fakeFullUDPConn) SetWriteBuffer(int) error { return nil }
func (c *fakeFullUDPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
}
func (c *fakeFullUDPConn) File() (*os.File, error) { return nil, nil }

type packetScriptItem struct {
	data []byte
	addr net.Addr
}

type scriptedPacketConn struct {
	packets []packetScriptItem
	err     error
	closed  atomic.Int32
}

func (c *scriptedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.packets) == 0 {
		return 0, nil, c.err
	}
	pkt := c.packets[0]
	c.packets = c.packets[1:]
	return copy(b, pkt.data), pkt.addr, nil
}
func (c *scriptedPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *scriptedPacketConn) Close() error                     { c.closed.Add(1); return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type recordingPacketConn struct {
	writes [][]byte
	err    error
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *recordingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return nil }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakeMulticastPacketConn struct {
	fakeNetPacketConn
	closed int
}

func (c *fakeMulticastPacketConn) Close() error {
	c.closed++
	return nil
}
func (c *fakeMulticastPacketConn) JoinGroup(NetworkInterface, net.Addr) error {
	return nil
}
func (c *fakeMulticastPacketConn) LeaveGroup(NetworkInterface, net.Addr) error {
	return nil
}
func (c *fakeMulticastPacketConn) SetControlMessage(ControlFlags, bool) error {
	return nil
}

func (c *fakeMulticastPacketConn) ReadFromControl(
	[]byte,
) (int, ControlMessage, net.Addr, error) {
	return 0, ControlMessage{}, nil, net.ErrClosed
}

func (c *fakeMulticastPacketConn) WriteToControl(
	b []byte,
	_ ControlMessage,
	_ net.Addr,
) (int, error) {
	return len(b), nil
}

type fakeCloser struct {
	closed int
	err    error
}

func (c *fakeCloser) Close() error {
	c.closed++
	return c.err
}

type defaultIfaceNetwork struct {
	conn      net.Conn
	dialErr   error
	ifaces    []NetworkInterface
	ifacesErr error
}

func (n *defaultIfaceNetwork) Dial(
	context.Context,
	string,
	string,
) (net.Conn, error) {
	if n.dialErr != nil {
		return nil, n.dialErr
	}
	return n.conn, nil
}

func (n *defaultIfaceNetwork) Interfaces() ([]NetworkInterface, error) {
	return n.ifaces, n.ifacesErr
}

type staticRouterCfg struct {
	slot int
}

func (c staticRouterCfg) DialTCP(string, string, string) int { return c.slot }
func (c staticRouterCfg) ListenTCP(string, string) int       { return c.slot }
func (c staticRouterCfg) DialUDP(string, string, string) int { return c.slot }
func (c staticRouterCfg) RouteUDP(string, net.Addr, net.Addr) int {
	return c.slot
}
func (c staticRouterCfg) Lookup(string, string) int { return c.slot }
