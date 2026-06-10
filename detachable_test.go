package gonnect_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestDetachedNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return gonnect.DetachNetwork(gonnect.NativeConfig{}.Build(), nil)
	})
}

func TestDetachedNetwork_Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		return gonnect.DetachNetwork(gonnect.NativeConfig{}.Build(), nil)
	}, "127.0.0.1:0")
}

func TestDetachedNetworkTcpPingPong(t *testing.T) {
	base := gonnect.NativeConfig{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base, nil),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestDetachedNetworkHTTP(t *testing.T) {
	base := gonnect.NativeConfig{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base, nil),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestDetachedNetworkUdpPingPong(t *testing.T) {
	base := gonnect.NativeConfig{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base, nil),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestDetachedNetworkDownDoesNotStopWrappedNetwork(t *testing.T) {
	base := gonnect.NativeConfig{}.Build()
	wrapper := gonnect.DetachNetwork(base, nil)

	if err := wrapper.Down(); err != nil {
		t.Fatalf("wrapper Down() error = %v", err)
	}

	ln, err := base.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wrapped Network stopped by wrapper Down(): %v", err)
	}
	_ = ln.Close()
}

func TestDetachedNetworkWrappersAreIndependent(t *testing.T) {
	base := gonnect.NativeConfig{}.Build()
	a := gonnect.DetachNetwork(base, nil)
	b := gonnect.DetachNetwork(base, nil)

	if err := a.Down(); err != nil {
		t.Fatalf("first wrapper Down() error = %v", err)
	}

	ln, err := b.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("second wrapper affected by first wrapper Down(): %v", err)
	}
	_ = ln.Close()
}

type testCloser struct {
	count atomic.Int32
}

func (c *testCloser) Close() error {
	c.count.Add(1)
	return nil
}

func (c *testCloser) closes() int32 {
	return c.count.Load()
}

func TestDetachedNetworkSubscribeCloser(t *testing.T) {
	wrapper := gonnect.DetachNetwork(gonnect.NativeConfig{}.Build(), nil)
	kept := &testCloser{}
	removed := &testCloser{}

	unsubscribeKept, err := wrapper.SubscribeCloser(kept)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeKept()

	unsubscribeRemoved, err := wrapper.SubscribeCloser(removed)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	unsubscribeRemoved()
	unsubscribeRemoved()

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if kept.closes() != 1 {
		t.Fatalf("subscribed closer Close() calls = %d, want 1", kept.closes())
	}
	if removed.closes() != 0 {
		t.Fatalf(
			"unsubscribed closer Close() calls = %d, want 0",
			removed.closes(),
		)
	}
}

func TestDetachedNetworkSubscribeCloserWhenClosed(t *testing.T) {
	wrapper := gonnect.DetachNetwork(gonnect.NativeConfig{}.Build(), nil)
	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	closer := &testCloser{}
	unsubscribe, err := wrapper.SubscribeCloser(closer)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SubscribeCloser() error = %v, want net.ErrClosed", err)
	}
	if unsubscribe != nil {
		t.Fatal("SubscribeCloser() returned unsubscribe after error")
	}
	if closer.closes() != 1 {
		t.Fatalf("closer Close() calls = %d, want 1", closer.closes())
	}
}

type blockingDialNetwork struct {
	gonnect.Network
	entered chan struct{}
}

func (n *blockingDialNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.entered <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDetachedNetworkDownCancelsParallelBlockedDials(t *testing.T) {
	wrapped := &blockingDialNetwork{
		Network: gonnect.NativeConfig{}.Build(),
		entered: make(chan struct{}, 2),
	}
	wrapper := gonnect.DetachNetwork(wrapped, nil)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := wrapper.Dial(context.Background(), "tcp", "blocked")
			errs <- err
		}()
	}

	for range 2 {
		select {
		case <-wrapped.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("blocked dials did not run in parallel")
		}
	}

	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not cancel blocked dials")
	}

	for range 2 {
		if err := <-errs; err == nil {
			t.Fatal("Dial returned nil error after Down()")
		}
	}
}

type blockingLookupNetwork struct {
	gonnect.Network
	entered chan struct{}
}

func (n *blockingLookupNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	n.entered <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDetachedNetworkDownCancelsBlockedLookup(t *testing.T) {
	wrapped := &blockingLookupNetwork{
		Network: gonnect.NativeConfig{}.Build(),
		entered: make(chan struct{}, 1),
	}
	wrapper := gonnect.DetachNetwork(wrapped, nil)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.LookupHost(context.Background(), "blocked")
		errCh <- err
	}()

	select {
	case <-wrapped.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked lookup did not start")
	}

	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("LookupHost returned nil error after Down()")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not cancel blocked lookup")
	}
}

type delayedLoopbackNetwork struct {
	gonnect.Network
	delay   time.Duration
	entered chan string
}

func (n *delayedLoopbackNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.entered <- "Dial"
	time.Sleep(n.delay)
	return n.Network.Dial(ctx, network, address)
}

func (n *delayedLoopbackNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	n.entered <- "Listen"
	time.Sleep(n.delay)
	return n.Network.Listen(ctx, network, address)
}

func TestDetachedNetworkCloseCancelsContextIgnoringDialAndListen(
	t *testing.T,
) {
	wrapped := &delayedLoopbackNetwork{
		Network: gonnect.NewLoopbackNetwok(),
		delay:   time.Second,
		entered: make(chan string, 2),
	}
	wrapper := gonnect.DetachNetwork(wrapped, nil)

	dialErr := make(chan error, 1)
	go func() {
		_, err := wrapper.Dial(context.Background(), "tcp", "127.0.0.1:9")
		dialErr <- err
	}()

	listenErr := make(chan error, 1)
	go func() {
		ln, err := wrapper.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err == nil {
			_ = ln.Close()
		}
		listenErr <- err
	}()

	for range 2 {
		select {
		case <-wrapped.entered:
		case <-time.After(200 * time.Millisecond):
			t.Fatal("delayed operation did not start")
		}
	}

	start := time.Now()
	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for _, ch := range []chan error{dialErr, listenErr} {
		select {
		case err := <-ch:
			if err == nil {
				t.Fatal("operation returned nil error after Close()")
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("Close() did not release delayed operation immediately")
		}
	}
	if elapsed := time.Since(start); elapsed >= wrapped.delay {
		t.Fatalf("operations waited for wrapped delay: %v", elapsed)
	}
}

type delayedLookupNetwork struct {
	gonnect.Network
	delay   time.Duration
	entered chan struct{}
}

func (n *delayedLookupNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	n.entered <- struct{}{}
	time.Sleep(n.delay)
	return []string{"127.0.0.1"}, nil
}

func TestDetachedNetworkCloseCancelsContextIgnoringLookup(t *testing.T) {
	wrapped := &delayedLookupNetwork{
		Network: gonnect.NativeConfig{}.Build(),
		delay:   time.Second,
		entered: make(chan struct{}, 1),
	}
	wrapper := gonnect.DetachNetwork(wrapped, nil)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.LookupHost(context.Background(), "example.test")
		errCh <- err
	}()

	select {
	case <-wrapped.entered:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("delayed lookup did not start")
	}

	start := time.Now()
	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("LookupHost returned nil error after Close()")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close() did not release delayed lookup immediately")
	}
	if elapsed := time.Since(start); elapsed >= wrapped.delay {
		t.Fatalf("lookup waited for wrapped delay: %v", elapsed)
	}
}

type detachedResolver struct {
	mu    sync.Mutex
	calls []string
}

func (r *detachedResolver) record(call string) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
}

func (r *detachedResolver) called(call string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == call {
			return true
		}
	}
	return false
}

func (r *detachedResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *detachedResolver) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	r.record("LookupIP")
	return []net.IP{net.ParseIP("192.0.2.10")}, nil
}

func (r *detachedResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	r.record("LookupIPAddr")
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
}

func (r *detachedResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	r.record("LookupNetIP")
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

func (r *detachedResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	r.record("LookupHost")
	return []string{"192.0.2.10"}, nil
}

func (r *detachedResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	r.record("LookupAddr")
	return []string{"host.test."}, nil
}

func (r *detachedResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	r.record("LookupCNAME")
	return "cname.test.", nil
}

func (r *detachedResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	r.record("LookupPort")
	return 8080, nil
}

func (r *detachedResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	r.record("LookupNS")
	return []*net.NS{{Host: "ns.test."}}, nil
}

func (r *detachedResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	r.record("LookupMX")
	return []*net.MX{{Host: "mx.test.", Pref: 10}}, nil
}

func (r *detachedResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	r.record("LookupSRV")
	return "srv.test.", []*net.SRV{{Target: "target.test.", Port: 443}}, nil
}

func (r *detachedResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	r.record("LookupTXT")
	return []string{"txt"}, nil
}

func TestDetachedNetworkRoutesLookupsToResolver(t *testing.T) {
	ctx := context.Background()
	resolver := &detachedResolver{}
	wrapper := gonnect.DetachNetwork(&gonnect.RejectNetwork{}, resolver)

	lookupCalls := []struct {
		name string
		call func() error
	}{
		{"LookupIP", func() error {
			_, err := wrapper.LookupIP(ctx, "ip", "host.test")
			return err
		}},
		{"LookupIPAddr", func() error {
			_, err := wrapper.LookupIPAddr(ctx, "host.test")
			return err
		}},
		{"LookupNetIP", func() error {
			_, err := wrapper.LookupNetIP(ctx, "ip", "host.test")
			return err
		}},
		{"LookupHost", func() error {
			_, err := wrapper.LookupHost(ctx, "host.test")
			return err
		}},
		{"LookupAddr", func() error {
			_, err := wrapper.LookupAddr(ctx, "192.0.2.10")
			return err
		}},
		{"LookupCNAME", func() error {
			_, err := wrapper.LookupCNAME(ctx, "host.test")
			return err
		}},
		{"LookupPort", func() error {
			_, err := wrapper.LookupPort(ctx, "tcp", "https")
			return err
		}},
		{"LookupTXT", func() error {
			_, err := wrapper.LookupTXT(ctx, "host.test")
			return err
		}},
		{"LookupMX", func() error {
			_, err := wrapper.LookupMX(ctx, "host.test")
			return err
		}},
		{"LookupNS", func() error {
			_, err := wrapper.LookupNS(ctx, "host.test")
			return err
		}},
		{"LookupSRV", func() error {
			_, _, err := wrapper.LookupSRV(ctx, "svc", "tcp", "host.test")
			return err
		}},
	}

	for _, lookup := range lookupCalls {
		t.Run(lookup.name, func(t *testing.T) {
			if err := lookup.call(); err != nil {
				t.Fatalf("%s() error = %v", lookup.name, err)
			}
			if !resolver.called(lookup.name) {
				t.Fatalf("%s() did not use resolver", lookup.name)
			}
		})
	}
}

var errDetachedCapture = errors.New("capture network called")

type detachedCaptureNetwork struct {
	gonnect.Network
	mu    sync.Mutex
	calls map[string][]string
}

func newDetachedCaptureNetwork() *detachedCaptureNetwork {
	return &detachedCaptureNetwork{
		Network: &gonnect.RejectNetwork{},
		calls:   make(map[string][]string),
	}
}

func (n *detachedCaptureNetwork) record(name string, args ...string) {
	n.mu.Lock()
	n.calls[name] = append([]string(nil), args...)
	n.mu.Unlock()
}

func (n *detachedCaptureNetwork) args(name string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls[name]...)
}

func (n *detachedCaptureNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.record("Dial", network, address)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	n.record("Listen", network, address)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	n.record("PacketDial", network, address)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	n.record("ListenPacket", network, address)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	n.record("DialTCP", network, laddr, raddr)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	n.record("ListenTCP", network, laddr)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	n.record("DialUDP", network, laddr, raddr)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	n.record("ListenUDP", network, laddr)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	n.record("ListenPacketConfig", network, address)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	n.record("ListenUDPConfig", network, laddr)
	return nil, errDetachedCapture
}

func (n *detachedCaptureNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts gonnect.MulticastOptions,
) (gonnect.MulticastPacketConn, error) {
	n.record("ListenMulticastUDP", network, address)
	return nil, errDetachedCapture
}

func TestDetachedNetworkResolverPreResolvesAddresses(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	wrapper := gonnect.DetachNetwork(wrapped, &detachedResolver{})
	named := "host.test:service"
	resolved := "192.0.2.10:8080"

	tests := []struct {
		name string
		call func() error
		want []string
	}{
		{
			name: "Dial",
			call: func() error {
				_, err := wrapper.Dial(ctx, "tcp", named)
				return err
			},
			want: []string{"tcp", resolved},
		},
		{
			name: "Listen",
			call: func() error {
				_, err := wrapper.Listen(ctx, "tcp", named)
				return err
			},
			want: []string{"tcp", resolved},
		},
		{
			name: "PacketDial",
			call: func() error {
				_, err := wrapper.PacketDial(ctx, "udp", named)
				return err
			},
			want: []string{"udp", resolved},
		},
		{
			name: "ListenPacket",
			call: func() error {
				_, err := wrapper.ListenPacket(ctx, "udp", named)
				return err
			},
			want: []string{"udp", resolved},
		},
		{
			name: "DialTCP",
			call: func() error {
				_, err := wrapper.DialTCP(ctx, "tcp", named, named)
				return err
			},
			want: []string{"tcp", resolved, resolved},
		},
		{
			name: "ListenTCP",
			call: func() error {
				_, err := wrapper.ListenTCP(ctx, "tcp", named)
				return err
			},
			want: []string{"tcp", resolved},
		},
		{
			name: "DialUDP",
			call: func() error {
				_, err := wrapper.DialUDP(ctx, "udp", named, named)
				return err
			},
			want: []string{"udp", resolved, resolved},
		},
		{
			name: "ListenUDP",
			call: func() error {
				_, err := wrapper.ListenUDP(ctx, "udp", named)
				return err
			},
			want: []string{"udp", resolved},
		},
		{
			name: "ListenPacketConfig",
			call: func() error {
				_, err := wrapper.ListenPacketConfig(ctx, nil, "udp", named)
				return err
			},
			want: []string{"udp", resolved},
		},
		{
			name: "ListenUDPConfig",
			call: func() error {
				_, err := wrapper.ListenUDPConfig(ctx, nil, "udp", named)
				return err
			},
			want: []string{"udp", resolved},
		},
		{
			name: "ListenMulticastUDP",
			call: func() error {
				_, err := wrapper.ListenMulticastUDP(
					ctx,
					"udp",
					named,
					gonnect.MulticastOptions{},
				)
				return err
			},
			want: []string{"udp", resolved},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, errDetachedCapture) {
				t.Fatalf("%s() error = %v, want capture error", tt.name, err)
			}
			if got := wrapped.args(tt.name); !stringSlicesEqual(got, tt.want) {
				t.Fatalf("%s args = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetachedNetworkResolverLeavesIPLiteralHosts(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	resolver := &detachedResolver{}
	wrapper := gonnect.DetachNetwork(wrapped, resolver)

	_, err := wrapper.Dial(ctx, "tcp", "127.0.0.1:service")
	if !errors.Is(err, errDetachedCapture) {
		t.Fatalf("Dial() error = %v, want capture error", err)
	}
	if got, want := wrapped.args(
		"Dial",
	), []string{
		"tcp",
		"127.0.0.1:8080",
	}; !stringSlicesEqual(
		got,
		want,
	) {
		t.Fatalf("Dial args = %v, want %v", got, want)
	}
	if resolver.called("LookupHost") {
		t.Fatal("resolver LookupHost called for IP literal host")
	}
	if !resolver.called("LookupPort") {
		t.Fatal("resolver LookupPort was not called for service name")
	}
}

func TestDetachedNetworkResolverNotUsedWhenStopped(t *testing.T) {
	ctx := context.Background()

	for _, tt := range []struct {
		name string
		stop func(*gonnect.DetachedNetwork) error
	}{
		{name: "down", stop: (*gonnect.DetachedNetwork).Down},
		{name: "closed", stop: (*gonnect.DetachedNetwork).Close},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &detachedResolver{}
			wrapper := gonnect.DetachNetwork(
				newDetachedCaptureNetwork(),
				resolver,
			)
			if err := tt.stop(wrapper); err != nil {
				t.Fatalf("%s wrapper error = %v", tt.name, err)
			}
			_, err := wrapper.Dial(ctx, "tcp", "host.test:service")
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Dial() error = %v, want net.ErrClosed", err)
			}
			if got := resolver.callCount(); got != 0 {
				t.Fatalf("resolver calls = %d, want 0", got)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
