package gonnect_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestRemapperRemapsOperationArguments(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	rules := []gonnect.RemapRule{
		{
			Filter: gonnect.RemapAddressFilter(
				gonnect.FilterFromString("example.com:80").Filter,
			),
			Endpoint: gonnect.RemapDst,
			Field:    gonnect.RemapAddrPort,
			Addr:     "100.100.100.100",
			Port:     "8080",
		},
		{
			Filter: gonnect.RemapAddressFilter(
				gonnect.FilterFromString("[::1]:0").Filter,
			),
			Endpoint: gonnect.RemapSrc,
			Field:    gonnect.RemapAddr,
			Addr:     "127.0.0.1",
		},
	}
	remapper := gonnect.NewRemapper(wrapped, rules)

	tests := []struct {
		name string
		call func() error
		want []string
	}{
		{
			name: "Dial",
			call: func() error {
				_, err := remapper.Dial(ctx, "tcp6", "example.com:80")
				return err
			},
			want: []string{"tcp4", "100.100.100.100:8080"},
		},
		{
			name: "Listen",
			call: func() error {
				_, err := remapper.Listen(ctx, "tcp6", "[::1]:0")
				return err
			},
			want: []string{"tcp4", "127.0.0.1:0"},
		},
		{
			name: "PacketDial",
			call: func() error {
				_, err := remapper.PacketDial(ctx, "udp6", "example.com:80")
				return err
			},
			want: []string{"udp4", "100.100.100.100:8080"},
		},
		{
			name: "ListenPacket",
			call: func() error {
				_, err := remapper.ListenPacket(ctx, "udp6", "[::1]:0")
				return err
			},
			want: []string{"udp4", "127.0.0.1:0"},
		},
		{
			name: "DialTCP",
			call: func() error {
				_, err := remapper.DialTCP(
					ctx,
					"tcp6",
					"[::1]:0",
					"example.com:80",
				)
				return err
			},
			want: []string{"tcp4", "127.0.0.1:0", "100.100.100.100:8080"},
		},
		{
			name: "ListenTCP",
			call: func() error {
				_, err := remapper.ListenTCP(ctx, "tcp6", "[::1]:0")
				return err
			},
			want: []string{"tcp4", "127.0.0.1:0"},
		},
		{
			name: "DialUDP",
			call: func() error {
				_, err := remapper.DialUDP(
					ctx,
					"udp6",
					"[::1]:0",
					"example.com:80",
				)
				return err
			},
			want: []string{"udp4", "127.0.0.1:0", "100.100.100.100:8080"},
		},
		{
			name: "ListenUDP",
			call: func() error {
				_, err := remapper.ListenUDP(ctx, "udp6", "[::1]:0")
				return err
			},
			want: []string{"udp4", "127.0.0.1:0"},
		},
		{
			name: "ListenPacketConfig",
			call: func() error {
				_, err := remapper.ListenPacketConfig(
					ctx,
					nil,
					"udp6",
					"[::1]:0",
				)
				return err
			},
			want: []string{"udp4", "127.0.0.1:0"},
		},
		{
			name: "ListenUDPConfig",
			call: func() error {
				_, err := remapper.ListenUDPConfig(ctx, nil, "udp6", "[::1]:0")
				return err
			},
			want: []string{"udp4", "127.0.0.1:0"},
		},
		{
			name: "ListenMulticastUDP",
			call: func() error {
				_, err := remapper.ListenMulticastUDP(
					ctx,
					"udp6",
					"[::1]:0",
					gonnect.MulticastOptions{},
				)
				return err
			},
			want: []string{"udp4", "127.0.0.1:0"},
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

func TestRemapperFieldEdgeCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		network     string
		address     string
		rule        gonnect.RemapRule
		wantNetwork string
		wantAddress string
	}{
		{
			name:    "port only preserves IPv6 host",
			network: "tcp6",
			address: "[::1]:80",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapPort,
				Port:     "443",
			},
			wantNetwork: "tcp6",
			wantAddress: "[::1]:443",
		},
		{
			name:    "addr only preserves port",
			network: "tcp6",
			address: "service.test:80",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddr,
				Addr:     "127.0.0.1",
			},
			wantNetwork: "tcp4",
			wantAddress: "127.0.0.1:80",
		},
		{
			name:    "addr only without port replaces whole address",
			network: "ip6",
			address: "service.test",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddr,
				Addr:     "127.0.0.1",
			},
			wantNetwork: "ip4",
			wantAddress: "127.0.0.1",
		},
		{
			name:    "port only without hostport leaves address unchanged",
			network: "tcp6",
			address: "service.test",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapPort,
				Port:     "443",
			},
			wantNetwork: "tcp6",
			wantAddress: "service.test",
		},
		{
			name:    "whole address allows empty host",
			network: "udp6",
			address: "service.test:53",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddrPort,
				Addr:     "",
				Port:     "5353",
			},
			wantNetwork: "udp6",
			wantAddress: ":5353",
		},
		{
			name:    "hostname rewrite keeps versioned network unchanged",
			network: "tcp6",
			address: "service.test:80",
			rule: gonnect.RemapRule{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddr,
				Addr:     "other.test",
			},
			wantNetwork: "tcp6",
			wantAddress: "other.test:80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := newDetachedCaptureNetwork()
			remapper := gonnect.NewRemapper(wrapped, []gonnect.RemapRule{
				tt.rule,
			})

			_, err := remapper.Dial(ctx, tt.network, tt.address)
			if !errors.Is(err, errDetachedCapture) {
				t.Fatalf("Dial() error = %v, want capture error", err)
			}
			want := []string{tt.wantNetwork, tt.wantAddress}
			if got := wrapped.args("Dial"); !stringSlicesEqual(got, want) {
				t.Fatalf("Dial args = %v, want %v", got, want)
			}
		})
	}
}

func TestRemapperNetworkFamilyAdjustment(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		network     string
		addr        string
		wantNetwork string
	}{
		{
			name:        "generic tcp stays generic",
			network:     "tcp",
			addr:        "127.0.0.1",
			wantNetwork: "tcp",
		},
		{
			name:        "tcp6 to IPv4 becomes tcp4",
			network:     "tcp6",
			addr:        "127.0.0.1",
			wantNetwork: "tcp4",
		},
		{
			name:        "tcp4 to IPv4 stays tcp4",
			network:     "tcp4",
			addr:        "127.0.0.1",
			wantNetwork: "tcp4",
		},
		{
			name:        "tcp4 to IPv6 becomes tcp6",
			network:     "tcp4",
			addr:        "::1",
			wantNetwork: "tcp6",
		},
		{
			name:        "udp6 to IPv4 becomes udp4",
			network:     "udp6",
			addr:        "127.0.0.1",
			wantNetwork: "udp4",
		},
		{
			name:        "unknown network stays unchanged",
			network:     "custom6",
			addr:        "127.0.0.1",
			wantNetwork: "custom6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := newDetachedCaptureNetwork()
			remapper := gonnect.NewRemapper(wrapped, []gonnect.RemapRule{{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddr,
				Addr:     tt.addr,
			}})

			_, err := remapper.Dial(ctx, tt.network, "service.test:80")
			if !errors.Is(err, errDetachedCapture) {
				t.Fatalf("Dial() error = %v, want capture error", err)
			}
			want := []string{
				tt.wantNetwork,
				net.JoinHostPort(tt.addr, "80"),
			}
			if got := wrapped.args("Dial"); !stringSlicesEqual(got, want) {
				t.Fatalf("Dial args = %v, want %v", got, want)
			}
		})
	}
}

func TestRemapperRulesAreSequential(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	remapper := gonnect.NewRemapper(wrapped, []gonnect.RemapRule{
		{
			Filter: gonnect.RemapAddressFilter(
				gonnect.FilterFromString("service.test:80").Filter,
			),
			Endpoint: gonnect.RemapDst,
			Field:    gonnect.RemapAddr,
			Addr:     "127.0.0.1",
		},
		{
			Filter: gonnect.RemapAddressFilter(
				gonnect.FilterFromString("127.0.0.1:80").Filter,
			),
			Endpoint: gonnect.RemapDst,
			Field:    gonnect.RemapPort,
			Port:     "8080",
		},
	})

	_, err := remapper.Dial(ctx, "tcp6", "service.test:80")
	if !errors.Is(err, errDetachedCapture) {
		t.Fatalf("Dial() error = %v, want capture error", err)
	}
	want := []string{"tcp4", "127.0.0.1:8080"}
	if got := wrapped.args("Dial"); !stringSlicesEqual(got, want) {
		t.Fatalf("Dial args = %v, want %v", got, want)
	}
}

func TestRemapperSkipsUnavailableSourceEndpoint(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	remapper := gonnect.NewRemapper(wrapped, []gonnect.RemapRule{{
		Endpoint: gonnect.RemapSrc,
		Field:    gonnect.RemapAddrPort,
		Addr:     "127.0.0.1",
		Port:     "0",
	}})

	_, err := remapper.DialTCP(ctx, "tcp6", "", "example.com:80")
	if !errors.Is(err, errDetachedCapture) {
		t.Fatalf("DialTCP() error = %v, want capture error", err)
	}
	want := []string{"tcp6", "", "example.com:80"}
	if got := wrapped.args("DialTCP"); !stringSlicesEqual(got, want) {
		t.Fatalf("DialTCP args = %v, want %v", got, want)
	}
}

func TestRemapperDoesNotResolveOperationAddresses(t *testing.T) {
	ctx := context.Background()
	wrapped := &remapperNoResolveNetwork{
		detachedCaptureNetwork: newDetachedCaptureNetwork(),
	}
	remapper := gonnect.NewRemapper(wrapped, []gonnect.RemapRule{{
		Filter: func(info gonnect.RemapInfo) bool {
			return info.Address == "host.test:service"
		},
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddrPort,
		Addr:     "next.test",
		Port:     "https",
	}})

	_, err := remapper.Dial(ctx, "tcp6", "host.test:service")
	if !errors.Is(err, errDetachedCapture) {
		t.Fatalf("Dial() error = %v, want capture error", err)
	}
	want := []string{"tcp6", "next.test:https"}
	if got := wrapped.args("Dial"); !stringSlicesEqual(got, want) {
		t.Fatalf("Dial args = %v, want %v", got, want)
	}
	if got := wrapped.lookupCalls.Load(); got != 0 {
		t.Fatalf("lookup calls = %d, want 0", got)
	}
}

func TestRemapperLifecycleNoOpsWhenWrappedNetworkDoesNotSupportThem(
	t *testing.T,
) {
	remapper := gonnect.NewRemapper(&gonnect.RejectNetwork{}, nil)

	if err := remapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := remapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if err := remapper.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if up, err := remapper.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true nil", up, err)
	}

	unsubscribeCloser, err := remapper.SubscribeCloser(&lifecycleCloser{})
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	unsubscribeCloser()
	unsubscribeCloser()

	unsubscribeUpDown, err := remapper.SubscribeUpDown(&lifecycleUpDown{})
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	unsubscribeUpDown()
	unsubscribeUpDown()
}

func TestRemapperLifecyclePassesThrough(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwok()
	remapper := gonnect.NewRemapper(wrapped, nil)
	closer := &lifecycleCloser{}
	updown := &lifecycleUpDown{}

	unsubscribeCloser, err := remapper.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeCloser()

	unsubscribeUpDown, err := remapper.SubscribeUpDown(updown)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribeUpDown()

	if err := remapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if updown.downs.Load() != 1 {
		t.Fatalf("subscribed Down calls = %d, want 1", updown.downs.Load())
	}
	if up, err := remapper.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}

	if err := remapper.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if updown.ups.Load() != 1 {
		t.Fatalf("subscribed Up calls = %d, want 1", updown.ups.Load())
	}

	if err := remapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("subscribed closer closes = %d, want 1", closer.closes())
	}
	if up, err := remapper.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Close = %v, %v, want false nil", up, err)
	}
}

func TestRemapperWrapsNetworkAndIsNonNative(t *testing.T) {
	wrapped := gonnect.NativeConfig{}.Build()
	rules := []gonnect.RemapRule{{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddr,
		Addr:     "127.0.0.1",
	}}
	remapper := gonnect.NewRemapper(wrapped, rules)
	rules[0].Addr = "::1"

	if remapper.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() did not return wrapped Network")
	}
	if remapper.GetNetwork() != wrapped {
		t.Fatal("GetNetwork() did not return wrapped Network")
	}
	if remapper.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	gotRules := remapper.GetRules()
	if len(gotRules) != 1 || gotRules[0].Addr != "127.0.0.1" {
		t.Fatalf("GetRules() = %#v, want constructor copy", gotRules)
	}
	gotRules[0].Addr = "::1"
	if remapper.GetRules()[0].Addr != "127.0.0.1" {
		t.Fatal("GetRules() returned mutable backing slice")
	}
}

func TestRemapperListenRemapWorksWithLoopbackNetwork(t *testing.T) {
	ctx := context.Background()
	remapper := gonnect.NewRemapper(
		gonnect.NewLoopbackNetwok(),
		[]gonnect.RemapRule{{
			Filter: func(info gonnect.RemapInfo) bool {
				return info.Operation == gonnect.RemapOpListenUDP &&
					info.Address == "[::1]:0"
			},
			Endpoint: gonnect.RemapSrc,
			Field:    gonnect.RemapAddr,
			Addr:     "127.0.0.1",
		}},
	)

	conn, err := remapper.ListenUDP(ctx, "udp6", "[::1]:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	addr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("LocalAddr() parse error = %v", err)
	}
	if !addr.Addr().Is4() {
		t.Fatalf("LocalAddr() = %v, want IPv4 address", conn.LocalAddr())
	}
}

func TestRemapperDialRemapWorksThroughRouter(t *testing.T) {
	ctx := context.Background()
	router := gonnect.NewRouter(nil)
	defer func() { _ = router.Close() }()
	if err := router.Attach(1, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Router Attach() error = %v", err)
	}

	listener, err := router.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Router ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("listener Addr() split error = %v", err)
	}
	remapper := gonnect.NewRemapper(router, []gonnect.RemapRule{{
		Filter: gonnect.RemapAddressFilter(
			gonnect.FilterFromString("example.com:80").Filter,
		),
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddrPort,
		Addr:     "127.0.0.1",
		Port:     port,
	}})

	client, err := remapper.DialTCP(ctx, "tcp", "", "example.com:80")
	if err != nil {
		t.Fatalf("Remapper DialTCP() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP() error = %v", err)
	}
	defer func() { _ = server.Close() }()

	deadline := time.Now().Add(time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("client SetDeadline() error = %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("server SetDeadline() error = %v", err)
	}

	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server ReadFull() error = %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("server read = %q, want ok", buf)
	}
}

type remapperNoResolveNetwork struct {
	*detachedCaptureNetwork
	lookupCalls atomic.Int32
}

func (n *remapperNoResolveNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	n.lookupCalls.Add(1)
	return nil, gonnect.NoSuchHost(host, "remapper-test")
}

func (n *remapperNoResolveNetwork) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	n.lookupCalls.Add(1)
	return 0, gonnect.NoSuchHost(service, "remapper-test")
}
