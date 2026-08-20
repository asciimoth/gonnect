package gonnect_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestNetworkWithResolverRoutesLookupsToResolver(t *testing.T) {
	ctx := context.Background()
	resolver := &detachedResolver{}
	wrapper := gonnect.NewNetworkWithResolver(
		&gonnect.RejectNetwork{},
		resolver,
	)

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
			_, err := wrapper.LookupPort(ctx, "tcp", "service")
			return err
		}},
		{"LookupNS", func() error {
			_, err := wrapper.LookupNS(ctx, "host.test")
			return err
		}},
		{"LookupMX", func() error {
			_, err := wrapper.LookupMX(ctx, "host.test")
			return err
		}},
		{"LookupSRV", func() error {
			_, _, err := wrapper.LookupSRV(ctx, "service", "tcp", "host.test")
			return err
		}},
		{"LookupTXT", func() error {
			_, err := wrapper.LookupTXT(ctx, "host.test")
			return err
		}},
	}

	for _, tt := range lookupCalls {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			if !resolver.called(tt.name) {
				t.Fatalf("resolver %s was not called", tt.name)
			}
		})
	}
}

func TestNetworkWithResolverResolverPreResolvesAddresses(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	wrapper := gonnect.NewNetworkWithResolver(wrapped, &detachedResolver{})
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

func TestNetworkWithResolverResolverLeavesIPLiteralHosts(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	resolver := &detachedResolver{}
	wrapper := gonnect.NewNetworkWithResolver(wrapped, resolver)

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

func TestNetworkWithResolverDelegatesInterfaceMethods(t *testing.T) {
	wrapped := &remapperInterfaceNetwork{}
	wrapper := gonnect.NewNetworkWithResolver(wrapped, &detachedResolver{})

	if got, err := wrapper.Interfaces(); err != nil ||
		len(got) != 1 || got[0].Name() != "test0" {
		t.Fatalf("Interfaces() = %v, %v", got, err)
	}
	if got, err := wrapper.InterfaceAddrs(); err != nil ||
		len(got) != 1 || got[0].String() != "192.0.2.1/32" {
		t.Fatalf("InterfaceAddrs() = %v, %v", got, err)
	}
	if got, err := wrapper.InterfaceMulticastAddrs(); err != nil ||
		len(got) != 1 || got[0].String() != "224.0.0.1/32" {
		t.Fatalf("InterfaceMulticastAddrs() = %v, %v", got, err)
	}
	if got, err := wrapper.InterfacesByIndex(7); err != nil ||
		len(got) != 1 || got[0].Index() != 7 {
		t.Fatalf("InterfacesByIndex() = %v, %v", got, err)
	}
	if got, err := wrapper.InterfacesByName("test0"); err != nil ||
		len(got) != 1 || got[0].Name() != "test0" {
		t.Fatalf("InterfacesByName() = %v, %v", got, err)
	}
	for _, name := range []string{
		"Interfaces",
		"InterfaceAddrs",
		"InterfaceMulticastAddrs",
		"InterfacesByIndex",
		"InterfacesByName",
	} {
		if !wrapped.called(name) {
			t.Fatalf("%s() did not delegate", name)
		}
	}
}

func TestNetworkWithResolverNilResolverUsesWrappedNetwork(t *testing.T) {
	ctx := context.Background()
	wrapped := newDetachedCaptureNetwork()
	wrapper := gonnect.NewNetworkWithResolver(wrapped, nil)

	_, err := wrapper.Dial(ctx, "tcp", "host.test:service")
	if !errors.Is(err, errDetachedCapture) {
		t.Fatalf("Dial() error = %v, want capture error", err)
	}
	if got, want := wrapped.args(
		"Dial",
	), []string{
		"tcp",
		"host.test:service",
	}; !stringSlicesEqual(
		got,
		want,
	) {
		t.Fatalf("Dial args = %v, want %v", got, want)
	}

	if _, err := wrapper.LookupHost(ctx, "host.test"); err == nil {
		t.Fatal(
			"LookupHost() with nil resolver succeeded through RejectNetwork",
		)
	}
}

func TestNetworkWithResolverLifecycleNoOpsWhenWrappedNetworkDoesNotSupportThem(
	t *testing.T,
) {
	wrapper := gonnect.NewNetworkWithResolver(&gonnect.RejectNetwork{}, nil)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if err := wrapper.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if up, err := wrapper.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true nil", up, err)
	}
	unsubscribeCloser, err := wrapper.SubscribeCloser(&lifecycleCloser{})
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	unsubscribeCloser()
	unsubscribeCloser()
	unsubscribeUpDown, err := wrapper.SubscribeUpDown(&lifecycleUpDown{})
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	unsubscribeUpDown()
	unsubscribeUpDown()
}

func TestNetworkWithResolverLifecyclePassesThrough(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwork()
	wrapper := gonnect.NewNetworkWithResolver(wrapped, nil)
	closer := &lifecycleCloser{}
	updown := &lifecycleUpDown{}

	unsubscribeCloser, err := wrapper.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeCloser()

	unsubscribeUpDown, err := wrapper.SubscribeUpDown(updown)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribeUpDown()

	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if updown.downs.Load() != 1 {
		t.Fatalf("subscribed Down calls = %d, want 1", updown.downs.Load())
	}
	if up, err := wrapper.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}

	if err := wrapper.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if updown.ups.Load() != 1 {
		t.Fatalf("subscribed Up calls = %d, want 1", updown.ups.Load())
	}

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("subscribed closer closes = %d, want 1", closer.closes())
	}
	if up, err := wrapper.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Close = %v, %v, want false nil", up, err)
	}
}

func TestNetworkWithResolverWrapsNetwork(t *testing.T) {
	wrapped := &gonnect.RejectNetwork{}
	wrapper := gonnect.NewNetworkWithResolver(wrapped, nil)

	if wrapper.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() did not return wrapped Network")
	}
	if wrapper.GetNetwork() != wrapped {
		t.Fatal("GetNetwork() did not return wrapped Network")
	}
	if wrapper.GetResolver() != nil {
		t.Fatal("GetResolver() = non-nil, want nil")
	}
	if wrapper.IsNative() != wrapped.IsNative() {
		t.Fatal("IsNative() did not delegate to wrapped Network")
	}
}

func TestNetworkWithResolverRejectsUnresolvableHostnames(t *testing.T) {
	ctx := context.Background()
	wrapper := gonnect.NewNetworkWithResolver(
		newDetachedCaptureNetwork(),
		&networkWithResolverEmptyResolver{},
	)

	_, err := wrapper.Dial(ctx, "tcp", "host.test:http")
	if err == nil {
		t.Fatal("Dial() succeeded with empty resolver results")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("Dial() error = %T %v, want *net.DNSError", err, err)
	}
}

type networkWithResolverEmptyResolver struct {
	detachedResolver
}

func (r *networkWithResolverEmptyResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	r.record("LookupHost")
	return nil, nil
}
