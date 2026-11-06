package gonnect_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestScopedIPv6ResolverWrappersForwardAddresses(t *testing.T) {
	ctx := context.Background()
	for _, wrapper := range []struct {
		name string
		make func(*detachedCaptureNetwork, *detachedResolver) gonnect.Network
	}{
		{"NetworkWithResolver", func(n *detachedCaptureNetwork, r *detachedResolver) gonnect.Network {
			return gonnect.NewNetworkWithResolver(n, r)
		}},
		{"DetachedNetwork", func(n *detachedCaptureNetwork, r *detachedResolver) gonnect.Network {
			return gonnect.DetachNetwork(n, r, nil)
		}},
	} {
		for _, port := range []struct{ input, output string }{
			{"9001", "9001"},
			{"service", "8080"},
		} {
			for _, op := range []struct {
				name    string
				network string
				dual    bool
				call    func(gonnect.Network, string) error
			}{
				{"Dial", "tcp6", false, func(n gonnect.Network, a string) error {
					_, err := n.Dial(ctx, "tcp6", a)
					return err
				}},
				{"Listen", "tcp6", false, func(n gonnect.Network, a string) error {
					_, err := n.Listen(ctx, "tcp6", a)
					return err
				}},
				{"PacketDial", "udp6", false, func(n gonnect.Network, a string) error {
					_, err := n.PacketDial(ctx, "udp6", a)
					return err
				}},
				{"ListenPacket", "udp6", false, func(n gonnect.Network, a string) error {
					_, err := n.ListenPacket(ctx, "udp6", a)
					return err
				}},
				{"DialTCP", "tcp6", true, func(n gonnect.Network, a string) error {
					_, err := n.DialTCP(ctx, "tcp6", a, a)
					return err
				}},
				{"ListenTCP", "tcp6", false, func(n gonnect.Network, a string) error {
					_, err := n.ListenTCP(ctx, "tcp6", a)
					return err
				}},
				{"DialUDP", "udp6", true, func(n gonnect.Network, a string) error {
					_, err := n.DialUDP(ctx, "udp6", a, a)
					return err
				}},
				{"ListenUDP", "udp6", false, func(n gonnect.Network, a string) error {
					_, err := n.ListenUDP(ctx, "udp6", a)
					return err
				}},
				{"ListenPacketConfig", "udp6", false, func(n gonnect.Network, a string) error {
					_, err := n.ListenPacketConfig(ctx, nil, "udp6", a)
					return err
				}},
				{"ListenUDPConfig", "udp6", false, func(n gonnect.Network, a string) error {
					_, err := n.ListenUDPConfig(ctx, nil, "udp6", a)
					return err
				}},
				{"ListenMulticastUDP", "udp6", false, func(n gonnect.Network, a string) error {
					_, e := n.ListenMulticastUDP(ctx, "udp6", a, gonnect.MulticastOptions{})
					return e
				}},
			} {
				t.Run(
					wrapper.name+"/"+port.input+"/"+op.name,
					func(t *testing.T) {
						capture := newDetachedCaptureNetwork()
						resolver := &detachedResolver{}
						n := wrapper.make(capture, resolver)
						input := "[fe80::1%eth0]:" + port.input
						output := "[fe80::1%eth0]:" + port.output
						if err := op.call(
							n,
							input,
						); !errors.Is(
							err,
							errDetachedCapture,
						) {
							t.Fatalf("error = %v, want capture error", err)
						}
						want := []string{op.network, output}
						if op.dual {
							want = append(want, output)
						}
						if got := capture.args(
							op.name,
						); !reflect.DeepEqual(
							got,
							want,
						) {
							t.Errorf(
								"forwarded arguments = %v, want %v",
								got,
								want,
							)
						}
						if resolver.called("LookupHost") {
							t.Error("scoped IP sent to host lookup")
						}
						if got, want := resolver.callCount(), 0; port.input == "service" {
							if op.name == "DialTCP" || op.name == "DialUDP" {
								want = 2
							} else {
								want = 1
							}
							if got != want {
								t.Errorf(
									"resolver calls = %d, want %d",
									got,
									want,
								)
							}
						} else if got != want {
							t.Errorf("resolver calls = %d, want %d", got, want)
						}
					},
				)
			}
		}
	}
}

func TestRouterScopedIPv6ForwardsToSelectedNetwork(t *testing.T) {
	ctx := context.Background()
	capture := newDetachedCaptureNetwork()
	resolver := &detachedResolver{}
	r := gonnect.NewRouter(nil)
	r.SetResolver(resolver)
	if err := r.Attach(1, capture); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	addr := "[fe80::1%eth0]:8080"
	for _, tt := range []struct {
		name string
		call func() error
		want []string
	}{
		{"DialTCP", func() error { _, e := r.DialTCP(ctx, "tcp6", addr, addr); return e }, []string{"tcp6", addr, addr}},
		{"ListenTCP", func() error { _, e := r.ListenTCP(ctx, "tcp6", addr); return e }, []string{"tcp6", addr}},
		{"DialUDP", func() error { _, e := r.DialUDP(ctx, "udp6", addr, addr); return e }, []string{"udp6", addr, addr}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_ = tt.call() // Capture backend returns a sentinel after recording the call.
			if got := capture.args(tt.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("forwarded arguments = %v, want %v", got, tt.want)
			}
		})
	}
	if resolver.called("LookupHost") || resolver.callCount() != 0 {
		t.Fatalf("scoped IP caused resolver calls: %d", resolver.callCount())
	}
	named := "[fe80::1%eth0]:service"
	_, _ = r.DialTCP(ctx, "tcp6", named, named)
	if got, want := capture.args(
		"DialTCP",
	), []string{
		"tcp6",
		addr,
		addr,
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Errorf("named service forwarded arguments = %v, want %v", got, want)
	}
	if resolver.called("LookupHost") || resolver.callCount() != 2 {
		t.Errorf(
			"named service resolver calls = %d, want two port lookups",
			resolver.callCount(),
		)
	}
}

func TestScopedIPv6FiltersTreatZonesAsIPMetadata(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		address string
		want    bool
	}{
		{"fe80::1", "[fe80::1%eth0]:9001", true},
		{"[fe80::1]:9001", "[fe80::1%eth0]:9001", true},
		{"[fe80::1%eth0]:9001", "[fe80::1%eth0]:9001", true},
		{"[fe80::1%eth1]:9001", "[fe80::1%eth0]:9001", false},
		{"[fe80::1%Eth0]:9001", "[fe80::1%Eth0]:9001", true},
		{"[fe80::1%Eth0]:9001", "[fe80::1%eth0]:9001", true},
		{"fe80::/10", "[fe80::1%eth0]:9001", true},
		{"fe80::1", "[fe80::2%eth0]:9001", false},
		{"[fe80::1]:9002", "[fe80::1%eth0]:9001", false},
	} {
		t.Run(tt.pattern+"/"+tt.address, func(t *testing.T) {
			if got := gonnect.FilterFromString(tt.pattern).
				Filter("tcp6", tt.address); got != tt.want {
				t.Errorf("Filter() = %t, want %t", got, tt.want)
			}
		})
	}
	for _, addr := range []string{"[::1%lo]:9001", "[::1%lo0]:9001"} {
		if !gonnect.LoopbackFilter("tcp6", addr) || !gonnect.IsLocal(addr) {
			t.Errorf("scoped loopback %q was not recognized", addr)
		}
	}
}
