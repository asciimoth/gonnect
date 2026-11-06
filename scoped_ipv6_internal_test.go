package gonnect

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

type scopedTestResolver struct {
	*net.Resolver
	hostCalls int
	portCalls int
}

func (r *scopedTestResolver) LookupIP(
	context.Context,
	string,
	string,
) ([]net.IP, error) {
	r.hostCalls++
	return nil, errors.New("unexpected host lookup")
}

func (r *scopedTestResolver) LookupPort(
	context.Context,
	string,
	string,
) (int, error) {
	r.portCalls++
	return 9001, nil
}

func TestNativeScopedIPv6AddressConversion(t *testing.T) {
	ctx := context.Background()
	r := &scopedTestResolver{Resolver: net.DefaultResolver}
	n := NativeConfig{}.Build()
	n.SetResolver(r)
	for _, tt := range []struct {
		address string
		port    int
	}{
		{"[fe80::1%eth0]:9001", 9001},
		{"[fe80::1%eth0]:service", 9001},
	} {
		t.Run(tt.address, func(t *testing.T) {
			tcp, err := n.resolveTCPAddr(ctx, "tcp6", tt.address, actionDial)
			if err != nil {
				t.Fatal(err)
			}
			udp, err := n.resolveUDPAddr(ctx, "udp6", tt.address, actionDial)
			if err != nil {
				t.Fatal(err)
			}
			if tcp.Zone != "eth0" || tcp.Port != tt.port ||
				tcp.String() != "[fe80::1%eth0]:9001" {
				t.Errorf("TCP address = %v, zone = %q", tcp, tcp.Zone)
			}
			if udp.Zone != "eth0" || udp.Port != tt.port ||
				udp.String() != "[fe80::1%eth0]:9001" {
				t.Errorf("UDP address = %v, zone = %q", udp, udp.Zone)
			}
		})
	}
	if r.hostCalls != 0 || r.portCalls != 2 {
		t.Fatalf(
			"resolver calls: host = %d, port = %d",
			r.hostCalls,
			r.portCalls,
		)
	}
	if _, _, err := n.LookupNetAddr(
		ctx,
		"tcp4",
		"[fe80::1%eth0]:9001",
	); err == nil {
		t.Fatal("IPv6 literal accepted on tcp4")
	}
}

func TestNativeScopedIPv6FilterKeepsZone(t *testing.T) {
	var addresses []string
	n := NativeConfig{Filter: func(_, address string) bool {
		addresses = append(addresses, address)
		return false
	}}.Build()
	n.SetResolver(&scopedTestResolver{Resolver: net.DefaultResolver})
	if _, err := n.resolveTCPAddr(
		context.Background(),
		"tcp6",
		"[fe80::1%eth0]:service",
		actionDial,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{"[fe80::1%eth0]:service", "[fe80::1%eth0]:9001"}
	if len(addresses) != len(want) {
		t.Fatalf("filtered addresses = %v, want %v", addresses, want)
	}
	for i := range want {
		if addresses[i] != want[i] {
			t.Errorf(
				"filtered address %d = %q, want %q",
				i,
				addresses[i],
				want[i],
			)
		}
	}
}

func TestScopedIPv6ResolverResultAndRejectError(t *testing.T) {
	if got := routerPickResolvedHost(
		"tcp6",
		[]string{"fe80::1%eth0"},
	); got != "fe80::1%eth0" {
		t.Errorf("resolved IPv6 host = %q", got)
	}
	if got := routerPickResolvedHost(
		"tcp4",
		[]string{"::ffff:192.0.2.1"},
	); got != "192.0.2.1" {
		t.Errorf("mapped IPv4 host = %q", got)
	}
	var dnsErr *net.DNSError
	if err := dialError(
		"tcp6",
		"[fe80::1%eth0]:9001",
	); errors.As(
		err,
		&dnsErr,
	) {
		t.Fatalf("scoped literal classified as DNS name: %v", err)
	}
}

func TestNativeScopedIPv6SocketControl(t *testing.T) {
	ctx := context.Background()
	want := "[fe80::1%eth0]:9001"
	stop := errors.New("socket address recorded")
	for _, tt := range []struct {
		name string
		call func(*NativeNetwork) error
	}{
		{"Listen", func(n *NativeNetwork) error { _, err := n.Listen(ctx, "tcp6", want); return err }},
		{"ListenTCP", func(n *NativeNetwork) error { _, err := n.ListenTCP(ctx, "tcp6", want); return err }},
		{"ListenPacket", func(n *NativeNetwork) error { _, err := n.ListenPacket(ctx, "udp6", want); return err }},
		{"ListenPacketConfig", func(n *NativeNetwork) error {
			_, err := n.ListenPacketConfig(ctx, nil, "udp6", want)
			return err
		}},
		{"ListenUDP", func(n *NativeNetwork) error { _, err := n.ListenUDP(ctx, "udp6", want); return err }},
		{"ListenUDPConfig", func(n *NativeNetwork) error { _, err := n.ListenUDPConfig(ctx, nil, "udp6", want); return err }},
		{"DialTCP", func(n *NativeNetwork) error { _, err := n.DialTCP(ctx, "tcp6", want, want); return err }},
		{"DialUDP", func(n *NativeNetwork) error { _, err := n.DialUDP(ctx, "udp6", want, want); return err }},
		{"PacketDial", func(n *NativeNetwork) error { _, err := n.PacketDial(ctx, "udp6", want); return err }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			check := func(_ string, addr string, _ syscall.RawConn) error {
				calls++
				if addr != want {
					t.Errorf("socket address = %q, want %q", addr, want)
				}
				return stop
			}
			n := NativeConfig{
				ListenCfg: &net.ListenConfig{Control: check},
				Control:   check,
			}.Build()
			if err := tt.call(n); !errors.Is(err, stop) {
				t.Fatalf("error = %v, want control error", err)
			}
			// Go may try more than one socket family for a TCP listen.
			if calls == 0 {
				t.Fatal("socket control was not called")
			}
		})
	}
}
