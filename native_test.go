// nolint
package gonnect_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestNativeNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return gonnect.NativeConfig{}.Build()
	})
}
func TestNativeNetworkTcpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NativeConfig{}.Build(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkHTTP(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NativeConfig{}.Build(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestNativeNetworkDialNoResolver(t *testing.T) {
	t.Parallel()

	var resolverDials atomic.Int32
	n := gonnect.NativeConfig{
		ResolverCfg: &gonnect.ResolverCfg{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				resolverDials.Add(1)
				return nil, errors.New("resolver dial should not be used")
			},
		},
	}.Build()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	conn, err := n.DialNoResolver(
		context.Background(),
		"tcp4",
		ln.Addr().String(),
	)
	if err != nil {
		t.Fatalf("DialNoResolver IP error = %v", err)
	}
	_ = conn.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	conn, err = n.DialNoResolver(
		context.Background(),
		"tcp4",
		net.JoinHostPort("localhost", strconv.Itoa(port)),
	)
	if err != nil {
		t.Fatalf("DialNoResolver localhost error = %v", err)
	}
	_ = conn.Close()

	if _, err := n.DialNoResolver(
		context.Background(),
		"tcp4",
		"no-such-host.example.invalid:80",
	); err == nil {
		t.Fatal("DialNoResolver unresolved host returned nil error")
	}

	if got := resolverDials.Load(); got != 0 {
		t.Fatalf("resolver dial calls = %d, want 0", got)
	}
}

func TestNativeNetworkTypedDialUsesControls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config func(calls *atomic.Int32) gonnect.NativeConfig
	}{
		{
			name: "Control",
			config: func(calls *atomic.Int32) gonnect.NativeConfig {
				return gonnect.NativeConfig{
					Control: func(
						network, address string,
						c syscall.RawConn,
					) error {
						calls.Add(1)
						return nil
					},
				}
			},
		},
		{
			name: "ControlContext",
			config: func(calls *atomic.Int32) gonnect.NativeConfig {
				return gonnect.NativeConfig{
					ControlContext: func(
						ctx context.Context,
						network, address string,
						c syscall.RawConn,
					) error {
						calls.Add(1)
						return nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			var calls atomic.Int32
			n := tt.config(&calls).Build()

			tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen error = %v", err)
			}
			t.Cleanup(func() { _ = tcpLn.Close() })

			accepted := make(chan net.Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				conn, err := tcpLn.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- conn
			}()

			tcpConn, err := n.DialTCP(ctx, "tcp4", "", tcpLn.Addr().String())
			if err != nil {
				t.Fatalf("DialTCP() error = %v", err)
			}
			_ = tcpConn.Close()

			select {
			case conn := <-accepted:
				_ = conn.Close()
			case err := <-acceptErr:
				t.Fatalf("Accept error = %v", err)
			case <-time.After(time.Second):
				t.Fatal("Accept timed out")
			}

			if got := calls.Load(); got == 0 {
				t.Fatal("DialTCP() did not invoke configured control")
			}

			beforeUDP := calls.Load()
			udpLn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("ListenPacket error = %v", err)
			}
			t.Cleanup(func() { _ = udpLn.Close() })

			udpConn, err := n.DialUDP(
				ctx,
				"udp4",
				"127.0.0.1:0",
				udpLn.LocalAddr().String(),
			)
			if err != nil {
				t.Fatalf("DialUDP() error = %v", err)
			}
			_ = udpConn.Close()

			if got := calls.Load(); got <= beforeUDP {
				t.Fatal("DialUDP() did not invoke configured control")
			}
		})
	}
}

func TestNativeNetworkTypedListenUsesControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var calls atomic.Int32
	n := gonnect.NativeConfig{
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				calls.Add(1)
				return nil
			},
		},
	}.Build()

	tcpLn, err := n.ListenTCP(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	if got := calls.Load(); got == 0 {
		t.Fatal("ListenTCP() did not invoke configured control")
	}

	beforeUDP := calls.Load()
	udpConn, err := n.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })

	if got := calls.Load(); got <= beforeUDP {
		t.Fatal("ListenUDP() did not invoke configured control")
	}
}

func TestNativeNetworkNumericIPDoesNotUseResolver(t *testing.T) {
	t.Parallel()

	dns := newNativeNameErrorDNS()
	t.Cleanup(func() { _ = dns.Close() })

	n := gonnect.NativeConfig{}.Build()
	n.SetResolver(gdns.NewResolver(dns))

	ln, err := n.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen numeric IP error = %v", err)
	}
	_ = ln.Close()

	if got := dns.calls.Load(); got != 0 {
		t.Fatalf("resolver calls after numeric Listen = %d, want 0", got)
	}

	if _, _, err := n.LookupNetAddr(
		context.Background(),
		"tcp6",
		"127.0.0.1:0",
	); err == nil {
		t.Fatal("LookupNetAddr incompatible numeric IP returned nil error")
	}

	if got := dns.calls.Load(); got != 0 {
		t.Fatalf("resolver calls after incompatible literal = %d, want 0", got)
	}
}

func TestNativeNetworkUdpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NativeConfig{}.Build(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkInterfaceMulticastAddrs(t *testing.T) {
	t.Parallel()

	n := gonnect.NativeConfig{}.Build()
	got, err := n.InterfaceMulticastAddrs()
	if err != nil {
		t.Fatalf("InterfaceMulticastAddrs() error = %v", err)
	}

	ifs, err := n.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces() error = %v", err)
	}
	var want []net.Addr
	for _, iface := range ifs {
		addrs, err := iface.MulticastAddrs()
		if err != nil {
			t.Fatalf(
				"interface %q MulticastAddrs() error = %v",
				iface.Name(),
				err,
			)
		}
		want = append(want, addrs...)
	}

	if len(got) != len(want) {
		t.Fatalf(
			"InterfaceMulticastAddrs() len = %d, want %d",
			len(got),
			len(want),
		)
	}
	for i := range want {
		if got[i].String() != want[i].String() {
			t.Fatalf(
				"InterfaceMulticastAddrs()[%d] = %q, want %q",
				i,
				got[i],
				want[i],
			)
		}
	}
}

type nativeNameErrorDNS struct {
	ch    chan gdns.Request
	calls atomic.Int32
}

func newNativeNameErrorDNS() *nativeNameErrorDNS {
	d := &nativeNameErrorDNS{ch: make(chan gdns.Request)}
	go func() {
		for req := range d.ch {
			d.calls.Add(1)
			req.Reply <- gdns.Response{
				Message: &gdns.Message{
					ID:       req.Message.ID,
					Response: true,
					RCode:    gdns.RCodeNameError,
				},
			}
		}
	}()
	return d
}

func (d *nativeNameErrorDNS) Requests() chan<- gdns.Request { return d.ch }

func (d *nativeNameErrorDNS) Close() error {
	close(d.ch)
	return nil
}

func TestNativeNetworkListenPacketConfig_MergesControls(t *testing.T) {
	t.Parallel()

	var defaultCalls atomic.Int32
	var listenCalls atomic.Int32
	var order []string

	n := gonnect.NativeConfig{
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				defaultCalls.Add(1)
				order = append(order, "default")
				return nil
			},
		},
	}.Build()

	pc, err := n.ListenPacketConfig(context.Background(), &gonnect.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			listenCalls.Add(1)
			order = append(order, "listen")
			return nil
		},
	}, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacketConfig() error = %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	if got := listenCalls.Load(); got == 0 {
		t.Fatal("ListenPacketConfig() did not invoke call-specific Control")
	}
	if got := defaultCalls.Load(); got == 0 {
		t.Fatal("ListenPacketConfig() did not invoke default Control")
	}
	if len(order) != 2 || order[0] != "listen" || order[1] != "default" {
		t.Fatalf(
			"ListenPacketConfig() Control order = %#v, want listen then default",
			order,
		)
	}

	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"ListenPacketConfig() local addr type = %T, want *net.UDPAddr",
			pc.LocalAddr(),
		)
	}
	if addr.Port == 0 {
		t.Fatal(
			"ListenPacketConfig() bound port = 0, want ephemeral port assigned",
		)
	}
}

func TestNativeNetworkListenUDPConfig_MergesControls(t *testing.T) {
	t.Parallel()

	var defaultCalls atomic.Int32
	var listenCalls atomic.Int32
	var order []string

	n := gonnect.NativeConfig{
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				defaultCalls.Add(1)
				order = append(order, "default")
				return nil
			},
		},
	}.Build()

	uc, err := n.ListenUDPConfig(context.Background(), &gonnect.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			listenCalls.Add(1)
			order = append(order, "listen")
			return nil
		},
	}, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDPConfig() error = %v", err)
	}
	t.Cleanup(func() { _ = uc.Close() })

	if got := listenCalls.Load(); got == 0 {
		t.Fatal("ListenUDPConfig() did not invoke call-specific Control")
	}
	if got := defaultCalls.Load(); got == 0 {
		t.Fatal("ListenUDPConfig() did not invoke default Control")
	}
	if len(order) != 2 || order[0] != "listen" || order[1] != "default" {
		t.Fatalf(
			"ListenUDPConfig() Control order = %#v, want listen then default",
			order,
		)
	}

	addr, ok := uc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"ListenUDPConfig() local addr type = %T, want *net.UDPAddr",
			uc.LocalAddr(),
		)
	}
	if addr.Port == 0 {
		t.Fatal(
			"ListenUDPConfig() bound port = 0, want ephemeral port assigned",
		)
	}
}
