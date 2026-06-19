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

	"github.com/asciimoth/gonnect"
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
