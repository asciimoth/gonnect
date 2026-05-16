package gonnect_test

import (
	"context"
	"net"
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

func TestNativeNetworkUdpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NativeConfig{}.Build(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkListenPacketConfig_UsesCallSpecificControl(t *testing.T) {
	t.Parallel()

	var defaultCalls atomic.Int32
	var listenCalls atomic.Int32

	n := gonnect.NativeConfig{
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				defaultCalls.Add(1)
				return nil
			},
		},
	}.Build()

	pc, err := n.ListenPacketConfig(context.Background(), &gonnect.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			listenCalls.Add(1)
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
	if got := defaultCalls.Load(); got != 0 {
		t.Fatalf("ListenPacketConfig() invoked default Control %d times", got)
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

func TestNativeNetworkListenUDPConfig_UsesCallSpecificControl(t *testing.T) {
	t.Parallel()

	var defaultCalls atomic.Int32
	var listenCalls atomic.Int32

	n := gonnect.NativeConfig{
		ListenCfg: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				defaultCalls.Add(1)
				return nil
			},
		},
	}.Build()

	uc, err := n.ListenUDPConfig(context.Background(), &gonnect.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			listenCalls.Add(1)
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
	if got := defaultCalls.Load(); got != 0 {
		t.Fatalf("ListenUDPConfig() invoked default Control %d times", got)
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
