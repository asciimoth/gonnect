package gonnect

import (
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

type testNetworkInterface struct {
	index int
	name  string
}

func (i testNetworkInterface) ID() string { return "test" }

func (i testNetworkInterface) Index() int { return i.index }

func (i testNetworkInterface) Name() string { return i.name }

func (i testNetworkInterface) MTU() int { return 1500 }

func (i testNetworkInterface) HardwareAddr() net.HardwareAddr { return nil }

func (i testNetworkInterface) Flags() net.Flags { return 0 }

func (i testNetworkInterface) Addrs() ([]net.Addr, error) { return nil, nil }

func (i testNetworkInterface) MulticastAddrs() ([]net.Addr, error) {
	return nil, nil
}

func TestNativeMulticastControlMessageHelpers(t *testing.T) {
	flags := nativeIPv6ControlFlags(ControlDst | ControlInterface)
	if flags&ipv6.FlagDst == 0 || flags&ipv6.FlagInterface == 0 {
		t.Fatalf("nativeIPv6ControlFlags() = %v, want dst and iface", flags)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353}
	native := controlMessageToNative(ControlMessage{Dst: dst})
	if native == nil || !native.Dst.Equal(dst.IP) {
		t.Fatalf("controlMessageToNative() = %+v, want dst %v", native, dst.IP)
	}

	got := controlMessageFromNative(&ipv6.ControlMessage{
		Dst:     net.ParseIP("2001:db8::2"),
		IfIndex: -1,
	})
	if got.IfIndex != -1 {
		t.Fatalf("controlMessageFromNative IfIndex = %d, want -1", got.IfIndex)
	}
	if got.Dst == nil || got.Dst.String() != "2001:db8::2" {
		t.Fatalf("controlMessageFromNative Dst = %v, want 2001:db8::2", got.Dst)
	}

	if got := addrIP(&net.IPAddr{IP: net.ParseIP("192.0.2.1")}); !got.Equal(
		net.ParseIP("192.0.2.1"),
	) {
		t.Fatalf("addrIP(IPAddr) = %v, want 192.0.2.1", got)
	}
	if got := addrIP(
		&net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 443},
	); !got.Equal(
		net.ParseIP("192.0.2.2"),
	) {
		t.Fatalf("addrIP(TCPAddr) = %v, want 192.0.2.2", got)
	}
}

func TestNativeNetInterfaceNotFound(t *testing.T) {
	_, err := nativeNetInterface(testNetworkInterface{})
	if err == nil {
		t.Fatal("nativeNetInterface(empty) error = nil, want not found")
	}
}
