//nolint:testpackage
package gonnect

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

func TestNativeMulticastSockoptHelpers(t *testing.T) {
	if err := setNativeMulticastSockopts(nil, MulticastOptions{}); !errors.Is(
		err,
		ErrUnsupported,
	) {
		t.Fatalf("setNativeMulticastSockopts(nil) = %v, want unsupported", err)
	}
	if err := setNativeReusePort(-1); err == nil {
		t.Fatal("setNativeReusePort(-1) error = nil, want error")
	}
	if err := setNativeRecvAnyIf(-1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("setNativeRecvAnyIf(-1) = %v, want unsupported", err)
	}

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("udp4 listener is not available: %v", err)
	}
	defer func() { _ = c.Close() }()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}
	if err := setNativeMulticastSockopts(raw, MulticastOptions{}); err != nil {
		t.Fatalf("setNativeMulticastSockopts(no opts) error = %v", err)
	}
	if err := setNativeMulticastSockopts(
		raw,
		MulticastOptions{ReuseAddr: true},
	); err != nil {
		t.Fatalf("setNativeMulticastSockopts(ReuseAddr) error = %v", err)
	}
}

func TestNativeMulticastPacketConnErrorsAndIO(t *testing.T) {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("udp6 listener is not available: %v", err)
	}
	defer func() { _ = c.Close() }()

	mc := &nativeMulticastPacketConn{
		UDPConn: c,
		pc:      ipv6.NewPacketConn(c),
	}
	if err := mc.JoinGroup(testNetworkInterface{}, nil); err == nil {
		t.Fatal("JoinGroup(empty interface) error = nil, want error")
	}
	if err := mc.LeaveGroup(testNetworkInterface{}, nil); err == nil {
		t.Fatal("LeaveGroup(empty interface) error = nil, want error")
	}
	if err := mc.SetControlMessage(
		ControlDst|ControlInterface,
		true,
	); err != nil {
		t.Fatalf("SetControlMessage() error = %v", err)
	}
	if err := c.SetReadDeadline(
		time.Now().Add(10 * time.Millisecond),
	); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 8)
	if _, _, _, err := mc.ReadFromControl(buf); err == nil {
		t.Fatal("ReadFromControl() error = nil, want deadline error")
	}
	if _, err := mc.WriteToControl(
		[]byte("x"),
		ControlMessage{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 9},
	); err != nil {
		t.Fatalf("WriteToControl() error = %v", err)
	}
}

func TestRouterSlotUpDownAndTrackUDPConn(t *testing.T) {
	r := NewRouter(nil)
	r.slotGen[0] = 7
	r.slotUp[0] = true
	u := &routerSlotUpDown{router: r, slot: 1, gen: 7}
	up, err := u.IsUp()
	if err != nil || !up {
		t.Fatalf("IsUp() = %v, %v; want true, nil", up, err)
	}
	u.gen = 8
	up, err = u.IsUp()
	if err != nil || up {
		t.Fatalf("stale IsUp() = %v, %v; want false, nil", up, err)
	}

	c := &fakeUDPConn{}
	r.up = true
	r.gen = 9
	tracked, err := r.trackUDPConn(r.gen, 1, c)
	if err != nil {
		t.Fatalf("trackUDPConn() error = %v", err)
	}
	if tracked == nil {
		t.Fatal("trackUDPConn() = nil, want connection")
	}
	if r.bySlot[0] == nil {
		t.Fatal("trackUDPConn() did not create slot tracking map")
	}
	if err := tracked.Close(); err != nil {
		t.Fatalf("tracked Close() error = %v", err)
	}
	if len(r.bySlot[0]) != 0 {
		t.Fatalf("slot tracking count = %d, want 0", len(r.bySlot[0]))
	}
}
