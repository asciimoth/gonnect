// nolint
package sockopt

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestIgnoreUnsupported(t *testing.T) {
	if err := IgnoreUnsupported(nil); err != nil {
		t.Fatalf("IgnoreUnsupported(nil) = %v, want nil", err)
	}
	if err := IgnoreUnsupported(ErrUnsupported); err != nil {
		t.Fatalf("IgnoreUnsupported(ErrUnsupported) = %v, want nil", err)
	}
	if err := IgnoreUnsupported(
		errors.New("feature is not supported here"),
	); err != nil {
		t.Fatalf("IgnoreUnsupported(not supported) = %v, want nil", err)
	}
	want := errors.New("other")
	if err := IgnoreUnsupported(want); !errors.Is(err, want) {
		t.Fatalf("IgnoreUnsupported(other) = %v, want %v", err, want)
	}
}

func TestControlAndGetFd(t *testing.T) {
	if err := Control(
		struct{}{},
		func(uintptr) {},
	); !errors.Is(
		err,
		ErrUnsupported,
	) {
		t.Fatalf("Control(unsupported) = %v, want ErrUnsupported", err)
	}
	fd, err := GetFd(struct{}{})
	if !errors.Is(err, ErrUnsupported) || fd != NOFD {
		t.Fatalf(
			"GetFd(unsupported) = %d, %v, want NOFD ErrUnsupported",
			fd,
			err,
		)
	}

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer conn.Close()
	var called bool
	if err := Control(conn, func(fd uintptr) {
		called = true
		if int(fd) == NOFD {
			t.Fatalf("fd = NOFD")
		}
	}); err != nil {
		t.Fatalf("Control(udp) error = %v", err)
	}
	if !called {
		t.Fatal("Control callback was not called")
	}
	fd, err = GetFd(conn)
	if err != nil || fd == NOFD {
		t.Fatalf("GetFd(udp) = %d, %v, want valid fd nil", fd, err)
	}
}

func TestLinuxSocketOptions(t *testing.T) {
	support := CheckSupport()
	if !support.BufSize || !support.RoutingMark || !support.BindToInterface ||
		!support.TCPUserTimeout || !support.TCPRtt {
		t.Fatalf("CheckSupport() = %#v, want all true on linux", support)
	}

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer conn.Close()
	if err := SetBufSize(conn, 4096); err != nil {
		t.Fatalf("SetBufSize error = %v", err)
	}
	recv, send, err := GetBuffSize(conn)
	if err != nil {
		t.Fatalf("GetBuffSize error = %v", err)
	}
	if recv <= 0 || send <= 0 {
		t.Fatalf("GetBuffSize = %d/%d, want positive sizes", recv, send)
	}
	if err := SetRoutingMark(conn, FwmarkIstio); err != nil {
		t.Fatalf("SetRoutingMark error = %v", err)
	}
	if _, err := GetRoutingMark(conn); err != nil {
		t.Fatalf("GetRoutingMark error = %v", err)
	}
}

func TestLinuxTCPOptions(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP error = %v", err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case err := <-errs:
		t.Fatalf("AcceptTCP error = %v", err)
	case server = <-accepted:
		defer server.Close()
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP timed out")
	}

	if err := SetTCPTimeout(client, time.Second); err != nil {
		t.Fatalf("SetTCPTimeout error = %v", err)
	}
	if _, err := GetTCPRTT(client); err != nil {
		t.Fatalf("GetTCPRTT(client) error = %v", err)
	}
	if err := SetBindToInterface(
		client,
		&gonnect.LiteralInterface{NameVal: "lo"},
	); err != nil {
		t.Logf(
			"SetBindToInterface(lo) unsupported in this environment: %v",
			err,
		)
	}
}
