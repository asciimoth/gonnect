package testing_test

import (
	"net"
	stdtesting "testing"
	"time"

	"github.com/asciimoth/gonnect"
	gonnecttesting "github.com/asciimoth/gonnect/testing"
)

func TestRunUDPPingPongTestSingleRoundUsesClientSequence(t *stdtesting.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer server.Close()

	dial := func(addr net.Addr) (gonnect.PacketConn, error) {
		raddr, ok := addr.(*net.UDPAddr)
		if !ok {
			t.Fatalf("server addr type = %T, want *net.UDPAddr", addr)
		}
		return net.DialUDP(addr.Network(), nil, raddr)
	}

	gonnecttesting.RunUDPPingPongTest(
		t,
		server,
		dial,
		1,
		1,
		20*time.Millisecond,
		0,
		3,
		0,
		time.Second,
	)
}
