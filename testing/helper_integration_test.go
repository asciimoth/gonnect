package testing_test

import (
	"context"
	"net"
	"sync"
	stdtesting "testing"
	"time"

	"github.com/asciimoth/gonnect"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestRunSimpleHTTPTestWithNativeNetwork(t *stdtesting.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	var d net.Dialer
	gt.RunSimpleHTTPTest(t, ln, d.DialContext)
}

func TestRunTCPPingPongTestWithNativeNetwork(t *stdtesting.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	var d net.Dialer
	gt.RunTCPPingPongTest(t, ln, func(addr net.Addr) (net.Conn, error) {
		return d.DialContext(
			context.Background(),
			addr.Network(),
			addr.String(),
		)
	})
}

func TestRunNetworkHelpersForNativeNetworks(t *stdtesting.T) {
	pair := gt.NetAddrPair{
		Network: gonnect.NativeConfig{}.Build(),
		Addr:    "127.0.0.1:0",
	}

	gt.RunTcpPingPongForNetworks(t, pair, pair)
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestRunNetworkErrorComplianceTestsWithNativeNetwork(t *stdtesting.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return gonnect.NativeConfig{}.Build()
	})
}

func TestRunStoppableNetworkTestsWithDetachedLoopback(t *stdtesting.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		base := gonnect.NewLoopbackNetwork()
		base.AllowAnyHost = true
		return gonnect.DetachNetwork(base, nil, nil)
	}, "127.0.0.1:0")
}

func TestRunUDPPingPongTestWithNativeNetwork(t *stdtesting.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer server.Close()

	gt.RunUDPPingPongTest(
		t,
		server,
		func(addr net.Addr) (gonnect.PacketConn, error) {
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				t.Fatalf("server addr type = %T, want *net.UDPAddr", addr)
			}
			return net.DialUDP("udp", nil, udpAddr)
		},
		2,
		2,
		100*time.Millisecond,
		time.Millisecond,
		5,
		0,
		2*time.Second,
	)
}

func TestRunUdpPingPongForNetworksUsesEachSideAddress(t *stdtesting.T) {
	a := &recordListenUDPNetwork{Network: gonnect.NativeConfig{}.Build()}
	b := &recordListenUDPNetwork{Network: gonnect.NativeConfig{}.Build()}

	pairA := gt.NetAddrPair{Network: a, Addr: "127.0.0.1:0"}
	pairB := gt.NetAddrPair{Network: b, Addr: "localhost:0"}

	gt.RunUdpPingPongForNetworks(t, pairA, pairB)

	if got := a.listenUDPAddr(); got != pairA.Addr {
		t.Fatalf("network A ListenUDP addr = %q, want %q", got, pairA.Addr)
	}
	if got := b.listenUDPAddr(); got != pairB.Addr {
		t.Fatalf("network B ListenUDP addr = %q, want %q", got, pairB.Addr)
	}
}

type recordListenUDPNetwork struct {
	gonnect.Network

	mu   sync.Mutex
	addr string
}

func (n *recordListenUDPNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	n.mu.Lock()
	n.addr = laddr
	n.mu.Unlock()

	return n.Network.ListenUDP(ctx, network, laddr)
}

func (n *recordListenUDPNetwork) listenUDPAddr() string {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.addr
}
