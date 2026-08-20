package sniffer_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestSnifferAccessorsLifecycleAndDelegates(t *testing.T) {
	ctx := context.Background()
	loop := gonnect.NewLoopbackNetwork()
	loop.AllowAnyHost = true
	t.Cleanup(func() { _ = loop.Close() })

	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs: []gonnect.Network{loop},
		Classifiers: []sniffer.Factory{
			sniffer.PrefixFactory([]byte("prefix")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = middleware.Close() })

	if middleware.IsNative() {
		t.Fatal("Sniffer reported native")
	}
	if got := middleware.Outputs(); len(got) != 1 || got[0] != loop {
		t.Fatalf("Outputs() = %v, want wrapped loopback", got)
	}
	if got := middleware.Classifiers(); len(got) != 1 {
		t.Fatalf("Classifiers() length = %d, want 1", len(got))
	}
	if up, err := middleware.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, err)
	}
	if err := middleware.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if unsubscribe, err := middleware.SubscribeCloser(
		noopCloser{},
	); err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	} else {
		unsubscribe()
	}
	if unsubscribe, err := middleware.SubscribeUpDown(
		noopUpDown{},
	); err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	} else {
		unsubscribe()
	}

	listener, err := middleware.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	_ = listener.Close()

	tcpListener, err := middleware.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	_ = tcpListener.Close()

	udp, err := middleware.ListenUDP(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = udp.Close() }()

	packet, err := middleware.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	_ = packet.Close()

	packetCfg, err := middleware.ListenPacketConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenPacketConfig() error = %v", err)
	}
	_ = packetCfg.Close()

	udpCfg, err := middleware.ListenUDPConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenUDPConfig() error = %v", err)
	}
	_ = udpCfg.Close()

	mcast, err := middleware.ListenMulticastUDP(
		ctx,
		"udp6",
		"[ff02::1]:0",
		gonnect.MulticastOptions{},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP() error = %v", err)
	}
	_ = mcast.Close()

	packetDial, err := middleware.PacketDial(
		ctx,
		"udp",
		udp.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("PacketDial() error = %v", err)
	}
	_ = packetDial.Close()

	dialUDP, err := middleware.DialUDP(ctx, "udp", "", udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	_ = dialUDP.Close()

	_, _ = middleware.LookupIP(ctx, "ip", "localhost")
	_, _ = middleware.LookupIPAddr(ctx, "localhost")
	_, _ = middleware.LookupNetIP(ctx, "ip", "localhost")
	_, _ = middleware.LookupHost(ctx, "localhost")
	_, _ = middleware.LookupAddr(ctx, "127.0.0.1")
	_, _ = middleware.LookupCNAME(ctx, "localhost")
	_, _ = middleware.LookupPort(ctx, "tcp", "http")
	_, _ = middleware.LookupNS(ctx, "localhost")
	_, _ = middleware.LookupMX(ctx, "localhost")
	_, _, _ = middleware.LookupSRV(ctx, "service", "tcp", "localhost")
	_, _ = middleware.LookupTXT(ctx, "localhost")
	_, _ = middleware.Interfaces()
	_, _ = middleware.InterfaceAddrs()
	_, _ = middleware.InterfaceMulticastAddrs()
	_, _ = middleware.InterfacesByIndex(1)
	_, _ = middleware.InterfacesByName("lo")

	if err := middleware.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if up, err := middleware.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false, nil", up, err)
	}
	if err := middleware.Up(); err != nil {
		t.Fatalf("Up() after Down error = %v", err)
	}
	if err := middleware.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := middleware.Up(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Up() after Close error = %v, want net.ErrClosed", err)
	}
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

type noopUpDown struct{}

func (noopUpDown) Up() error { return nil }

func (noopUpDown) Down() error { return nil }

func (noopUpDown) IsUp() (bool, error) { return true, nil }
