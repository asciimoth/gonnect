package tls_test

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"testing"

	"github.com/asciimoth/gonnect"
	gonnecttls "github.com/asciimoth/gonnect/tls"
)

func TestNetworkDelegatesNonTCPMethods(t *testing.T) {
	ctx := context.Background()
	loop := gonnect.NewLoopbackNetwork()
	loop.AllowAnyHost = true
	t.Cleanup(func() { _ = loop.Close() })

	ca, _ := testCA(t, "mitm.test")
	network, err := gonnecttls.NewNetwork(loop, ca, nil)
	if err != nil {
		t.Fatal(err)
	}

	if network.GetWrapped() != loop || network.GetNetwork() != loop {
		t.Fatal("wrapped network accessors returned wrong value")
	}
	if network.IsNative() {
		t.Fatal("TLS middleware reported native")
	}
	if up, err := network.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, err)
	}
	if err := network.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if unsubscribe, err := network.SubscribeCloser(noopCloser{}); err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	} else {
		unsubscribe()
	}
	if unsubscribe, err := network.SubscribeUpDown(noopUpDown{}); err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	} else {
		unsubscribe()
	}

	listener, err := network.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	_ = listener.Close()

	tcpListener, err := network.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	_ = tcpListener.Close()

	udp, err := network.ListenUDP(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = udp.Close() }()

	packet, err := network.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	_ = packet.Close()

	packetCfg, err := network.ListenPacketConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenPacketConfig() error = %v", err)
	}
	_ = packetCfg.Close()

	udpCfg, err := network.ListenUDPConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenUDPConfig() error = %v", err)
	}
	_ = udpCfg.Close()

	mcast, err := network.ListenMulticastUDP(
		ctx,
		"udp6",
		"[ff02::1]:0",
		gonnect.MulticastOptions{},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP() error = %v", err)
	}
	_ = mcast.Close()

	packetDial, err := network.PacketDial(ctx, "udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("PacketDial() error = %v", err)
	}
	_ = packetDial.Close()

	dialUDP, err := network.DialUDP(ctx, "udp", "", udp.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	_ = dialUDP.Close()

	_, _ = network.LookupIP(ctx, "ip", "localhost")
	_, _ = network.LookupIPAddr(ctx, "localhost")
	_, _ = network.LookupNetIP(ctx, "ip", "localhost")
	_, _ = network.LookupHost(ctx, "localhost")
	_, _ = network.LookupAddr(ctx, "127.0.0.1")
	_, _ = network.LookupCNAME(ctx, "localhost")
	_, _ = network.LookupPort(ctx, "tcp", "http")
	_, _ = network.LookupNS(ctx, "localhost")
	_, _ = network.LookupMX(ctx, "localhost")
	_, _, _ = network.LookupSRV(ctx, "service", "tcp", "localhost")
	_, _ = network.LookupTXT(ctx, "localhost")
	_, _ = network.Interfaces()
	_, _ = network.InterfaceAddrs()
	_, _ = network.InterfaceMulticastAddrs()
	_, _ = network.InterfacesByIndex(1)
	_, _ = network.InterfacesByName("lo")
}

func TestClientServerNetworkDelegatesNonTCPMethods(t *testing.T) {
	ctx := context.Background()
	loop := gonnect.NewLoopbackNetwork()
	loop.AllowAnyHost = true
	t.Cleanup(func() { _ = loop.Close() })

	network, err := gonnecttls.NewClientServerNetwork(
		loop,
		&stdtls.Config{MinVersion: stdtls.VersionTLS12},
		&stdtls.Config{MinVersion: stdtls.VersionTLS12},
	)
	if err != nil {
		t.Fatal(err)
	}

	if network.GetWrapped() != loop || network.GetNetwork() != loop {
		t.Fatal("wrapped network accessors returned wrong value")
	}
	if network.IsNative() {
		t.Fatal("client/server middleware reported native")
	}
	if up, err := network.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, err)
	}
	if err := network.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}

	udp, err := network.ListenUDP(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = udp.Close() }()

	packet, err := network.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	_ = packet.Close()

	_, _ = network.PacketDial(ctx, "udp", udp.LocalAddr().String())
	_, _ = network.DialUDP(ctx, "udp", "", udp.LocalAddr().String())
	_, _ = network.ListenPacketConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	_, _ = network.ListenUDPConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	if mcast, err := network.ListenMulticastUDP(
		ctx,
		"udp6",
		"[ff02::1]:0",
		gonnect.MulticastOptions{},
	); err == nil {
		_ = mcast.Close()
	} else {
		t.Fatalf("ListenMulticastUDP() error = %v", err)
	}
	_, _ = network.LookupIP(ctx, "ip", "localhost")
	_, _ = network.LookupIPAddr(ctx, "localhost")
	_, _ = network.LookupNetIP(ctx, "ip", "localhost")
	_, _ = network.LookupHost(ctx, "localhost")
	_, _ = network.LookupAddr(ctx, "127.0.0.1")
	_, _ = network.LookupCNAME(ctx, "localhost")
	_, _ = network.LookupPort(ctx, "tcp", "http")
	_, _ = network.LookupNS(ctx, "localhost")
	_, _ = network.LookupMX(ctx, "localhost")
	_, _, _ = network.LookupSRV(ctx, "service", "tcp", "localhost")
	_, _ = network.LookupTXT(ctx, "localhost")
	_, _ = network.Interfaces()
	_, _ = network.InterfaceAddrs()
	_, _ = network.InterfaceMulticastAddrs()
	_, _ = network.InterfacesByIndex(1)
	_, _ = network.InterfacesByName("lo")
}

func TestTerminatorUnsupportedMethods(t *testing.T) {
	ctx := context.Background()
	loop := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = loop.Close() })

	ca, _ := testCA(t, "terminator.test")
	terminator, err := gonnecttls.NewTerminator(loop, ca)
	if err != nil {
		t.Fatal(err)
	}
	if terminator.GetWrapped() != loop || terminator.GetNetwork() != loop {
		t.Fatal("wrapped network accessors returned wrong value")
	}
	if terminator.IsNative() {
		t.Fatal("terminator reported native")
	}
	if up, err := terminator.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, err)
	}

	checkUnsupported := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, gonnecttls.ErrTerminatorUnsupported) {
			t.Fatalf("%s error = %v, want ErrTerminatorUnsupported", name, err)
		}
	}

	_, err = terminator.Dial(ctx, "udp", "127.0.0.1:1")
	checkUnsupported("Dial udp", err)
	_, err = terminator.Listen(ctx, "tcp", "127.0.0.1:0")
	checkUnsupported("Listen", err)
	_, err = terminator.PacketDial(ctx, "udp", "127.0.0.1:1")
	checkUnsupported("PacketDial", err)
	_, err = terminator.ListenPacket(ctx, "udp", "127.0.0.1:0")
	checkUnsupported("ListenPacket", err)
	_, err = terminator.DialTCP(ctx, "udp", "", "127.0.0.1:1")
	checkUnsupported("DialTCP udp", err)
	_, err = terminator.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	checkUnsupported("ListenTCP", err)
	_, err = terminator.DialUDP(ctx, "udp", "", "127.0.0.1:1")
	checkUnsupported("DialUDP", err)
	_, err = terminator.ListenUDP(ctx, "udp", "127.0.0.1:0")
	checkUnsupported("ListenUDP", err)
	_, err = terminator.ListenPacketConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	checkUnsupported("ListenPacketConfig", err)
	_, err = terminator.ListenUDPConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp",
		"127.0.0.1:0",
	)
	checkUnsupported("ListenUDPConfig", err)
	_, err = terminator.ListenMulticastUDP(
		ctx,
		"udp",
		"224.0.0.1:9999",
		gonnect.MulticastOptions{},
	)
	checkUnsupported("ListenMulticastUDP", err)

	if _, err := terminator.LookupIP(
		ctx,
		"ip",
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupIP() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupIPAddr(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf(
			"LookupIPAddr() error = %v, want ErrTerminatorUnsupported",
			err,
		)
	}
	if _, err := terminator.LookupNetIP(
		ctx,
		"ip",
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupNetIP() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupHost(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupHost() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupAddr(
		ctx,
		"127.0.0.1",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupAddr() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupCNAME(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupCNAME() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupPort(
		ctx,
		"tcp",
		"http",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupPort() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupNS(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupNS() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupMX(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupMX() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, _, err := terminator.LookupSRV(
		ctx,
		"service",
		"tcp",
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupSRV() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.LookupTXT(
		ctx,
		"localhost",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("LookupTXT() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.Interfaces(); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf("Interfaces() error = %v, want ErrTerminatorUnsupported", err)
	}
	if _, err := terminator.InterfaceAddrs(); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf(
			"InterfaceAddrs() error = %v, want ErrTerminatorUnsupported",
			err,
		)
	}
	if _, err := terminator.InterfaceMulticastAddrs(); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf(
			"InterfaceMulticastAddrs() error = %v, want ErrTerminatorUnsupported",
			err,
		)
	}
	if _, err := terminator.InterfacesByIndex(
		1,
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf(
			"InterfacesByIndex() error = %v, want ErrTerminatorUnsupported",
			err,
		)
	}
	if _, err := terminator.InterfacesByName(
		"lo",
	); !errors.Is(
		err,
		gonnecttls.ErrTerminatorUnsupported,
	) {
		t.Fatalf(
			"InterfacesByName() error = %v, want ErrTerminatorUnsupported",
			err,
		)
	}
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

type noopUpDown struct{}

func (noopUpDown) Up() error { return nil }

func (noopUpDown) Down() error { return nil }

func (noopUpDown) IsUp() (bool, error) { return true, nil }
