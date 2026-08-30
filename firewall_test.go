package gonnect_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestFirewallConfigMatchingAndClone(t *testing.T) {
	cfg := &gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{
			{Network: "tcp", Ports: []uint16{80}},
			{Network: "udp", Hosts: []string{"10.0.0.0/8"}},
			{
				Network: "tcp6",
				Hosts:   []string{"*.example.com"},
				PortRanges: []gonnect.FirewallPortRange{{
					First: 8000,
					Last:  9000,
				}},
			},
		},
		Include: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"TRUSTED.EXAMPLE.COM."},
			Ports:   []uint16{443},
		}},
	}

	tests := []struct {
		name    string
		network string
		address string
		blocked bool
	}{
		{"TCP generic family", "tcp4", "192.0.2.1:80", true},
		{"TCP service name", "tcp", "192.0.2.1:http", true},
		{"TCP other port", "tcp", "192.0.2.1:81", false},
		{"UDP subnet", "udp6", "10.2.3.4:65535", true},
		{"UDP outside subnet", "udp", "192.0.2.1:53", false},
		{"host wildcard and range", "tcp6", "api.example.com:8500", true},
		{"host wildcard wrong family", "tcp4", "api.example.com:8500", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cfg.BlocksOutgoing(
				test.network,
				test.address,
			); got != test.blocked {
				t.Fatalf("BlocksOutgoing() = %v, want %v", got, test.blocked)
			}
		})
	}
	if !cfg.AllowsIncoming("tcp4", "trusted.example.com:443") {
		t.Fatal("AllowsIncoming() = false, want true")
	}
	if cfg.AllowsIncoming("tcp", "trusted.example.com:80") {
		t.Fatal("AllowsIncoming() = true for the wrong local port")
	}
	if !(&gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
		Network: "ip4",
	}}}).BlocksOutgoing("udp4", "192.0.2.1:53") {
		t.Fatal("ip4 rule did not match UDP over IPv4")
	}

	clone := cfg.Clone()
	cfg.Exclude[0].Ports[0] = 81
	cfg.Include[0].Hosts[0] = "changed.example.com"
	if !clone.BlocksOutgoing("tcp", "192.0.2.1:80") {
		t.Fatal("Clone changed after source mutation")
	}
	if !clone.AllowsIncoming("tcp", "trusted.example.com:443") {
		t.Fatal("Clone host changed after source mutation")
	}
	clone.Exclude[0].Ports[0] = 82
	if cfg.Exclude[0].Ports[0] != 81 {
		t.Fatal("Source changed after clone mutation")
	}
}

func TestFirewallConfigTypedIPMatching(t *testing.T) {
	cfg := (&gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{
			{
				Network: "tcp4",
				Hosts:   []string{"192.0.2.0/24"},
				Ports:   []uint16{443},
			},
			{Network: "ip:47", Hosts: []string{"2001:db8::1"}},
			{Network: "icmp", Hosts: []string{"*"}},
		},
		Include: []gonnect.FirewallRule{{
			Network: "udp6",
			Hosts:   []string{"2001:db8::/32"},
			Ports:   []uint16{53},
		}},
	}).Optimize()

	if !cfg.BlocksOutgoingAddrPort(
		"tcp4",
		netip.MustParseAddrPort("192.0.2.4:443"),
	) {
		t.Fatal("BlocksOutgoingAddrPort() did not match IPv4 endpoint")
	}
	if !cfg.BlocksOutgoingIP(
		6,
		netip.MustParseAddrPort("192.0.2.4:443"),
	) {
		t.Fatal("BlocksOutgoingIP() did not match TCP/IPv4 packet")
	}
	if cfg.BlocksOutgoingIP(
		6,
		netip.MustParseAddrPort("[2001:db8::4]:443"),
	) {
		t.Fatal("BlocksOutgoingIP() matched TCP/IPv6 against tcp4")
	}
	if !cfg.BlocksOutgoingIP(
		47,
		netip.MustParseAddrPort("[2001:db8::1]:0"),
	) {
		t.Fatal("BlocksOutgoingIP() did not match generic protocol rule")
	}
	if !cfg.BlocksOutgoingIP(
		1,
		netip.MustParseAddrPort("192.0.2.9:0"),
	) || !cfg.BlocksOutgoingIP(
		58,
		netip.MustParseAddrPort("[2001:db8::9]:0"),
	) {
		t.Fatal("BlocksOutgoingIP() did not match ICMP protocol family")
	}
	if !cfg.AllowsIncomingAddrPort(
		"udp6",
		netip.MustParseAddrPort("[2001:db8::2]:53"),
	) || !cfg.AllowsIncomingIP(
		17,
		netip.MustParseAddrPort("[2001:db8::2]:53"),
	) {
		t.Fatal("typed incoming match did not permit UDP/IPv6 packet")
	}
}

func TestFirewallConfigIncomingLocalHosts(t *testing.T) {
	cfg := &gonnect.FirewallConfig{Include: []gonnect.FirewallRule{
		{
			Network:    "tcp",
			Hosts:      []string{"trusted.example"},
			LocalHosts: []string{"SERVICE.EXAMPLE.", "192.0.2.0/24"},
			Ports:      []uint16{443},
		},
		{
			Network:    "udp6",
			Hosts:      []string{"2001:db8:2::/48"},
			LocalHosts: []string{"2001:db8:1::/48"},
			Ports:      []uint16{53},
		},
	}}

	if !cfg.AllowsIncoming(
		"tcp4",
		"trusted.example:50000",
		"service.example:443",
	) {
		t.Fatal("hostname local destination did not match")
	}
	if !cfg.AllowsIncoming(
		"tcp4",
		"trusted.example:50000",
		"192.0.2.8:443",
	) {
		t.Fatal("CIDR local destination did not match")
	}
	if cfg.AllowsIncoming(
		"tcp4",
		"trusted.example:50000",
		"198.51.100.8:443",
	) {
		t.Fatal("wrong local destination matched")
	}
	if cfg.AllowsIncoming("tcp4", "trusted.example:443") {
		t.Fatal("local selector matched without a local endpoint")
	}

	peer := netip.MustParseAddrPort("[2001:db8:2::8]:50000")
	local := netip.MustParseAddrPort("[2001:db8:1::8]:53")
	if !cfg.AllowsIncomingAddrPort("udp6", peer, local) ||
		!cfg.AllowsIncomingIP(17, peer, local) {
		t.Fatal("typed local destination did not match")
	}
	wrongLocal := netip.MustParseAddrPort("[2001:db8:3::8]:53")
	if cfg.AllowsIncomingAddrPort("udp6", peer, wrongLocal) ||
		cfg.AllowsIncomingIP(17, peer, wrongLocal) {
		t.Fatal("wrong typed local destination matched")
	}

	clone := cfg.Clone()
	cfg.Include[0].LocalHosts[0] = "changed.example"
	if !clone.AllowsIncoming(
		"tcp4",
		"trusted.example:50000",
		"service.example:443",
	) {
		t.Fatal("Clone local host changed after source mutation")
	}

	exclude := (&gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
		Network:    "tcp",
		Hosts:      []string{"blocked.example"},
		LocalHosts: []string{"ignored.example"},
	}}}).Optimize()
	if !exclude.BlocksOutgoing("tcp", "blocked.example:443") ||
		len(exclude.Exclude[0].LocalHosts) != 0 {
		t.Fatal("outgoing rule did not ignore its local selector")
	}
}

func TestFirewallCachedReverseDNSHostnameSelectors(t *testing.T) {
	blockedAddr := netip.MustParseAddr("192.0.2.10")
	blockedIPv6 := netip.MustParseAddr("2001:db8::10")
	peerAddr := netip.MustParseAddr("198.51.100.20")
	localAddr := netip.MustParseAddr("203.0.113.53")
	cache := newFirewallTestDNSCache(map[netip.Addr][]string{
		blockedAddr: {"other.test.", "API.Example.Test."},
		blockedIPv6: {"ipv6.example.test."},
		peerAddr:    {"TRUSTED.Example.Test."},
		localAddr:   {"Service.Example.Test."},
	})
	cfg := (&gonnect.FirewallConfig{
		DNSCache: cache,
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"*.example.test"},
			Ports:   []uint16{443},
		}},
		Include: []gonnect.FirewallRule{{
			Network:    "udp",
			Hosts:      []string{"trusted.example.test"},
			LocalHosts: []string{"service.example.test"},
			Ports:      []uint16{53},
		}},
	}).Optimize()

	blocked := netip.AddrPortFrom(blockedAddr, 443)
	if !cfg.BlocksOutgoing("tcp4", blocked.String()) ||
		!cfg.BlocksOutgoingAddrPort("tcp4", blocked) ||
		!cfg.BlocksOutgoingIP(6, blocked) {
		t.Fatal("cached hostname did not match numeric outgoing endpoints")
	}
	if got := cache.callsFor(blockedAddr); got != 3 {
		t.Fatalf("blocked address cache calls = %d, want 3", got)
	}
	blocked6 := netip.AddrPortFrom(blockedIPv6, 443)
	if !cfg.BlocksOutgoingAddrPort("tcp6", blocked6) ||
		!cfg.BlocksOutgoingIP(6, blocked6) {
		t.Fatal("cached hostname did not match a numeric IPv6 endpoint")
	}

	peer := netip.AddrPortFrom(peerAddr, 40000)
	local := netip.AddrPortFrom(localAddr, 53)
	if !cfg.AllowsIncoming(
		"udp4",
		peer.String(),
		local.String(),
	) || !cfg.AllowsIncomingAddrPort("udp4", peer, local) ||
		!cfg.AllowsIncomingIP(17, peer, local) {
		t.Fatal(
			"cached peer and local hostnames did not allow incoming traffic",
		)
	}
	if got := cache.callsFor(peerAddr); got != 3 {
		t.Fatalf("peer address cache calls = %d, want 3", got)
	}
	if got := cache.callsFor(localAddr); got != 3 {
		t.Fatalf("local address cache calls = %d, want 3", got)
	}

	withoutCache := cfg.Clone()
	withoutCache.DNSCache = nil
	if withoutCache.BlocksOutgoingAddrPort("tcp4", blocked) {
		t.Fatal("hostname selector matched a numeric endpoint without a cache")
	}

	directCfg := (&gonnect.FirewallConfig{
		DNSCache: cache,
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"192.0.2.10", "*.example.test"},
			Ports:   []uint16{443},
		}},
	}).Optimize()
	before := cache.callsFor(blockedAddr)
	if !directCfg.BlocksOutgoingAddrPort("tcp4", blocked) {
		t.Fatal("direct IP selector did not match")
	}
	if directCfg.BlocksOutgoingAddrPort(
		"tcp4",
		netip.AddrPortFrom(blockedAddr, 80),
	) {
		t.Fatal("wrong port matched")
	}
	if got := cache.callsFor(blockedAddr); got != before {
		t.Fatalf("unnecessary cache calls = %d, want %d", got, before)
	}

	firewall := gonnect.NewFirewall(&gonnect.RejectNetwork{}, cfg)
	if _, err := firewall.DialTCP(
		context.Background(),
		"tcp4",
		"",
		blocked.String(),
	); !errors.Is(err, gonnect.ErrFirewallDenied) {
		t.Fatalf("DialTCP() error = %v, want ErrFirewallDenied", err)
	}
}

func TestFirewallOptimizesInstalledConfig(t *testing.T) {
	source := &gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{
		{
			Network: " TCP ",
			Hosts:   []string{"API.EXAMPLE."},
			Ports:   []uint16{80},
		},
		{
			Network: "tcp",
			Hosts:   []string{"api.example"},
			Ports:   []uint16{81},
		},
	}}
	firewall := gonnect.NewFirewall(gonnect.NewLoopbackNetwork(), source)
	defer closeFirewallTestResource(firewall)

	active := firewall.GetConfig()
	if len(active.Exclude) != 1 ||
		len(active.Exclude[0].PortRanges) != 1 ||
		active.Exclude[0].PortRanges[0] != (gonnect.FirewallPortRange{
			First: 80,
			Last:  81,
		}) {
		t.Fatalf("installed config was not optimized: %#v", active.Exclude)
	}
	if source.Exclude[0].Network != " TCP " {
		t.Fatal("NewFirewall modified its source config")
	}
}

func TestFirewallTCPPolicySwapAndLifecycle(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	firewall := gonnect.NewFirewall(backend, nil)
	defer closeFirewallTestResource(firewall)

	if firewall.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	if gonnect.GetWrapped(firewall) != backend {
		t.Fatal("GetWrapped() did not return the backend")
	}
	up, err := firewall.IsUp()
	if err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true, nil", up, err)
	}

	listener, err := firewall.ListenTCP(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer closeFirewallTestResource(listener)
	port := firewallTestPort(t, listener.Addr())

	blockedClient, err := backend.DialTCP(
		ctx,
		"tcp4",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("blocked DialTCP() error = %v", err)
	}
	defer closeFirewallTestResource(blockedClient)

	accepted := make(chan gonnect.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, acceptError := listener.AcceptTCP()
		if acceptError != nil {
			acceptErr <- acceptError
			return
		}
		accepted <- conn
	}()

	deadline := time.Now().Add(time.Second)
	_ = blockedClient.SetReadDeadline(deadline)
	if _, err := blockedClient.Read(
		make([]byte, 1),
	); !errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) {
		t.Fatalf(
			"blocked accepted connection read error = %v, want closed",
			err,
		)
	}

	cfg := &gonnect.FirewallConfig{Include: []gonnect.FirewallRule{{
		Network:    "tcp",
		Hosts:      []string{"127.0.0.1"},
		LocalHosts: []string{"127.0.0.1"},
		Ports:      []uint16{port},
	}}}
	firewall.SetConfig(cfg)
	cfg.Include[0].Ports[0] = port + 1

	allowedClient, err := backend.DialTCP(
		ctx,
		"tcp4",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("allowed DialTCP() error = %v", err)
	}
	defer closeFirewallTestResource(allowedClient)
	select {
	case conn := <-accepted:
		defer closeFirewallTestResource(conn)
	case err := <-acceptErr:
		t.Fatalf("AcceptTCP() error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP() did not return the included connection")
	}

	active := firewall.GetConfig()
	active.Include[0].Ports[0] = port + 2
	if firewall.GetConfig().Include[0].Ports[0] != port {
		t.Fatal("GetConfig() returned shared configuration data")
	}

	denyDial := &gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
		Network: "tcp",
		Ports:   []uint16{port},
	}}}
	firewall.SetConfig(denyDial)
	if _, err := firewall.DialTCP(
		ctx,
		"tcp4",
		"",
		listener.Addr().String(),
	); !errors.Is(
		err,
		gonnect.ErrFirewallDenied,
	) {
		t.Fatalf("DialTCP() error = %v, want ErrFirewallDenied", err)
	}

	subscriber := &firewallTestUpDown{}
	unsubscribe, err := firewall.SubscribeUpDown(subscriber)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribe()
	if err := firewall.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if subscriber.downs != 1 {
		t.Fatalf("subscriber Down calls = %d, want 1", subscriber.downs)
	}
	if err := firewall.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if subscriber.ups != 1 {
		t.Fatalf("subscriber Up calls = %d, want 1", subscriber.ups)
	}
}

func TestFirewallUDPResponsesAndOutgoingSwap(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	defer closeFirewallTestResource(backend)
	firewall := gonnect.NewFirewall(backend, nil)

	server, err := firewall.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(server)
	client, err := backend.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(client)
	attacker, err := backend.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("attacker ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(attacker)

	if _, err := attacker.WriteTo(
		[]byte("unsolicited"),
		server.LocalAddr(),
	); err != nil {
		t.Fatalf("unsolicited WriteTo() error = %v", err)
	}
	if _, err := server.WriteTo(
		[]byte("request"),
		client.LocalAddr(),
	); err != nil {
		t.Fatalf("request WriteTo() error = %v", err)
	}
	buf := make([]byte, 64)
	n, peer, err := client.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "request" {
		t.Fatalf("client ReadFrom() = %q, %v, want request", buf[:n], err)
	}
	if _, err := client.WriteTo([]byte("response"), peer); err != nil {
		t.Fatalf("response WriteTo() error = %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "response" {
		t.Fatalf("server ReadFrom() = %q, %v, want response", buf[:n], err)
	}

	clientPort := firewallTestPort(t, client.LocalAddr())
	firewall.SetConfig(&gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
		Network: "udp",
		Ports:   []uint16{clientPort},
	}}})
	if _, err := server.WriteTo(
		[]byte("blocked"),
		client.LocalAddr(),
	); !errors.Is(
		err,
		gonnect.ErrFirewallDenied,
	) {
		t.Fatalf("WriteTo() error = %v, want ErrFirewallDenied", err)
	}
}

func TestFirewallMiddlewareChain(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	defer closeFirewallTestResource(backend)
	listener, err := backend.ListenTCP(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer closeFirewallTestResource(listener)
	port := firewallTestPort(t, listener.Addr())

	remapper := gonnect.NewRemapper(backend, []gonnect.RemapRule{{
		Filter: gonnect.RemapAddressFilter(
			gonnect.FilterFromString("service.test:80").Filter,
		),
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddrPort,
		Addr:     "127.0.0.1",
		Port:     strconv.Itoa(int(port)),
	}})
	chain := gonnect.DetachNetwork(
		gonnect.NewFirewall(
			remapper,
			&gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{{
				Network: "tcp",
				Hosts:   []string{"blocked.test"},
			}}},
		),
		nil,
		nil,
	)
	defer closeFirewallTestResource(chain)

	if _, err := chain.DialTCP(
		ctx,
		"tcp4",
		"",
		"blocked.test:80",
	); !errors.Is(
		err,
		gonnect.ErrFirewallDenied,
	) {
		t.Fatalf("blocked chain DialTCP() error = %v", err)
	}
	client, err := chain.DialTCP(ctx, "tcp4", "", "service.test:80")
	if err != nil {
		t.Fatalf("allowed chain DialTCP() error = %v", err)
	}
	defer closeFirewallTestResource(client)
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP() error = %v", err)
	}
	defer closeFirewallTestResource(server)
}

func TestFirewallNetworkEntryPointVariants(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	defer closeFirewallTestResource(backend)
	firewall := gonnect.NewFirewall(backend, &gonnect.FirewallConfig{
		Include: []gonnect.FirewallRule{{Network: "ip"}},
	})
	if firewall.GetNetwork() != backend {
		t.Fatal("GetNetwork() returned the wrong backend")
	}

	listener, err := firewall.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer closeFirewallTestResource(listener)
	client, err := firewall.Dial(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial(tcp4) error = %v", err)
	}
	defer closeFirewallTestResource(client)
	server, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer closeFirewallTestResource(server)

	packetListener, err := firewall.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer closeFirewallTestResource(packetListener)
	packetClient, err := firewall.PacketDial(
		ctx,
		"udp4",
		packetListener.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("PacketDial() error = %v", err)
	}
	defer closeFirewallTestResource(packetClient)
	if _, err := packetClient.Write([]byte("packet")); err != nil {
		t.Fatalf("PacketConn.Write() error = %v", err)
	}
	buf := make([]byte, 64)
	n, peer, err := packetListener.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "packet" {
		t.Fatalf("PacketConn.ReadFrom() = %q, %v", buf[:n], err)
	}
	if _, err := packetListener.WriteTo([]byte("reply"), peer); err != nil {
		t.Fatalf("PacketConn.WriteTo() error = %v", err)
	}
	n, err = packetClient.Read(buf)
	if err != nil || string(buf[:n]) != "reply" {
		t.Fatalf("PacketConn.Read() = %q, %v", buf[:n], err)
	}

	packetConfig, err := firewall.ListenPacketConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenPacketConfig() error = %v", err)
	}
	_ = packetConfig.Close()
	udpConfig, err := firewall.ListenUDPConfig(
		ctx,
		&gonnect.ListenConfig{},
		"udp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenUDPConfig() error = %v", err)
	}
	_ = udpConfig.Close()

	directUDP, err := backend.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("direct ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(directUDP)
	udpClient, err := firewall.DialUDP(
		ctx,
		"udp4",
		"",
		directUDP.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer closeFirewallTestResource(udpClient)
	if _, err := udpClient.Write([]byte("dial-udp")); err != nil {
		t.Fatalf("DialUDP Write() error = %v", err)
	}
	n, _, err = directUDP.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "dial-udp" {
		t.Fatalf("direct ReadFrom() = %q, %v", buf[:n], err)
	}

	genericUDP, err := firewall.Dial(
		ctx,
		"udp4",
		directUDP.LocalAddr().String(),
	)
	if err != nil {
		t.Fatalf("Dial(udp4) error = %v", err)
	}
	defer closeFirewallTestResource(genericUDP)
	if _, err := genericUDP.Write([]byte("generic-udp")); err != nil {
		t.Fatalf("generic UDP Write() error = %v", err)
	}
	n, _, err = directUDP.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "generic-udp" {
		t.Fatalf("generic UDP delivery = %q, %v", buf[:n], err)
	}
}

func TestFirewallUDPSpecializedMethods(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	defer closeFirewallTestResource(backend)
	firewall := gonnect.NewFirewall(backend, &gonnect.FirewallConfig{
		Include: []gonnect.FirewallRule{{Network: "udp"}},
	})
	server, err := firewall.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(server)
	client, err := backend.ListenUDP(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client ListenUDP() error = %v", err)
	}
	defer closeFirewallTestResource(client)
	serverAddr, err := net.ResolveUDPAddr("udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr(server) error = %v", err)
	}
	serverAddrPort := serverAddr.AddrPort()
	clientAddr, err := net.ResolveUDPAddr("udp4", client.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr(client) error = %v", err)
	}
	clientAddrPort := clientAddr.AddrPort()
	buf := make([]byte, 64)
	oob := make([]byte, 64)

	_, _ = client.WriteToUDP([]byte("one"), serverAddr)
	n, _, err := server.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "one" {
		t.Fatalf("ReadFromUDPAddrPort() = %q, %v", buf[:n], err)
	}
	_, _ = client.WriteToUDPAddrPort([]byte("two"), serverAddrPort)
	n, _, _, _, err = server.ReadMsgUDP(buf, oob)
	if err != nil || string(buf[:n]) != "two" {
		t.Fatalf("ReadMsgUDP() = %q, %v", buf[:n], err)
	}
	_, _, _ = client.WriteMsgUDP([]byte("three"), nil, serverAddr)
	n, _, _, _, err = server.ReadMsgUDPAddrPort(buf, oob)
	if err != nil || string(buf[:n]) != "three" {
		t.Fatalf("ReadMsgUDPAddrPort() = %q, %v", buf[:n], err)
	}
	_, _, _ = client.WriteMsgUDPAddrPort([]byte("four"), nil, serverAddrPort)
	n, err = server.Read(buf)
	if err != nil || string(buf[:n]) != "four" {
		t.Fatalf("Read() = %q, %v", buf[:n], err)
	}

	if _, err := server.WriteToUDP([]byte("a"), clientAddr); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
	_, _, _ = client.ReadFromUDP(buf)
	if _, err := server.WriteToUDPAddrPort(
		[]byte("b"),
		clientAddrPort,
	); err != nil {
		t.Fatalf("WriteToUDPAddrPort() error = %v", err)
	}
	_, _, _ = client.ReadFromUDP(buf)
	if _, _, err := server.WriteMsgUDP(
		[]byte("c"),
		nil,
		clientAddr,
	); err != nil {
		t.Fatalf("WriteMsgUDP() error = %v", err)
	}
	_, _, _ = client.ReadFromUDP(buf)
	if _, _, err := server.WriteMsgUDPAddrPort(
		[]byte("d"),
		nil,
		clientAddrPort,
	); err != nil {
		t.Fatalf("WriteMsgUDPAddrPort() error = %v", err)
	}
	_, _, _ = client.ReadFromUDP(buf)
}

func TestFirewallMulticastMethods(t *testing.T) {
	ctx := context.Background()
	backend := gonnect.NewLoopbackNetwork()
	defer closeFirewallTestResource(backend)
	firewall := gonnect.NewFirewall(backend, nil)
	conn, err := firewall.ListenMulticastUDP(
		ctx,
		"udp6",
		"[::]:0",
		gonnect.MulticastOptions{ControlFlags: gonnect.ControlDst},
	)
	if err != nil {
		t.Fatalf("ListenMulticastUDP() error = %v", err)
	}
	defer closeFirewallTestResource(conn)
	groupPort := firewallTestPort(t, conn.LocalAddr())
	group := &net.UDPAddr{
		IP:   net.ParseIP("ff02::1234"),
		Port: int(groupPort),
		Zone: "lo",
	}
	firewall.SetConfig(&gonnect.FirewallConfig{Include: []gonnect.FirewallRule{{
		Network: "udp",
		Hosts:   []string{"fe80::1"},
		Ports:   []uint16{groupPort},
	}}})
	if err := conn.JoinGroup(nil, group); err != nil {
		t.Fatalf("JoinGroup() error = %v", err)
	}
	defer func() { _ = conn.LeaveGroup(nil, group) }()
	if _, err := conn.WriteToControl(
		[]byte("control"),
		gonnect.ControlMessage{Dst: group},
		group,
	); err != nil {
		t.Fatalf("WriteToControl() error = %v", err)
	}
	buf := make([]byte, 64)
	n, _, _, err := conn.ReadFromControl(buf)
	if err != nil || string(buf[:n]) != "control" {
		t.Fatalf("ReadFromControl() = %q, %v", buf[:n], err)
	}
	if _, err := conn.WriteTo([]byte("plain"), group); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	n, _, err = conn.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "plain" {
		t.Fatalf("ReadFrom() = %q, %v", buf[:n], err)
	}
}

type firewallTestUpDown struct {
	mu         sync.Mutex
	ups, downs int
}

type firewallTestDNSCache struct {
	mu    sync.Mutex
	names map[netip.Addr][]string
	calls map[netip.Addr]int
}

func newFirewallTestDNSCache(
	names map[netip.Addr][]string,
) *firewallTestDNSCache {
	return &firewallTestDNSCache{
		names: names,
		calls: make(map[netip.Addr]int),
	}
}

func (c *firewallTestDNSCache) ReverseDNSNames(
	addr netip.Addr,
	_ time.Time,
) []string {
	addr = addr.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[addr]++
	return append([]string(nil), c.names[addr]...)
}

func (c *firewallTestDNSCache) callsFor(addr netip.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[addr.Unmap()]
}

func (u *firewallTestUpDown) Up() error {
	u.mu.Lock()
	u.ups++
	u.mu.Unlock()
	return nil
}

func (u *firewallTestUpDown) Down() error {
	u.mu.Lock()
	u.downs++
	u.mu.Unlock()
	return nil
}

func (u *firewallTestUpDown) IsUp() (bool, error) { return true, nil }

func firewallTestPort(t *testing.T, addr net.Addr) uint16 {
	t.Helper()
	_, service, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", addr, err)
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(%q) error = %v", service, err)
	}
	return uint16(port)
}

func closeFirewallTestResource(closer io.Closer) {
	_ = closer.Close()
}

var _ io.Closer = (*gonnect.Firewall)(nil)
