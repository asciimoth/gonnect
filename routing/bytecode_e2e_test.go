// nolint
package routing

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

func TestBytecodeRouterCfgE2EComplexRuleset(t *testing.T) {
	ctx := t.Context()
	const (
		tcp4Port = 34081
		tcp6Port = 34082
		udp4Port = 34083
	)

	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		Strings: []string{
			"127.0.0.1",
			"::1",
			"localhost",
		},
		Regexps: []*regexp.Regexp{
			regexp.MustCompile(`^127\.0\.0\.1$`),
			regexp.MustCompile(`^::1$`),
			regexp.MustCompile(`^local`),
		},
		IPv4Addrs: []uint32{
			ip4(127, 0, 0, 1),
		},
		IPv4Subnets: []IPv4Subnet{
			{Addr: ip4(127, 0, 0, 0), Bits: 8},
		},
		IPv6Addrs: []netip.Addr{
			netip.MustParseAddr("::1"),
		},
		IPv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("::1/128"),
		},
		DialTCP:   complexRouterDialTCP(tcp4Port, tcp6Port),
		ListenTCP: complexRouterListenTCP(tcp4Port, tcp6Port),
		DialUDP:   complexRouterDialUDP(udp4Port),
		RouteUDP:  complexRouterRouteUDP(udp4Port),
		Lookup:    complexRouterLookup(),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	r := gonnect.NewRouter()
	t.Cleanup(func() { _ = r.Close() })
	r.SetCfg(cfg)
	if err := r.Attach(2, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(2) error = %v", err)
	}
	if err := r.Attach(3, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(3) error = %v", err)
	}

	assertRouterTCPRoundTrip(
		t,
		ctx,
		r,
		"tcp4",
		"127.0.0.1:34081",
		"127.0.0.1:0",
		"tcp4-e2e",
	)
	assertRouterTCPRoundTrip(
		t,
		ctx,
		r,
		"tcp6",
		"[::1]:34082",
		"[::1]:0",
		"tcp6-e2e",
	)
	assertRouterUDPRoundTrip(t, ctx, r, udp4Port)

	hosts, err := r.LookupHost(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupHost(localhost) error = %v", err)
	}
	if len(hosts) == 0 {
		t.Fatal("LookupHost(localhost) returned no hosts")
	}
	if _, err := r.LookupHost(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupHost(example.invalid) succeeded, want drop/reject")
	}
}

func TestBytecodeRouterCfgE2EComplexRulesetFromLanguage(t *testing.T) {
	ctx := t.Context()
	const (
		tcp4Port = 34081
		tcp6Port = 34082
		udp4Port = 34083
	)

	rules, err := NewBytecodeRules(
		complexRouterDialTCPSrc(tcp4Port, tcp6Port),
		complexRouterListenTCPSrc(tcp4Port, tcp6Port),
		complexRouterDialUDPSrc(udp4Port),
		complexRouterRouteUDPSrc(udp4Port),
		complexRouterLookupSrc(),
	)
	if err != nil {
		t.Fatalf("NewBytecodeRules() error = %v", err)
	}
	cfg, err := NewBytecodeRouterCfg(rules)
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	r := gonnect.NewRouter()
	t.Cleanup(func() { _ = r.Close() })
	r.SetCfg(cfg)
	if err := r.Attach(2, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(2) error = %v", err)
	}
	if err := r.Attach(3, gonnect.NewLoopbackNetwok()); err != nil {
		t.Fatalf("Attach(3) error = %v", err)
	}

	assertRouterTCPRoundTrip(
		t,
		ctx,
		r,
		"tcp4",
		"127.0.0.1:34081",
		"127.0.0.1:0",
		"tcp4-e2e",
	)
	assertRouterTCPRoundTrip(
		t,
		ctx,
		r,
		"tcp6",
		"[::1]:34082",
		"[::1]:0",
		"tcp6-e2e",
	)
	assertRouterUDPRoundTrip(t, ctx, r, udp4Port)

	hosts, err := r.LookupHost(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupHost(localhost) error = %v", err)
	}
	if len(hosts) == 0 {
		t.Fatal("LookupHost(localhost) returned no hosts")
	}
	if _, err := r.LookupHost(ctx, "example.invalid"); err == nil {
		t.Fatal("LookupHost(example.invalid) succeeded, want drop/reject")
	}
}

func TestBytecodeSplitRouterE2EComplexRuleset(t *testing.T) {
	matcher := &testIPMatcher{
		rules: map[uint64]bool{99: true},
		info: &sysnet.NetInfo{
			Cgroup:    7,
			UID:       1000,
			GID:       1000,
			User:      "alice",
			RouteMark: -7,
			PID:       123,
		},
	}
	router, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher: matcher,
		Strings: []string{
			"192.0.2.2",
			"10.0.0.1",
			"2001:db8::2",
			"2001:db8::1",
			"alice",
		},
		Regexps: []*regexp.Regexp{
			regexp.MustCompile(`^192\.0\.2\.`),
			regexp.MustCompile(`^10\.0\.0\.`),
			regexp.MustCompile(`^2001:db8::`),
			regexp.MustCompile(`^ali`),
		},
		IPv4Addrs: []uint32{
			ip4(192, 0, 2, 2),
			ip4(10, 0, 0, 1),
		},
		IPv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(10, 0, 0, 0), Bits: 24},
		},
		IPv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::2"),
			netip.MustParseAddr("2001:db8::1"),
		},
		IPv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
		},
		Route: complexSplitRoute(),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	backend, peer := tun.Pipe(4, 1500, 3, 5)
	t.Cleanup(func() { _ = backend.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	s := tun.NewSplitter()
	t.Cleanup(func() { _ = s.Close() })
	s.SetRouter(router)
	f2 := s.Get(2)
	f3 := s.Get(3)
	if err := s.Attach(nativeTestTun{Tun: backend}); err != nil {
		t.Fatalf("Attach(native pipe) error = %v", err)
	}

	tcp4 := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)
	writeTunPacket(t, peer, tcp4)
	if got := readTunPacket(t, f2); !bytes.Equal(got, tcp4) {
		t.Fatalf("frontend 2 packet = %x, want %x", got, tcp4)
	}

	udp6 := ipv6UDPPacket(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		5353,
		53,
		[]byte{1, 2, 3, 4},
	)
	writeTunPacket(t, peer, udp6)
	if got := readTunPacket(t, f3); !bytes.Equal(got, udp6) {
		t.Fatalf("frontend 3 packet = %x, want %x", got, udp6)
	}

	writeTunPacket(t, peer, []byte{0x45, 0x00})
	assertNoTunPacket(t, f2)
	assertNoTunPacket(t, f3)

	if matcher.matchCalls == 0 {
		t.Fatal("IPMatcher.Match was not called for native packet")
	}
	if matcher.infoCalls == 0 {
		t.Fatal("IPMatcher.PktInfo was not called for native packet")
	}
	if matcher.locks == 0 || matcher.unlocks == 0 {
		t.Fatalf(
			"matcher locks = %d/%d, want nonzero",
			matcher.locks,
			matcher.unlocks,
		)
	}
}

func TestBytecodeSplitRouterE2EComplexRulesetFromLanguage(t *testing.T) {
	matcher := &testIPMatcher{
		rules: map[uint64]bool{99: true},
		info: &sysnet.NetInfo{
			Cgroup:    7,
			UID:       1000,
			GID:       1000,
			User:      "alice",
			RouteMark: -7,
			PID:       123,
		},
	}
	rules, err := NewSplitBytecodeRules(matcher, complexSplitRouteSrc())
	if err != nil {
		t.Fatalf("NewSplitBytecodeRules() error = %v", err)
	}
	router, err := NewBytecodeSplitRouter(rules)
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	backend, peer := tun.Pipe(4, 1500, 3, 5)
	t.Cleanup(func() { _ = backend.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	s := tun.NewSplitter()
	t.Cleanup(func() { _ = s.Close() })
	s.SetRouter(router)
	f2 := s.Get(2)
	f3 := s.Get(3)
	if err := s.Attach(nativeTestTun{Tun: backend}); err != nil {
		t.Fatalf("Attach(native pipe) error = %v", err)
	}

	tcp4 := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)
	writeTunPacket(t, peer, tcp4)
	if got := readTunPacket(t, f2); !bytes.Equal(got, tcp4) {
		t.Fatalf("frontend 2 packet = %x, want %x", got, tcp4)
	}

	udp6 := ipv6UDPPacket(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		5353,
		53,
		[]byte{1, 2, 3, 4},
	)
	writeTunPacket(t, peer, udp6)
	if got := readTunPacket(t, f3); !bytes.Equal(got, udp6) {
		t.Fatalf("frontend 3 packet = %x, want %x", got, udp6)
	}

	writeTunPacket(t, peer, []byte{0x45, 0x00})
	assertNoTunPacket(t, f2)
	assertNoTunPacket(t, f3)

	if matcher.matchCalls == 0 {
		t.Fatal("IPMatcher.Match was not called for native packet")
	}
	if matcher.infoCalls == 0 {
		t.Fatal("IPMatcher.PktInfo was not called for native packet")
	}
	if matcher.locks == 0 || matcher.unlocks == 0 {
		t.Fatalf(
			"matcher locks = %d/%d, want nonzero",
			matcher.locks,
			matcher.unlocks,
		)
	}
}

func TestBytecodeSplitRouterE2ENonNativeSkipsMatcher(t *testing.T) {
	matcher := &testIPMatcher{
		rules: map[uint64]bool{99: true},
		info:  &sysnet.NetInfo{UID: 1000},
	}
	router, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		Matcher: matcher,
		Route: append(
			append(
				append([]byte{OP_RULE}, param64Bytes(99)...),
				param64(OP_UID, 1000)...,
			),
			OP_OR, OP_SLOT, 4,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	backend, peer := tun.Pipe(1, 1500, 0, 0)
	t.Cleanup(func() { _ = backend.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	s := tun.NewSplitter()
	t.Cleanup(func() { _ = s.Close() })
	s.SetRouter(router)
	f4 := s.Get(4)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach(pipe) error = %v", err)
	}

	writeTunPacket(t, peer, ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		1,
		2,
	))
	assertNoTunPacket(t, f4)
	if matcher.matchCalls != 0 {
		t.Fatalf("non-native Match calls = %d, want 0", matcher.matchCalls)
	}
	if matcher.infoCalls != 0 {
		t.Fatalf("non-native PktInfo calls = %d, want 0", matcher.infoCalls)
	}
}

func complexRouterDialTCP(tcp4Port, tcp6Port int) []byte {
	code := []byte{OP_FALSE, OP_DROP}
	code = append(code, slotWhen(andAll(
		[]byte{OP_TRUE},
		[]byte{OP_TCP},
		[]byte{OP_NET4},
		notOp([]byte{OP_FQDN}),
		notOp([]byte{OP_LFQDN}),
		param16(OP_ADDR_S, 0),
		param16(OP_LADDR_S, 0),
		param16(OP_ADDR_RE, 0),
		param16(OP_LADDR_RE, 0),
		param16(OP_ADDR4, 0),
		param16(OP_LADDR4, 0),
		param16(OP_SNET4, 0),
		param16(OP_LSNET4, 0),
		param16(OP_PORT, uint16(tcp4Port)),
		param16(OP_LPORT, 0),
	), 2)...)
	code = append(code, slotWhen(andAll(
		[]byte{OP_NET6},
		[]byte{OP_TCP},
		orOp(param16(OP_ADDR6, 0), []byte{OP_FALSE}),
		param16(OP_LADDR6, 0),
		param16(OP_SNET6, 0),
		param16(OP_LSNET6, 0),
		param16(OP_ADDR_RE, 1),
		param16(OP_LADDR_RE, 1),
		param16(OP_PORT, uint16(tcp6Port)),
		param16(OP_LPORT, 0),
	), 3)...)
	return code
}

func complexRouterListenTCP(tcp4Port, tcp6Port int) []byte {
	code := []byte{OP_FALSE, OP_DROP}
	code = append(code, slotWhen(andAll(
		[]byte{OP_TCP},
		[]byte{OP_NET4},
		notOp([]byte{OP_LFQDN}),
		param16(OP_LADDR_S, 0),
		param16(OP_LADDR_RE, 0),
		param16(OP_LADDR4, 0),
		param16(OP_LSNET4, 0),
		param16(OP_LPORT, uint16(tcp4Port)),
	), 2)...)
	code = append(code, slotWhen(andAll(
		[]byte{OP_TCP},
		[]byte{OP_NET6},
		param16(OP_LADDR_S, 1),
		param16(OP_LADDR_RE, 1),
		param16(OP_LADDR6, 0),
		param16(OP_LSNET6, 0),
		param16(OP_LPORT, uint16(tcp6Port)),
	), 3)...)
	return code
}

func complexRouterDialUDP(port int) []byte {
	return slotWhen(andAll(
		[]byte{OP_UDP},
		[]byte{OP_NET4},
		param16(OP_ADDR4, 0),
		param16(OP_SNET4, 0),
		param16(OP_PORT, uint16(port)),
	), 2)
}

func complexRouterRouteUDP(port int) []byte {
	return slotWhen(andAll(
		[]byte{OP_UDP},
		[]byte{OP_NET4},
		param16(OP_ADDR4, 0),
		param16(OP_SNET4, 0),
		param16(OP_LSNET4, 0),
		param16(OP_LPORT, uint16(port)),
	), 2)
}

func complexRouterLookup() []byte {
	return slotWhen(andAll(
		[]byte{OP_FQDN},
		orOp(param16(OP_ADDR_S, 2), param16(OP_ADDR_RE, 2)),
	), 2)
}

func complexSplitRoute() []byte {
	code := []byte{OP_FALSE, OP_DROP}
	code = append(code, slotWhen(andAll(
		[]byte{OP_NET4},
		[]byte{OP_TCP},
		notOp([]byte{OP_FQDN}),
		notOp([]byte{OP_LFQDN}),
		param16(OP_ADDR_S, 0),
		param16(OP_LADDR_S, 1),
		param16(OP_ADDR_RE, 0),
		param16(OP_LADDR_RE, 1),
		param16(OP_ADDR4, 0),
		param16(OP_LADDR4, 1),
		param16(OP_SNET4, 0),
		param16(OP_LSNET4, 1),
		param16(OP_PORT, 443),
		param16(OP_LPORT, 12345),
		param64(OP_RULE, 99),
		param64(OP_RULE, 99),
		param64(OP_CGRP, 7),
		param64(OP_UID, 1000),
		param64(OP_GID, 1000),
		param16(OP_UNAME, 4),
		param16(OP_UEXP, 3),
		param32(OP_MARK, ^uint32(6)),
		param32(OP_PID, 123),
	), 2)...)
	code = append(code, slotWhen(andAll(
		[]byte{OP_NET6},
		[]byte{OP_UDP},
		orOp(param16(OP_ADDR_S, 2), []byte{OP_FALSE}),
		param16(OP_LADDR_S, 3),
		param16(OP_ADDR_RE, 2),
		param16(OP_LADDR_RE, 2),
		param16(OP_ADDR6, 0),
		param16(OP_LADDR6, 1),
		param16(OP_SNET6, 0),
		param16(OP_LSNET6, 0),
		param16(OP_PORT, 53),
		param16(OP_LPORT, 5353),
	), 3)...)
	return code
}

func complexRouterDialTCPSrc(tcp4Port, tcp6Port int) string {
	return fmt.Sprintf(`
FALSE
DROP
TRUE
TCP
AND
NET4
AND
FQDN
NOT
AND
LFQDN
NOT
AND
ADDR_S 127.0.0.1
AND
LADDR_S 127.0.0.1
AND
ADDR_RE ^127\.0\.0\.1$
AND
LADDR_RE ^127\.0\.0\.1$
AND
ADDR4 127.0.0.1
AND
LADDR4 127.0.0.1
AND
SNET4 127.0.0.0/8
AND
LSNET4 127.0.0.0/8
AND
PORT %d
AND
LPORT 0
AND
SLOT 2
NET6
TCP
AND
ADDR6 ::1
FALSE
OR
AND
LADDR6 ::1
AND
SNET6 ::1/128
AND
LSNET6 ::1/128
AND
ADDR_RE ^::1$
AND
LADDR_RE ^::1$
AND
PORT %d
AND
LPORT 0
AND
SLOT 3
`, tcp4Port, tcp6Port)
}

func complexRouterListenTCPSrc(tcp4Port, tcp6Port int) string {
	return fmt.Sprintf(`
FALSE
DROP
TCP
NET4
AND
LFQDN
NOT
AND
LADDR_S 127.0.0.1
AND
LADDR_RE ^127\.0\.0\.1$
AND
LADDR4 127.0.0.1
AND
LSNET4 127.0.0.0/8
AND
LPORT %d
AND
SLOT 2
TCP
NET6
AND
LADDR_S ::1
AND
LADDR_RE ^::1$
AND
LADDR6 ::1
AND
LSNET6 ::1/128
AND
LPORT %d
AND
SLOT 3
`, tcp4Port, tcp6Port)
}

func complexRouterDialUDPSrc(port int) string {
	return fmt.Sprintf(`
UDP
NET4
AND
ADDR4 127.0.0.1
AND
SNET4 127.0.0.0/8
AND
PORT %d
AND
SLOT 2
`, port)
}

func complexRouterRouteUDPSrc(port int) string {
	return fmt.Sprintf(`
UDP
NET4
AND
ADDR4 127.0.0.1
AND
SNET4 127.0.0.0/8
AND
LSNET4 127.0.0.0/8
AND
LPORT %d
AND
SLOT 2
`, port)
}

func complexRouterLookupSrc() string {
	return `
FQDN
ADDR_S localhost
ADDR_RE ^local
OR
AND
SLOT 2
`
}

func complexSplitRouteSrc() string {
	return `
FALSE
DROP
NET4
TCP
AND
FQDN
NOT
AND
LFQDN
NOT
AND
ADDR_S 192.0.2.2
AND
LADDR_S 10.0.0.1
AND
ADDR_RE ^192\.0\.2\.
AND
LADDR_RE ^10\.0\.0\.
AND
ADDR4 192.0.2.2
AND
LADDR4 10.0.0.1
AND
SNET4 192.0.2.0/24
AND
LSNET4 10.0.0.0/24
AND
PORT 443
AND
LPORT 12345
AND
RULE 99
AND
RULE 99
AND
CGRP 7
AND
UID 1000
AND
GID 1000
AND
UNAME alice
AND
UEXP ^ali
AND
MARK -7
AND
PID 123
AND
SLOT 2
NET6
UDP
AND
ADDR_S 2001:db8::2
FALSE
OR
AND
LADDR_S 2001:db8::1
AND
ADDR_RE ^2001:db8::
AND
LADDR_RE ^2001:db8::
AND
ADDR6 2001:db8::2
AND
LADDR6 2001:db8::1
AND
SNET6 2001:db8::/64
AND
LSNET6 2001:db8::/64
AND
PORT 53
AND
LPORT 5353
AND
SLOT 3
`
}

func assertRouterTCPRoundTrip(
	t *testing.T,
	ctx context.Context,
	r *gonnect.Router,
	network,
	listenAddr,
	dialLAddr,
	payload string,
) {
	t.Helper()
	ln, err := r.ListenTCP(ctx, network, listenAddr)
	if err != nil {
		t.Fatalf("ListenTCP(%s, %s) error = %v", network, listenAddr, err)
	}
	defer ln.Close()

	accepted := make(chan gonnect.TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- c
	}()

	client, err := r.DialTCP(ctx, network, dialLAddr, listenAddr)
	if err != nil {
		t.Fatalf(
			"DialTCP(%s, %s -> %s) error = %v",
			network,
			dialLAddr,
			listenAddr,
			err,
		)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))

	var server gonnect.TCPConn
	select {
	case server = <-accepted:
	case err := <-errs:
		t.Fatalf("AcceptTCP() error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP() timed out")
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))

	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server Read() error = %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("server Read() = %q, want %q", buf[:n], payload)
	}
}

func assertRouterUDPRoundTrip(
	t *testing.T,
	ctx context.Context,
	r *gonnect.Router,
	port int,
) {
	t.Helper()
	server, err := r.ListenUDP(
		ctx,
		"udp4",
		net.JoinHostPort("127.0.0.1", "34083"),
	)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer server.Close()
	client, err := r.DialUDP(
		ctx,
		"udp4",
		"127.0.0.1:0",
		net.JoinHostPort("127.0.0.1", "34083"),
	)
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(time.Second))
	_ = client.SetDeadline(time.Now().Add(time.Second))

	if _, err := client.Write([]byte("udp-dial")); err != nil {
		t.Fatalf("client UDP Write() error = %v", err)
	}
	buf := make([]byte, 64)
	n, addr, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server UDP ReadFrom() error = %v", err)
	}
	if string(buf[:n]) != "udp-dial" {
		t.Fatalf("server UDP ReadFrom() = %q, want udp-dial", buf[:n])
	}
	if _, err := server.WriteTo([]byte("udp-route"), addr); err != nil {
		t.Fatalf("server UDP WriteTo(port %d) error = %v", port, err)
	}
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client UDP Read() error = %v", err)
	}
	if string(buf[:n]) != "udp-route" {
		t.Fatalf("client UDP Read() = %q, want udp-route", buf[:n])
	}
}

func andAll(parts ...[]byte) []byte {
	if len(parts) == 0 {
		return []byte{OP_TRUE}
	}
	out := append([]byte(nil), parts[0]...)
	for _, part := range parts[1:] {
		out = append(out, part...)
		out = append(out, OP_AND)
	}
	return out
}

func orOp(left, right []byte) []byte {
	out := append([]byte(nil), left...)
	out = append(out, right...)
	out = append(out, OP_OR)
	return out
}

func notOp(expr []byte) []byte {
	out := append([]byte(nil), expr...)
	out = append(out, OP_NOT)
	return out
}

func slotWhen(expr []byte, slot byte) []byte {
	out := append([]byte(nil), expr...)
	out = append(out, OP_SLOT, slot)
	return out
}

type nativeTestTun struct {
	tun.Tun
}

func (n nativeTestTun) IsNative() bool { return true }

func writeTunPacket(t *testing.T, dst tun.Tun, pkt []byte) {
	t.Helper()
	buf := make([]byte, dst.MWO()+len(pkt))
	copy(buf[dst.MWO():], pkt)
	if n, err := dst.Write([][]byte{buf}, dst.MWO()); err != nil || n != 1 {
		t.Fatalf("Tun Write() = %d, %v; want 1, nil", n, err)
	}
}

func readTunPacket(t *testing.T, src tun.Tun) []byte {
	t.Helper()
	type result struct {
		data []byte
		err  error
		n    int
		size int
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, src.MRO()+1500)
		sizes := make([]int, 1)
		n, err := src.Read([][]byte{buf}, sizes, src.MRO())
		res := result{err: err, n: n}
		if len(sizes) > 0 {
			res.size = sizes[0]
			if n > 0 && sizes[0] >= 0 && src.MRO()+sizes[0] <= len(buf) {
				res.data = append(
					[]byte(nil),
					buf[src.MRO():src.MRO()+sizes[0]]...)
			}
		}
		ch <- res
	}()
	select {
	case res := <-ch:
		if res.err != nil || res.n != 1 {
			t.Fatalf(
				"Tun Read() = n:%d size:%d err:%v, want one packet",
				res.n,
				res.size,
				res.err,
			)
		}
		return res.data
	case <-time.After(time.Second):
		t.Fatal("Tun Read() timed out")
		return nil
	}
}

func assertNoTunPacket(t *testing.T, src tun.Tun) {
	t.Helper()
	done := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, src.MRO()+1500)
		sizes := make([]int, 1)
		_, _ = src.Read([][]byte{buf}, sizes, src.MRO())
		done <- struct{}{}
	}()
	select {
	case <-done:
		t.Fatal("Tun Read() returned a packet, want drop")
	case <-time.After(50 * time.Millisecond):
		_ = src.Close()
	}
}

func ipv6UDPPacket(
	src, dst netip.Addr,
	srcPort, dstPort uint16,
	payload []byte,
) []byte {
	pkt := make([]byte, 48+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	pkt[6] = 17
	pkt[7] = 64
	src16 := src.As16()
	dst16 := dst.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(8+len(payload)))
	copy(pkt[48:], payload)
	return pkt
}
