// nolint
package sysnetdebug

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestMapResolverLookups(t *testing.T) {
	resolver := newMapResolver(map[string]string{
		"Example.COM.": "192.0.2.10",
		"v6.test":      "2001:db8::1",
		"root":         "203.0.113.7",
	})

	ips, err := resolver.LookupIP(context.Background(), "ip4", "example.com")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("LookupIP() = %v, %v", ips, err)
	}

	ipAddrs, err := resolver.LookupIPAddr(context.Background(), "EXAMPLE.COM.")
	if err != nil || len(ipAddrs) != 1 ||
		!ipAddrs[0].IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("LookupIPAddr() = %v, %v", ipAddrs, err)
	}

	netIPs, err := resolver.LookupNetIP(
		context.Background(),
		"tcp6",
		"v6.test.",
	)
	if err != nil || len(netIPs) != 1 ||
		netIPs[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("LookupNetIP() = %v, %v", netIPs, err)
	}

	hosts, err := resolver.LookupHost(context.Background(), "example.com.")
	if err != nil || len(hosts) != 1 || hosts[0] != "192.0.2.10" {
		t.Fatalf("LookupHost() = %v, %v", hosts, err)
	}

	names, err := resolver.LookupAddr(context.Background(), "192.0.2.10.")
	if err != nil || len(names) != 1 || names[0] != "example.com." {
		t.Fatalf("LookupAddr() = %v, %v", names, err)
	}

	cname, err := resolver.LookupCNAME(context.Background(), "example.com")
	if err != nil || cname != "example.com." {
		t.Fatalf("LookupCNAME() = %q, %v", cname, err)
	}

	port, err := resolver.LookupPort(context.Background(), "tcp", "443")
	if err != nil || port != 443 {
		t.Fatalf("LookupPort() = %d, %v", port, err)
	}
}

func TestMapResolverErrors(t *testing.T) {
	resolver := newMapResolver(map[string]string{
		"v4.test":  "192.0.2.10",
		"bad.test": "not-an-ip",
	})

	_, err := resolver.LookupIP(context.Background(), "ip6", "v4.test")
	assertNotFound(t, err, "v4.test")

	_, err = resolver.LookupIP(context.Background(), "ip", "missing.test")
	assertNotFound(t, err, "missing.test")

	if _, err = resolver.LookupHost(
		context.Background(),
		"bad.test",
	); err == nil {
		t.Fatal("LookupHost(bad.test) error = nil, want parse error")
	}

	_, err = resolver.LookupAddr(context.Background(), "203.0.113.9")
	assertNotFound(t, err, "203.0.113.9")

	_, err = resolver.LookupPort(context.Background(), "tcp", "0")
	assertNotFound(t, err, "0")

	for name, run := range map[string]func() error{
		"LookupNS": func() error {
			_, err := resolver.LookupNS(context.Background(), "example.com")
			return err
		},
		"LookupMX": func() error {
			_, err := resolver.LookupMX(context.Background(), "example.com")
			return err
		},
		"LookupSRV": func() error {
			_, _, err := resolver.LookupSRV(
				context.Background(),
				"xmpp",
				"tcp",
				"example.com",
			)
			return err
		},
		"LookupTXT": func() error {
			_, err := resolver.LookupTXT(context.Background(), "example.com")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertNotFound(t, run(), "example.com")
		})
	}
}

func TestMapResolverHonorsContext(t *testing.T) {
	resolver := newMapResolver(map[string]string{"example.com": "192.0.2.10"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for name, run := range map[string]func() error{
		"LookupIP": func() error {
			_, err := resolver.LookupIP(ctx, "ip", "example.com")
			return err
		},
		"LookupIPAddr": func() error {
			_, err := resolver.LookupIPAddr(ctx, "example.com")
			return err
		},
		"LookupNetIP": func() error {
			_, err := resolver.LookupNetIP(ctx, "ip", "example.com")
			return err
		},
		"LookupHost": func() error {
			_, err := resolver.LookupHost(ctx, "example.com")
			return err
		},
		"LookupAddr": func() error {
			_, err := resolver.LookupAddr(ctx, "192.0.2.10")
			return err
		},
		"LookupCNAME": func() error {
			_, err := resolver.LookupCNAME(ctx, "example.com")
			return err
		},
		"LookupPort": func() error {
			_, err := resolver.LookupPort(ctx, "tcp", "443")
			return err
		},
		"LookupNS": func() error {
			_, err := resolver.LookupNS(ctx, "example.com")
			return err
		},
		"LookupMX": func() error {
			_, err := resolver.LookupMX(ctx, "example.com")
			return err
		},
		"LookupSRV": func() error {
			_, _, err := resolver.LookupSRV(ctx, "xmpp", "tcp", "example.com")
			return err
		},
		"LookupTXT": func() error {
			_, err := resolver.LookupTXT(ctx, "example.com")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("%s error = %v, want context.Canceled", name, err)
			}
		})
	}
}

func TestMapResolverHelpers(t *testing.T) {
	if got := normalizeHost("Example.COM."); got != "example.com" {
		t.Fatalf("normalizeHost() = %q", got)
	}
	if got := dnsName(""); got != "." {
		t.Fatalf("dnsName(empty) = %q", got)
	}
	if !networkMatchesAddr("udp4", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("udp4 did not match IPv4 address")
	}
	if networkMatchesAddr("tcp6", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("tcp6 matched IPv4 address")
	}
	if !networkMatchesAddr("tcp", netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("tcp did not match IPv6 address without version suffix")
	}
}

func assertNotFound(t *testing.T, err error, name string) {
	t.Helper()

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("error = %T %v, want *net.DNSError", err, err)
	}
	if dnsErr.Name != name || !dnsErr.IsNotFound {
		t.Fatalf("error = %#v, want not found for %q", dnsErr, name)
	}
}
