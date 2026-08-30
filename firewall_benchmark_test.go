package gonnect_test

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func BenchmarkFirewallConfigBlocksOutgoing(b *testing.B) {
	rules := make([]gonnect.FirewallRule, 64)
	port := uint16(1000)
	for i := range rules {
		rules[i] = gonnect.FirewallRule{
			Network: "udp",
			Hosts:   []string{"192.0.2." + strconv.Itoa(i)},
			Ports:   []uint16{port},
		}
		port++
	}
	cfg := (&gonnect.FirewallConfig{Exclude: rules}).Optimize()

	b.ReportAllocs()
	for b.Loop() {
		_ = cfg.BlocksOutgoing("udp4", "192.0.2.63:1063")
	}
}

func BenchmarkFirewallConfigAllowsIncomingLocalHost(b *testing.B) {
	rules := make([]gonnect.FirewallRule, 64)
	for i := range rules {
		rules[i] = gonnect.FirewallRule{
			Network:    "udp",
			Hosts:      []string{"192.0.2.1"},
			LocalHosts: []string{"198.51.100." + strconv.Itoa(i)},
			Ports:      []uint16{53},
		}
	}
	cfg := (&gonnect.FirewallConfig{Include: rules}).Optimize()
	peer := netip.MustParseAddrPort("192.0.2.1:40000")
	local := netip.MustParseAddrPort("198.51.100.63:53")

	b.ReportAllocs()
	for b.Loop() {
		_ = cfg.AllowsIncomingAddrPort("udp4", peer, local)
	}
}

func BenchmarkFirewallConfigBlocksOutgoingHostname(b *testing.B) {
	rules := make([]gonnect.FirewallRule, 64)
	for i := range rules {
		rules[i] = gonnect.FirewallRule{
			Network: "tcp",
			Hosts:   []string{"host" + strconv.Itoa(i) + ".example"},
			Ports:   []uint16{443},
		}
	}
	cfg := (&gonnect.FirewallConfig{Exclude: rules}).Optimize()

	b.ReportAllocs()
	for b.Loop() {
		_ = cfg.BlocksOutgoing("tcp4", "host63.example:443")
	}
}

func BenchmarkFirewallConfigBlocksOutgoingCachedHostname(b *testing.B) {
	cfg := (&gonnect.FirewallConfig{
		DNSCache: firewallBenchmarkDNSCache{"api.example.test."},
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"*.example.test"},
			Ports:   []uint16{443},
		}},
	}).Optimize()
	address := netip.MustParseAddrPort("192.0.2.10:443")

	b.ReportAllocs()
	for b.Loop() {
		_ = cfg.BlocksOutgoingAddrPort("tcp4", address)
	}
}

type firewallBenchmarkDNSCache []string

func (c firewallBenchmarkDNSCache) ReverseDNSNames(
	netip.Addr,
	time.Time,
) []string {
	return c
}
