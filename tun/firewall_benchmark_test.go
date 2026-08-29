// This benchmark uses the private packet matching path.
package tun //nolint:testpackage

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/asciimoth/gonnect"
)

func BenchmarkFirewallBlocksOutgoing(b *testing.B) {
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
	firewall := NewFirewall(newFirewallTestTun(1), &gonnect.FirewallConfig{
		Exclude: rules,
	})
	flow := firewallFlow{
		version: 4,
		proto:   17,
		dst:     netip.MustParseAddr("192.0.2.63"),
		dstPort: 1063,
	}

	b.ReportAllocs()
	for b.Loop() {
		_ = firewall.blocksOutgoing(flow)
	}
}

func BenchmarkFirewallRecordResponse(b *testing.B) {
	firewall := NewFirewall(newFirewallTestTun(1), nil)
	flow := firewallFlow{
		version: 4,
		proto:   17,
		src:     netip.MustParseAddr("192.0.2.1"),
		dst:     netip.MustParseAddr("192.0.2.2"),
		srcPort: 1000,
		dstPort: 2000,
	}

	b.ReportAllocs()
	for b.Loop() {
		firewall.recordResponse(flow)
	}
}
