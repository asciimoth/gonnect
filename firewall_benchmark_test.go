package gonnect_test

import (
	"strconv"
	"testing"

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
