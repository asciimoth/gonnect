package gonnect_test

import (
	"math/rand"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestFirewallConfigOptimizeCanonicalizesAndCombines(t *testing.T) {
	source := &gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{
			{
				Network: " TCP ",
				Hosts:   []string{"API.Example.COM.", "api.example.com"},
				Ports:   []uint16{80, 80},
				PortRanges: []gonnect.FirewallPortRange{
					{First: 83, Last: 81},
					{First: 83, Last: 85},
				},
			},
			{
				Network: "tcp",
				Hosts:   []string{"api.example.com"},
				Ports:   []uint16{86},
			},
			{
				Network: "tcp",
				Hosts:   []string{"www.example.com"},
				PortRanges: []gonnect.FirewallPortRange{{
					First: 80,
					Last:  86,
				}},
			},
			{
				Network: "tcp4",
				Hosts:   []string{"api.example.com"},
				Ports:   []uint16{81},
			},
		},
		Include: []gonnect.FirewallRule{
			{
				Network: "UDP",
				Hosts:   []string{"10.0.0.1", "10.0.0.0/8", "10.0.0.0/8"},
				Ports:   []uint16{55},
				PortRanges: []gonnect.FirewallPortRange{{
					First: 60,
					Last:  50,
				}},
			},
			{Network: "udp", Hosts: []string{""}},
		},
		ResponseTTL: 7 * time.Minute,
	}
	before := source.Clone()
	optimized := source.Optimize()

	wantExclude := []gonnect.FirewallRule{{
		Network: "tcp",
		Hosts:   []string{"api.example.com", "www.example.com"},
		PortRanges: []gonnect.FirewallPortRange{{
			First: 80,
			Last:  86,
		}},
	}}
	wantInclude := []gonnect.FirewallRule{{
		Network: "udp",
		Hosts:   []string{"10.0.0.0/8"},
		PortRanges: []gonnect.FirewallPortRange{{
			First: 50,
			Last:  60,
		}},
	}}
	if !reflect.DeepEqual(optimized.Exclude, wantExclude) {
		t.Fatalf(
			"optimized Exclude = %#v, want %#v",
			optimized.Exclude,
			wantExclude,
		)
	}
	if !reflect.DeepEqual(optimized.Include, wantInclude) {
		t.Fatalf(
			"optimized Include = %#v, want %#v",
			optimized.Include,
			wantInclude,
		)
	}
	if optimized.ResponseTTL != source.ResponseTTL {
		t.Fatalf(
			"ResponseTTL = %v, want %v",
			optimized.ResponseTTL,
			source.ResponseTTL,
		)
	}
	if !firewallConfigPublicEqual(source, before) {
		t.Fatal("Optimize modified its input")
	}

	assertFirewallConfigsEquivalent(t, source, optimized)
	firewallConfigHostMutationForTest(t, optimized)
	if source.Exclude[0].Hosts[0] != "API.Example.COM." {
		t.Fatal("optimized config shares host storage with its input")
	}
}

func TestFirewallConfigOptimizeDoesNotExpandCrossProduct(t *testing.T) {
	source := &gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{
		{
			Network: "tcp",
			Hosts:   []string{"a.example"},
			Ports:   []uint16{80},
		},
		{
			Network: "tcp",
			Hosts:   []string{"b.example"},
			Ports:   []uint16{81},
		},
	}}
	optimized := source.Optimized()
	if len(optimized.Exclude) != 2 {
		t.Fatalf("optimized rule count = %d, want 2", len(optimized.Exclude))
	}
	assertFirewallConfigsEquivalent(t, source, optimized)
	if optimized.BlocksOutgoing("tcp", "a.example:81") {
		t.Fatal("optimization introduced host A and port 81 cross-product")
	}
	if optimized.BlocksOutgoing("tcp", "b.example:80") {
		t.Fatal("optimization introduced host B and port 80 cross-product")
	}
}

func TestFirewallConfigOptimizeRemovesSubsumedRules(t *testing.T) {
	source := &gonnect.FirewallConfig{Exclude: []gonnect.FirewallRule{
		{
			Network: "ip",
			Hosts:   []string{"192.0.2.0/24", "192.0.2.12"},
			PortRanges: []gonnect.FirewallPortRange{{
				First: 100,
				Last:  200,
			}},
		},
		{
			Network: "tcp4",
			Hosts:   []string{"192.0.2.12"},
			Ports:   []uint16{150},
		},
	}}
	optimized := source.Optimize()
	if len(optimized.Exclude) != 1 {
		t.Fatalf("optimized rule count = %d, want 1", len(optimized.Exclude))
	}
	wantHosts := []string{"192.0.2.0/24"}
	if !reflect.DeepEqual(optimized.Exclude[0].Hosts, wantHosts) {
		t.Fatalf(
			"optimized hosts = %v, want %v",
			optimized.Exclude[0].Hosts,
			wantHosts,
		)
	}
	assertFirewallConfigsEquivalent(t, source, optimized)

	allowAll := (&gonnect.FirewallConfig{Include: []gonnect.FirewallRule{
		{Network: "*", Hosts: []string{"*"}},
		{Network: "tcp", Hosts: []string{"unused.example"}, Ports: []uint16{80}},
	}}).Optimize()
	if len(allowAll.Include) != 1 || allowAll.Include[0].Network != "" ||
		len(allowAll.Include[0].Hosts) != 0 {
		t.Fatalf("allow-all optimization = %#v", allowAll.Include)
	}
}

func TestMergeFirewallConfigs(t *testing.T) {
	first := &gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"api.example"},
			Ports:   []uint16{80},
		}},
		Include: []gonnect.FirewallRule{{
			Network: "udp",
			Hosts:   []string{"10.0.0.0/8"},
			Ports:   []uint16{53},
		}},
		ResponseTTL: time.Minute,
	}
	second := &gonnect.FirewallConfig{
		Exclude: []gonnect.FirewallRule{{
			Network: "tcp",
			Hosts:   []string{"api.example"},
			Ports:   []uint16{81},
		}},
		Include: []gonnect.FirewallRule{{
			Network: "udp",
			Hosts:   []string{"10.0.0.1"},
			Ports:   []uint16{53},
		}},
		ResponseTTL: 5 * time.Minute,
	}
	firstBefore := first.Clone()
	secondBefore := second.Clone()

	merged := gonnect.MergeFirewallConfigs(nil, first, second)
	if merged.ResponseTTL != 5*time.Minute {
		t.Fatalf("merged ResponseTTL = %v, want 5m", merged.ResponseTTL)
	}
	if len(merged.Exclude) != 1 {
		t.Fatalf("merged Exclude count = %d, want 1", len(merged.Exclude))
	}
	if !merged.BlocksOutgoing("tcp", "api.example:80") ||
		!merged.BlocksOutgoing("tcp", "api.example:81") ||
		merged.BlocksOutgoing("tcp", "other.example:80") {
		t.Fatal("merged Exclude policy is incorrect")
	}
	if len(merged.Include) != 1 ||
		!merged.AllowsIncoming("udp", "10.0.0.1:53") ||
		!merged.AllowsIncoming("udp", "10.2.3.4:53") {
		t.Fatal("merged Include policy is incorrect")
	}
	if !firewallConfigPublicEqual(first, firstBefore) ||
		!firewallConfigPublicEqual(second, secondBefore) {
		t.Fatal("MergeFirewallConfigs modified an input")
	}

	methodMerged := first.Merge(second)
	if !reflect.DeepEqual(methodMerged, merged) {
		t.Fatalf("Merge() = %#v, want %#v", methodMerged, merged)
	}
	methodMerged.Exclude[0].Hosts[0] = "changed.example"
	if first.Exclude[0].Hosts[0] != "api.example" ||
		second.Exclude[0].Hosts[0] != "api.example" {
		t.Fatal("merged config shares host storage with an input")
	}

	defaultWins := gonnect.MergeFirewallConfigs(
		&gonnect.FirewallConfig{},
		&gonnect.FirewallConfig{ResponseTTL: time.Minute},
	)
	if defaultWins.ResponseTTL != 0 {
		t.Fatalf(
			"merged default ResponseTTL = %v, want zero/default",
			defaultWins.ResponseTTL,
		)
	}
	empty := gonnect.MergeFirewallConfigs(nil)
	if empty == nil || len(empty.Exclude) != 0 || len(empty.Include) != 0 {
		t.Fatalf("empty merge = %#v", empty)
	}
}

func TestFirewallConfigOptimizeRandomizedEquivalence(t *testing.T) {
	random := rand.New(rand.NewSource(1)) //nolint:gosec
	networkRules := []string{
		"",
		"tcp",
		"tcp4",
		"tcp6",
		"udp",
		"udp4",
		"ip",
		"ip4",
		"ip:47",
	}
	hostRules := [][]string{
		nil,
		{"*"},
		{"api.example.com"},
		{"*.example.com"},
		{"192.0.2.1"},
		{"192.0.2.0/24"},
		{"192.0.2.0/24", "192.0.2.1"},
	}
	portRules := []struct {
		ports  []uint16
		ranges []gonnect.FirewallPortRange
	}{
		{},
		{ports: []uint16{53}},
		{ports: []uint16{80, 81}},
		{ranges: []gonnect.FirewallPortRange{{First: 80, Last: 90}}},
		{
			ports:  []uint16{85},
			ranges: []gonnect.FirewallPortRange{{First: 90, Last: 80}},
		},
	}

	for iteration := range 300 {
		ruleCount := 1 + random.Intn(8)
		cfg := &gonnect.FirewallConfig{}
		for range ruleCount {
			ports := portRules[random.Intn(len(portRules))]
			rule := gonnect.FirewallRule{
				Network: networkRules[random.Intn(len(networkRules))],
				Hosts: append(
					[]string(nil),
					hostRules[random.Intn(len(hostRules))]...),
				Ports: append([]uint16(nil), ports.ports...),
				PortRanges: append(
					[]gonnect.FirewallPortRange(nil),
					ports.ranges...),
			}
			if random.Intn(2) == 0 {
				cfg.Exclude = append(cfg.Exclude, rule)
			} else {
				cfg.Include = append(cfg.Include, rule)
			}
		}
		optimized := cfg.Optimize()
		for _, network := range []string{
			"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip4:47", "ip6:47",
		} {
			for _, host := range []string{
				"api.example.com", "www.example.com", "other.test", "192.0.2.1", "192.0.3.1",
			} {
				for _, port := range []uint16{0, 53, 79, 80, 81, 85, 90, 91} {
					address := host + ":" + strconv.Itoa(int(port))
					if cfg.BlocksOutgoing(network, address) !=
						optimized.BlocksOutgoing(network, address) {
						t.Fatalf(
							"iteration %d changed outgoing %s %s",
							iteration,
							network,
							address,
						)
					}
					if cfg.AllowsIncoming(network, address) !=
						optimized.AllowsIncoming(network, address) {
						t.Fatalf(
							"iteration %d changed incoming %s %s",
							iteration,
							network,
							address,
						)
					}
				}
			}
		}
	}
}

func assertFirewallConfigsEquivalent(
	t *testing.T,
	a, b *gonnect.FirewallConfig,
) {
	t.Helper()
	networks := []string{"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip4:47"}
	addresses := []string{
		"api.example.com:49",
		"api.example.com:50",
		"api.example.com:80",
		"api.example.com:81",
		"api.example.com:86",
		"api.example.com:87",
		"www.example.com:80",
		"other.example.com:80",
		"10.0.0.1:53",
		"10.255.255.255:60",
		"11.0.0.1:53",
		"192.0.2.12:150",
		"192.0.3.12:150",
	}
	for _, network := range networks {
		for _, address := range addresses {
			if got, want := b.BlocksOutgoing(network, address),
				a.BlocksOutgoing(network, address); got != want {
				t.Fatalf(
					"BlocksOutgoing(%q, %q) after optimization = %v, want %v",
					network,
					address,
					got,
					want,
				)
			}
			if got, want := b.AllowsIncoming(network, address),
				a.AllowsIncoming(network, address); got != want {
				t.Fatalf(
					"AllowsIncoming(%q, %q) after optimization = %v, want %v",
					network,
					address,
					got,
					want,
				)
			}
		}
	}
}

func firewallConfigHostMutationForTest(
	t *testing.T,
	cfg *gonnect.FirewallConfig,
) {
	t.Helper()
	if len(cfg.Exclude) == 0 || len(cfg.Exclude[0].Hosts) == 0 {
		t.Fatal("optimized config has no host to mutate")
	}
	cfg.Exclude[0].Hosts[0] = "mutated.example"
}

func firewallConfigPublicEqual(a, b *gonnect.FirewallConfig) bool {
	return a.ResponseTTL == b.ResponseTTL &&
		reflect.DeepEqual(a.Exclude, b.Exclude) &&
		reflect.DeepEqual(a.Include, b.Include)
}
