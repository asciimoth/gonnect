package gonnect //nolint:testpackage // Fuzzes internal firewall compilation.

import "testing"

func FuzzTextInputs(f *testing.F) {
	f.Add("localhost,127.0.0.1,*.example.test:443", "tcp", "example.test:443")
	f.Add("[::1],2001:db8::/32", "udp6", "[2001:db8::1]:53")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, rules, network, address string) {
		if len(rules) > 16<<10 || len(network) > 256 || len(address) > 4<<10 {
			t.Skip()
		}

		filter := FilterFromString(rules)
		_ = filter.Filter(network, address)
		_, port := SplitHostPort(network, address, 0)
		_ = LoopbackFilter(network, address)
		// The input limit keeps this conversion in range.
		lastPort := uint16(len(address)) //nolint:gosec

		config := (&FirewallConfig{
			Exclude: []FirewallRule{{
				Network:    network,
				Hosts:      []string{address, rules},
				Ports:      []uint16{port},
				PortRanges: []FirewallPortRange{{First: port, Last: lastPort}},
			}},
			Include: []FirewallRule{{
				Network:    rules,
				Hosts:      []string{address},
				LocalHosts: []string{network},
			}},
		}).Optimize()
		_ = config.Optimize()
	})
}
