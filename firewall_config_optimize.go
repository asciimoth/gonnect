package gonnect

import (
	"net/netip"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Optimize returns a canonical, independent config with the same policy. It
// retains the same DNSCache because the cache is shared runtime state.
//
// Optimize normalizes rule text, ports, and ranges. It removes duplicate and
// subsumed rules. It also combines rules when they differ only in their host
// selectors or only in their port selectors. It does not combine rules when
// doing so would allow unintended host-and-port combinations.
//
// Optimize does not modify cfg. A nil receiver produces an empty config.
func (cfg *FirewallConfig) Optimize() *FirewallConfig {
	optimized := &FirewallConfig{}
	if cfg != nil {
		optimized.ResponseTTL = cfg.ResponseTTL
		optimized.DNSCache = cfg.DNSCache
		optimized.Exclude = optimizeFirewallRules(cfg.Exclude, false)
		optimized.Include = optimizeFirewallRules(cfg.Include, true)
	}
	optimized.exclude = compileFirewallRules(optimized.Exclude)
	optimized.include = compileFirewallRules(optimized.Include)
	return optimized
}

// Optimized is an alias for Optimize.
func (cfg *FirewallConfig) Optimized() *FirewallConfig { return cfg.Optimize() }

// Merge returns an optimized config that contains the union of cfg and others.
// It does not modify any input config.
func (cfg *FirewallConfig) Merge(others ...*FirewallConfig) *FirewallConfig {
	configs := make([]*FirewallConfig, 0, len(others)+1)
	configs = append(configs, cfg)
	configs = append(configs, others...)
	return MergeFirewallConfigs(configs...)
}

// MergeFirewallConfigs returns an optimized union of configs.
//
// Exclude and Include rules are combined independently. Nil configs are
// ignored. The merged ResponseTTL is the longest effective TTL in the inputs;
// a non-positive TTL has its documented two-minute value for this comparison.
// The first non-nil DNSCache is retained because cache instances are shared
// runtime state, not policy data.
// With no non-nil inputs, the result is an empty config with the default TTL.
func MergeFirewallConfigs(configs ...*FirewallConfig) *FirewallConfig {
	merged := &FirewallConfig{}
	var selectedTTL time.Duration
	var longestTTL time.Duration
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		merged.Exclude = append(
			merged.Exclude,
			cloneFirewallRules(cfg.Exclude)...)
		merged.Include = append(
			merged.Include,
			cloneFirewallRules(cfg.Include)...)
		if merged.DNSCache == nil {
			merged.DNSCache = cfg.DNSCache
		}
		effective := cfg.responseTTL()
		if effective > longestTTL {
			longestTTL = effective
			selectedTTL = cfg.ResponseTTL
		}
	}
	merged.ResponseTTL = selectedTTL
	return merged.Optimize()
}

func optimizeFirewallRules(
	rules []FirewallRule,
	matchLocalHosts bool,
) []FirewallRule {
	optimized := make([]FirewallRule, 0, len(rules))
	for _, rule := range rules {
		canonical, useful := canonicalFirewallRule(rule, matchLocalHosts)
		if useful {
			optimized = append(optimized, canonical)
		}
	}
	optimized = removeSubsumedFirewallRules(optimized)

	for {
		merged := false
		for i := 0; i < len(optimized) && !merged; i++ {
			for j := i + 1; j < len(optimized); j++ {
				combined, ok := mergeFirewallRules(optimized[i], optimized[j])
				if !ok {
					continue
				}
				optimized[i] = combined
				optimized = append(optimized[:j], optimized[j+1:]...)
				optimized = removeSubsumedFirewallRules(optimized)
				merged = true
				break
			}
		}
		if !merged {
			break
		}
	}

	sort.Slice(optimized, func(i, j int) bool {
		return firewallRuleSortKey(
			optimized[i],
		) < firewallRuleSortKey(
			optimized[j],
		)
	})
	if len(optimized) == 0 {
		return nil
	}
	return optimized
}

func canonicalFirewallRule(
	rule FirewallRule,
	matchLocalHosts bool,
) (FirewallRule, bool) {
	canonical := FirewallRule{
		Network: strings.ToLower(strings.TrimSpace(rule.Network)),
	}
	if canonical.Network == "*" {
		canonical.Network = ""
	}

	hosts, anyHost := canonicalFirewallHosts(rule.Hosts)
	if len(rule.Hosts) != 0 && !anyHost && len(hosts) == 0 {
		return FirewallRule{}, false
	}
	if !anyHost {
		canonical.Hosts = hosts
	}
	if matchLocalHosts {
		localHosts, anyLocalHost := canonicalFirewallHosts(rule.LocalHosts)
		if len(rule.LocalHosts) != 0 &&
			!anyLocalHost && len(localHosts) == 0 {
			return FirewallRule{}, false
		}
		if !anyLocalHost {
			canonical.LocalHosts = localHosts
		}
	}
	canonical.Ports, canonical.PortRanges = canonicalFirewallPorts(
		rule.Ports,
		rule.PortRanges,
	)
	return canonical, true
}

func canonicalFirewallHosts(hosts []string) ([]string, bool) {
	if len(hosts) == 0 {
		return nil, true
	}
	unique := make(map[string]struct{}, len(hosts))
	for _, raw := range hosts {
		host := trimDot(strings.ToLower(raw))
		if host == "*" {
			return nil, true
		}
		if host == "" {
			continue
		}
		if withoutZone, _, ok := strings.Cut(
			strings.Trim(host, "[]"),
			"%",
		); ok {
			host = withoutZone
		}
		if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			host = addr.Unmap().String()
		} else if prefix, err := netip.ParsePrefix(host); err == nil {
			host = canonicalFirewallPrefix(prefix).String()
		} else if _, err := path.Match(host, ""); err != nil {
			continue
		}
		unique[host] = struct{}{}
	}
	canonical := make([]string, 0, len(unique))
	for host := range unique {
		canonical = append(canonical, host)
	}
	slices.Sort(canonical)
	canonical = removeSubsumedFirewallHosts(canonical)
	return canonical, false
}

func canonicalFirewallPrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

func removeSubsumedFirewallHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for i, host := range hosts {
		subsumed := false
		for j, candidate := range hosts {
			if i != j && firewallHostSubsumes(candidate, host) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			out = append(out, host)
		}
	}
	return out
}

func canonicalFirewallPorts(
	ports []uint16,
	ranges []FirewallPortRange,
) ([]uint16, []FirewallPortRange) {
	if len(ports) == 0 && len(ranges) == 0 {
		return nil, nil
	}
	intervals := make([]FirewallPortRange, 0, len(ports)+len(ranges))
	for _, port := range ports {
		intervals = append(
			intervals,
			FirewallPortRange{First: port, Last: port},
		)
	}
	for _, interval := range ranges {
		if interval.Last < interval.First {
			interval.First, interval.Last = interval.Last, interval.First
		}
		intervals = append(intervals, interval)
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].First == intervals[j].First {
			return intervals[i].Last < intervals[j].Last
		}
		return intervals[i].First < intervals[j].First
	})
	merged := make([]FirewallPortRange, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 {
			merged = append(merged, interval)
			continue
		}
		last := &merged[len(merged)-1]
		adjacent := last.Last != ^uint16(0) && interval.First == last.Last+1
		if interval.First <= last.Last || adjacent {
			if interval.Last > last.Last {
				last.Last = interval.Last
			}
			continue
		}
		merged = append(merged, interval)
	}

	canonicalPorts := make([]uint16, 0, len(merged))
	canonicalRanges := make([]FirewallPortRange, 0, len(merged))
	for _, interval := range merged {
		if interval.First == interval.Last {
			canonicalPorts = append(canonicalPorts, interval.First)
		} else {
			canonicalRanges = append(canonicalRanges, interval)
		}
	}
	if len(canonicalPorts) == 0 {
		canonicalPorts = nil
	}
	if len(canonicalRanges) == 0 {
		canonicalRanges = nil
	}
	return canonicalPorts, canonicalRanges
}

func removeSubsumedFirewallRules(rules []FirewallRule) []FirewallRule {
	keep := make([]bool, len(rules))
	for i := range keep {
		keep[i] = true
	}
	for i := range rules {
		if !keep[i] {
			continue
		}
		for j := range rules {
			if i == j || !keep[j] {
				continue
			}
			if firewallRuleSubsumes(rules[i], rules[j]) {
				keep[j] = false
			}
		}
	}
	out := make([]FirewallRule, 0, len(rules))
	for i, rule := range rules {
		if keep[i] {
			out = append(out, rule)
		}
	}
	return out
}

func firewallRuleSubsumes(a, b FirewallRule) bool {
	return firewallNetworkSubsumes(a.Network, b.Network) &&
		firewallHostsSubsumes(a.Hosts, b.Hosts) &&
		firewallHostsSubsumes(a.LocalHosts, b.LocalHosts) &&
		firewallPortsSubsume(a, b)
}

func firewallNetworkSubsumes(a, b string) bool {
	if a == b || a == "" {
		return true
	}
	if b == "" {
		return false
	}
	switch a {
	case "ip":
		return firewallRuleNetworkIsIP(b)
	case "ip4":
		return b == "tcp4" || b == "udp4" || b == "icmp4" ||
			strings.HasPrefix(b, "ip4:")
	case "ip6":
		return b == "tcp6" || b == "udp6" || b == "icmp6" ||
			strings.HasPrefix(b, "ip6:")
	case "tcp":
		return b == "tcp4" || b == "tcp6"
	case "udp":
		return b == "udp4" || b == "udp6"
	case "icmp":
		return b == "icmp4" || b == "icmp6"
	}
	if strings.HasPrefix(a, "ip:") {
		protocol := strings.TrimPrefix(a, "ip:")
		return b == "ip4:"+protocol || b == "ip6:"+protocol
	}
	return false
}

func firewallRuleNetworkIsIP(network string) bool {
	return network == "ip" || network == "ip4" || network == "ip6" ||
		network == "tcp" || network == "tcp4" || network == "tcp6" ||
		network == "udp" || network == "udp4" || network == "udp6" ||
		network == "icmp" || network == "icmp4" || network == "icmp6" ||
		strings.HasPrefix(network, "ip:") ||
		strings.HasPrefix(network, "ip4:") ||
		strings.HasPrefix(network, "ip6:")
}

func firewallHostsSubsumes(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, host := range b {
		covered := false
		for _, candidate := range a {
			if firewallHostSubsumes(candidate, host) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func firewallHostSubsumes(a, b string) bool {
	if a == b {
		return true
	}
	aPrefix, aPrefixErr := netip.ParsePrefix(a)
	bPrefix, bPrefixErr := netip.ParsePrefix(b)
	aAddr, aAddrErr := netip.ParseAddr(a)
	bAddr, bAddrErr := netip.ParseAddr(b)
	if aPrefixErr == nil {
		if bAddrErr == nil {
			return aPrefix.Contains(bAddr)
		}
		if bPrefixErr == nil {
			return aPrefix.Bits() <= bPrefix.Bits() &&
				aPrefix.Contains(bPrefix.Addr())
		}
		return false
	}
	if aAddrErr == nil {
		return bAddrErr == nil && aAddr == bAddr
	}
	if bAddrErr == nil || bPrefixErr == nil {
		return false
	}
	if strings.ContainsAny(b, "*?[") {
		return false
	}
	matched, err := path.Match(a, b)
	return err == nil && matched
}

func firewallPortsSubsume(a, b FirewallRule) bool {
	aIntervals := firewallRulePortIntervals(a)
	bIntervals := firewallRulePortIntervals(b)
	if aIntervals == nil {
		return true
	}
	if bIntervals == nil {
		return false
	}
	for _, bInterval := range bIntervals {
		covered := false
		for _, aInterval := range aIntervals {
			if aInterval.First <= bInterval.First &&
				aInterval.Last >= bInterval.Last {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func firewallRulePortIntervals(rule FirewallRule) []FirewallPortRange {
	if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
		return nil
	}
	intervals := make(
		[]FirewallPortRange,
		0,
		len(rule.Ports)+len(rule.PortRanges),
	)
	for _, port := range rule.Ports {
		intervals = append(
			intervals,
			FirewallPortRange{First: port, Last: port},
		)
	}
	return append(intervals, rule.PortRanges...)
}

func mergeFirewallRules(a, b FirewallRule) (FirewallRule, bool) {
	if a.Network != b.Network {
		return FirewallRule{}, false
	}
	hostsEqual := slices.Equal(a.Hosts, b.Hosts)
	localHostsEqual := slices.Equal(a.LocalHosts, b.LocalHosts)
	portsEqual := slices.Equal(a.Ports, b.Ports) &&
		slices.Equal(a.PortRanges, b.PortRanges)
	switch {
	case hostsEqual && localHostsEqual:
		merged := a
		if len(a.Ports) == 0 && len(a.PortRanges) == 0 ||
			len(b.Ports) == 0 && len(b.PortRanges) == 0 {
			merged.Ports = nil
			merged.PortRanges = nil
		} else {
			merged.Ports, merged.PortRanges = canonicalFirewallPorts(
				append(append([]uint16(nil), a.Ports...), b.Ports...),
				append(
					append([]FirewallPortRange(nil), a.PortRanges...),
					b.PortRanges...,
				),
			)
		}
		return merged, true
	case localHostsEqual && portsEqual:
		merged := a
		merged.Hosts = mergeFirewallHostSelectors(a.Hosts, b.Hosts)
		return merged, true
	case hostsEqual && portsEqual:
		merged := a
		merged.LocalHosts = mergeFirewallHostSelectors(
			a.LocalHosts,
			b.LocalHosts,
		)
		return merged, true
	default:
		return FirewallRule{}, false
	}
}

func mergeFirewallHostSelectors(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	merged, _ := canonicalFirewallHosts(
		append(append([]string(nil), a...), b...),
	)
	return merged
}

func firewallRuleSortKey(rule FirewallRule) string {
	var builder strings.Builder
	builder.WriteString(rule.Network)
	builder.WriteByte(0)
	for _, host := range rule.Hosts {
		builder.WriteString(host)
		builder.WriteByte(0)
	}
	builder.WriteByte(1)
	for _, host := range rule.LocalHosts {
		builder.WriteString(host)
		builder.WriteByte(0)
	}
	builder.WriteByte(1)
	for _, interval := range firewallRulePortIntervals(rule) {
		builder.WriteString(strconv.Itoa(int(interval.First)))
		builder.WriteByte('-')
		builder.WriteString(strconv.Itoa(int(interval.Last)))
		builder.WriteByte(0)
	}
	return builder.String()
}
