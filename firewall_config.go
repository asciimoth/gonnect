package gonnect

import (
	"errors"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultFirewallResponseTTL = 2 * time.Minute

// ErrFirewallDenied identifies an outgoing operation that an Exclude rule
// denied. Network methods wrap this error in net.OpError.
var ErrFirewallDenied = errors.Join(
	syscall.EACCES,
	errors.New("gonnect: firewall denied traffic"),
)

// FirewallPortRange is an inclusive transport-port range.
type FirewallPortRange struct {
	First uint16
	Last  uint16
}

// FirewallDNSCache supplies cached reverse-DNS names for firewall matching.
//
// Implementations must be safe for concurrent use and must not do a live DNS
// lookup. ReverseDNSNames returns only names that are valid at now. The
// github.com/asciimoth/gonnect/dns package provides cache implementations and
// an adapter for its CacheStorage interface.
type FirewallDNSCache interface {
	ReverseDNSNames(addr netip.Addr, now time.Time) []string
}

// FirewallRule matches traffic by protocol, endpoints, and service port.
//
// Network can be tcp, tcp4, tcp6, udp, udp4, udp6, ip, ip4, ip6, or an
// implementation-specific IP protocol name. An empty Network matches all
// protocols. The generic tcp and udp names match both address families. The ip
// name matches all IP protocols.
//
// Hosts contains peer host names, IP addresses, and CIDR prefixes. For
// outgoing traffic, the peer is the remote destination. For incoming traffic,
// the peer is the remote source. Host names use path.Match syntax and are
// matched without case or a final dot. A literal "*" matches every peer,
// including numeric IP addresses. An empty Hosts slice also matches every peer.
//
// LocalHosts optionally contains local destination host names, IP addresses,
// and CIDR prefixes for incoming traffic. It uses the same syntax as Hosts. An
// empty LocalHosts slice matches every local destination. Exclude rules ignore
// LocalHosts because they apply only to outgoing traffic.
//
// Ports and PortRanges select service ports. For outgoing traffic this is the
// remote destination port. For incoming traffic this is the local destination
// port. Empty port fields match every port.
type FirewallRule struct {
	Network    string
	Hosts      []string
	LocalHosts []string
	Ports      []uint16
	PortRanges []FirewallPortRange
}

// FirewallConfig defines the common policy used by Firewall and tun.Firewall.
//
// Exclude is a deny list for outgoing traffic. Include is an allow list for
// unsolicited incoming traffic. Incoming responses to allowed outgoing
// traffic do not need an Include rule.
//
// ResponseTTL controls how long packet response state is retained. Values less
// than or equal to zero select a two-minute default.
//
// DNSCache enables hostname selectors for numeric IP endpoints. The firewall
// checks cached reverse-DNS names only after direct IP and CIDR checks fail. It
// does not make live DNS requests. Use the same storage as a
// github.com/asciimoth/gonnect/dns.Cache that has reverse lookups enabled so
// successful A and AAAA queries populate the names. Include rules use these
// names as access-control data, so use a trusted cache.
type FirewallConfig struct {
	Exclude     []FirewallRule
	Include     []FirewallRule
	ResponseTTL time.Duration
	DNSCache    FirewallDNSCache

	exclude []compiledFirewallRule
	include []compiledFirewallRule
}

// FirewallCfg is a short alias for FirewallConfig.
type FirewallCfg = FirewallConfig

type compiledFirewallRule struct {
	network    string
	ipVersion  uint8
	ipProtocol uint16
	matchesIP  bool
	peer       compiledFirewallHostSelector
	local      compiledFirewallHostSelector
	ports      []uint16
	ranges     []FirewallPortRange
}

type compiledFirewallHostSelector struct {
	any      bool
	hosts    []string
	addrs    []netip.Addr
	prefixes []netip.Prefix
}

const (
	anyFirewallIPProtocol  = 1 << 8
	icmpFirewallIPProtocol = anyFirewallIPProtocol + 1
)

func cloneFirewallConfig(cfg *FirewallConfig) *FirewallConfig {
	if cfg == nil {
		cfg = &FirewallConfig{}
	}
	clone := &FirewallConfig{
		Exclude:     cloneFirewallRules(cfg.Exclude),
		Include:     cloneFirewallRules(cfg.Include),
		ResponseTTL: cfg.ResponseTTL,
		DNSCache:    cfg.DNSCache,
	}
	clone.exclude = compileFirewallRules(clone.Exclude)
	clone.include = compileFirewallRules(clone.Include)
	return clone
}

func cloneFirewallRules(rules []FirewallRule) []FirewallRule {
	if rules == nil {
		return nil
	}
	out := make([]FirewallRule, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].Hosts = append([]string(nil), rule.Hosts...)
		out[i].LocalHosts = append([]string(nil), rule.LocalHosts...)
		out[i].Ports = append([]uint16(nil), rule.Ports...)
		out[i].PortRanges = append(
			[]FirewallPortRange(nil),
			rule.PortRanges...,
		)
	}
	return out
}

func compileFirewallRules(rules []FirewallRule) []compiledFirewallRule {
	out := make([]compiledFirewallRule, 0, len(rules))
	for _, rule := range rules {
		compiled := compiledFirewallRule{
			network: strings.ToLower(strings.TrimSpace(rule.Network)),
			peer:    compileFirewallHostSelector(rule.Hosts),
			local:   compileFirewallHostSelector(rule.LocalHosts),
			ports:   append([]uint16(nil), rule.Ports...),
			ranges:  append([]FirewallPortRange(nil), rule.PortRanges...),
		}
		compiled.ipVersion, compiled.ipProtocol, compiled.matchesIP =
			compileFirewallIPSelector(compiled.network)
		out = append(out, compiled)
	}
	return out
}

func compileFirewallHostSelector(
	hosts []string,
) compiledFirewallHostSelector {
	compiled := compiledFirewallHostSelector{any: len(hosts) == 0}
	for _, raw := range hosts {
		host := trimDot(strings.ToLower(raw))
		if host == "*" {
			compiled.any = true
			continue
		}
		ipHost := strings.Trim(host, "[]")
		if withoutZone, _, ok := strings.Cut(ipHost, "%"); ok {
			ipHost = withoutZone
		}
		if addr, err := netip.ParseAddr(ipHost); err == nil {
			compiled.addrs = append(
				compiled.addrs,
				normalizeFirewallAddr(addr),
			)
			continue
		}
		if prefix, err := netip.ParsePrefix(host); err == nil {
			compiled.prefixes = append(
				compiled.prefixes,
				canonicalFirewallPrefix(prefix),
			)
			continue
		}
		if host != "" {
			compiled.hosts = append(compiled.hosts, host)
		}
	}
	return compiled
}

// Clone returns an independent copy of the policy in cfg. It retains the same
// DNSCache because the cache is shared runtime state.
func (cfg *FirewallConfig) Clone() *FirewallConfig {
	return cloneFirewallConfig(cfg)
}

// BlocksOutgoing reports whether Exclude denies an outgoing endpoint.
func (cfg *FirewallConfig) BlocksOutgoing(network, address string) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.exclude == nil && len(compiled.Exclude) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	host, port := splitFirewallEndpoint(network, address)
	return matchFirewallRules(
		compiled.exclude,
		network,
		host,
		port,
		compiled.DNSCache,
	)
}

// BlocksOutgoingAddrPort reports whether Exclude denies a numeric outgoing
// endpoint. It avoids text conversion when the caller already has an AddrPort.
func (cfg *FirewallConfig) BlocksOutgoingAddrPort(
	network string,
	address netip.AddrPort,
) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.exclude == nil && len(compiled.Exclude) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	return matchFirewallAddrRules(
		compiled.exclude,
		network,
		address.Addr(),
		address.Port(),
		compiled.DNSCache,
	)
}

// BlocksOutgoingIP reports whether Exclude denies an outgoing IP packet.
// address contains the destination address and destination transport port.
// protocol is the IP protocol number.
func (cfg *FirewallConfig) BlocksOutgoingIP(
	protocol uint8,
	address netip.AddrPort,
) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.exclude == nil && len(compiled.Exclude) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	return matchFirewallIPRules(
		compiled.exclude,
		protocol,
		address,
		compiled.DNSCache,
	)
}

// AllowsIncoming reports whether Include permits incoming traffic.
//
// address contains the peer host and local service port. If localAddress is
// present, address and localAddress are the peer and local endpoints, and the
// local endpoint supplies the service port. Rules that use LocalHosts do not
// match when localAddress is absent.
func (cfg *FirewallConfig) AllowsIncoming(
	network, address string,
	localAddress ...string,
) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.include == nil && len(compiled.Include) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	host, port := splitFirewallEndpoint(network, address)
	if len(localAddress) == 0 {
		return matchIncomingFirewallRules(
			compiled.include,
			network,
			host,
			"",
			port,
			false,
			compiled.DNSCache,
		)
	}
	localHost, localPort := splitFirewallEndpoint(network, localAddress[0])
	return matchIncomingFirewallRules(
		compiled.include,
		network,
		host,
		localHost,
		localPort,
		true,
		compiled.DNSCache,
	)
}

// AllowsIncomingAddrPort reports whether Include permits numeric incoming
// traffic.
//
// address contains the peer address and local service port. If localAddress is
// present, address and localAddress are the peer and local endpoints, and the
// local endpoint supplies the service port. Rules that use LocalHosts do not
// match when localAddress is absent.
func (cfg *FirewallConfig) AllowsIncomingAddrPort(
	network string,
	address netip.AddrPort,
	localAddress ...netip.AddrPort,
) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.include == nil && len(compiled.Include) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	if len(localAddress) == 0 {
		return matchIncomingFirewallAddrRules(
			compiled.include,
			network,
			address.Addr(),
			netip.Addr{},
			address.Port(),
			false,
			compiled.DNSCache,
		)
	}
	return matchIncomingFirewallAddrRules(
		compiled.include,
		network,
		address.Addr(),
		localAddress[0].Addr(),
		localAddress[0].Port(),
		true,
		compiled.DNSCache,
	)
}

// AllowsIncomingIP reports whether Include permits an incoming IP packet.
// address contains the peer address and the local transport port. If
// localAddress is present, address and localAddress are the peer and local
// endpoints, and the local endpoint supplies the transport port. protocol is
// the IP protocol number. Rules that use LocalHosts do not match when
// localAddress is absent.
func (cfg *FirewallConfig) AllowsIncomingIP(
	protocol uint8,
	address netip.AddrPort,
	localAddress ...netip.AddrPort,
) bool {
	compiled := cfg
	if compiled == nil ||
		compiled.include == nil && len(compiled.Include) != 0 {
		compiled = cloneFirewallConfig(cfg)
	}
	if len(localAddress) == 0 {
		return matchIncomingFirewallIPRules(
			compiled.include,
			protocol,
			address,
			netip.AddrPort{},
			false,
			compiled.DNSCache,
		)
	}
	return matchIncomingFirewallIPRules(
		compiled.include,
		protocol,
		address,
		localAddress[0],
		true,
		compiled.DNSCache,
	)
}

func (cfg *FirewallConfig) responseTTL() time.Duration {
	if cfg == nil || cfg.ResponseTTL <= 0 {
		return defaultFirewallResponseTTL
	}
	return cfg.ResponseTTL
}

func splitFirewallEndpoint(network, address string) (string, uint16) {
	host, port := SplitHostPort(network, address, 0)
	return strings.Trim(host, "[]"), port
}

func matchFirewallRules(
	rules []compiledFirewallRule,
	network, host string,
	port uint16,
	dnsCache FirewallDNSCache,
) bool {
	network = normalizeFirewallNetwork(network)
	var endpoint firewallHost
	endpointReady := false
	for i := range rules {
		rule := &rules[i]
		if !firewallNetworkMatches(rule.network, network) ||
			!rule.portMatches(port) {
			continue
		}
		if rule.peer.any {
			return true
		}
		if !endpointReady {
			endpoint = parseFirewallHost(host)
			endpointReady = true
		}
		if rule.peer.matches(&endpoint, dnsCache) {
			return true
		}
	}
	return false
}

func matchFirewallAddrRules(
	rules []compiledFirewallRule,
	network string,
	addr netip.Addr,
	port uint16,
	dnsCache FirewallDNSCache,
) bool {
	network = normalizeFirewallNetwork(network)
	addr = normalizeFirewallAddr(addr)
	endpoint := firewallHost{addr: addr}
	for i := range rules {
		rule := &rules[i]
		if firewallNetworkMatches(rule.network, network) &&
			rule.portMatches(port) &&
			(rule.peer.any || rule.peer.matches(&endpoint, dnsCache)) {
			return true
		}
	}
	return false
}

func matchFirewallIPRules(
	rules []compiledFirewallRule,
	protocol uint8,
	address netip.AddrPort,
	dnsCache FirewallDNSCache,
) bool {
	addr := normalizeFirewallAddr(address.Addr())
	if !addr.IsValid() {
		return false
	}
	version := uint8(6)
	if addr.Is4() {
		version = 4
	}
	endpoint := firewallHost{addr: addr}
	for i := range rules {
		rule := &rules[i]
		if rule.matchesIP &&
			(rule.ipVersion == 0 || rule.ipVersion == version) &&
			rule.ipProtocolMatches(version, protocol) &&
			rule.portMatches(address.Port()) &&
			(rule.peer.any || rule.peer.matches(&endpoint, dnsCache)) {
			return true
		}
	}
	return false
}

func matchIncomingFirewallRules(
	rules []compiledFirewallRule,
	network, peerHost, localHost string,
	port uint16,
	localKnown bool,
	dnsCache FirewallDNSCache,
) bool {
	network = normalizeFirewallNetwork(network)
	var peer, local firewallHost
	peerReady, localReady := false, false
	for i := range rules {
		rule := &rules[i]
		if !firewallNetworkMatches(rule.network, network) ||
			!rule.portMatches(port) {
			continue
		}
		if !rule.local.any {
			if !localKnown {
				continue
			}
			if !localReady {
				local = parseFirewallHost(localHost)
				localReady = true
			}
			if !rule.local.matches(&local, dnsCache) {
				continue
			}
		}
		if rule.peer.any {
			return true
		}
		if !peerReady {
			peer = parseFirewallHost(peerHost)
			peerReady = true
		}
		if rule.peer.matches(&peer, dnsCache) {
			return true
		}
	}
	return false
}

func matchIncomingFirewallAddrRules(
	rules []compiledFirewallRule,
	network string,
	peer, local netip.Addr,
	port uint16,
	localKnown bool,
	dnsCache FirewallDNSCache,
) bool {
	network = normalizeFirewallNetwork(network)
	peer = normalizeFirewallAddr(peer)
	peerEndpoint := firewallHost{addr: peer}
	localEndpoint := firewallHost{}
	if localKnown {
		local = normalizeFirewallAddr(local)
		localEndpoint.addr = local
	}
	for i := range rules {
		rule := &rules[i]
		if !firewallNetworkMatches(rule.network, network) ||
			!rule.portMatches(port) {
			continue
		}
		if !rule.local.any && (!localKnown ||
			!rule.local.matches(&localEndpoint, dnsCache)) {
			continue
		}
		if rule.peer.any || rule.peer.matches(&peerEndpoint, dnsCache) {
			return true
		}
	}
	return false
}

func matchIncomingFirewallIPRules(
	rules []compiledFirewallRule,
	protocol uint8,
	peer, local netip.AddrPort,
	localKnown bool,
	dnsCache FirewallDNSCache,
) bool {
	peerAddr := normalizeFirewallAddr(peer.Addr())
	if !peerAddr.IsValid() {
		return false
	}
	localAddr := netip.Addr{}
	port := peer.Port()
	versionAddr := peerAddr
	if localKnown {
		localAddr = normalizeFirewallAddr(local.Addr())
		if !localAddr.IsValid() {
			return false
		}
		port = local.Port()
		versionAddr = localAddr
	}
	version := uint8(6)
	if versionAddr.Is4() {
		version = 4
	}
	peerEndpoint := firewallHost{addr: peerAddr}
	localEndpoint := firewallHost{addr: localAddr}
	for i := range rules {
		rule := &rules[i]
		if !rule.matchesIP ||
			(rule.ipVersion != 0 && rule.ipVersion != version) ||
			!rule.ipProtocolMatches(version, protocol) ||
			!rule.portMatches(port) {
			continue
		}
		if !rule.local.any && (!localKnown ||
			!rule.local.matches(&localEndpoint, dnsCache)) {
			continue
		}
		if rule.peer.any || rule.peer.matches(&peerEndpoint, dnsCache) {
			return true
		}
	}
	return false
}

func (rule *compiledFirewallRule) ipProtocolMatches(
	version, protocol uint8,
) bool {
	switch rule.ipProtocol {
	case anyFirewallIPProtocol:
		return true
	case icmpFirewallIPProtocol:
		return version == 4 && protocol == 1 ||
			version == 6 && protocol == 58
	default:
		return rule.ipProtocol == uint16(protocol)
	}
}

type firewallHost struct {
	name         string
	addr         netip.Addr
	reverseDone  bool
	reverseNames []string
}

func parseFirewallHost(host string) firewallHost {
	normalized := trimDot(strings.ToLower(strings.Trim(host, "[]")))
	if withoutZone, _, ok := strings.Cut(normalized, "%"); ok {
		normalized = withoutZone
	}
	if !firewallHostMayBeAddr(normalized) {
		return firewallHost{name: normalized}
	}
	addr, err := netip.ParseAddr(normalized)
	if err != nil {
		return firewallHost{name: normalized}
	}
	return firewallHost{addr: normalizeFirewallAddr(addr)}
}

func firewallHostMayBeAddr(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	if host == "" {
		return false
	}
	for _, char := range host {
		if char != '.' && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func normalizeFirewallAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr
}

func (selector *compiledFirewallHostSelector) matches(
	host *firewallHost,
	dnsCache FirewallDNSCache,
) bool {
	if host == nil {
		return false
	}
	if host.addr.IsValid() {
		if selector.addrMatches(host.addr) {
			return true
		}
		if len(selector.hosts) == 0 {
			return false
		}
		for _, name := range host.cachedNames(dnsCache) {
			if selector.nameMatches(name) {
				return true
			}
		}
		return false
	}
	return selector.nameMatches(host.name)
}

func (selector *compiledFirewallHostSelector) nameMatches(name string) bool {
	name = trimDot(strings.ToLower(name))
	if name == "" {
		return false
	}
	for _, pattern := range selector.hosts {
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

func (host *firewallHost) cachedNames(
	dnsCache FirewallDNSCache,
) []string {
	if host == nil || dnsCache == nil || !host.addr.IsValid() {
		return nil
	}
	if !host.reverseDone {
		host.reverseDone = true
		host.reverseNames = dnsCache.ReverseDNSNames(host.addr, time.Now())
	}
	return host.reverseNames
}

func (selector *compiledFirewallHostSelector) addrMatches(
	addr netip.Addr,
) bool {
	for _, candidate := range selector.addrs {
		if candidate == addr {
			return true
		}
	}
	for _, prefix := range selector.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (rule *compiledFirewallRule) portMatches(port uint16) bool {
	if len(rule.ports) == 0 && len(rule.ranges) == 0 {
		return true
	}
	for _, candidate := range rule.ports {
		if candidate == port {
			return true
		}
	}
	for _, candidate := range rule.ranges {
		first, last := candidate.First, candidate.Last
		if last < first {
			first, last = last, first
		}
		if port >= first && port <= last {
			return true
		}
	}
	return false
}

func firewallNetworkMatches(rule, network string) bool {
	if rule == "" || rule == "*" || rule == network {
		return true
	}
	if rule == "ip" {
		return firewallIPNetwork(network)
	}
	if rule == "ip4" {
		return network == "tcp4" || network == "udp4" ||
			network == "icmp4" || strings.HasPrefix(network, "ip4:")
	}
	if rule == "ip6" {
		return network == "tcp6" || network == "udp6" ||
			network == "icmp6" || strings.HasPrefix(network, "ip6:")
	}
	if rule == "tcp" {
		return network == "tcp4" || network == "tcp6"
	}
	if rule == "udp" {
		return network == "udp4" || network == "udp6"
	}
	if rule == "icmp" {
		return network == "icmp4" || network == "icmp6"
	}
	if strings.HasPrefix(rule, "ip:") {
		protocol := strings.TrimPrefix(rule, "ip:")
		return network == "ip4:"+protocol || network == "ip6:"+protocol
	}
	return false
}

func normalizeFirewallNetwork(network string) string {
	return strings.ToLower(strings.TrimSpace(network))
}

func compileFirewallIPSelector(network string) (uint8, uint16, bool) {
	switch network {
	case "", "*", "ip":
		return 0, anyFirewallIPProtocol, true
	case "ip4":
		return 4, anyFirewallIPProtocol, true
	case "ip6":
		return 6, anyFirewallIPProtocol, true
	case "tcp":
		return 0, 6, true
	case "tcp4":
		return 4, 6, true
	case "tcp6":
		return 6, 6, true
	case "udp":
		return 0, 17, true
	case "udp4":
		return 4, 17, true
	case "udp6":
		return 6, 17, true
	case "icmp":
		return 0, icmpFirewallIPProtocol, true
	case "icmp4":
		return 4, 1, true
	case "icmp6":
		return 6, 58, true
	}

	version := uint8(0)
	var protocolText string
	switch {
	case strings.HasPrefix(network, "ip:"):
		protocolText = strings.TrimPrefix(network, "ip:")
	case strings.HasPrefix(network, "ip4:"):
		version = 4
		protocolText = strings.TrimPrefix(network, "ip4:")
	case strings.HasPrefix(network, "ip6:"):
		version = 6
		protocolText = strings.TrimPrefix(network, "ip6:")
	default:
		return 0, 0, false
	}
	protocol, err := strconv.ParseUint(protocolText, 10, 8)
	if err != nil {
		return 0, 0, false
	}
	return version, uint16(protocol), true
}

func firewallIPNetwork(network string) bool {
	return network == "ip4" || network == "ip6" ||
		strings.HasPrefix(network, "tcp") ||
		strings.HasPrefix(network, "udp") ||
		strings.HasPrefix(network, "icmp") ||
		strings.HasPrefix(network, "ip:") ||
		strings.HasPrefix(network, "ip4:") ||
		strings.HasPrefix(network, "ip6:")
}
