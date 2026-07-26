package gonnect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
)

var _ interface {
	Network
	UpDown
	io.Closer
	CloserSubscriber
	UpDownSubscriber
	Wrapper
} = (*Remapper)(nil)

// RemapEndpoint identifies which endpoint address a RemapRule can change.
//
// Dial and PacketDial expose only a destination endpoint. DialTCP and DialUDP
// expose both source and destination endpoints when their laddr argument is
// non-empty. Listen, ListenTCP, ListenPacket, ListenUDP, ListenPacketConfig,
// ListenUDPConfig, and ListenMulticastUDP expose their listen address as a
// source endpoint.
type RemapEndpoint int

const (
	// RemapDst selects the destination address of a dial-style operation.
	RemapDst RemapEndpoint = iota
	// RemapSrc selects the source address of a listen-style operation, or the
	// non-empty local address of DialTCP and DialUDP.
	RemapSrc
)

// RemapField identifies which part of an endpoint address a RemapRule changes.
type RemapField int

const (
	// RemapAddrPort replaces the whole endpoint with net.JoinHostPort using
	// RemapRule.Addr and RemapRule.Port.
	RemapAddrPort RemapField = iota
	// RemapAddr replaces only the host/address part. If the current endpoint is
	// a valid host:port pair, its port is preserved; otherwise the whole
	// endpoint becomes RemapRule.Addr.
	RemapAddr
	// RemapPort replaces only the port part. If the current endpoint is not a
	// valid host:port pair, the rule leaves it unchanged.
	RemapPort
)

// RemapOperation names the Network method currently being remapped.
//
// These values intentionally match the corresponding Network method names.
type RemapOperation string

const (
	// RemapOpDial identifies Remapper.Dial.
	RemapOpDial RemapOperation = "Dial"
	// RemapOpListen identifies Remapper.Listen.
	RemapOpListen RemapOperation = "Listen"
	// RemapOpPacketDial identifies Remapper.PacketDial.
	RemapOpPacketDial RemapOperation = "PacketDial"
	// RemapOpListenPacket identifies Remapper.ListenPacket.
	RemapOpListenPacket RemapOperation = "ListenPacket"
	// RemapOpDialTCP identifies Remapper.DialTCP.
	RemapOpDialTCP RemapOperation = "DialTCP"
	// RemapOpListenTCP identifies Remapper.ListenTCP.
	RemapOpListenTCP RemapOperation = "ListenTCP"
	// RemapOpDialUDP identifies Remapper.DialUDP.
	RemapOpDialUDP RemapOperation = "DialUDP"
	// RemapOpListenUDP identifies Remapper.ListenUDP.
	RemapOpListenUDP RemapOperation = "ListenUDP"
	// RemapOpListenPacketConfig identifies Remapper.ListenPacketConfig.
	RemapOpListenPacketConfig RemapOperation = "ListenPacketConfig"
	// RemapOpListenUDPConfig identifies Remapper.ListenUDPConfig.
	RemapOpListenUDPConfig RemapOperation = "ListenUDPConfig"
	// RemapOpListenMulticastUDP identifies Remapper.ListenMulticastUDP.
	RemapOpListenMulticastUDP RemapOperation = "ListenMulticastUDP"
)

// RemapInfo is passed to RemapFilter while a rule is being evaluated.
//
// Network is the current network string after any earlier matching rules have
// adjusted it. Address is the current value of the endpoint selected by the
// rule. SrcAddr and DstAddr contain the current source and destination strings;
// the unused endpoint for an operation is empty.
type RemapInfo struct {
	Operation RemapOperation
	Network   string
	Endpoint  RemapEndpoint
	Address   string
	SrcAddr   string
	DstAddr   string
}

// RemapFilter decides whether a RemapRule applies to a candidate endpoint.
//
// Filters must be syntactic. Remapper never resolves host names or service
// names before calling a filter.
type RemapFilter func(info RemapInfo) bool

// RemapAddressFilter adapts the package-level Filter type for use in RemapRule.
//
// The adapted filter receives RemapInfo.Network and RemapInfo.Address. This is
// useful with FilterFromString for rules that only need to match the current
// endpoint address:
//
//	rules := []gonnect.RemapRule{{
//		Filter:   gonnect.RemapAddressFilter(gonnect.FilterFromString("example.com:80").Filter),
//		Endpoint: gonnect.RemapDst,
//		Field:    gonnect.RemapAddrPort,
//		Addr:     "100.100.100.100",
//		Port:     "8080",
//	}}
func RemapAddressFilter(filter Filter) RemapFilter {
	if filter == nil {
		return nil
	}
	return func(info RemapInfo) bool {
		return filter(info.Network, info.Address)
	}
}

// RemapRule describes one syntactic address rewrite.
//
// Rules are evaluated in constructor order, and every matching rule applies.
// Later rules see the addresses left by earlier rules, so callers can compose
// rules such as "change destination host" followed by "change destination port".
// When multiple matching rules change the same field, the later rule wins.
//
// A nil Filter matches every available endpoint of the selected Endpoint type.
// Source endpoints are unavailable for Dial, PacketDial, and DialTCP/DialUDP
// calls with an empty laddr; source rules are skipped for those cases.
//
// Addr is a host/address string, not a host:port pair, for RemapAddr and
// RemapAddrPort. Port is a decimal port or service string. Remapper does not
// validate either field and does not call LookupHost or LookupPort; validation
// is left to the wrapped Network.
//
// If a rule changes Addr to an IP literal and the current network is exactly
// tcp4, tcp6, udp4, udp6, ip4, or ip6, Remapper changes that family suffix to
// match the new literal address. Generic networks such as tcp and udp, unknown
// networks, service names, and host names are left unchanged because Remapper
// performs no address resolution.
type RemapRule struct {
	Filter   RemapFilter
	Endpoint RemapEndpoint
	Field    RemapField
	Addr     string
	Port     string
}

// Remapper is a Network middleware that rewrites operation address arguments.
//
// Remapper is intentionally a syntactic wrapper. It never resolves host names
// or service names while remapping Dial, Listen, TCP, UDP, or multicast
// operations. Lookup methods are delegated unchanged to the wrapped Network.
//
// Lifecycle calls are delegated when the wrapped Network implements the
// matching optional interface. If it does not, Close, Up, Down,
// SubscribeCloser, and SubscribeUpDown are no-ops, and IsUp reports true.
// IsNative always reports false because Remapper can change operation targets.
type Remapper struct {
	network Network
	rules   []RemapRule
}

// NewRemapper wraps network with the provided remapping rules.
//
// The rules slice is copied, so later changes to the caller's slice do not
// change this Remapper. The rules themselves should still be treated as
// immutable if their Filter functions close over mutable state.
func NewRemapper(network Network, rules []RemapRule) *Remapper {
	return &Remapper{
		network: network,
		rules:   append([]RemapRule(nil), rules...),
	}
}

// GetWrapped returns the wrapped Network.
func (n *Remapper) GetWrapped() any { return n.network }

// GetNetwork returns the wrapped Network.
func (n *Remapper) GetNetwork() Network { return n.network }

// GetRules returns a copy of the rules configured on this Remapper.
func (n *Remapper) GetRules() []RemapRule {
	return append([]RemapRule(nil), n.rules...)
}

// IsNative always reports false because Remapper mutates Network operations.
func (n *Remapper) IsNative() bool { return false }

// Close closes the wrapped Network when it implements io.Closer.
func (n *Remapper) Close() error {
	if closer, ok := n.network.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (n *Remapper) SubscribeCloser(c io.Closer) (func(), error) {
	if sub, ok := n.network.(CloserSubscriber); ok {
		return sub.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements UpDown.
func (n *Remapper) Up() error {
	if updown, ok := n.network.(UpDown); ok {
		return updown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements UpDown.
func (n *Remapper) Down() error {
	if updown, ok := n.network.(UpDown); ok {
		return updown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements UpDown.
func (n *Remapper) IsUp() (bool, error) {
	if updown, ok := n.network.(UpDown); ok {
		return updown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (n *Remapper) SubscribeUpDown(u UpDown) (func(), error) {
	if sub, ok := n.network.(UpDownSubscriber); ok {
		return sub.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial remaps the destination address and forwards the call.
func (n *Remapper) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	network, _, address = n.remap(
		RemapOpDial,
		network,
		"", false,
		address, true,
	)
	return n.network.Dial(ctx, network, address)
}

// Listen remaps the source listen address and forwards the call.
func (n *Remapper) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	network, address, _ = n.remap(
		RemapOpListen,
		network,
		address, true,
		"", false,
	)
	return n.network.Listen(ctx, network, address)
}

// PacketDial remaps the destination address and forwards the call.
func (n *Remapper) PacketDial(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	network, _, address = n.remap(
		RemapOpPacketDial,
		network,
		"", false,
		address, true,
	)
	return n.network.PacketDial(ctx, network, address)
}

// ListenPacket remaps the source listen address and forwards the call.
func (n *Remapper) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	network, address, _ = n.remap(
		RemapOpListenPacket,
		network,
		address, true,
		"", false,
	)
	return n.network.ListenPacket(ctx, network, address)
}

// DialTCP remaps the non-empty local source address and remote destination
// address, then forwards the call.
func (n *Remapper) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	network, laddr, raddr = n.remap(
		RemapOpDialTCP,
		network,
		laddr, laddr != "",
		raddr, true,
	)
	return n.network.DialTCP(ctx, network, laddr, raddr)
}

// ListenTCP remaps the source listen address and forwards the call.
func (n *Remapper) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	network, laddr, _ = n.remap(
		RemapOpListenTCP,
		network,
		laddr, true,
		"", false,
	)
	return n.network.ListenTCP(ctx, network, laddr)
}

// DialUDP remaps the non-empty local source address and remote destination
// address, then forwards the call.
func (n *Remapper) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	network, laddr, raddr = n.remap(
		RemapOpDialUDP,
		network,
		laddr, laddr != "",
		raddr, true,
	)
	return n.network.DialUDP(ctx, network, laddr, raddr)
}

// ListenUDP remaps the source listen address and forwards the call.
func (n *Remapper) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	network, laddr, _ = n.remap(
		RemapOpListenUDP,
		network,
		laddr, true,
		"", false,
	)
	return n.network.ListenUDP(ctx, network, laddr)
}

// ListenPacketConfig remaps the source listen address and forwards the call.
func (n *Remapper) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	network, address, _ = n.remap(
		RemapOpListenPacketConfig,
		network,
		address, true,
		"", false,
	)
	return n.network.ListenPacketConfig(ctx, lc, network, address)
}

// ListenUDPConfig remaps the source listen address and forwards the call.
func (n *Remapper) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	network, laddr, _ = n.remap(
		RemapOpListenUDPConfig,
		network,
		laddr, true,
		"", false,
	)
	return n.network.ListenUDPConfig(ctx, lc, network, laddr)
}

// ListenMulticastUDP remaps the source multicast listen address and forwards
// the call.
func (n *Remapper) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	network, address, _ = n.remap(
		RemapOpListenMulticastUDP,
		network,
		address, true,
		"", false,
	)
	return n.network.ListenMulticastUDP(ctx, network, address, opts)
}

// LookupIP delegates to the wrapped Network.
func (n *Remapper) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return n.network.LookupIP(ctx, network, address)
}

// LookupIPAddr delegates to the wrapped Network.
func (n *Remapper) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return n.network.LookupIPAddr(ctx, host)
}

// LookupNetIP delegates to the wrapped Network.
func (n *Remapper) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return n.network.LookupNetIP(ctx, network, host)
}

// LookupHost delegates to the wrapped Network.
func (n *Remapper) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return n.network.LookupHost(ctx, host)
}

// LookupAddr delegates to the wrapped Network.
func (n *Remapper) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return n.network.LookupAddr(ctx, addr)
}

// LookupCNAME delegates to the wrapped Network.
func (n *Remapper) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return n.network.LookupCNAME(ctx, host)
}

// LookupPort delegates to the wrapped Network.
func (n *Remapper) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return n.network.LookupPort(ctx, network, service)
}

// LookupNS delegates to the wrapped Network.
func (n *Remapper) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return n.network.LookupNS(ctx, name)
}

// LookupMX delegates to the wrapped Network.
func (n *Remapper) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return n.network.LookupMX(ctx, name)
}

// LookupSRV delegates to the wrapped Network.
func (n *Remapper) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return n.network.LookupSRV(ctx, service, proto, name)
}

// LookupTXT delegates to the wrapped Network.
func (n *Remapper) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return n.network.LookupTXT(ctx, name)
}

// Interfaces forwards the call to the wrapped Network.
func (n *Remapper) Interfaces() ([]NetworkInterface, error) {
	return n.network.Interfaces()
}

// InterfaceAddrs forwards the call to the wrapped Network.
func (n *Remapper) InterfaceAddrs() ([]net.Addr, error) {
	return n.network.InterfaceAddrs()
}

// InterfaceMulticastAddrs forwards the call to the wrapped Network.
func (n *Remapper) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return n.network.InterfaceMulticastAddrs()
}

// InterfacesByIndex forwards the call to the wrapped Network.
func (n *Remapper) InterfacesByIndex(
	index int,
) ([]NetworkInterface, error) {
	return n.network.InterfacesByIndex(index)
}

// InterfacesByName forwards the call to the wrapped Network.
func (n *Remapper) InterfacesByName(
	name string,
) ([]NetworkInterface, error) {
	return n.network.InterfacesByName(name)
}

func (n *Remapper) remap(
	op RemapOperation,
	network string,
	src string,
	hasSrc bool,
	dst string,
	hasDst bool,
) (string, string, string) {
	for _, rule := range n.rules {
		info := RemapInfo{
			Operation: op,
			Network:   network,
			Endpoint:  rule.Endpoint,
			SrcAddr:   src,
			DstAddr:   dst,
		}

		var current string
		switch rule.Endpoint {
		case RemapSrc:
			if !hasSrc {
				continue
			}
			current = src
		case RemapDst:
			if !hasDst {
				continue
			}
			current = dst
		default:
			continue
		}
		info.Address = current

		if rule.Filter != nil && !rule.Filter(info) {
			continue
		}

		next, changedAddr := remapAddress(current, rule)
		switch rule.Endpoint {
		case RemapSrc:
			src = next
		case RemapDst:
			dst = next
		}
		if changedAddr {
			network = remapNetworkForHost(network, rule.Addr)
		}
	}
	return network, src, dst
}

func remapAddress(address string, rule RemapRule) (string, bool) {
	switch rule.Field {
	case RemapAddrPort:
		return net.JoinHostPort(rule.Addr, rule.Port), true
	case RemapAddr:
		_, port, ok := remapSplitHostPort(address)
		if !ok {
			return rule.Addr, true
		}
		return net.JoinHostPort(rule.Addr, port), true
	case RemapPort:
		host, _, ok := remapSplitHostPort(address)
		if !ok {
			return address, false
		}
		return net.JoinHostPort(host, rule.Port), false
	default:
		return address, false
	}
}

func remapSplitHostPort(address string) (string, string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}

func remapNetworkForHost(network, host string) string {
	family := remapHostFamily(host)
	if family == "" {
		return network
	}

	switch network {
	case "tcp4", "tcp6":
		return "tcp" + family
	case "udp4", "udp6":
		return "udp" + family
	case "ip4", "ip6":
		return "ip" + family
	default:
		return network
	}
}

func remapHostFamily(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if h, _, ok := strings.Cut(host, "%"); ok {
		host = h
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if addr.Is4() {
		return "4"
	}
	if addr.Is6() {
		return "6"
	}
	return ""
}
