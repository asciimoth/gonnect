package gonnect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
)

var _ interface {
	Network
	UpDown
	io.Closer
	CloserSubscriber
	UpDownSubscriber
	Wrapper
} = (*NetworkWithResolver)(nil)

// NetworkWithResolver is a Network middleware that uses a separate Resolver for
// name resolution while forwarding network operations to another Network.
//
// Lookup methods are served by the wrapped Resolver. If the Resolver is nil,
// lookups are forwarded to the wrapped Network instead.
//
// Dial, Listen, and packet/TCP/UDP methods resolve address arguments before
// calling the wrapped Network. Host names are resolved with LookupHost and
// service names are resolved with LookupPort; IP literal hosts and numeric ports
// are passed through unchanged. The resolved address passed downstream always
// has numeric host and port components. Empty addresses are left unchanged so
// methods that accept an optional local address keep their usual semantics.
//
// Lifecycle calls are delegated when the wrapped Network implements the
// matching optional interface. If it does not, Close, Up, Down,
// SubscribeCloser, and SubscribeUpDown are no-ops, and IsUp reports true.
type NetworkWithResolver struct {
	network  Network
	resolver Resolver
}

// NewNetworkWithResolver wraps network with resolver-backed name resolution.
func NewNetworkWithResolver(
	network Network,
	resolver Resolver,
) *NetworkWithResolver {
	return &NetworkWithResolver{network: network, resolver: resolver}
}

// GetWrapped returns the wrapped Network.
func (n *NetworkWithResolver) GetWrapped() any { return n.network }

// GetNetwork returns the wrapped Network.
func (n *NetworkWithResolver) GetNetwork() Network { return n.network }

// GetResolver returns the Resolver used by this wrapper.
func (n *NetworkWithResolver) GetResolver() Resolver { return n.resolver }

// IsNative reports the wrapped Network native status.
func (n *NetworkWithResolver) IsNative() bool { return n.network.IsNative() }

// Close closes the wrapped Network when it implements io.Closer.
func (n *NetworkWithResolver) Close() error {
	if closer, ok := n.network.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (n *NetworkWithResolver) SubscribeCloser(c io.Closer) (func(), error) {
	if sub, ok := n.network.(CloserSubscriber); ok {
		return sub.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements UpDown.
func (n *NetworkWithResolver) Up() error {
	if updown, ok := n.network.(UpDown); ok {
		return updown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements UpDown.
func (n *NetworkWithResolver) Down() error {
	if updown, ok := n.network.(UpDown); ok {
		return updown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements UpDown.
func (n *NetworkWithResolver) IsUp() (bool, error) {
	if updown, ok := n.network.(UpDown); ok {
		return updown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (n *NetworkWithResolver) SubscribeUpDown(u UpDown) (func(), error) {
	if sub, ok := n.network.(UpDownSubscriber); ok {
		return sub.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial resolves address and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.Dial(ctx, network, address)
}

// Listen resolves address and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.Listen(ctx, network, address)
}

// PacketDial resolves address and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) PacketDial(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.PacketDial(ctx, network, address)
}

// ListenPacket resolves address and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.ListenPacket(ctx, network, address)
}

// DialTCP resolves laddr and raddr and forwards the call to the wrapped
// Network.
func (n *NetworkWithResolver) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	var err error
	laddr, err = n.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	raddr, err = n.resolveNetAddr(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	return n.network.DialTCP(ctx, network, laddr, raddr)
}

// ListenTCP resolves laddr and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	laddr, err := n.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return n.network.ListenTCP(ctx, network, laddr)
}

// DialUDP resolves laddr and raddr and forwards the call to the wrapped
// Network.
func (n *NetworkWithResolver) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	var err error
	laddr, err = n.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	raddr, err = n.resolveNetAddr(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	return n.network.DialUDP(ctx, network, laddr, raddr)
}

// ListenUDP resolves laddr and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	laddr, err := n.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return n.network.ListenUDP(ctx, network, laddr)
}

// ListenPacketConfig resolves address and forwards the call to the wrapped
// Network.
func (n *NetworkWithResolver) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.ListenPacketConfig(ctx, lc, network, address)
}

// ListenUDPConfig resolves laddr and forwards the call to the wrapped Network.
func (n *NetworkWithResolver) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	laddr, err := n.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return n.network.ListenUDPConfig(ctx, lc, network, laddr)
}

// ListenMulticastUDP resolves address and forwards the call to the wrapped
// Network.
func (n *NetworkWithResolver) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	address, err := n.resolveNetAddr(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.network.ListenMulticastUDP(ctx, network, address, opts)
}

// LookupIP delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return n.lookupResolver().LookupIP(ctx, network, address)
}

// LookupIPAddr delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return n.lookupResolver().LookupIPAddr(ctx, host)
}

// LookupNetIP delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return n.lookupResolver().LookupNetIP(ctx, network, host)
}

// LookupHost delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return n.lookupResolver().LookupHost(ctx, host)
}

// LookupAddr delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return n.lookupResolver().LookupAddr(ctx, addr)
}

// LookupCNAME delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return n.lookupResolver().LookupCNAME(ctx, host)
}

// LookupPort delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return n.lookupResolver().LookupPort(ctx, network, service)
}

// LookupNS delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return n.lookupResolver().LookupNS(ctx, name)
}

// LookupMX delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return n.lookupResolver().LookupMX(ctx, name)
}

// LookupSRV delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return n.lookupResolver().LookupSRV(ctx, service, proto, name)
}

// LookupTXT delegates to the wrapped Resolver.
func (n *NetworkWithResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return n.lookupResolver().LookupTXT(ctx, name)
}

// Interfaces forwards the call to the wrapped Network.
func (n *NetworkWithResolver) Interfaces() ([]NetworkInterface, error) {
	return n.network.Interfaces()
}

// InterfaceAddrs forwards the call to the wrapped Network.
func (n *NetworkWithResolver) InterfaceAddrs() ([]net.Addr, error) {
	return n.network.InterfaceAddrs()
}

// InterfaceMulticastAddrs forwards the call to the wrapped Network.
func (n *NetworkWithResolver) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return n.network.InterfaceMulticastAddrs()
}

// InterfacesByIndex forwards the call to the wrapped Network.
func (n *NetworkWithResolver) InterfacesByIndex(
	index int,
) ([]NetworkInterface, error) {
	return n.network.InterfacesByIndex(index)
}

// InterfacesByName forwards the call to the wrapped Network.
func (n *NetworkWithResolver) InterfacesByName(
	name string,
) ([]NetworkInterface, error) {
	return n.network.InterfacesByName(name)
}

func (n *NetworkWithResolver) lookupResolver() Resolver {
	if n.resolver != nil {
		return n.resolver
	}
	return n.network
}

func (n *NetworkWithResolver) resolveNetAddr(
	ctx context.Context,
	network, address string,
) (string, error) {
	if address == "" || n.resolver == nil {
		return address, nil
	}

	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}

	if _, err := strconv.Atoi(service); err != nil {
		port, err := n.resolver.LookupPort(ctx, NormalNet(network), service)
		if err != nil {
			return "", err
		}
		service = strconv.Itoa(port)
	}

	if host == "" || net.ParseIP(host) != nil {
		return net.JoinHostPort(host, service), nil
	}

	lookupHost := host
	hosts, err := n.resolver.LookupHost(ctx, lookupHost)
	if err != nil {
		return "", err
	}
	host = routerPickResolvedHost(network, hosts)
	if host == "" {
		return "", NoSuchHost(lookupHost, "resolverdns")
	}
	return net.JoinHostPort(host, service), nil
}
