package gonnect

import (
	"context"
	"net"
	"net/netip"
)

// Static type assertions
var (
	_ Network = &RejectNetwork{}
)

// RejectNetwork is a network implementation that rejects all operations with canonical errors.
// It implements gonnect.RejectNetwork.
type RejectNetwork struct{}

func (n *RejectNetwork) IsNative() bool {
	return false
}

// dialError returns an appropriate error for dial operations based on the network and address.
// It returns net.UnknownNetworkError for unknown networks, *net.AddrError for malformed addresses,
// and *net.DNSError for host not found errors.
func dialError(network, address string) error {
	// Check for unknown network first
	if !isKnownNetwork(network) {
		return net.UnknownNetworkError(network)
	}

	// Check for malformed address (missing port)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port or malformed - return AddrError
		return &net.AddrError{Err: "missing port in address", Addr: address}
	}

	// Check if host is an IP address or a hostname
	if net.ParseIP(host) != nil {
		// It's an IP address - return connection refused
		return ConnRefused(network, address)
	}

	// It's a hostname - return DNS error with just the hostname (not host:port)
	return NoSuchHost(host, "rejectdns")
}

// listenError returns an appropriate error for listen operations based on the network and address.
// It returns net.UnknownNetworkError for unknown networks and *net.AddrError for malformed addresses.
func listenError(network, address string) error {
	// Check for unknown network first
	if !isKnownNetwork(network) {
		return net.UnknownNetworkError(network)
	}

	// Check for malformed address (missing port)
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port or malformed - return AddrError
		return &net.AddrError{Err: "missing port in address", Addr: address}
	}

	// Valid format - return listen denied
	return ListenDeniedErr(network, address)
}

// isKnownNetwork returns true if the network is a known network type.
func isKnownNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		return true
	default:
		return false
	}
}

// Dial returns an appropriate error based on the network and address.
func (n *RejectNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	return nil, dialError(network, address)
}

// Listen returns an appropriate error based on the network and address.
func (n *RejectNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return nil, listenError(network, address)
}

// ListenPacket returns an appropriate error based on the network and address.
func (n *RejectNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	return nil, listenError(network, address)
}

// DialTCP returns an appropriate error based on the network and address.
func (n *RejectNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	return nil, dialError(network, raddr)
}

// ListenTCP returns an appropriate error based on the network and address.
func (n *RejectNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	return nil, listenError(network, laddr)
}

// PacketDial returns an appropriate error based on the network and address.
func (n *RejectNetwork) PacketDial(
	ctx context.Context, network, address string,
) (PacketConn, error) {
	return nil, dialError(network, address)
}

// DialUDP returns an appropriate error based on the network and address.
func (n *RejectNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	return nil, dialError(network, raddr)
}

// ListenUDP returns an appropriate error based on the network and address.
func (n *RejectNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	return nil, listenError(network, laddr)
}

// ListenPacketConfig returns an appropriate error based on the network and address.
func (n *RejectNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	return n.ListenPacket(ctx, network, address)
}

// ListenUDPConfig returns an appropriate error based on the network and address.
func (n *RejectNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	return n.ListenUDP(ctx, network, laddr)
}

func (n *RejectNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	return nil, listenError(network, address)
}

// Interfaces returns an empty slice and nil error.
func (n *RejectNetwork) Interfaces() ([]NetworkInterface, error) {
	return []NetworkInterface{}, nil
}

// InterfaceAddrs returns an empty slice and nil error.
func (n *RejectNetwork) InterfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{}, nil
}

// InterfaceMulticastAddrs returns an empty slice and nil error.
func (n *RejectNetwork) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return []net.Addr{}, nil
}

// InterfacesByIndex returns an empty slice and "interface not found" error.
func (n *RejectNetwork) InterfacesByIndex(
	index int,
) ([]NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// InterfacesByName returns an empty slice and "interface not found" error.
func (n *RejectNetwork) InterfacesByName(
	name string,
) ([]NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// LookupIP returns a NoSuchHost error.
func (n *RejectNetwork) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return nil, NoSuchHost(address, "rejectdns")
}

// LookupIPAddr returns a NoSuchHost error.
func (n *RejectNetwork) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return nil, NoSuchHost(host, "rejectdns")
}

// LookupNetIP returns a NoSuchHost error.
func (n *RejectNetwork) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return nil, NoSuchHost(host, "rejectdns")
}

// LookupHost returns a NoSuchHost error.
func (n *RejectNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return nil, NoSuchHost(host, "rejectdns")
}

// LookupAddr returns a NoSuchHost error.
func (n *RejectNetwork) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return nil, NoSuchHost(addr, "rejectdns")
}

// LookupCNAME returns a NoSuchHost error.
func (n *RejectNetwork) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return "", NoSuchHost(host, "rejectdns")
}

// LookupPort returns a NoSuchHost error for the service.
func (n *RejectNetwork) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return 0, NoSuchHost(service, "rejectdns")
}

// LookupTXT returns a NoSuchHost error.
func (n *RejectNetwork) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return nil, NoSuchHost(name, "rejectdns")
}

// LookupMX returns a NoSuchHost error.
func (n *RejectNetwork) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return nil, NoSuchHost(name, "rejectdns")
}

// LookupNS returns a NoSuchHost error.
func (n *RejectNetwork) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return nil, NoSuchHost(name, "rejectdns")
}

// LookupSRV returns a NoSuchHost error.
func (n *RejectNetwork) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return "", nil, NoSuchHost(
		"_"+service+"._"+proto+"."+name,
		"rejectdns",
	)
}
