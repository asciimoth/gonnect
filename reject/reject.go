// Package reject provides a network implementation that rejects all operations
// with canonical errors. It implements the gonnect.Network, gonnect.InterfaceNetwork,
// and gonnect.Resolver interfaces, returning appropriate errors for all methods.
package reject

import (
	"context"
	"net"
	"net/netip"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/errors"
)

// Static type assertions
var (
	_ gonnect.Network          = &Network{}
	_ gonnect.InterfaceNetwork = &Network{}
	_ gonnect.Resolver         = &Network{}
)

// Network is a network implementation that rejects all operations with canonical errors.
// It implements gonnect.Network, gonnect.InterfaceNetwork, and gonnect.Resolver interfaces.
type Network struct{}

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
		return errors.ConnRefused(network, address)
	}

	// It's a hostname - return DNS error with just the hostname (not host:port)
	return errors.NoSuchHost(host, "rejectdns")
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
	return errors.ListenDeniedErr(network, address)
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
func (n *Network) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	return nil, dialError(network, address)
}

// Listen returns an appropriate error based on the network and address.
func (n *Network) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return nil, listenError(network, address)
}

// ListenPacket returns an appropriate error based on the network and address.
func (n *Network) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return nil, listenError(network, address)
}

// DialTCP returns an appropriate error based on the network and address.
func (n *Network) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	return nil, dialError(network, raddr)
}

// ListenTCP returns an appropriate error based on the network and address.
func (n *Network) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	return nil, listenError(network, laddr)
}

// DialUDP returns an appropriate error based on the network and address.
func (n *Network) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	return nil, dialError(network, raddr)
}

// ListenUDP returns an appropriate error based on the network and address.
func (n *Network) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return nil, listenError(network, laddr)
}

// Interfaces returns an empty slice and nil error.
func (n *Network) Interfaces() ([]gonnect.NetworkInterface, error) {
	return []gonnect.NetworkInterface{}, nil
}

// InterfaceAddrs returns an empty slice and nil error.
func (n *Network) InterfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{}, nil
}

// InterfacesByIndex returns an empty slice and "interface not found" error.
func (n *Network) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// InterfacesByName returns an empty slice and "interface not found" error.
func (n *Network) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// LookupIP returns a NoSuchHost error.
func (n *Network) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return nil, errors.NoSuchHost(address, "rejectdns")
}

// LookupIPAddr returns a NoSuchHost error.
func (n *Network) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return nil, errors.NoSuchHost(host, "rejectdns")
}

// LookupNetIP returns a NoSuchHost error.
func (n *Network) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return nil, errors.NoSuchHost(host, "rejectdns")
}

// LookupHost returns a NoSuchHost error.
func (n *Network) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return nil, errors.NoSuchHost(host, "rejectdns")
}

// LookupAddr returns a NoSuchHost error.
func (n *Network) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return nil, errors.NoSuchHost(addr, "rejectdns")
}

// LookupCNAME returns a NoSuchHost error.
func (n *Network) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return "", errors.NoSuchHost(host, "rejectdns")
}

// LookupPort returns a NoSuchHost error for the service.
func (n *Network) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return 0, errors.NoSuchHost(service, "rejectdns")
}

// LookupTXT returns a NoSuchHost error.
func (n *Network) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return nil, errors.NoSuchHost(name, "rejectdns")
}

// LookupMX returns a NoSuchHost error.
func (n *Network) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return nil, errors.NoSuchHost(name, "rejectdns")
}

// LookupNS returns a NoSuchHost error.
func (n *Network) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return nil, errors.NoSuchHost(name, "rejectdns")
}

// LookupSRV returns a NoSuchHost error.
func (n *Network) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return "", nil, errors.NoSuchHost(
		"_"+service+"._"+proto+"."+name,
		"rejectdns",
	)
}
