package gonnect

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Static type assertions
var (
	_ Network = &NativeNetwork{}

	_ Dial         = (&NativeNetwork{}).Dial
	_ Listen       = (&NativeNetwork{}).Listen
	_ LookupIP     = (&NativeNetwork{}).LookupIP
	_ LookupIPAddr = (&NativeNetwork{}).LookupIPAddr
	_ LookupNetIP  = (&NativeNetwork{}).LookupNetIP
	_ LookupHost   = (&NativeNetwork{}).LookupHost
	_ LookupAddr   = (&NativeNetwork{}).LookupAddr
	_ LookupCNAME  = (&NativeNetwork{}).LookupCNAME
	_ LookupPort   = (&NativeNetwork{}).LookupPort
	_ LookupTXT    = (&NativeNetwork{}).LookupTXT
	_ LookupMX     = (&NativeNetwork{}).LookupMX
	_ LookupNS     = (&NativeNetwork{}).LookupNS
	_ LookupSRV    = (&NativeNetwork{}).LookupSRV
)

const (
	actionDial = iota
	actionListen
	actionLookup
)

// errForAction returns an appropriate error based on the action type.
// For lookup actions, it returns a NoSuchHost error; for listen actions,
// a ListenDeniedErr; and for dial actions, a ConnRefused error.
func errForAction(action int, network, address string) error {
	if action == actionLookup {
		err := nativeNoSuchHost(address, "rejectdns")
		err.UnwrapErr = fmt.Errorf("rejected by filter")
		return err
	}
	if action == actionListen {
		return nativeListenDeniedErr(network, address)
	}
	return nativeConnRefused(network, address)
}

type nativeAddr struct {
	network string
	address string
}

func (a nativeAddr) Network() string { return a.network }
func (a nativeAddr) String() string  { return a.address }

func nativeNoSuchHost(host, srv string) *net.DNSError {
	return &net.DNSError{
		Err:         "no such host",
		Name:        host,
		Server:      srv,
		IsTemporary: true,
		IsNotFound:  true,
	}
}

func nativeConnRefused(network, address string) error {
	return &net.OpError{
		Op:     "dial",
		Net:    network,
		Source: nil,
		Addr: nativeAddr{
			network: network,
			address: address,
		},
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.ECONNREFUSED,
		},
	}
}

func nativeListenDeniedErr(network, address string) error {
	return &net.OpError{
		Op:     "listen",
		Net:    network,
		Source: nil,
		Addr: nativeAddr{
			network: network,
			address: address,
		},
		Err: &os.SyscallError{
			Syscall: "bind",
			Err:     syscall.EACCES,
		},
	}
}

func nativeJoinIPPort(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

func nativeFamilyFromNetwork(network string) string {
	if strings.HasPrefix(network, "ip4") ||
		strings.HasPrefix(network, "tcp4") ||
		strings.HasPrefix(network, "udp4") {
		return "ip4"
	}
	if strings.HasPrefix(network, "ip6") ||
		strings.HasPrefix(network, "tcp6") ||
		strings.HasPrefix(network, "udp6") {
		return "ip6"
	}
	return "ip"
}

func nativePickIP(ips []net.IP, prefer int) net.IP {
	if len(ips) == 0 {
		return nil
	}
	if prefer != 4 && prefer != 6 {
		return ips[0]
	}
	for _, ip := range ips {
		if prefer == 4 && ip.To4() != nil {
			return ip
		}
		if prefer == 6 && ip.To4() == nil {
			return ip
		}
	}
	return ips[0]
}

// NativeConfig holds configuration options for building a Network.
type NativeConfig struct {
	// Filter is an optional filter function that can reject network operations.
	// It should return true to reject the operation.
	//
	// NOTE: filtering works only for connections establishing, unbinded DNS sockset can be used to bypass it
	Filter Filter
	// ResolverCfg configures the DNS resolver used by the Network.
	// If nil, new one will be built.
	ResolverCfg *ResolverCfg

	// PreferIP specifies IP version preference:
	// 4 for IPv4, 6 for IPv6, or 0 for no preference.
	PreferIP int

	// ListenCfg configures the listen operations. If nil, defaults are used.
	ListenCfg *net.ListenConfig

	// net.Dialer options
	Timeout         time.Duration
	Deadline        time.Time
	LocalAddr       net.Addr
	FallbackDelay   time.Duration
	KeepAlive       time.Duration
	KeepAliveConfig net.KeepAliveConfig
	Control         func(network, address string, c syscall.RawConn) error
	ControlContext  func(ctx context.Context, network, address string, c syscall.RawConn) error
}

// Build creates and returns a new NativeNetwork instance from the configuration.
func (c NativeConfig) Build() *NativeNetwork {
	n := &NativeNetwork{
		filter:    c.Filter,
		preferIP:  c.PreferIP,
		listenCfg: c.ListenCfg,
	}

	rc := ResolverCfg{}
	if c.ResolverCfg != nil {
		rc = *c.ResolverCfg
	}
	r := rc.Build()
	r.Dial = n.dialInternal
	n.resolver = &r

	n.dialer = net.Dialer{
		Resolver: &r,

		Timeout:         c.Timeout,
		Deadline:        c.Deadline,
		LocalAddr:       c.LocalAddr,
		FallbackDelay:   c.FallbackDelay,
		KeepAlive:       c.KeepAlive,
		KeepAliveConfig: c.KeepAliveConfig,
		Control:         c.Control,
		ControlContext:  c.ControlContext,
	}
	return n
}

// NativeNetwork is a filtered network provider that implements Network.
// It wraps Go's standard net package to provide controlled dialing,
// listening, and DNS resolution with optional filtering.
//
// NativeNetwork does not implement UpDown. Wrap it with DetachNetwork when an
// independently stoppable native network is needed:
//
//	n := DetachNetwork(NativeConfig{}.Build())
type NativeNetwork struct {
	// filter is an optional function to reject network operations.
	filter Filter
	// resolver is the DNS resolver used for lookups.
	resolver *net.Resolver
	// dialer is used for establishing connections.
	dialer net.Dialer
	// listenCfg configures listen operations.
	listenCfg *net.ListenConfig

	// preferIP specifies IP version preference (4, 6, or 0).
	preferIP int
}

func (n *NativeNetwork) IsNative() bool {
	return true
}

// LookupIP looks up the host and returns a slice of its IPv4 and IPv6 addresses.
// The network parameter specifies the network type ("ip", "ip4", or "ip6").
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	err := n.doFilter(network, address, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupIP(ctx, network, address)
}

// LookupIPAddr looks up the host and returns a slice of IPAddr structures.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupIPAddr(ctx, host)
}

// LookupNetIP looks up the host and returns a slice of netip.Addr values.
// The network parameter specifies the network type ("ip", "ip4", or "ip6").
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	err := n.doFilter(network, host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupNetIP(ctx, network, host)
}

// LookupHost looks up the host and returns a slice of IP address strings.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupHost(ctx, host)
}

// LookupAddr performs a reverse lookup for the given address,
// returning a slice of names mapping to that address.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	err := n.doFilter("", addr, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupAddr(ctx, addr)
}

// LookupCNAME returns the canonical name for the given host.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return "", err
	}
	return n.getResolver().LookupCNAME(ctx, host)
}

// LookupPort looks up the port number for the given network and service.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	err := n.doFilter("", service, actionLookup)
	if err != nil {
		return 0, err
	}
	return n.getResolver().LookupPort(ctx, network, service)
}

// LookupTXT returns the DNS TXT records for the given domain name.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	err := n.doFilter("", name, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupTXT(ctx, name)
}

// LookupMX returns the DNS MX records for the given domain name,
// sorted by preference.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	err := n.doFilter("", name, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupMX(ctx, name)
}

// LookupNS returns the DNS NS records for the given domain name.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	err := n.doFilter("", name, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupNS(ctx, name)
}

// LookupSRV tries to resolve an SRV query for the given service, protocol, and domain name.
// The proto parameter is "tcp" or "udp".
// Returns the canonical host name and a slice of SRV records.
// This method applies filtering before performing the lookup.
func (n *NativeNetwork) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	err := n.doFilter(proto, name, actionLookup)
	if err != nil {
		return "", nil, err
	}
	return n.getResolver().LookupSRV(ctx, service, proto, name)
}

// LookupNetAddr resolves a network address string (e.g., "localhost:8080")
// into an IP address and port number.
// The network parameter specifies the network type (e.g., "tcp4", "udp6", "tcp").
// This method applies filtering before performing the resolution.
func (n *NativeNetwork) LookupNetAddr(
	ctx context.Context,
	network, addr string,
) (net.IP, int, error) {
	return n.resolveAddr(ctx, network, addr, actionLookup)
}

// InterfaceAddrs returns the unicast interface addresses associated with the system.
// This method delegates to net.InterfaceAddrs.
func (n *NativeNetwork) InterfaceAddrs() ([]net.Addr, error) {
	return net.InterfaceAddrs()
}

// Interfaces returns all network interfaces available on the system.
// This method delegates to net.Interfaces.
func (n *NativeNetwork) Interfaces() ([]NetworkInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return WrapNativeInterfaces(ifs), nil
}

// InterfacesByIndex returns the network interface with the given index.
// This method delegates to net.InterfaceByIndex.
func (n *NativeNetwork) InterfacesByIndex(
	index int,
) ([]NetworkInterface, error) {
	i, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}
	return []NetworkInterface{&NativeInterface{Iface: *i}}, nil
}

// InterfacesByName returns the network interface with the given name.
// This method delegates to net.InterfaceByName.
func (n *NativeNetwork) InterfacesByName(
	name string,
) ([]NetworkInterface, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return []NetworkInterface{&NativeInterface{Iface: *i}}, nil
}

// Dial establishes a connection to the address on the specified network.
// It applies filtering before dialing.
func (n *NativeNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	err := n.doFilter(network, address, actionDial)
	if err != nil {
		return nil, err
	}
	return n.dialer.DialContext(ctx, network, address)
}

// Listen announces on the specified network and address.
// It resolves the address, applies filtering, and creates a listener.
func (n *NativeNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	ip, port, err := n.resolveAddr(ctx, network, address, actionListen)
	if err != nil {
		return nil, err
	}
	address = nativeJoinIPPort(ip, port)
	return n.getListenCfg().Listen(ctx, network, address)
}

// ListenPacket announces on the specified network and address for packet-oriented protocols.
// It resolves the address, applies filtering, and creates a packet connection.
func (n *NativeNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	ip, port, err := n.resolveAddr(ctx, network, address, actionListen)
	if err != nil {
		return nil, err
	}
	address = nativeJoinIPPort(ip, port)

	c, err := n.getListenCfg().ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	pc, ok := c.(PacketConn)
	if ok {
		return pc, nil
	}

	_ = c.Close()
	return nil, nativeConnRefused(network, address)
}

// ListenPacketConfig announces on the specified network and address for
// packet-oriented protocols using the provided listen configuration.
// It resolves the address, applies filtering, and creates a packet connection.
func (n *NativeNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	ip, port, err := n.resolveAddr(ctx, network, address, actionListen)
	if err != nil {
		return nil, err
	}
	address = nativeJoinIPPort(ip, port)

	c, err := n.getListenCfgWith(lc).ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	pc, ok := c.(PacketConn)
	if ok {
		return pc, nil
	}

	_ = c.Close()
	return nil, nativeConnRefused(network, address)
}

// DialTCP establishes a TCP connection to the remote address using the specified network.
// If laddr is not empty, it is used as the local address for the connection.
func (n *NativeNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	var laddrTCP *net.TCPAddr
	var err error
	if laddr != "" {
		laddrTCP, err = n.resolveTCPAddr(ctx, network, laddr, actionDial)
		if err != nil {
			return nil, err
		}
	}
	raddrTCP, err := n.resolveTCPAddr(ctx, network, raddr, actionDial)
	if err != nil {
		return nil, err
	}

	// WARN: In go 1.25 there is no DialTCP method for net.Dialer
	// TODO: Change to n.dialer.DialTCP after bumping to next go version
	c, err := net.DialTCP(network, laddrTCP, raddrTCP)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenTCP announces on the specified network and address for TCP connections.
// It resolves the address, applies filtering, and creates a TCP listener.
func (n *NativeNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	laddrTCP, err := n.resolveTCPAddr(ctx, network, laddr, actionListen)
	if err != nil {
		return nil, err
	}

	// WARN: In go 1.25 there is no ListenTCP method for net.ListenConfig
	// TODO: Change to n.getListener().ListenTCP after bumping to next go version
	l, err := net.ListenTCP(network, laddrTCP)
	if err != nil {
		return nil, err
	}
	return &NetTCPListener{
		TCPListener: l,
	}, nil
}

// PacketDial establishes a UDP connection to the remote address using the specified network.
func (n *NativeNetwork) PacketDial(
	ctx context.Context, network, address string,
) (PacketConn, error) {
	return n.DialUDP(ctx, network, "", address)
}

// DialUDP establishes a UDP connection to the remote address using the specified network.
// If laddr is not empty, it is used as the local address for the connection.
func (n *NativeNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	var laddrUDP *net.UDPAddr
	var err error
	if laddr != "" {
		laddrUDP, err = n.resolveUDPAddr(ctx, network, laddr, actionDial)
		if err != nil {
			return nil, err
		}
	}
	raddrUDP, err := n.resolveUDPAddr(ctx, network, raddr, actionDial)
	if err != nil {
		return nil, err
	}

	// WARN: In go 1.25 there is no DialUDP method for net.Dialer
	// TODO: Change to n.dialer.DialUDP after bumping to next go version
	c, err := net.DialUDP(network, laddrUDP, raddrUDP)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenUDP announces on the specified network and address for UDP connections.
// It resolves the address, applies filtering, and creates a UDP connection.
func (n *NativeNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	laddrUDP, err := n.resolveUDPAddr(ctx, network, laddr, actionListen)
	if err != nil {
		return nil, err
	}

	// WARN: In go 1.25 there is no ListenTCP method for net.ListenConfig
	// TODO: Change to n.getListener().ListenTCP after bumping to next go version
	c, err := net.ListenUDP(network, laddrUDP)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenUDPConfig announces on the specified network and address for UDP
// connections using the provided listen configuration. Since net.ListenConfig
// does not expose ListenUDP, this is implemented via ListenPacket and narrowed
// back to UDPConn.
func (n *NativeNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	laddrUDP, err := n.resolveUDPAddr(ctx, network, laddr, actionListen)
	if err != nil {
		return nil, err
	}

	c, err := n.getListenCfgWith(lc).
		ListenPacket(ctx, network, laddrUDP.String())
	if err != nil {
		return nil, err
	}

	uc, ok := c.(UDPConn)
	if ok {
		return uc, nil
	}

	_ = c.Close()
	return nil, nativeConnRefused(network, laddrUDP.String())
}

// doFilter applies the filter function if set.
// It returns an error if the filter rejects the operation.
func (n *NativeNetwork) doFilter(network, address string, action int) error {
	if n.filter == nil {
		return nil
	}
	if n.filter(network, address) {
		return errForAction(action, network, address)
	}
	return nil
}

// dialInternal is the internal dial function used by the resolver.
// It applies filtering before establishing the connection.
func (n *NativeNetwork) dialInternal(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	err := n.doFilter(network, address, actionDial)
	if err != nil {
		return nil, err
	}
	return n.dialer.DialContext(ctx, network, address)
}

// getResolver returns the configured resolver or net.DefaultResolver if none is set.
func (n *NativeNetwork) getResolver() *net.Resolver {
	if n.resolver == nil {
		return net.DefaultResolver
	}
	return n.resolver
}

// getListenCfg returns the configured listen config or a default one if none is set.
func (n *NativeNetwork) getListenCfg() *net.ListenConfig {
	if n.listenCfg == nil {
		return &net.ListenConfig{}
	}
	return n.listenCfg
}

// getListenCfgWith returns a copy of the configured listen config with fields
// from ListenConfig overlaid on top.
func (n *NativeNetwork) getListenCfgWith(lc *ListenConfig) *net.ListenConfig {
	cfg := *n.getListenCfg()
	if lc != nil && lc.Control != nil {
		cfg.Control = lc.Control
	}
	return &cfg
}

// resolveAddr resolves a network address string into an IP and port.
// It applies filtering before and after resolution (if port lookup is needed).
func (n *NativeNetwork) resolveAddr(
	ctx context.Context, network, addr string, action int,
) (net.IP, int, error) {
	err := n.doFilter(network, addr, action)
	if err != nil {
		return nil, 0, err
	}

	host, serv, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	resolver := n.getResolver()
	ipNet := nativeFamilyFromNetwork(network) // "ip","ip4" or "ip6"

	ips, err := resolver.LookupIP(ctx, ipNet, host)
	if err != nil {
		return nil, 0, err
	}

	ip := nativePickIP(ips, n.preferIP)

	port, err := strconv.Atoi(serv)
	if err != nil {
		// serv is not a port, lookup
		port, err = resolver.LookupPort(ctx, network, serv)
		if err != nil {
			return nil, 0, err
		}

		err = n.doFilter(
			network, net.JoinHostPort(ip.String(), strconv.Itoa(port)), action,
		)
	} else {
		// serv is a port already
		err = n.doFilter(network, net.JoinHostPort(ip.String(), serv), action)
	}
	if err != nil {
		return nil, 0, err
	}

	return ip, port, nil
}

// resolveTCPAddr resolves a network address string into a TCPAddr.
// It applies filtering through resolveAddr before constructing the result.
func (n *NativeNetwork) resolveTCPAddr(
	ctx context.Context,
	network, addr string,
	action int,
) (*net.TCPAddr, error) {
	ip, port, err := n.resolveAddr(ctx, network, addr, action)
	if err != nil {
		return nil, err
	}
	addrTCP := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	return addrTCP, nil
}

// resolveUDPAddr resolves a network address string into a UDPAddr.
// It applies filtering through resolveAddr before constructing the result.
func (n *NativeNetwork) resolveUDPAddr(
	ctx context.Context,
	network, addr string,
	action int,
) (*net.UDPAddr, error) {
	ip, port, err := n.resolveAddr(ctx, network, addr, action)
	if err != nil {
		return nil, err
	}
	addrUDP := &net.UDPAddr{
		IP:   ip,
		Port: port,
	}
	return addrUDP, nil
}
