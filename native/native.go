// Package native provides a native implementation of the gonnect network
// interfaces based Go's standard net package.
package native

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/errors"
	"github.com/asciimoth/gonnect/helpers"
)

// Static type assertions
var (
	_ gonnect.Network          = &Network{}
	_ gonnect.InterfaceNetwork = &Network{}
	_ gonnect.Resolver         = &Network{}
	_ gonnect.UpDown           = &Network{}

	_ gonnect.Dial         = (&Network{}).Dial
	_ gonnect.Listen       = (&Network{}).Listen
	_ gonnect.LookupIP     = (&Network{}).LookupIP
	_ gonnect.LookupIPAddr = (&Network{}).LookupIPAddr
	_ gonnect.LookupNetIP  = (&Network{}).LookupNetIP
	_ gonnect.LookupHost   = (&Network{}).LookupHost
	_ gonnect.LookupAddr   = (&Network{}).LookupAddr
	_ gonnect.LookupCNAME  = (&Network{}).LookupCNAME
	_ gonnect.LookupPort   = (&Network{}).LookupPort
	_ gonnect.LookupTXT    = (&Network{}).LookupTXT
	_ gonnect.LookupMX     = (&Network{}).LookupMX
	_ gonnect.LookupNS     = (&Network{}).LookupNS
	_ gonnect.LookupSRV    = (&Network{}).LookupSRV
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
		err := errors.NoSuchHost(address, "rejectdns")
		err.UnwrapErr = fmt.Errorf("rejected by filter")
		return err
	}
	if action == actionListen {
		return errors.ListenDeniedErr(network, address)
	}
	return errors.ConnRefused(network, address)
}

// Config holds configuration options for building a Network.
type Config struct {
	// Filter is an optional filter function that can reject network operations.
	// It should return true to reject the operation.
	//
	// NOTE: filtering works only for connections establishing, unbinded DNS sockset can be used to bypass it
	Filter gonnect.Filter
	// ResolverCfg configures the DNS resolver used by the Network.
	// If nil, new one will be built.
	ResolverCfg *gonnect.ResolverCfg

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

// Build creates and returns a new Network instance from the configuration.
func (c Config) Build() *Network {
	n := &Network{
		up:        true,
		filter:    c.Filter,
		preferIP:  c.PreferIP,
		listenCfg: c.ListenCfg,
	}

	rc := gonnect.ResolverCfg{}
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

// Network is a filtered network provider that implements gonnect.Network,
// gonnect.InterfaceNetwork, and gonnect.Resolver interfaces.
// It wraps Go's standard net package to provide controlled dialing,
// listening, and DNS resolution with optional filtering and connection tracking.
type Network struct {
	mu sync.Mutex

	// up indicates whether the network is currently active.
	up bool

	// filter is an optional function to reject network operations.
	filter gonnect.Filter
	// resolver is the DNS resolver used for lookups.
	resolver *net.Resolver
	// dialer is used for establishing connections.
	dialer net.Dialer
	// listenCfg configures listen operations.
	listenCfg *net.ListenConfig

	// preferIP specifies IP version preference (4, 6, or 0).
	preferIP int

	// nextID is the next ID to assign to a tracked connection.
	nextID uint64
	// closers tracks all open connections and listeners by ID.
	closers map[uint64]io.Closer
}

func (n *Network) IsNative() bool {
	return true
}

// Down shuts down the network by closing all tracked connections and listeners.
// After calling Down, the network will reject new operations until Up() is called.
func (n *Network) Down() error {
	closers := n.downPrep()
	helpers.CloseAll(closers)
	return nil
}

// Up re-enables the network after it has been shut down with Down().
func (n *Network) Up() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.up = true
	return nil
}

// IsUp returns whether the network is currently active.
func (n *Network) IsUp() (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up, nil
}

// LookupIP looks up the host and returns a slice of its IPv4 and IPv6 addresses.
// The network parameter specifies the network type ("ip", "ip4", or "ip6").
// This method applies filtering before performing the lookup.
func (n *Network) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter(network, address, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupIP(ctx, network, address)
}

// LookupIPAddr looks up the host and returns a slice of IPAddr structures.
// This method applies filtering before performing the lookup.
func (n *Network) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupIPAddr(ctx, host)
}

// LookupNetIP looks up the host and returns a slice of netip.Addr values.
// The network parameter specifies the network type ("ip", "ip4", or "ip6").
// This method applies filtering before performing the lookup.
func (n *Network) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter(network, host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupNetIP(ctx, network, host)
}

// LookupHost looks up the host and returns a slice of IP address strings.
// This method applies filtering before performing the lookup.
func (n *Network) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupHost(ctx, host)
}

// LookupAddr performs a reverse lookup for the given address,
// returning a slice of names mapping to that address.
// This method applies filtering before performing the lookup.
func (n *Network) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", addr, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupAddr(ctx, addr)
}

// LookupCNAME returns the canonical name for the given host.
// This method applies filtering before performing the lookup.
func (n *Network) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", host, actionLookup)
	if err != nil {
		return "", err
	}
	return n.getResolver().LookupCNAME(ctx, host)
}

// LookupPort looks up the port number for the given network and service.
// This method applies filtering before performing the lookup.
func (n *Network) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", service, actionLookup)
	if err != nil {
		return 0, err
	}
	return n.getResolver().LookupPort(ctx, network, service)
}

// LookupTXT returns the DNS TXT records for the given domain name.
// This method applies filtering before performing the lookup.
func (n *Network) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", name, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupTXT(ctx, name)
}

// LookupMX returns the DNS MX records for the given domain name,
// sorted by preference.
// This method applies filtering before performing the lookup.
func (n *Network) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter("", name, actionLookup)
	if err != nil {
		return nil, err
	}
	return n.getResolver().LookupMX(ctx, name)
}

// LookupNS returns the DNS NS records for the given domain name.
// This method applies filtering before performing the lookup.
func (n *Network) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
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
func (n *Network) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
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
func (n *Network) LookupNetAddr(
	ctx context.Context,
	network, addr string,
) (net.IP, int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.resolveAddr(ctx, network, addr, actionLookup)
}

// InterfaceAddrs returns the unicast interface addresses associated with the system.
// This method delegates to net.InterfaceAddrs.
func (n *Network) InterfaceAddrs() ([]net.Addr, error) {
	return net.InterfaceAddrs()
}

// Interfaces returns all network interfaces available on the system.
// This method delegates to net.Interfaces.
func (n *Network) Interfaces() ([]gonnect.NetworkInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return gonnect.WrapNativeInterfaces(ifs), nil
}

// InterfacesByIndex returns the network interface with the given index.
// This method delegates to net.InterfaceByIndex.
func (n *Network) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	i, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}
	return []gonnect.NetworkInterface{&gonnect.NativeInterface{Iface: *i}}, nil
}

// InterfacesByName returns the network interface with the given name.
// This method delegates to net.InterfaceByName.
func (n *Network) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return []gonnect.NetworkInterface{&gonnect.NativeInterface{Iface: *i}}, nil
}

// Dial establishes a connection to the address on the specified network.
// It applies filtering before dialing and tracks the connection for cleanup.
// The returned connection is wrapped with callbacks for automatic tracking.
func (n *Network) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	err := n.doFilter(network, address, actionDial)
	if err != nil {
		return nil, err
	}

	c, err := n.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	id := n.getID()
	c = gonnect.ConnWithCallbacks(c, &gonnect.Callbacks{
		BeforeClose: n.buildUnregCallback(id),
	})
	n.register(id, c)

	return c, nil
}

// Listen announces on the specified network and address.
// It resolves the address, applies filtering, and creates a listener.
// The returned listener is wrapped with callbacks for automatic connection tracking.
func (n *Network) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ip, port, err := n.resolveAddr(ctx, network, address, actionListen)
	if err != nil {
		return nil, err
	}
	address = helpers.JointIPPort(ip, port)

	listener, err := n.getListenCfg().Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}

	id := n.getID()
	listener = gonnect.ListenerWithCallbacks(listener, &gonnect.Callbacks{
		BeforeClose: n.buildUnregCallback(id),
		OnAccept:    n.registerConnCallback,
		OnAcceptTCP: n.registerTCPConnCallback,
	})
	n.register(id, listener)

	return listener, nil
}

// ListenPacket announces on the specified network and address for packet-oriented protocols.
// It resolves the address, applies filtering, and creates a packet connection.
// The returned PacketConn is wrapped with callbacks for automatic tracking.
func (n *Network) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ip, port, err := n.resolveAddr(ctx, network, address, actionListen)
	address = helpers.JointIPPort(ip, port)
	if err != nil {
		return nil, err
	}

	c, err := n.getListenCfg().ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	pc, ok := c.(gonnect.PacketConn)
	if ok {
		id := n.getID()
		c = gonnect.PacketConnWithCallbacks(pc, &gonnect.Callbacks{
			BeforeClose: n.buildUnregCallback(id),
		})
		n.register(id, c)

		return pc, nil
	}

	_ = c.Close()
	return nil, errors.ConnRefused(network, address)
}

// DialTCP establishes a TCP connection to the remote address using the specified network.
// If laddr is not empty, it is used as the local address for the connection.
// The returned TCPConn is wrapped with callbacks for automatic tracking.
func (n *Network) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

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

	id := n.getID()
	cc := &gonnect.CallbackTCPConn{
		TCPConn: c,
		CB: &gonnect.Callbacks{
			BeforeClose: n.buildUnregCallback(id),
		},
	}
	n.register(id, cc)

	return cc, nil
}

// ListenTCP announces on the specified network and address for TCP connections.
// It resolves the address, applies filtering, and creates a TCP listener.
// The returned TCPListener is wrapped with callbacks for automatic connection tracking.
func (n *Network) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

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
	id := n.getID()
	listener := &gonnect.CallbackTCPListener{
		TCPListener: &gonnect.NetTCPListener{
			TCPListener: l,
		},
		CB: &gonnect.Callbacks{
			BeforeClose: n.buildUnregCallback(id),
			OnAccept:    n.registerConnCallback,
			OnAcceptTCP: n.registerTCPConnCallback,
		},
	}
	n.register(id, listener)

	return listener, nil
}

// PacketDial establishes a UDP connection to the remote address using the specified network.
// The returned PacketConn is wrapped with callbacks for automatic tracking.
func (n *Network) PacketDial(
	ctx context.Context, network, address string,
) (gonnect.PacketConn, error) {
	return n.DialUDP(ctx, network, "", address)
}

// DialUDP establishes a UDP connection to the remote address using the specified network.
// If laddr is not empty, it is used as the local address for the connection.
// The returned UDPConn is wrapped with callbacks for automatic tracking.
func (n *Network) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

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

	id := n.getID()
	cc := gonnect.UDPConnWithCallbacks(c, &gonnect.Callbacks{
		BeforeClose: n.buildUnregCallback(id),
	})
	n.register(id, cc)

	return cc, err
}

// ListenUDP announces on the specified network and address for UDP connections.
// It resolves the address, applies filtering, and creates a UDP connection.
// The returned UDPConn is wrapped with callbacks for automatic tracking.
func (n *Network) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

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

	id := n.getID()
	cc := gonnect.UDPConnWithCallbacks(c, &gonnect.Callbacks{
		BeforeClose: n.buildUnregCallback(id),
	})
	n.register(id, cc)

	return cc, err
}

// doFilter checks if the network is up and applies the filter function if set.
// It returns an error if the network is down or if the filter rejects the operation.
// WARN: Not thread safe - caller must hold n.mu lock.
func (n *Network) doFilter(network, address string, action int) error {
	if !n.up {
		return errForAction(action, network, address)
	}
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
// WARN: Not thread safe - caller must hold n.mu lock.
func (n *Network) dialInternal(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	err := n.doFilter(network, address, actionDial)
	if err != nil {
		return nil, err
	}
	return n.dialer.DialContext(ctx, network, address)
}

// getID returns the next unique ID for tracking connections.
// WARN: NOT thread safe - caller must hold n.mu lock.
func (n *Network) getID() uint64 {
	id := n.nextID
	n.nextID += 1
	return id
}

// register stores a connection or listener with the given ID for tracking.
// WARN: NOT thread safe - caller must hold n.mu lock.
func (n *Network) register(id uint64, c io.Closer) {
	if n.closers == nil {
		n.closers = make(map[uint64]io.Closer)
	}
	n.closers[id] = c
}

// unregister removes a connection or listener from tracking by ID.
func (n *Network) unregister(id uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.closers, id)
}

// buildUnregCallback returns a callback function that unregisters a connection
// by ID when called. This is used as the BeforeClose callback for tracked connections.
func (n *Network) buildUnregCallback(id uint64) func() {
	return func() {
		n.unregister(id)
	}
}

// registerConnCallback wraps an accepted connection with tracking callbacks.
// It rejects the connection if the network is down.
func (n *Network) registerConnCallback(conn net.Conn) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return nil, errors.ConnRefused(
			helpers.NetworkFromConn(conn),
			conn.RemoteAddr().String(),
		)
	}
	id := n.getID()
	conn = gonnect.ConnWithCallbacks(conn, &gonnect.Callbacks{
		BeforeClose: n.buildUnregCallback(id),
	})
	n.register(id, conn)
	return conn, nil
}

// registerTCPConnCallback wraps an accepted TCP connection with tracking callbacks.
// It rejects the connection if the network is down.
func (n *Network) registerTCPConnCallback(
	conn gonnect.TCPConn,
) (gonnect.TCPConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return nil, errors.ConnRefused(
			helpers.NetworkFromConn(conn),
			conn.RemoteAddr().String(),
		)
	}
	id := n.getID()
	conn = &gonnect.CallbackTCPConn{
		TCPConn: conn,
		CB: &gonnect.Callbacks{
			BeforeClose: n.buildUnregCallback(id),
		},
	}
	n.register(id, conn)
	return conn, nil
}

// downPrep prepares the network for shutdown by marking it as down
// and collecting all tracked closers for cleanup.
// It returns the closers that should be closed after releasing the lock.
func (n *Network) downPrep() (closers []io.Closer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return
	}
	n.up = false
	closers = make([]io.Closer, len(n.closers))
	if n.closers == nil {
		return
	}
	closers = slices.Collect(maps.Values(n.closers))
	return
}

// getResolver returns the configured resolver or net.DefaultResolver if none is set.
func (n *Network) getResolver() *net.Resolver {
	if n.resolver == nil {
		return net.DefaultResolver
	}
	return n.resolver
}

// getListenCfg returns the configured listen config or a default one if none is set.
func (n *Network) getListenCfg() *net.ListenConfig {
	if n.listenCfg == nil {
		return &net.ListenConfig{}
	}
	return n.listenCfg
}

// resolveAddr resolves a network address string into an IP and port.
// It applies filtering before and after resolution (if port lookup is needed).
// WARN: NOT thread safe - caller must hold n.mu lock.
func (n *Network) resolveAddr(
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
	ipNet := helpers.FamilyFromNetwork(network) // "ip","ip4" or "ip6"

	ips, err := resolver.LookupIP(ctx, ipNet, host)
	if err != nil {
		return nil, 0, err
	}

	ip := helpers.PickIP(ips, n.preferIP)

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
// WARN: NOT thread safe - caller must hold n.mu lock.
func (n *Network) resolveTCPAddr(
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
// WARN: NOT thread safe - caller must hold n.mu lock.
func (n *Network) resolveUDPAddr(
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
