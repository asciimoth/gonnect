// Package loopback provides an in-memory loopback network implementation that
// simulates network operations without using actual network sockets.
// It implements the gonnect.Network, gonnect.InterfaceNetwork, and gonnect.Resolver
// interfaces, providing TCP and UDP communication between clients within the same process.
package loopback

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/asciimoth/gonnect"
	ge "github.com/asciimoth/gonnect/errors"
	"github.com/asciimoth/gonnect/helpers"
)

// Static type assertions
var (
	_ gonnect.Network          = &LoopbackNetwork{}
	_ gonnect.InterfaceNetwork = &LoopbackNetwork{}
	_ gonnect.Resolver         = &LoopbackNetwork{}
	_ gonnect.UpDown           = &LoopbackNetwork{}
)

var ErrNetworkDown = &net.OpError{
	Op:  "network",
	Net: "down",
	Err: errors.New("network is down"),
}

// LoopbackNetwork is an in-memory network implementation that simulates
// loopback network operations. It provides TCP and UDP communication using
// net.Pipe() for TCP and buffered channels for UDP, all without creating
// actual network sockets.
type LoopbackNetwork struct {
	mu sync.Mutex

	// up indicates whether the network is currently active.
	up bool

	tcp4reg *loopbackTCPRegistry
	tcp6reg *loopbackTCPRegistry
	udp4reg *loopbackUDPRegistry
	udp6reg *loopbackUDPRegistry

	// nextID is the next ID to assign to a tracked connection.
	nextID uint64
	// closers tracks all open connections and listeners by ID.
	closers map[uint64]io.Closer
}

// NewLoopbackNetwok creates and returns a new loopback network instance.
// The returned network provides simulated TCP and UDP communication on
// IPv4 (127.0.0.1) and IPv6 (::1) loopback addresses.
func NewLoopbackNetwok() *LoopbackNetwork {
	return &LoopbackNetwork{
		up: true,
		tcp4reg: &loopbackTCPRegistry{
			Network: "tcp4",
			Host:    "127.0.0.1",
		},
		tcp6reg: &loopbackTCPRegistry{
			Network: "tcp6",
			Host:    "::1",
		},
		udp4reg: &loopbackUDPRegistry{
			Network: "udp4",
			Host:    "127.0.0.1",
		},
		udp6reg: &loopbackUDPRegistry{
			Network: "udp6",
			Host:    "::1",
		},
	}
}

// Interfaces returns a slice containing the loopback network interface.
// It returns a single interface representing "lo" with index 1, MTU 65536,
// and the net.FlagLoopback and net.FlagUp flags set.
func (ln *LoopbackNetwork) Interfaces() ([]gonnect.NetworkInterface, error) {
	return []gonnect.NetworkInterface{&gonnect.LiteralInterface{
		IndexVal:        1,
		MTUVal:          65536,
		NameVal:         "lo",
		HardwareAddrVal: nil,
		FlagsVal:        net.FlagLoopback | net.FlagUp,
	}}, nil
}

// InterfaceAddrs returns the unicast interface addresses for the loopback interface.
// It returns the IPv4 loopback range 127.0.0.0/8 to be permissive.
func (ln *LoopbackNetwork) InterfaceAddrs() ([]net.Addr, error) {
	// Use IPv4 localhost /8 to be permissive
	ipnet := &net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.CIDRMask(8, 32),
	}
	return []net.Addr{ipnet}, nil
}

// InterfacesByIndex returns the network interface with the given index.
// It returns the loopback interface only if index is 1, otherwise returns
// an error indicating the interface was not found.
func (ln *LoopbackNetwork) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	if index == 1 {
		ifs, _ := ln.Interfaces()
		return ifs, nil
	}
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// InterfacesByName returns the network interface with the given name.
// It returns the loopback interface only if name is "lo", otherwise returns
// an error indicating the interface was not found.
func (ln *LoopbackNetwork) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	if name == "lo" {
		ifs, _ := ln.Interfaces()
		return ifs, nil
	}
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// LookupMX returns an error indicating no MX records exist for the given name.
// The loopback network does not support DNS MX record lookups.
func (ln *LoopbackNetwork) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       name,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	// TODO: Better error?
	return nil, &net.DNSError{
		Name:       name,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupSRV returns an error indicating no SRV records exist for the given service.
// The loopback network does not support DNS SRV record lookups.
func (ln *LoopbackNetwork) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return "", nil, &net.DNSError{
			Name:       "_svc._" + proto + "." + name,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	// TODO: Better error?
	return "", nil, &net.DNSError{
		Name:       "_svc._" + proto + "." + name,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupTXT returns an empty slice for local addresses, or an error for non-local addresses.
// The loopback network does not support DNS TXT record lookups for external hosts.
func (ln *LoopbackNetwork) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       name,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(name) {
		return make([]string, 0), nil
	}
	// TODO: Better error?
	return nil, &net.DNSError{
		Name:       name,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupAddr performs a reverse lookup for the given address.
// It returns ["localhost"] for local addresses, or an error for non-local addresses.
func (ln *LoopbackNetwork) LookupAddr(
	ctx context.Context, addr string,
) (names []string, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       addr,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(addr) {
		return []string{"localhost"}, nil
	}
	// TODO: Better error?
	return nil, &net.DNSError{
		Name:       addr,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupCNAME returns an error indicating no CNAME exists for the given host.
// The loopback network does not support DNS CNAME lookups.
func (ln *LoopbackNetwork) LookupCNAME(
	ctx context.Context, host string,
) (cname string, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return "", &net.DNSError{
			Name:       host,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	// TODO: Better error?
	return "", &net.DNSError{
		Name:       host,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupPort looks up the port number for the given network and service.
// It delegates to gonnect.LookupPortOffline for offline port resolution.
func (ln *LoopbackNetwork) LookupPort(
	ctx context.Context, network, service string,
) (port int, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return 0, &net.DNSError{
			Name:       service,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	return gonnect.LookupPortOffline(network, service)
}

// LookupHost looks up the host and returns a slice of IP address strings.
// It returns ["127.0.0.1", "::1"] for local hosts, or an error for non-local hosts.
func (ln *LoopbackNetwork) LookupHost(
	ctx context.Context, host string,
) (addrs []string, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       host,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(host) {
		return []string{"127.0.0.1", "::1"}, nil
	}
	return nil, &net.DNSError{
		Name:       host,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupIP looks up the host and returns a slice of net.IP values.
// The network parameter specifies the IP version: "ip4" returns IPv4 only,
// "ip6" returns IPv6 only, and other values return both IPv4 and IPv6.
// Returns an error for non-local addresses.
func (ln *LoopbackNetwork) LookupIP(
	ctx context.Context, network, address string,
) (addrs []net.IP, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       address,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(address) {
		if strings.HasSuffix(network, "4") {
			return []net.IP{net.ParseIP("127.0.0.1").To4()}, nil
		}
		if strings.HasSuffix(network, "6") {
			return []net.IP{net.ParseIP("::1").To16()}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil
	}
	return nil, &net.DNSError{
		Name:       address,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupNetIP looks up the host and returns a slice of netip.Addr values.
// The network parameter specifies the IP version: "ip4" returns IPv4 only,
// "ip6" returns IPv6 only, and other values return both IPv4 and IPv6.
// Returns an error for non-local addresses.
func (ln *LoopbackNetwork) LookupNetIP(
	ctx context.Context, network, address string,
) (addrs []netip.Addr, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       address,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(address) {
		ip4, _ := netip.AddrFromSlice(net.ParseIP("127.0.0.1").To4())
		ip6, _ := netip.AddrFromSlice(net.ParseIP("::1").To4())
		if strings.HasSuffix(network, "4") {
			return []netip.Addr{ip4}, nil
		}
		if strings.HasSuffix(network, "6") {
			return []netip.Addr{ip6}, nil
		}
		return []netip.Addr{
			ip4,
			ip6,
		}, nil
	}
	return nil, &net.DNSError{
		Name:       address,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupNS returns an error indicating no NS records exist for the given name.
// The loopback network does not support DNS NS record lookups.
func (ln *LoopbackNetwork) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       name,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	// TODO: Better error?
	return nil, &net.DNSError{
		Name:       name,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// LookupIPAddr looks up the host and returns a slice of net.IPAddr values.
// It returns both IPv4 and IPv6 loopback addresses for local hosts,
// or an error for non-local hosts.
func (ln *LoopbackNetwork) LookupIPAddr(
	ctx context.Context, host string,
) (addrs []net.IPAddr, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, &net.DNSError{
			Name:       host,
			Err:        "network is down",
			IsNotFound: true,
		}
	}
	if helpers.IsLocal(host) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("::1")},
		}, nil
	}
	return nil, &net.DNSError{
		Name:       host,
		Err:        "no such host",
		IsNotFound: true,
	}
}

// Listen announces on the specified network and address.
// It delegates to ListenTCP for TCP-based networks.
// The returned listener is wrapped with loopback-specific error handling.
func (ln *LoopbackNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackListenErrWrap(err, network, address)
	}
	ln.mu.Unlock()

	l, err := ln.ListenTCP(ctx, network, address)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, address)
	}
	return l, err
}

// ListenTCP announces on the specified TCP network and address.
// It accepts "tcp", "tcp4", or "tcp6" as valid network types.
// The returned TCPListener is an in-memory listener that accepts
// connections via net.Pipe().
func (ln *LoopbackNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackListenErrWrap(err, network, laddr)
	}
	ln.mu.Unlock()

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}

	host, port, err := loopbackListenPrep(network, laddr)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, laddr)
	}

	reg := ln.tcp4reg
	if host == "::1" {
		reg = ln.tcp6reg
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	listener, err := newLoopbackTCPListener(reg, port)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, laddr)
	}

	// Wrap with callbacks for tracking
	ln.mu.Lock()
	id := ln.getID()
	listener.cb = &gonnect.Callbacks{
		BeforeClose: ln.buildUnregCallback(id),
		OnAcceptTCP: ln.registerTCPConnCallback,
	}
	ln.register(id, listener)
	ln.mu.Unlock()

	return listener, err
}

// ListenPacket announces on the specified network and address for packet-oriented protocols.
// It delegates to ListenUDP for UDP-based networks.
// The returned PacketConn is wrapped with loopback-specific error handling.
func (ln *LoopbackNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackListenErrWrap(err, network, address)
	}
	ln.mu.Unlock()

	conn, err := ln.ListenUDP(ctx, network, address)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, address)
	}
	return conn, err
}

// ListenUDP announces on the specified UDP network and address.
// It accepts "udp", "udp4", or "udp6" as valid network types.
// The returned UDPConn is an in-memory UDP connection that communicates
// via buffered channels.
func (ln *LoopbackNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackListenErrWrap(err, network, laddr)
	}
	ln.mu.Unlock()

	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, net.UnknownNetworkError(network)
	}

	host, port, err := loopbackListenPrep(network, laddr)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, laddr)
	}

	reg := ln.udp4reg
	if host == "::1" {
		reg = ln.udp6reg
		network = "udp6"
	} else {
		network = "udp4"
	}

	conn, err := newLoopbackUDPConn(reg, port, nil)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, laddr)
	}

	// Wrap with callbacks for tracking
	ln.mu.Lock()
	id := ln.getID()
	conn.cb = &gonnect.Callbacks{
		BeforeClose: ln.buildUnregCallback(id),
	}
	ln.register(id, conn)
	ln.mu.Unlock()

	return conn, err
}

// DialTCP establishes a TCP connection to the remote address using the specified network.
// It accepts "tcp", "tcp4", or "tcp6" as valid network types.
// If laddr is not empty, it is used as the local address for the connection.
// The connection is established using net.Pipe() between the client and server.
// Returns an error if no listener is bound to the remote address.
func (ln *LoopbackNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}
	ln.mu.Unlock()

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, net.UnknownNetworkError(network)
	}

	host, lport, rport, err := loopbackDialPrep(network, laddr, raddr)
	if err != nil {
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}

	reg := ln.tcp4reg
	if host == "::1" {
		reg = ln.tcp6reg
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	raddr = net.JoinHostPort(host, strconv.Itoa(rport))
	serverAddr := &helpers.NetAddr{Net: network, Addr: raddr}
	listener := reg.Lookup(serverAddr)
	if listener == nil {
		return nil, ge.ConnRefused(network, raddr)
	}

	serverPipe, clientPipe := net.Pipe()
	serverConn := &loopbackTCPConn{
		Conn:  serverPipe,
		Laddr: serverAddr,
	}
	clientConn := &loopbackTCPConn{
		Conn:  clientPipe,
		Raddr: serverAddr,
	}
	err = reg.RegConn(lport, clientConn)
	if err != nil {
		_ = serverPipe.Close()
		_ = clientPipe.Close()
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}
	serverConn.Raddr = clientConn.Laddr
	err = listener.NewConn(serverConn)
	if err != nil {
		_ = serverPipe.Close()
		_ = clientConn.Close()
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}

	// Wrap with callbacks for tracking
	ln.mu.Lock()
	id := ln.getID()
	clientConn.cb = &gonnect.Callbacks{
		BeforeClose: ln.buildUnregCallback(id),
	}
	ln.register(id, clientConn)
	ln.mu.Unlock()

	return clientConn, nil
}

// DialUDP establishes a UDP connection to the remote address using the specified network.
// It accepts "udp", "udp4", or "udp6" as valid network types.
// If laddr is not empty, it is used as the local address for the connection.
// The returned UDPConn is an in-memory UDP connection that communicates
// via buffered channels.
func (ln *LoopbackNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}
	ln.mu.Unlock()

	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, net.UnknownNetworkError(network)
	}

	host, lport, rport, err := loopbackDialPrep(network, laddr, raddr)
	if err != nil {
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}

	reg := ln.udp4reg
	if host == "::1" {
		reg = ln.udp6reg
		network = "udp6"
	} else {
		network = "udp4"
	}

	if rport < 0 || rport > 65535 {
		return nil, loopbackDialErrWrap(&net.AddrError{
			Err:  "invalid port",
			Addr: raddr,
		}, network, laddr, raddr)
	}
	port := uint16(rport)
	con, err := newLoopbackUDPConn(reg, lport, &port)
	if err != nil {
		return nil, loopbackDialErrWrap(err, network, laddr, raddr)
	}

	// Wrap with callbacks for tracking
	ln.mu.Lock()
	id := ln.getID()
	con.cb = &gonnect.Callbacks{
		BeforeClose: ln.buildUnregCallback(id),
	}
	ln.register(id, con)
	ln.mu.Unlock()

	return con, loopbackDialErrWrap(err, network, laddr, raddr)
}

// Dial establishes a connection to the address on the specified network.
// It routes to DialTCP for TCP networks ("tcp", "tcp4", "tcp6") or
// to DialUDP for UDP networks ("udp", "udp4", "udp6").
// Returns an error for unknown network types.
func (ln *LoopbackNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackDialErrWrap(err, network, address, "")
	}
	ln.mu.Unlock()

	var conn net.Conn
	var dialErr error
	switch {
	case strings.HasPrefix(network, "tcp"):
		conn, dialErr = ln.DialTCP(ctx, network, "", address)
	case strings.HasPrefix(network, "udp"):
		conn, dialErr = ln.DialUDP(ctx, network, "", address)
	default:
		return nil, net.UnknownNetworkError(network)
	}
	if dialErr != nil {
		return nil, loopbackDialErrWrap(dialErr, network, address, "")
	}
	return conn, dialErr
}

// Down shuts down the network by closing all tracked connections and listeners.
// After calling Down, the network will reject new operations until Up() is called.
func (ln *LoopbackNetwork) Down() error {
	closers := ln.downPrep()
	for _, c := range closers {
		_ = c.Close()
	}
	return nil
}

// Up re-enables the network after it has been shut down with Down().
func (ln *LoopbackNetwork) Up() error {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	ln.up = true
	return nil
}

// IsUp returns whether the network is currently active.
func (ln *LoopbackNetwork) IsUp() (bool, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	return ln.up, nil
}

// downPrep prepares the network for shutdown by marking it as down
// and collecting all tracked closers for cleanup.
// It returns the closers that should be closed after releasing the lock.
func (ln *LoopbackNetwork) downPrep() (closers []io.Closer) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return
	}
	ln.up = false
	closers = make([]io.Closer, len(ln.closers))
	if ln.closers == nil {
		return
	}
	closers = slices.Collect(maps.Values(ln.closers))
	return
}

// getID returns the next unique ID for tracking connections.
// WARN: NOT thread safe - caller must hold ln.mu lock.
func (ln *LoopbackNetwork) getID() uint64 {
	id := ln.nextID
	ln.nextID += 1
	return id
}

// register stores a connection or listener with the given ID for tracking.
// WARN: NOT thread safe - caller must hold ln.mu lock.
func (ln *LoopbackNetwork) register(id uint64, c io.Closer) {
	if ln.closers == nil {
		ln.closers = make(map[uint64]io.Closer)
	}
	ln.closers[id] = c
}

// unregister removes a connection or listener from tracking by ID.
func (ln *LoopbackNetwork) unregister(id uint64) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	delete(ln.closers, id)
}

// buildUnregCallback returns a callback function that unregisters a connection
// by ID when called. This is used as the BeforeClose callback for tracked connections.
func (ln *LoopbackNetwork) buildUnregCallback(id uint64) func() {
	return func() {
		ln.unregister(id)
	}
}

// checkUp returns an error if the network is down.
// WARN: NOT thread safe - caller must hold ln.mu lock.
func (ln *LoopbackNetwork) checkUp() error {
	if !ln.up {
		return ErrNetworkDown
	}
	return nil
}

// registerTCPConnCallback wraps an accepted TCP connection with tracking callbacks.
// It rejects the connection if the network is down.
func (ln *LoopbackNetwork) registerTCPConnCallback(
	conn gonnect.TCPConn,
) (gonnect.TCPConn, error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.up {
		return nil, ge.ConnRefused(
			"tcp",
			conn.RemoteAddr().String(),
		)
	}
	id := ln.getID()
	conn = &gonnect.CallbackTCPConn{
		TCPConn: conn,
		CB: &gonnect.Callbacks{
			BeforeClose: ln.buildUnregCallback(id),
		},
	}
	ln.register(id, conn)
	return conn, nil
}
