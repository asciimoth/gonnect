package tls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

var _ interface {
	gonnect.Network
	gonnect.UpDown
	io.Closer
	gonnect.CloserSubscriber
	gonnect.UpDownSubscriber
	gonnect.Wrapper
} = (*ClientServerNetwork)(nil)

// ClientServerConfig configures ClientServerNetwork.
type ClientServerConfig struct {
	// ClientConfig is the base TLS client config used for TCP Dial and
	// DialTCP. It is required and cloned by the constructor.
	//
	// When ClientConfig.ServerName is empty, ClientServerNetwork sets it to the
	// Dial destination host before the TLS handshake. This matches the default
	// SNI behavior of crypto/tls dial helpers.
	ClientConfig *stdtls.Config

	// ServerConfig is the base TLS server config used for TCP Listen and
	// ListenTCP. It is required and cloned by the constructor.
	ServerConfig *stdtls.Config

	// Mappings optionally select TLS options from connection metadata. Rules
	// never change the network, source address, or destination address. Use
	// other gonnect.Network middlewares for routing or address remapping.
	Mappings []ClientServerMapping
}

// ClientServerMapping maps TCP connection metadata to TLS options.
//
// Empty match fields are wildcards. Values in one field are ORed. Different
// fields are ANDed. Rules are applied in order, and later matching rules can
// replace options set by earlier matching rules.
//
// Networks are exact or glob patterns over the Network method network string,
// such as "tcp", "tcp4", or "tcp*".
//
// For Dial, ConnDsts match the requested remote address and the actual remote
// socket address after dialing. Dial has no requested source address.
//
// For DialTCP, ConnSrcs match the requested local address and the actual local
// socket address after dialing. ConnDsts match the requested remote address and
// the actual remote socket address after dialing.
//
// For Listen and ListenTCP, ConnSrcs match the accepted peer address. ConnDsts
// match the requested listen address and the accepted connection local address.
// Source and destination patterns use the same syntax as
// gonnect.FilterFromString: host, host:port, IP, IP:port, CIDR, and host
// wildcards are supported.
type ClientServerMapping struct {
	Networks []string
	ConnSrcs []string
	ConnDsts []string

	// Client applies when this rule matches a TCP Dial or DialTCP call.
	Client ClientServerTLSOptions

	// Server applies when this rule matches a connection accepted from a TCP
	// Listen or ListenTCP call.
	Server ClientServerTLSOptions
}

// ClientServerTLSOptions contains TLS options selected by a mapping.
type ClientServerTLSOptions struct {
	// Config replaces the side's base tls.Config when this option set applies.
	// It is cloned by the constructor and cloned again for each connection.
	// ServerName and NextProtos below are applied after Config is selected. On
	// the server side they are also applied to a non-nil config returned by
	// Config.GetConfigForClient.
	Config *stdtls.Config

	// ServerName sets tls.Config.ServerName. On the client side this controls
	// certificate verification and the SNI host sent to the server. Empty means
	// no override, so the client-side default can still use the dial
	// destination host.
	ServerName string

	// NextProtos replaces tls.Config.NextProtos. Nil means no override. A
	// non-nil empty slice disables ALPN.
	NextProtos []string
}

// ClientServerNetwork is a gonnect.Network middleware that wraps TCP streams
// in TLS on both client and server sides.
//
// Dial and DialTCP delegate the TCP connection to the wrapped Network, apply
// the client TLS config, complete the TLS client handshake, and return the TLS
// connection. Listen and ListenTCP delegate the TCP listener to the wrapped
// Network and return a listener whose accepted connections are TLS server
// connections.
//
// Non-TCP dial and listen operations, UDP, packet operations, resolvers, and
// interface calls are delegated unchanged. Lifecycle calls are delegated when
// the wrapped Network implements the matching optional interface. If it does
// not, Close, Up, Down, SubscribeCloser, and SubscribeUpDown are no-ops, and
// IsUp reports true. IsNative always reports false because this middleware
// changes TCP behavior.
type ClientServerNetwork struct {
	network      gonnect.Network
	clientConfig *stdtls.Config
	serverConfig *stdtls.Config
	mappings     []compiledClientServerMapping
}

// NewClientServerNetwork wraps network with client and server TLS behavior.
func NewClientServerNetwork(
	network gonnect.Network,
	clientConfig *stdtls.Config,
	serverConfig *stdtls.Config,
	mappings ...ClientServerMapping,
) (*ClientServerNetwork, error) {
	return NewClientServerNetworkWithConfig(network, ClientServerConfig{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
		Mappings:     mappings,
	})
}

// NewClientServerNetworkWithConfig wraps network with client and server TLS
// behavior.
func NewClientServerNetworkWithConfig(
	network gonnect.Network,
	config ClientServerConfig,
) (*ClientServerNetwork, error) {
	if network == nil {
		return nil, errors.New("gonnect/tls: nil Network")
	}
	if config.ClientConfig == nil {
		return nil, errors.New("gonnect/tls: nil client tls.Config")
	}
	if config.ServerConfig == nil {
		return nil, errors.New("gonnect/tls: nil server tls.Config")
	}

	mappings, err := compileClientServerMappings(config.Mappings)
	if err != nil {
		return nil, err
	}

	return &ClientServerNetwork{
		network:      network,
		clientConfig: config.ClientConfig.Clone(),
		serverConfig: config.ServerConfig.Clone(),
		mappings:     mappings,
	}, nil
}

// GetWrapped returns the wrapped Network.
func (n *ClientServerNetwork) GetWrapped() any { return n.network }

// GetNetwork returns the wrapped Network.
func (n *ClientServerNetwork) GetNetwork() gonnect.Network { return n.network }

// IsNative always reports false because the middleware changes TCP behavior.
func (n *ClientServerNetwork) IsNative() bool { return false }

// Close closes the wrapped Network when it implements io.Closer.
func (n *ClientServerNetwork) Close() error {
	if closer, ok := n.network.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (n *ClientServerNetwork) SubscribeCloser(c io.Closer) (func(), error) {
	if sub, ok := n.network.(gonnect.CloserSubscriber); ok {
		return sub.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements gonnect.UpDown.
func (n *ClientServerNetwork) Up() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements gonnect.UpDown.
func (n *ClientServerNetwork) Down() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements gonnect.UpDown.
func (n *ClientServerNetwork) IsUp() (bool, error) {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (n *ClientServerNetwork) SubscribeUpDown(
	u gonnect.UpDown,
) (func(), error) {
	if sub, ok := n.network.(gonnect.UpDownSubscriber); ok {
		return sub.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial wraps TCP dials in a TLS client connection and delegates all other
// networks unchanged.
func (n *ClientServerNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.Dial(ctx, network, address)
	}

	raw, err := n.network.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	info := clientServerDialInfo(network, "", address, raw)
	config := n.clientTLSConfig(info)
	conn := stdtls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Listen wraps TCP listeners in TLS server behavior and delegates all other
// networks unchanged.
func (n *ClientServerNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.Listen(ctx, network, address)
	}

	listener, err := n.network.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &clientServerListener{
		Listener: listener,
		owner:    n,
		network:  network,
		address:  address,
	}, nil
}

// PacketDial delegates to the wrapped Network.
func (n *ClientServerNetwork) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.PacketDial(ctx, network, address)
}

// ListenPacket delegates to the wrapped Network.
func (n *ClientServerNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.ListenPacket(ctx, network, address)
}

// DialTCP wraps TCP dials in a TLS client connection and delegates unknown or
// non-TCP networks unchanged.
func (n *ClientServerNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.DialTCP(ctx, network, laddr, raddr)
	}

	raw, err := n.network.DialTCP(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	info := clientServerDialInfo(network, laddr, raddr, raw)
	config := n.clientTLSConfig(info)
	conn := stdtls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &clientServerTCPConn{Conn: conn, wrapped: raw}, nil
}

// ListenTCP wraps TCP listeners in TLS server behavior and delegates unknown
// or non-TCP networks unchanged.
func (n *ClientServerNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.ListenTCP(ctx, network, laddr)
	}

	listener, err := n.network.ListenTCP(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return &clientServerTCPListener{
		TCPListener: listener,
		owner:       n,
		network:     network,
		address:     laddr,
	}, nil
}

// DialUDP delegates to the wrapped Network.
func (n *ClientServerNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	return n.network.DialUDP(ctx, network, laddr, raddr)
}

// ListenUDP delegates to the wrapped Network.
func (n *ClientServerNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return n.network.ListenUDP(ctx, network, laddr)
}

// ListenPacketConfig delegates to the wrapped Network.
func (n *ClientServerNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.ListenPacketConfig(ctx, lc, network, address)
}

// ListenUDPConfig delegates to the wrapped Network.
func (n *ClientServerNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return n.network.ListenUDPConfig(ctx, lc, network, laddr)
}

// ListenMulticastUDP delegates to the wrapped Network.
func (n *ClientServerNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts gonnect.MulticastOptions,
) (gonnect.MulticastPacketConn, error) {
	return n.network.ListenMulticastUDP(ctx, network, address, opts)
}

// LookupIP delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return n.network.LookupIP(ctx, network, address)
}

// LookupIPAddr delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return n.network.LookupIPAddr(ctx, host)
}

// LookupNetIP delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return n.network.LookupNetIP(ctx, network, host)
}

// LookupHost delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return n.network.LookupHost(ctx, host)
}

// LookupAddr delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return n.network.LookupAddr(ctx, addr)
}

// LookupCNAME delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return n.network.LookupCNAME(ctx, host)
}

// LookupPort delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return n.network.LookupPort(ctx, network, service)
}

// LookupNS delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return n.network.LookupNS(ctx, name)
}

// LookupMX delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return n.network.LookupMX(ctx, name)
}

// LookupSRV delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return n.network.LookupSRV(ctx, service, proto, name)
}

// LookupTXT delegates to the wrapped Network.
func (n *ClientServerNetwork) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return n.network.LookupTXT(ctx, name)
}

// Interfaces delegates to the wrapped Network.
func (n *ClientServerNetwork) Interfaces() ([]gonnect.NetworkInterface, error) {
	return n.network.Interfaces()
}

// InterfaceAddrs delegates to the wrapped Network.
func (n *ClientServerNetwork) InterfaceAddrs() ([]net.Addr, error) {
	return n.network.InterfaceAddrs()
}

// InterfaceMulticastAddrs delegates to the wrapped Network.
func (n *ClientServerNetwork) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return n.network.InterfaceMulticastAddrs()
}

// InterfacesByIndex delegates to the wrapped Network.
func (n *ClientServerNetwork) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	return n.network.InterfacesByIndex(index)
}

// InterfacesByName delegates to the wrapped Network.
func (n *ClientServerNetwork) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	return n.network.InterfacesByName(name)
}

type clientServerConnInfo struct {
	network      string
	requestedSrc string
	requestedDst string
	actualSrc    string
	actualDst    string
}

func clientServerDialInfo(
	network string,
	laddr string,
	raddr string,
	conn net.Conn,
) clientServerConnInfo {
	return clientServerConnInfo{
		network:      network,
		requestedSrc: laddr,
		requestedDst: raddr,
		actualSrc:    addrString(conn.LocalAddr()),
		actualDst:    addrString(conn.RemoteAddr()),
	}
}

func clientServerListenInfo(
	network string,
	laddr string,
	conn net.Conn,
) clientServerConnInfo {
	return clientServerConnInfo{
		network:      network,
		requestedDst: laddr,
		actualSrc:    addrString(conn.RemoteAddr()),
		actualDst:    addrString(conn.LocalAddr()),
	}
}

func (n *ClientServerNetwork) clientTLSConfig(
	info clientServerConnInfo,
) *stdtls.Config {
	defaultServerName := dialDestinationHost(info.requestedDst)
	config := n.clientConfig.Clone()
	if config.ServerName == "" {
		config.ServerName = defaultServerName
	}

	for _, mapping := range n.mappings {
		if !mapping.match(info) {
			continue
		}
		config = mapping.client.apply(config, defaultServerName)
	}
	return config
}

func (n *ClientServerNetwork) serverTLSConfig(
	info clientServerConnInfo,
) *stdtls.Config {
	config := n.serverConfig.Clone()
	var overrides []compiledClientServerTLSOptions
	for _, mapping := range n.mappings {
		if !mapping.match(info) {
			continue
		}
		config = mapping.server.apply(config, "")
		if mapping.server.config != nil {
			overrides = nil
		}
		if mapping.server.hasScalarOverrides() {
			overrides = append(overrides, mapping.server)
		}
	}
	return configWithServerOptionOverrides(config, overrides)
}

func dialDestinationHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return host
}

type compiledClientServerMapping struct {
	networks patternMatcher
	connSrcs addressMatcher
	connDsts addressMatcher
	client   compiledClientServerTLSOptions
	server   compiledClientServerTLSOptions
}

func compileClientServerMappings(
	mappings []ClientServerMapping,
) ([]compiledClientServerMapping, error) {
	compiled := make([]compiledClientServerMapping, len(mappings))
	for i, mapping := range mappings {
		networks, err := newPatternMatcher(
			"ClientServer network",
			mapping.Networks,
			false,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"gonnect/tls: compile ClientServer mapping %d: %w",
				i,
				err,
			)
		}
		compiled[i] = compiledClientServerMapping{
			networks: networks,
			connSrcs: newAddressMatcher(mapping.ConnSrcs),
			connDsts: newAddressMatcher(mapping.ConnDsts),
			client:   compileClientServerTLSOptions(mapping.Client),
			server:   compileClientServerTLSOptions(mapping.Server),
		}
	}
	return compiled, nil
}

func (m compiledClientServerMapping) match(info clientServerConnInfo) bool {
	if !m.networks.match(info.network) {
		return false
	}
	if !m.connSrcs.match(
		info.network,
		info.requestedSrc,
		info.actualSrc,
	) {
		return false
	}
	if !m.connDsts.match(
		info.network,
		info.requestedDst,
		info.actualDst,
	) {
		return false
	}
	return true
}

type compiledClientServerTLSOptions struct {
	config        *stdtls.Config
	serverName    string
	nextProtos    []string
	nextProtosSet bool
}

func compileClientServerTLSOptions(
	options ClientServerTLSOptions,
) compiledClientServerTLSOptions {
	var config *stdtls.Config
	if options.Config != nil {
		config = options.Config.Clone()
	}
	return compiledClientServerTLSOptions{
		config:        config,
		serverName:    options.ServerName,
		nextProtos:    append([]string(nil), options.NextProtos...),
		nextProtosSet: options.NextProtos != nil,
	}
}

func (o compiledClientServerTLSOptions) apply(
	config *stdtls.Config,
	defaultServerName string,
) *stdtls.Config {
	if o.config != nil {
		config = o.config.Clone()
		if config.ServerName == "" {
			config.ServerName = defaultServerName
		}
	}
	if o.serverName != "" {
		config.ServerName = o.serverName
	}
	if o.nextProtosSet {
		config.NextProtos = append([]string(nil), o.nextProtos...)
	}
	return config
}

func (o compiledClientServerTLSOptions) applyScalars(
	config *stdtls.Config,
) {
	if o.serverName != "" {
		config.ServerName = o.serverName
	}
	if o.nextProtosSet {
		config.NextProtos = append([]string(nil), o.nextProtos...)
	}
}

func (o compiledClientServerTLSOptions) hasScalarOverrides() bool {
	return o.serverName != "" || o.nextProtosSet
}

func configWithServerOptionOverrides(
	config *stdtls.Config,
	overrides []compiledClientServerTLSOptions,
) *stdtls.Config {
	if len(overrides) == 0 || config.GetConfigForClient == nil {
		return config
	}

	getConfigForClient := config.GetConfigForClient
	config.GetConfigForClient = func(
		hello *stdtls.ClientHelloInfo,
	) (*stdtls.Config, error) {
		selected, err := getConfigForClient(hello)
		if err != nil || selected == nil {
			return selected, err
		}
		selected = selected.Clone()
		for _, override := range overrides {
			override.applyScalars(selected)
		}
		return selected, nil
	}
	return config
}

type clientServerListener struct {
	net.Listener
	owner   *ClientServerNetwork
	network string
	address string
}

var _ gonnect.Wrapper = (*clientServerListener)(nil)

func (l *clientServerListener) GetWrapped() any { return l.Listener }

func (l *clientServerListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	config := l.owner.serverTLSConfig(
		clientServerListenInfo(l.network, l.address, conn),
	)
	return stdtls.Server(conn, config), nil
}

type clientServerTCPListener struct {
	gonnect.TCPListener
	owner   *ClientServerNetwork
	network string
	address string
}

var _ interface {
	gonnect.TCPListener
	gonnect.Wrapper
} = (*clientServerTCPListener)(nil)

func (l *clientServerTCPListener) GetWrapped() any { return l.TCPListener }

func (l *clientServerTCPListener) Accept() (net.Conn, error) {
	return l.AcceptTCP()
}

func (l *clientServerTCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	config := l.owner.serverTLSConfig(
		clientServerListenInfo(l.network, l.address, conn),
	)
	tlsConn := stdtls.Server(conn, config)
	return &clientServerTCPConn{
		Conn:    tlsConn,
		wrapped: conn,
	}, nil
}

type clientServerTCPConn struct {
	*stdtls.Conn

	wrapped  gonnect.TCPConn
	closeMux sync.Once
	closeErr error
}

var _ interface {
	gonnect.TCPConn
	gonnect.Wrapper
} = (*clientServerTCPConn)(nil)

func (c *clientServerTCPConn) GetWrapped() any { return c.wrapped }

func (c *clientServerTCPConn) Close() error {
	c.closeMux.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *clientServerTCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.Conn, r)
}

func (c *clientServerTCPConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, c.Conn)
}

func (c *clientServerTCPConn) SetKeepAlive(keepalive bool) error {
	return c.wrapped.SetKeepAlive(keepalive)
}

func (c *clientServerTCPConn) SetKeepAliveConfig(
	config net.KeepAliveConfig,
) error {
	return c.wrapped.SetKeepAliveConfig(config)
}

func (c *clientServerTCPConn) SetKeepAlivePeriod(d time.Duration) error {
	return c.wrapped.SetKeepAlivePeriod(d)
}

func (c *clientServerTCPConn) SetLinger(sec int) error {
	return c.wrapped.SetLinger(sec)
}

func (c *clientServerTCPConn) SetNoDelay(noDelay bool) error {
	return c.wrapped.SetNoDelay(noDelay)
}

func (c *clientServerTCPConn) CloseRead() error {
	return c.wrapped.CloseRead()
}

func (c *clientServerTCPConn) CloseWrite() error {
	return c.Conn.CloseWrite()
}
