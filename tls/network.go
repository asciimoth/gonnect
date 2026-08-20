package tls

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

var _ interface {
	gonnect.Network
	gonnect.UpDown
	io.Closer
	gonnect.CloserSubscriber
	gonnect.UpDownSubscriber
	gonnect.Wrapper
} = (*Network)(nil)

const (
	defaultLeafTTL      = 24 * time.Hour
	maxLeafCacheEntries = 256
)

var (
	// ErrNoVisibleSNI is used when a TLS ClientHello does not contain a
	// visible server name. The middleware needs that name to create a leaf
	// certificate and to set the upstream tls.Config ServerName.
	ErrNoVisibleSNI = errors.New(
		"gonnect/tls: TLS connection has no visible SNI",
	)

	// ErrEncryptedClientHello is used when a ClientHello signals encrypted
	// client hello. The middleware rejects the connection because it cannot
	// see the inner SNI name.
	ErrEncryptedClientHello = errors.New(
		"gonnect/tls: TLS connection uses encrypted client hello",
	)

	errCannotInterceptTLS = errors.New(
		"gonnect/tls: cannot intercept TLS connection",
	)
)

// Config configures a TLS MITM Network.
type Config struct {
	// CA is the certificate authority used to sign generated leaf
	// certificates. It must include at least one certificate and a private key.
	CA stdtls.Certificate

	// ClientConfig configures the upstream TLS client connection. The
	// middleware clones this config for each intercepted connection and sets
	// ServerName and NextProtos from the client's ClientHello. Nil uses the Go
	// TLS defaults with ServerName and NextProtos set from the ClientHello.
	ClientConfig *stdtls.Config

	// SniffBufferSize is the maximum number of bytes inspected from the first
	// client write. Zero uses sniffer.DefaultTLSClientHelloMaxBytes. A smaller
	// value can cause large TLS ClientHello messages to be rejected.
	SniffBufferSize int

	// LeafTTL is the validity period for generated leaf certificates. Zero uses
	// a conservative default. The CA expiration still bounds the leaf
	// certificate expiration.
	LeafTTL time.Duration

	// InterceptionFilter optionally selects which TLS connections are
	// intercepted. The zero value keeps the default behavior and intercepts
	// every interceptable TLS ClientHello. Filtered-out TLS connections are
	// passed through unchanged to the wrapped Network.
	InterceptionFilter InterceptionFilter

	// Spawner optionally starts background copy workers. Nil uses normal
	// goroutines.
	Spawner gonnect.Spawner
}

// Network is a gonnect.Network middleware that MITMs outgoing TLS TCP dials.
//
// Dial and DialTCP establish the real upstream TCP connection immediately, so
// dial errors are still returned by those calls. The returned connection is a
// local TCP-like pipe. A background worker sniffs the first client bytes. If
// they are interceptable TLS, the worker terminates client TLS with a generated
// certificate and then opens upstream TLS through the already-dialed connection.
// If they are non-TLS, the worker relays bytes without modification.
// Server-first TCP protocols are out of scope; callers should use connection
// deadlines or another timeout policy and close the connection on timeout.
//
// Lifecycle calls are delegated when the wrapped Network implements the
// matching optional interface. If it does not, Close, Up, Down,
// SubscribeCloser, and SubscribeUpDown are no-ops, and IsUp reports true.
// IsNative always reports false because this middleware changes TCP behavior.
type Network struct {
	network         gonnect.Network
	ca              stdtls.Certificate
	caCert          *x509.Certificate
	clientConfig    *stdtls.Config
	sniffBufferSize int
	leafTTL         time.Duration
	filter          compiledInterceptionFilter
	spawner         gonnect.Spawner

	leafMu    sync.Mutex
	leafCache map[string]stdtls.Certificate
}

// NewNetwork wraps network with TLS MITM behavior.
func NewNetwork(
	network gonnect.Network,
	ca stdtls.Certificate,
	clientConfig *stdtls.Config,
) (*Network, error) {
	return NewNetworkWithConfig(network, Config{
		CA:           ca,
		ClientConfig: clientConfig,
	})
}

// NewNetworkWithConfig wraps network with TLS MITM behavior.
func NewNetworkWithConfig(
	network gonnect.Network,
	config Config,
) (*Network, error) {
	if network == nil {
		return nil, errors.New("gonnect/tls: nil Network")
	}
	if config.SniffBufferSize < 0 {
		return nil, errors.New("gonnect/tls: negative SniffBufferSize")
	}
	if config.LeafTTL < 0 {
		return nil, errors.New("gonnect/tls: negative LeafTTL")
	}
	filter, err := compileInterceptionFilter(config.InterceptionFilter)
	if err != nil {
		return nil, err
	}

	ca, caCert, err := parseCA(config.CA)
	if err != nil {
		return nil, err
	}

	sniffBufferSize := config.SniffBufferSize
	if sniffBufferSize == 0 {
		sniffBufferSize = sniffer.DefaultTLSClientHelloMaxBytes
	}

	leafTTL := config.LeafTTL
	if leafTTL == 0 {
		leafTTL = defaultLeafTTL
	}

	var clientConfig *stdtls.Config
	if config.ClientConfig != nil {
		clientConfig = config.ClientConfig.Clone()
	}

	return &Network{
		network:         network,
		ca:              ca,
		caCert:          caCert,
		clientConfig:    clientConfig,
		sniffBufferSize: sniffBufferSize,
		leafTTL:         leafTTL,
		filter:          filter,
		spawner:         config.Spawner,
	}, nil
}

// GetWrapped returns the wrapped Network.
func (n *Network) GetWrapped() any { return n.network }

// GetNetwork returns the wrapped Network.
func (n *Network) GetNetwork() gonnect.Network { return n.network }

// IsNative always reports false because the middleware changes TCP behavior.
func (n *Network) IsNative() bool { return false }

// Close closes the wrapped Network when it implements io.Closer.
func (n *Network) Close() error {
	if closer, ok := n.network.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (n *Network) SubscribeCloser(c io.Closer) (func(), error) {
	if sub, ok := n.network.(gonnect.CloserSubscriber); ok {
		return sub.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements gonnect.UpDown.
func (n *Network) Up() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements gonnect.UpDown.
func (n *Network) Down() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements gonnect.UpDown.
func (n *Network) IsUp() (bool, error) {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (n *Network) SubscribeUpDown(u gonnect.UpDown) (func(), error) {
	if sub, ok := n.network.(gonnect.UpDownSubscriber); ok {
		return sub.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial intercepts TCP dials and delegates all other networks unchanged.
func (n *Network) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.Dial(ctx, network, address)
	}

	upstream, err := n.network.Dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return n.newClientConn(network, "", address, upstream)
}

// Listen delegates to the wrapped Network.
func (n *Network) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return n.network.Listen(ctx, network, address)
}

// PacketDial delegates to the wrapped Network.
func (n *Network) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.PacketDial(ctx, network, address)
}

// ListenPacket delegates to the wrapped Network.
func (n *Network) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.ListenPacket(ctx, network, address)
}

// DialTCP intercepts TCP dials and delegates unknown or non-TCP networks
// unchanged.
func (n *Network) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return n.network.DialTCP(ctx, network, laddr, raddr)
	}

	upstream, err := n.network.DialTCP(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return n.newClientConn(network, laddr, raddr, upstream)
}

// ListenTCP delegates to the wrapped Network.
func (n *Network) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	return n.network.ListenTCP(ctx, network, laddr)
}

// DialUDP delegates to the wrapped Network.
func (n *Network) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	return n.network.DialUDP(ctx, network, laddr, raddr)
}

// ListenUDP delegates to the wrapped Network.
func (n *Network) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return n.network.ListenUDP(ctx, network, laddr)
}

// ListenPacketConfig delegates to the wrapped Network.
func (n *Network) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	return n.network.ListenPacketConfig(ctx, lc, network, address)
}

// ListenUDPConfig delegates to the wrapped Network.
func (n *Network) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return n.network.ListenUDPConfig(ctx, lc, network, laddr)
}

// ListenMulticastUDP delegates to the wrapped Network.
func (n *Network) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts gonnect.MulticastOptions,
) (gonnect.MulticastPacketConn, error) {
	return n.network.ListenMulticastUDP(ctx, network, address, opts)
}

// LookupIP delegates to the wrapped Network.
func (n *Network) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return n.network.LookupIP(ctx, network, address)
}

// LookupIPAddr delegates to the wrapped Network.
func (n *Network) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return n.network.LookupIPAddr(ctx, host)
}

// LookupNetIP delegates to the wrapped Network.
func (n *Network) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return n.network.LookupNetIP(ctx, network, host)
}

// LookupHost delegates to the wrapped Network.
func (n *Network) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return n.network.LookupHost(ctx, host)
}

// LookupAddr delegates to the wrapped Network.
func (n *Network) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return n.network.LookupAddr(ctx, addr)
}

// LookupCNAME delegates to the wrapped Network.
func (n *Network) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return n.network.LookupCNAME(ctx, host)
}

// LookupPort delegates to the wrapped Network.
func (n *Network) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return n.network.LookupPort(ctx, network, service)
}

// LookupNS delegates to the wrapped Network.
func (n *Network) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return n.network.LookupNS(ctx, name)
}

// LookupMX delegates to the wrapped Network.
func (n *Network) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return n.network.LookupMX(ctx, name)
}

// LookupSRV delegates to the wrapped Network.
func (n *Network) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return n.network.LookupSRV(ctx, service, proto, name)
}

// LookupTXT delegates to the wrapped Network.
func (n *Network) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return n.network.LookupTXT(ctx, name)
}

// Interfaces delegates to the wrapped Network.
func (n *Network) Interfaces() ([]gonnect.NetworkInterface, error) {
	return n.network.Interfaces()
}

// InterfaceAddrs delegates to the wrapped Network.
func (n *Network) InterfaceAddrs() ([]net.Addr, error) {
	return n.network.InterfaceAddrs()
}

// InterfaceMulticastAddrs delegates to the wrapped Network.
func (n *Network) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return n.network.InterfaceMulticastAddrs()
}

// InterfacesByIndex delegates to the wrapped Network.
func (n *Network) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	return n.network.InterfacesByIndex(index)
}

// InterfacesByName delegates to the wrapped Network.
func (n *Network) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	return n.network.InterfacesByName(name)
}

func (n *Network) newClientConn(
	network string,
	laddr string,
	raddr string,
	upstream net.Conn,
) (gonnect.TCPConn, error) {
	connInfo := interceptionConnInfo{
		network:      network,
		requestedSrc: laddr,
		requestedDst: raddr,
		actualSrc:    addrString(upstream.LocalAddr()),
		actualDst:    addrString(upstream.RemoteAddr()),
	}

	client, server := gonnect.PipeTCP()
	wrapped := &tcpConn{
		TCPConn:  client,
		upstream: upstream,
		local:    upstream.LocalAddr(),
		remote:   upstream.RemoteAddr(),
	}
	if wrapped.remote == nil {
		wrapped.remote = &gonnect.NetAddr{Net: network, Addr: raddr}
	}
	if tcp, ok := upstream.(gonnect.TCPConn); ok {
		wrapped.upstreamTCP = tcp
	}

	if err := n.spawn(func() {
		n.serveConn(server, upstream, connInfo)
	}, "gonnect/tls.Network.bridge"); err != nil {
		_ = wrapped.Close()
		_ = server.Close()
		return nil, err
	}

	return wrapped, nil
}

func (n *Network) serveConn(
	client gonnect.TCPConn,
	upstream net.Conn,
	connInfo interceptionConnInfo,
) {
	defer client.Close()   //nolint:errcheck
	defer upstream.Close() //nolint:errcheck

	pb := putback.New(client, nil)
	route, err := n.sniffRoute(pb, connInfo)
	if err != nil {
		return
	}

	switch route {
	case routePassthrough:
		_ = gonnect.PipeConn(pb, upstream, n.spawner)
	case routeInterceptTLS:
		_ = n.pipeTLS(pb, upstream)
	case routeRejectTLS:
	default:
	}
}

type sniffRoute uint8

const (
	routePassthrough sniffRoute = iota
	routeInterceptTLS
	routeRejectTLS
)

func (n *Network) sniffRoute(
	conn putback.Conn,
	connInfo interceptionConnInfo,
) (sniffRoute, error) {
	hello, ok, err := sniffer.SniffTLSClientHello(
		make([]byte, n.sniffBufferSize),
		conn,
	)
	if err != nil {
		return routeRejectTLS, err
	}
	if ok {
		if !n.filter.intercepts(connInfo, &hello) {
			return routePassthrough, nil
		}
		if hello.SNIEncrypted {
			return routeRejectTLS, ErrEncryptedClientHello
		}
		if hello.SNIHostname == "" {
			return routeRejectTLS, ErrNoVisibleSNI
		}
		return routeInterceptTLS, nil
	}

	index, err := sniffer.Sniff(
		make([]byte, 2),
		conn,
		sniffer.Prefix([]byte{0x16, 0x03}),
	)
	if err != nil {
		return routeRejectTLS, err
	}
	if index == 0 {
		if !n.filter.intercepts(connInfo, nil) {
			return routePassthrough, nil
		}
		return routeRejectTLS, errCannotInterceptTLS
	}
	return routePassthrough, nil
}

func (n *Network) pipeTLS(client putback.Conn, upstream net.Conn) error {
	var upstreamTLS *stdtls.Conn
	serverConfig := &stdtls.Config{ // #nosec G402 -- Go defaults are used for the client-facing TLS leg.
		GetConfigForClient: func(
			hello *stdtls.ClientHelloInfo,
		) (*stdtls.Config, error) {
			host, err := normalizeServerName(hello.ServerName)
			if err != nil {
				return nil, err
			}

			upstreamConfig := n.upstreamConfig(host, hello.SupportedProtos)
			nextUpstreamTLS := stdtls.Client(upstream, upstreamConfig)
			if err := nextUpstreamTLS.HandshakeContext(
				context.Background(),
			); err != nil {
				return nil, err
			}
			upstreamTLS = nextUpstreamTLS

			cert, err := n.leafCertificate(host)
			if err != nil {
				return nil, err
			}

			selectedProtocol := upstreamTLS.ConnectionState().NegotiatedProtocol
			return &stdtls.Config{ // #nosec G402 -- Go defaults are used for the client-facing TLS leg.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   selectedNextProtos(selectedProtocol),
			}, nil
		},
	}

	clientTLS := stdtls.Server(client, serverConfig)
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		if upstreamTLS != nil {
			_ = upstreamTLS.CloseWrite()
		}
		return err
	}
	if upstreamTLS == nil {
		return errCannotInterceptTLS
	}
	return gonnect.PipeConn(
		&closePhaseTLSConn{Conn: clientTLS, wrapped: client},
		&closePhaseTLSConn{Conn: upstreamTLS, wrapped: upstream},
		n.spawner,
	)
}

type closePhaseTLSConn struct {
	*stdtls.Conn
	wrapped net.Conn

	preCloseOnce  sync.Once
	preCloseErr   error
	postCloseOnce sync.Once
	postCloseErr  error
}

var _ interface {
	net.Conn
	gonnect.TwoStepCloser
} = (*closePhaseTLSConn)(nil)

func (c *closePhaseTLSConn) PreClose() error {
	c.preCloseOnce.Do(func() {
		c.preCloseErr = errors.Join(
			c.CloseWrite(),
			gonnect.PreClose(c.wrapped),
		)
	})
	return c.preCloseErr
}

func (c *closePhaseTLSConn) PostClose() error {
	c.postCloseOnce.Do(func() {
		c.postCloseErr = errors.Join(c.PreClose(), gonnect.PostClose(c.wrapped))
	})
	return c.postCloseErr
}

func (c *closePhaseTLSConn) Close() error {
	return errors.Join(c.PreClose(), c.PostClose())
}

func selectedNextProtos(proto string) []string {
	if proto == "" {
		return nil
	}
	return []string{proto}
}

func (n *Network) upstreamConfig(
	host string,
	clientProtos []string,
) *stdtls.Config {
	var config *stdtls.Config
	if n.clientConfig != nil {
		config = n.clientConfig.Clone()
	} else {
		config = &stdtls.Config{} // #nosec G402 -- ServerName is set below.
	}
	config.ServerName = host
	config.NextProtos = append([]string(nil), clientProtos...)
	return config
}

func (n *Network) leafCertificate(host string) (stdtls.Certificate, error) {
	key := leafCacheKey(host)
	now := time.Now()

	n.leafMu.Lock()
	if n.leafCache != nil {
		if cert, ok := n.leafCache[key]; ok &&
			cert.Leaf != nil &&
			cert.Leaf.NotAfter.After(now) {
			n.leafMu.Unlock()
			return cert, nil
		}
		delete(n.leafCache, key)
	}
	n.leafMu.Unlock()

	cert, err := leafCertificate(n.ca, n.caCert, n.leafTTL, host)
	if err != nil {
		return stdtls.Certificate{}, err
	}

	n.leafMu.Lock()
	defer n.leafMu.Unlock()
	if n.leafCache == nil {
		n.leafCache = make(map[string]stdtls.Certificate)
	}
	if cached, ok := n.leafCache[key]; ok &&
		cached.Leaf != nil &&
		cached.Leaf.NotAfter.After(now) {
		return cached, nil
	}
	n.leafCache[key] = cert
	n.evictLeafCacheLocked()
	return cert, nil
}

func (n *Network) evictLeafCacheLocked() {
	for len(n.leafCache) > maxLeafCacheEntries {
		var evictKey string
		var evictExpiry time.Time
		for key, cert := range n.leafCache {
			expiry := time.Time{}
			if cert.Leaf != nil {
				expiry = cert.Leaf.NotAfter
			}
			if evictKey == "" || expiry.Before(evictExpiry) {
				evictKey = key
				evictExpiry = expiry
			}
		}
		delete(n.leafCache, evictKey)
	}
}

func leafCacheKey(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func leafCertificate(
	ca stdtls.Certificate,
	caCert *x509.Certificate,
	leafTTL time.Duration,
	host string,
) (stdtls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return stdtls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return stdtls.Certificate{}, err
	}

	now := time.Now()
	notAfter := now.Add(leafTTL)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(now) {
		return stdtls.Certificate{}, errors.New(
			"gonnect/tls: CA certificate is expired",
		)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caCert,
		&priv.PublicKey,
		ca.PrivateKey,
	)
	if err != nil {
		return stdtls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return stdtls.Certificate{}, err
	}

	chain := make([][]byte, 0, 1+len(ca.Certificate))
	chain = append(chain, der)
	for _, cert := range ca.Certificate {
		chain = append(chain, append([]byte(nil), cert...))
	}
	return stdtls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

func (n *Network) spawn(worker func(), name string) error {
	if n.spawner == nil {
		go worker()
		return nil
	}
	_, err := n.spawner.Spawn(worker, name)
	return err
}

func parseCA(
	ca stdtls.Certificate,
) (stdtls.Certificate, *x509.Certificate, error) {
	if len(ca.Certificate) == 0 {
		return stdtls.Certificate{}, nil, errors.New(
			"gonnect/tls: CA certificate chain is empty",
		)
	}
	if ca.PrivateKey == nil {
		return stdtls.Certificate{}, nil, errors.New(
			"gonnect/tls: CA private key is nil",
		)
	}
	if _, ok := ca.PrivateKey.(crypto.Signer); !ok {
		return stdtls.Certificate{}, nil, errors.New(
			"gonnect/tls: CA private key is not a crypto.Signer",
		)
	}

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return stdtls.Certificate{}, nil, fmt.Errorf(
			"gonnect/tls: parse CA certificate: %w",
			err,
		)
	}
	if !caCert.IsCA {
		return stdtls.Certificate{}, nil, errors.New(
			"gonnect/tls: certificate is not a CA",
		)
	}
	if caCert.KeyUsage != 0 &&
		caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return stdtls.Certificate{}, nil, errors.New(
			"gonnect/tls: CA certificate cannot sign certificates",
		)
	}

	owned := stdtls.Certificate{
		Certificate: append([][]byte(nil), ca.Certificate...),
		PrivateKey:  ca.PrivateKey,
		Leaf:        caCert,
	}
	for i := range owned.Certificate {
		owned.Certificate[i] = append([]byte(nil), owned.Certificate[i]...)
	}
	return owned, caCert, nil
}

func normalizeServerName(name string) (string, error) {
	if name == "" {
		return "", ErrNoVisibleSNI
	}
	if strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("%w: trailing dot", ErrNoVisibleSNI)
	}
	for i := range len(name) {
		b := name[i]
		if b <= ' ' || b == 0x7f {
			return "", fmt.Errorf("%w: invalid byte", ErrNoVisibleSNI)
		}
		switch b {
		case '/', '\\', ':', '[', ']', '@':
			return "", fmt.Errorf("%w: invalid host %q", ErrNoVisibleSNI, name)
		}
	}
	return name, nil
}

type tcpConn struct {
	gonnect.TCPConn

	upstream    net.Conn
	upstreamTCP gonnect.TCPConn
	local       net.Addr
	remote      net.Addr
	closeOnce   sync.Once
}

var _ interface {
	gonnect.TCPConn
	gonnect.Wrapper
} = (*tcpConn)(nil)

func (c *tcpConn) GetWrapped() any { return c.TCPConn }

func (c *tcpConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.TCPConn.LocalAddr()
}

func (c *tcpConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.TCPConn.RemoteAddr()
}

func (c *tcpConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = errors.Join(c.TCPConn.Close(), c.upstream.Close())
	})
	return err
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.TCPConn.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.TCPConn.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.TCPConn.SetWriteDeadline(t)
}

func (c *tcpConn) SetKeepAlive(keepalive bool) error {
	if c.upstreamTCP != nil {
		return c.upstreamTCP.SetKeepAlive(keepalive)
	}
	return c.TCPConn.SetKeepAlive(keepalive)
}

func (c *tcpConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if c.upstreamTCP != nil {
		return c.upstreamTCP.SetKeepAliveConfig(config)
	}
	return c.TCPConn.SetKeepAliveConfig(config)
}

func (c *tcpConn) SetKeepAlivePeriod(d time.Duration) error {
	if c.upstreamTCP != nil {
		return c.upstreamTCP.SetKeepAlivePeriod(d)
	}
	return c.TCPConn.SetKeepAlivePeriod(d)
}

func (c *tcpConn) SetLinger(sec int) error {
	if c.upstreamTCP != nil {
		return c.upstreamTCP.SetLinger(sec)
	}
	return c.TCPConn.SetLinger(sec)
}

func (c *tcpConn) SetNoDelay(noDelay bool) error {
	if c.upstreamTCP != nil {
		return c.upstreamTCP.SetNoDelay(noDelay)
	}
	return c.TCPConn.SetNoDelay(noDelay)
}
