package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

// TODO:
// - DTLS
// - WebRTC
// - QUIC

var _ interface {
	gonnect.Network
	gonnect.UpDown
	io.Closer
	gonnect.CloserSubscriber
	gonnect.UpDownSubscriber
	gonnect.Wrapper
} = (*Terminator)(nil)

var (
	// ErrNonTLSConnection is used when Terminator receives client-first
	// bytes that are not a TLS ClientHello.
	ErrNonTLSConnection = errors.New(
		"gonnect/tls: connection is not TLS",
	)

	// ErrTerminatorUnsupported is used when a caller uses an operation that a
	// TLS terminator cannot handle. Terminator only allows outgoing TLS over
	// TCP Dial and DialTCP.
	ErrTerminatorUnsupported = errors.New(
		"gonnect/tls: terminator supports only outgoing TLS over TCP",
	)

	errCannotTerminateTLS = errors.New(
		"gonnect/tls: cannot terminate TLS connection",
	)
)

// TerminatorConfig configures a TLS terminating Network.
type TerminatorConfig struct {
	// CA is the certificate authority used to sign generated leaf
	// certificates. It must include at least one certificate and a private key.
	CA stdtls.Certificate

	// SniffBufferSize is the maximum number of bytes inspected from the first
	// client write. Zero uses sniffer.DefaultTLSClientHelloMaxBytes. A smaller
	// value can cause large TLS ClientHello messages to be rejected.
	SniffBufferSize int

	// LeafTTL is the validity period for generated leaf certificates. Zero uses
	// a conservative default. The CA expiration still bounds the leaf
	// certificate expiration.
	LeafTTL time.Duration

	// DestinationRemaps optionally replace the upstream plaintext TCP
	// destination. Rules are checked in order, and the first match wins. When
	// no rule matches, Terminator uses the original dial destination unless
	// UseSNIHostname is true.
	DestinationRemaps []TerminatorDestinationRemap

	// UseSNIHostname makes the default upstream destination use the SNI host
	// with the original destination port. It is ignored when a destination
	// remap matches. The zero value keeps the original destination.
	UseSNIHostname bool

	// NextProtos is the list of ALPN protocols the client-facing TLS server
	// can select. Empty disables ALPN selection. Remap rules still match the
	// ALPN protocols offered by the client.
	NextProtos []string

	// Spawner optionally starts background copy workers. Nil uses normal
	// goroutines.
	Spawner gonnect.Spawner
}

// TerminatorDestinationRemap maps intercepted TLS connections to another
// plaintext TCP destination.
//
// Empty match fields are wildcards. Values in one field are ORed. Different
// fields are ANDed. OriginalDsts use the address syntax accepted by
// gonnect.FilterFromString. SNIHosts and ALPNs use whole-value glob patterns,
// where * matches any byte sequence and ? matches one byte. SNIHosts match
// case-insensitively. ALPNs match the client offer, not the selected ALPN.
type TerminatorDestinationRemap struct {
	// OriginalDsts match the original Dial or DialTCP remote address.
	OriginalDsts []string

	// SNIHosts match the visible SNI host_name.
	SNIHosts []string

	// ALPNs match any ALPN protocol offered by the client.
	ALPNs []string

	// Dst is the plaintext TCP destination used when this rule matches. It
	// must use host:port syntax.
	Dst string
}

// Terminator is a gonnect.Network middleware that terminates outgoing TLS over
// TCP and sends plaintext TCP to the wrapped Network.
//
// Dial and DialTCP return a local TCP-like pipe immediately. A background
// worker waits for the first client bytes, requires a valid TLS ClientHello
// with visible SNI and no ECH signal, selects the upstream plaintext
// destination, dials it through the wrapped Network, completes client-facing
// TLS with a generated certificate, and then copies decrypted bytes to the
// upstream TCP connection.
//
// Non-TLS TCP is rejected. TLS without visible SNI, TLS with ECH, malformed
// TLS, and TLS over the sniff limit are rejected. No rejected stream is passed
// through or dialed upstream. Operations other than TCP Dial and DialTCP return
// ErrTerminatorUnsupported and do not call the wrapped Network.
//
// The Dial or DialTCP context is checked before the local pipe is returned.
// After Dial or DialTCP returns, canceling that context does not stop the
// background worker. Close the returned connection to abort sniffing, hidden
// upstream dials, and bridge work.
//
// Lifecycle calls are delegated when the wrapped Network implements the
// matching optional interface. If it does not, Close, Up, Down,
// SubscribeCloser, and SubscribeUpDown are no-ops, and IsUp reports true.
// IsNative always reports false because this middleware changes TCP behavior.
type Terminator struct {
	network         gonnect.Network
	ca              stdtls.Certificate
	caCert          *x509.Certificate
	sniffBufferSize int
	leafTTL         time.Duration
	remaps          []compiledTerminatorDestinationRemap
	useSNIHostname  bool
	nextProtos      []string
	spawner         gonnect.Spawner
}

// NewTerminator wraps network with TLS termination behavior.
func NewTerminator(
	network gonnect.Network,
	ca stdtls.Certificate,
) (*Terminator, error) {
	return NewTerminatorWithConfig(network, TerminatorConfig{CA: ca})
}

// NewTerminatorWithConfig wraps network with TLS termination behavior.
func NewTerminatorWithConfig(
	network gonnect.Network,
	config TerminatorConfig,
) (*Terminator, error) {
	if network == nil {
		return nil, errors.New("gonnect/tls: nil Network")
	}
	if config.SniffBufferSize < 0 {
		return nil, errors.New("gonnect/tls: negative SniffBufferSize")
	}
	if config.LeafTTL < 0 {
		return nil, errors.New("gonnect/tls: negative LeafTTL")
	}

	ca, caCert, err := parseCA(config.CA)
	if err != nil {
		return nil, err
	}
	remaps, err := compileTerminatorDestinationRemaps(
		config.DestinationRemaps,
	)
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

	return &Terminator{
		network:         network,
		ca:              ca,
		caCert:          caCert,
		sniffBufferSize: sniffBufferSize,
		leafTTL:         leafTTL,
		remaps:          remaps,
		useSNIHostname:  config.UseSNIHostname,
		nextProtos:      append([]string(nil), config.NextProtos...),
		spawner:         config.Spawner,
	}, nil
}

// GetWrapped returns the wrapped Network.
func (n *Terminator) GetWrapped() any { return n.network }

// GetNetwork returns the wrapped Network.
func (n *Terminator) GetNetwork() gonnect.Network { return n.network }

// IsNative always reports false because the middleware changes TCP behavior.
func (n *Terminator) IsNative() bool { return false }

// Close closes the wrapped Network when it implements io.Closer.
func (n *Terminator) Close() error {
	if closer, ok := n.network.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (n *Terminator) SubscribeCloser(c io.Closer) (func(), error) {
	if sub, ok := n.network.(gonnect.CloserSubscriber); ok {
		return sub.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements gonnect.UpDown.
func (n *Terminator) Up() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements gonnect.UpDown.
func (n *Terminator) Down() error {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements gonnect.UpDown.
func (n *Terminator) IsUp() (bool, error) {
	if updown, ok := n.network.(gonnect.UpDown); ok {
		return updown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (n *Terminator) SubscribeUpDown(u gonnect.UpDown) (func(), error) {
	if sub, ok := n.network.(gonnect.UpDownSubscriber); ok {
		return sub.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial accepts only TCP networks and terminates client TLS before upstream.
func (n *Terminator) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return nil, terminatorUnsupportedOp("dial", network, address)
	}
	return n.newClientConn(ctx, terminatorDialInfo{
		network:      network,
		requestedDst: address,
		dial: func(ctx context.Context, dst string) (net.Conn, error) {
			return n.network.Dial(ctx, network, dst)
		},
	})
}

// Listen is not supported by Terminator.
func (n *Terminator) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return nil, terminatorUnsupportedOp("listen", network, address)
}

// PacketDial is not supported by Terminator.
func (n *Terminator) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return nil, terminatorUnsupportedOp("dial", network, address)
}

// ListenPacket is not supported by Terminator.
func (n *Terminator) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	return nil, terminatorUnsupportedOp("listen", network, address)
}

// DialTCP accepts only TCP networks and terminates client TLS before upstream.
func (n *Terminator) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	if !gonnect.IsTCPNetwork(network) {
		return nil, terminatorUnsupportedOp("dial", network, raddr)
	}
	return n.newClientConn(ctx, terminatorDialInfo{
		network:      network,
		requestedSrc: laddr,
		requestedDst: raddr,
		dial: func(ctx context.Context, dst string) (net.Conn, error) {
			return n.network.DialTCP(ctx, network, laddr, dst)
		},
	})
}

// ListenTCP is not supported by Terminator.
func (n *Terminator) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	return nil, terminatorUnsupportedOp("listen", network, laddr)
}

// DialUDP is not supported by Terminator.
func (n *Terminator) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	return nil, terminatorUnsupportedOp("dial", network, raddr)
}

// ListenUDP is not supported by Terminator.
func (n *Terminator) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return nil, terminatorUnsupportedOp("listen", network, laddr)
}

// ListenPacketConfig is not supported by Terminator.
func (n *Terminator) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	return nil, terminatorUnsupportedOp("listen", network, address)
}

// ListenUDPConfig is not supported by Terminator.
func (n *Terminator) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	return nil, terminatorUnsupportedOp("listen", network, laddr)
}

// ListenMulticastUDP is not supported by Terminator.
func (n *Terminator) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts gonnect.MulticastOptions,
) (gonnect.MulticastPacketConn, error) {
	return nil, terminatorUnsupportedOp("listen", network, address)
}

// LookupIP is not supported by Terminator.
func (n *Terminator) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupIPAddr is not supported by Terminator.
func (n *Terminator) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupNetIP is not supported by Terminator.
func (n *Terminator) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupHost is not supported by Terminator.
func (n *Terminator) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupAddr is not supported by Terminator.
func (n *Terminator) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupCNAME is not supported by Terminator.
func (n *Terminator) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return "", ErrTerminatorUnsupported
}

// LookupPort is not supported by Terminator.
func (n *Terminator) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return 0, ErrTerminatorUnsupported
}

// LookupNS is not supported by Terminator.
func (n *Terminator) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupMX is not supported by Terminator.
func (n *Terminator) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return nil, ErrTerminatorUnsupported
}

// LookupSRV is not supported by Terminator.
func (n *Terminator) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return "", nil, ErrTerminatorUnsupported
}

// LookupTXT is not supported by Terminator.
func (n *Terminator) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return nil, ErrTerminatorUnsupported
}

// Interfaces is not supported by Terminator.
func (n *Terminator) Interfaces() ([]gonnect.NetworkInterface, error) {
	return nil, ErrTerminatorUnsupported
}

// InterfaceAddrs is not supported by Terminator.
func (n *Terminator) InterfaceAddrs() ([]net.Addr, error) {
	return nil, ErrTerminatorUnsupported
}

// InterfaceMulticastAddrs is not supported by Terminator.
func (n *Terminator) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return nil, ErrTerminatorUnsupported
}

// InterfacesByIndex is not supported by Terminator.
func (n *Terminator) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	return nil, ErrTerminatorUnsupported
}

// InterfacesByName is not supported by Terminator.
func (n *Terminator) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	return nil, ErrTerminatorUnsupported
}

type terminatorDialInfo struct {
	network      string
	requestedSrc string
	requestedDst string
	dial         func(context.Context, string) (net.Conn, error)
}

func (n *Terminator) newClientConn(
	ctx context.Context,
	info terminatorDialInfo,
) (*terminatorTCPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(info.requestedDst); err != nil {
		return nil, &net.AddrError{
			Err:  err.Error(),
			Addr: info.requestedDst,
		}
	}

	client, server := gonnect.PipeTCP()
	bridgeCtx, cancelBridge := context.WithCancel(context.Background())
	wrapped := &terminatorTCPConn{
		TCPConn:      client,
		cancelBridge: cancelBridge,
		local:        netAddrOrNil(info.network, info.requestedSrc),
		remote: &gonnect.NetAddr{
			Net:  info.network,
			Addr: info.requestedDst,
		},
	}

	if err := n.spawn(func() {
		n.serveConn(bridgeCtx, server, wrapped, info)
	}, "gonnect/tls.Terminator.bridge"); err != nil {
		_ = wrapped.Close()
		_ = server.Close()
		return nil, err
	}

	return wrapped, nil
}

func (n *Terminator) serveConn(
	ctx context.Context,
	client gonnect.TCPConn,
	returned *terminatorTCPConn,
	info terminatorDialInfo,
) {
	defer client.Close() //nolint:errcheck
	defer returned.cancelBridge()

	pb := putback.New(client, nil)
	hello, err := n.sniffClientHello(pb)
	if err != nil {
		return
	}

	host, err := normalizeServerName(hello.SNIHostname)
	if err != nil {
		return
	}

	dst, err := n.upstreamDestination(info, hello)
	if err != nil {
		return
	}

	upstream, err := info.dial(ctx, dst)
	if err != nil {
		return
	}
	defer upstream.Close() //nolint:errcheck
	returned.setAddrs(upstream.LocalAddr(), upstream.RemoteAddr())

	_ = n.pipeTLS(pb, upstream, host)
}

func (n *Terminator) sniffClientHello(
	conn putback.Conn,
) (sniffer.TLSClientHelloInfo, error) {
	hello, ok, err := sniffer.SniffTLSClientHello(
		make([]byte, n.sniffBufferSize),
		conn,
	)
	if err != nil {
		return sniffer.TLSClientHelloInfo{}, err
	}
	if ok {
		if hello.SNIEncrypted {
			return sniffer.TLSClientHelloInfo{}, ErrEncryptedClientHello
		}
		if hello.SNIHostname == "" {
			return sniffer.TLSClientHelloInfo{}, ErrNoVisibleSNI
		}
		return hello, nil
	}

	index, err := sniffer.Sniff(
		make([]byte, 2),
		conn,
		sniffer.Prefix([]byte{0x16, 0x03}),
	)
	if err != nil {
		return sniffer.TLSClientHelloInfo{}, err
	}
	if index == 0 {
		return sniffer.TLSClientHelloInfo{}, errCannotTerminateTLS
	}
	return sniffer.TLSClientHelloInfo{}, ErrNonTLSConnection
}

func (n *Terminator) upstreamDestination(
	info terminatorDialInfo,
	hello sniffer.TLSClientHelloInfo,
) (string, error) {
	for _, remap := range n.remaps {
		if remap.match(info.network, info.requestedDst, hello) {
			return remap.dst, nil
		}
	}

	if !n.useSNIHostname {
		return info.requestedDst, nil
	}

	_, port, err := net.SplitHostPort(info.requestedDst)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(hello.SNIHostname, port), nil
}

func (n *Terminator) pipeTLS(
	client putback.Conn,
	upstream net.Conn,
	host string,
) error {
	cert, err := leafCertificate(n.ca, n.caCert, n.leafTTL, host)
	if err != nil {
		return err
	}

	clientTLS := stdtls.Server(
		client,
		&stdtls.Config{ // #nosec G402 -- Go defaults are used for the client-facing TLS leg.
			Certificates: []stdtls.Certificate{cert},
			NextProtos:   append([]string(nil), n.nextProtos...),
		},
	)
	if err := clientTLS.HandshakeContext(context.Background()); err != nil {
		return err
	}

	return gonnect.PipeConn(
		&closePhaseTLSConn{Conn: clientTLS, wrapped: client},
		upstream,
		n.spawner,
	)
}

func (n *Terminator) spawn(worker func(), name string) error {
	if n.spawner == nil {
		go worker()
		return nil
	}
	_, err := n.spawner.Spawn(worker, name)
	return err
}

type terminatorTCPConn struct {
	gonnect.TCPConn

	mu           sync.RWMutex
	local        net.Addr
	remote       net.Addr
	cancelBridge context.CancelFunc
	closeMux     sync.Once
}

var _ interface {
	gonnect.TCPConn
	gonnect.Wrapper
} = (*terminatorTCPConn)(nil)

func (c *terminatorTCPConn) GetWrapped() any { return c.TCPConn }

func (c *terminatorTCPConn) LocalAddr() net.Addr {
	c.mu.RLock()
	local := c.local
	c.mu.RUnlock()
	if local != nil {
		return local
	}
	return c.TCPConn.LocalAddr()
}

func (c *terminatorTCPConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	remote := c.remote
	c.mu.RUnlock()
	if remote != nil {
		return remote
	}
	return c.TCPConn.RemoteAddr()
}

func (c *terminatorTCPConn) Close() error {
	var err error
	c.closeMux.Do(func() {
		if c.cancelBridge != nil {
			c.cancelBridge()
		}
		err = c.TCPConn.Close()
	})
	return err
}

func (c *terminatorTCPConn) setAddrs(local, remote net.Addr) {
	c.mu.Lock()
	c.local = local
	c.remote = remote
	c.mu.Unlock()
}

func netAddrOrNil(network, address string) net.Addr {
	if address == "" {
		return nil
	}
	return &gonnect.NetAddr{Net: network, Addr: address}
}

func terminatorUnsupportedOp(op, network, address string) error {
	var addr net.Addr
	if address != "" {
		addr = &gonnect.NetAddr{Net: network, Addr: address}
	}
	return &net.OpError{
		Op:   op,
		Net:  network,
		Addr: addr,
		Err:  ErrTerminatorUnsupported,
	}
}

type compiledTerminatorDestinationRemap struct {
	originalDsts addressMatcher
	sniHosts     patternMatcher
	alpns        patternMatcher
	dst          string
}

func compileTerminatorDestinationRemaps(
	remaps []TerminatorDestinationRemap,
) ([]compiledTerminatorDestinationRemap, error) {
	compiled := make([]compiledTerminatorDestinationRemap, len(remaps))
	for i, remap := range remaps {
		dst := strings.TrimSpace(remap.Dst)
		if dst == "" {
			return nil, fmt.Errorf(
				"gonnect/tls: Terminator destination remap %d has empty Dst",
				i,
			)
		}
		if _, _, err := net.SplitHostPort(dst); err != nil {
			return nil, fmt.Errorf(
				"gonnect/tls: Terminator destination remap %d has invalid Dst %q: %w",
				i,
				remap.Dst,
				err,
			)
		}

		sniHosts, err := newPatternMatcher(
			"Terminator SNI host",
			remap.SNIHosts,
			true,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"gonnect/tls: compile Terminator destination remap %d: %w",
				i,
				err,
			)
		}
		alpns, err := newPatternMatcher(
			"Terminator ALPN",
			remap.ALPNs,
			false,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"gonnect/tls: compile Terminator destination remap %d: %w",
				i,
				err,
			)
		}

		compiled[i] = compiledTerminatorDestinationRemap{
			originalDsts: newAddressMatcher(remap.OriginalDsts),
			sniHosts:     sniHosts,
			alpns:        alpns,
			dst:          dst,
		}
	}
	return compiled, nil
}

func (r compiledTerminatorDestinationRemap) match(
	network string,
	originalDst string,
	hello sniffer.TLSClientHelloInfo,
) bool {
	if !r.originalDsts.match(network, originalDst) {
		return false
	}
	if !r.sniHosts.match(hello.SNIHostname) {
		return false
	}
	if !r.alpns.matchAny(hello.ALPNProtocols) {
		return false
	}
	return true
}
