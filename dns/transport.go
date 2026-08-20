package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

const maxDNSMessageSize = 1<<16 - 1

const (
	defaultPacketMaxConcurrentRequests = 256
	defaultPacketRequestTimeout        = 5 * time.Second
)

// PacketOptions configures DNS packet request handling.
//
// MaxConcurrentRequests limits active packet handlers. Extra packets wait at
// the packet input path, which applies backpressure to the caller or listener.
// Values less than 1 use a safe default.
//
// RequestTimeout limits one forwarded request. Values less than 1 use a safe
// default.
type PacketOptions struct {
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
}

func normalizePacketOptions(opts PacketOptions) PacketOptions {
	if opts.MaxConcurrentRequests < 1 {
		opts.MaxConcurrentRequests = defaultPacketMaxConcurrentRequests
	}
	if opts.RequestTimeout < 1 {
		opts.RequestTimeout = defaultPacketRequestTimeout
	}
	return opts
}

type packetLimiter chan struct{}

func newPacketLimiter(limit int) packetLimiter {
	return make(packetLimiter, limit)
}

func (l packetLimiter) acquire(ctx context.Context) bool {
	select {
	case l <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l packetLimiter) release() {
	select {
	case <-l:
	default:
	}
}

// Client is a simple DNS client for udp://, tcp://, and dot:// servers.
//
// It sends supported DNS query messages to the configured servers and returns
// the first successful wire response. The client allocates a fresh wire ID for
// every upstream request and maps the response ID back to the caller's message
// ID before replying.
//
// Configured server URLs are tried in order. When a server URL uses a hostname,
// the hostname is resolved through the bootstrap DNS interface passed to
// NewClient, and every returned IP address is tried in resolver order before the
// client moves to the next configured server. If bootstrap is nil, server URLs
// must use IP literal hosts; hostname servers fail before dialing.
type Client struct {
	// TLSConfig configures TLS for dot:// upstreams. The config is cloned for
	// each connection. If ServerName is empty, the URL host is used.
	TLSConfig *tls.Config

	dial      gonnect.Dial
	bootstrap Interface
	servers   []string
	timeout   time.Duration
	p         *provider
	spawner   gonnect.Spawner
}

// NewClient creates a DNS client using dial, bootstrap DNS, and server URLs.
// If dial is nil, all requests fail with ErrNoDialer. bootstrap is used only to
// resolve non-IP server URL hostnames. If bootstrap is nil, server URLs with
// hostname hosts are rejected, while IP literal server URLs remain usable.
//
// Supported schemes are udp, tcp, and dot. Server URLs are attempted in order.
// If a server hostname resolves to multiple IP addresses, those addresses are
// attempted in bootstrap resolver order before the next server URL is tried.
func NewClient(
	dial gonnect.Dial,
	bootstrap Interface,
	spawner gonnect.Spawner,
	servers ...string,
) *Client {
	c := &Client{
		dial:      dial,
		bootstrap: bootstrap,
		servers:   append([]string(nil), servers...),
		timeout:   5 * time.Second,
		spawner:   spawner,
	}
	c.p = newProvider(c.handle, spawner)
	return c
}

func (c *Client) Requests() chan<- Request { return c.p.Requests() }
func (c *Client) Close() error             { return c.p.Close() }

func (c *Client) handle(root context.Context, req Request) {
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if c.timeout > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, c.timeout)
		defer cancelTimeout()
	}
	go func() {
		select {
		case <-root.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	if c.dial == nil {
		sendResponse(req, nil, ErrNoDialer)
		return
	}
	var last error
	for _, server := range c.servers {
		resp, err := c.exchange(ctx, server, req.Message)
		if err == nil {
			resp.ID = req.Message.ID
			sendResponse(req, resp, nil)
			return
		}
		last = err
	}
	if last == nil {
		last = ErrNoUpstream
	}
	sendResponse(req, nil, last)
}

func (c *Client) exchange(
	ctx context.Context,
	server string,
	msg *Message,
) (*Message, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	network := u.Scheme
	addr := u.Host
	if addr == "" {
		addr = u.Path
	}
	switch network {
	case "udp", "tcp", "dot":
	default:
		return nil, net.UnknownNetworkError(network)
	}
	host, port, err := splitServerHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := c.serverAddrs(ctx, host, port)
	if err != nil {
		return nil, err
	}
	wire := msg.Copy()
	wire.ID = NextID()
	pkt, err := Pack(wire)
	if err != nil {
		return nil, err
	}
	var last error
	for _, addr := range addrs {
		resp, err := c.exchangeOne(ctx, network, addr, pkt)
		if err == nil && resp.ID != wire.ID {
			err = errors.New("dns: response ID mismatch")
		}
		if err == nil {
			return resp, nil
		}
		last = err
	}
	if last == nil {
		last = ErrNoUpstream
	}
	return nil, last
}

type serverAddr struct {
	addr          string
	tlsServerName string
}

func splitServerHostPort(addr string) (string, string, error) {
	if addr == "" {
		return "", "", errors.New("dns: empty server address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return host, port, nil
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.String(), "53", nil
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.String(), "53", nil
		}
	}
	if strings.Count(addr, ":") > 1 {
		return "", "", err
	}
	return addr, "53", nil
}

func (c *Client) serverAddrs(
	ctx context.Context,
	host, port string,
) ([]serverAddr, error) {
	if host == "" {
		return []serverAddr{{addr: net.JoinHostPort(host, port)}}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
		return []serverAddr{{
			addr:          net.JoinHostPort(host, port),
			tlsServerName: host,
		}}, nil
	}
	if c.bootstrap == nil {
		return nil, gonnect.NoSuchHost(host, "dns bootstrap")
	}
	ips, err := NewResolver(c.bootstrap).LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]serverAddr, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		addrs = append(addrs, serverAddr{
			addr:          net.JoinHostPort(ip.String(), port),
			tlsServerName: host,
		})
	}
	if len(addrs) == 0 {
		return nil, gonnect.NoSuchHost(host, "dns bootstrap")
	}
	return addrs, nil
}

func (c *Client) exchangeOne(
	ctx context.Context,
	network string,
	addr serverAddr,
	pkt []byte,
) (*Message, error) {
	switch network {
	case "udp":
		return c.exchangeUDP(ctx, addr.addr, pkt)
	case "tcp":
		return c.exchangeStream(ctx, "tcp", addr.addr, pkt, "")
	case "dot":
		return c.exchangeStream(ctx, "tcp", addr.addr, pkt, addr.tlsServerName)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func (c *Client) exchangeUDP(
	ctx context.Context,
	addr string,
	pkt []byte,
) (*Message, error) {
	conn, err := c.dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	done := closeConnOnContext(ctx, conn)
	defer done()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err = conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return Unpack(buf[:n])
}

func (c *Client) exchangeStream(
	ctx context.Context,
	network, addr string,
	pkt []byte,
	tlsServerName string,
) (*Message, error) {
	conn, err := c.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	done := closeConnOnContext(ctx, conn)
	defer done()
	if tlsServerName != "" {
		conn = tls.Client(conn, c.tlsConfig(tlsServerName))
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	var lenBuf [2]byte
	if len(pkt) > maxDNSMessageSize {
		return nil, errors.New("dns: message too large")
	}
	// #nosec G115 -- len(pkt) is checked against the DNS TCP length limit.
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(pkt)))
	if _, err = conn.Write(append(lenBuf[:], pkt...)); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, int(size))
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return Unpack(buf)
}

func (c *Client) tlsConfig(host string) *tls.Config {
	if c.TLSConfig == nil {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	cfg := c.TLSConfig.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

func closeConnOnContext(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Server is a simple UDP DNS server backed by a packet connection.
//
// For every client packet it unpacks the DNS message, replaces the client's ID
// with a new internal ID before forwarding through the attached DNS Interface,
// then maps the response ID back to the original client ID. Attach and Detach
// can replace the upstream without closing the packet connection; detaching
// cancels requests currently waiting on the old upstream.
type Server struct {
	conn    net.PacketConn
	p       *provider
	spawner gonnect.Spawner
	timeout time.Duration
	limit   packetLimiter

	mu       sync.Mutex
	upstream Interface
	gen      uint64
	done     chan struct{}

	closeOnce sync.Once
}

// NewServer starts serving DNS packets from conn.
func NewServer(
	conn net.PacketConn,
	upstream Interface,
	spawner gonnect.Spawner,
) *Server {
	return NewServerWithOptions(conn, upstream, spawner, PacketOptions{})
}

// NewServerWithOptions starts serving DNS packets from conn.
func NewServerWithOptions(
	conn net.PacketConn,
	upstream Interface,
	spawner gonnect.Spawner,
	opts PacketOptions,
) *Server {
	opts = normalizePacketOptions(opts)
	s := &Server{
		conn:    conn,
		spawner: spawner,
		timeout: opts.RequestTimeout,
		limit:   newPacketLimiter(opts.MaxConcurrentRequests),
	}
	s.Attach(upstream)
	ctx, cancel := context.WithCancel(context.Background())
	s.p = &provider{
		ch:      make(chan Request),
		cancel:  cancel,
		done:    make(chan struct{}),
		spawner: spawner,
	}
	if err := spawn(spawner, func() {
		defer close(s.p.done)
		s.serve(ctx)
	}, "dns.Server.serve"); err != nil {
		cancel()
		close(s.p.done)
	}
	return s
}

func (s *Server) Requests() chan<- Request { return s.p.Requests() }

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.p.cancel()
		_ = s.conn.Close()
		s.Detach()
	})
	<-s.p.done
	return nil
}

// Attach replaces the upstream DNS interface and cancels requests using the
// previous upstream.
func (s *Server) Attach(upstream Interface) {
	s.mu.Lock()
	if s.done != nil {
		close(s.done)
	}
	s.upstream = upstream
	s.done = make(chan struct{})
	s.gen++
	s.mu.Unlock()
}

// Detach removes the upstream and cancels in-flight forwarded requests.
func (s *Server) Detach() { s.Attach(nil) }

func (s *Server) serve(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if !s.limit.acquire(ctx) {
			return
		}
		if err := spawn(s.spawner, func() {
			defer s.limit.release()
			s.handlePacket(ctx, pkt, addr)
		}, "dns.Server.handlePacket"); err != nil {
			s.limit.release()
			return
		}
	}
}

func (s *Server) handlePacket(ctx context.Context, pkt []byte, addr net.Addr) {
	req, err := Unpack(pkt)
	if err != nil {
		return
	}
	clientID := req.ID
	req.ID = NextID()
	up, _, done := s.current()
	if up == nil {
		resp := responseFor(req)
		resp.ID = clientID
		resp.RCode = RCodeServerFailure
		s.write(addr, resp)
		return
	}
	qctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	go func() {
		select {
		case <-done:
			cancel()
		case <-qctx.Done():
		}
	}()
	resp, err := Query(qctx, up, req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		resp = responseFor(req)
		resp.RCode = RCodeServerFailure
	}
	resp.ID = clientID
	s.write(addr, resp)
}

func (s *Server) current() (Interface, uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstream, s.gen, s.done
}

func (s *Server) write(addr net.Addr, msg *Message) {
	pkt, err := Pack(msg)
	if err != nil {
		return
	}
	_, _ = s.conn.WriteTo(pkt, addr)
}
