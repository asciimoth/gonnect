package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

const maxDNSMessageSize = 1<<16 - 1

// Client is a simple DNS client for udp://, tcp://, and dot:// servers.
//
// It sends supported DNS query messages to the configured servers and returns
// the first successful wire response. The client allocates a fresh wire ID for
// every upstream request and maps the response ID back to the caller's message
// ID before replying.
type Client struct {
	// TLSConfig configures TLS for dot:// upstreams. The config is cloned for
	// each connection. If ServerName is empty, the URL host is used.
	TLSConfig *tls.Config

	dial    gonnect.Dial
	servers []string
	timeout time.Duration
	p       *provider
}

// NewClient creates a DNS client using dial and server URLs. If dial is nil,
// net.Dialer.DialContext is used. Supported schemes are udp, tcp, and dot.
func NewClient(dial gonnect.Dial, servers ...string) *Client {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	c := &Client{
		dial:    dial,
		servers: append([]string(nil), servers...),
		timeout: 5 * time.Second,
	}
	c.p = newProvider(c.handle)
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
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "53")
	}
	wire := msg.Copy()
	wire.ID = NextID()
	pkt, err := Pack(wire)
	if err != nil {
		return nil, err
	}
	switch network {
	case "udp":
		return c.exchangeUDP(ctx, addr, pkt)
	case "tcp":
		return c.exchangeStream(ctx, "tcp", addr, pkt, false)
	case "dot":
		return c.exchangeStream(ctx, "tcp", addr, pkt, true)
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
	tlsMode bool,
) (*Message, error) {
	conn, err := c.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	done := closeConnOnContext(ctx, conn)
	defer done()
	if tlsMode {
		host, _, _ := net.SplitHostPort(addr)
		conn = tls.Client(conn, c.tlsConfig(host))
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
	conn net.PacketConn
	p    *provider

	mu       sync.Mutex
	upstream Interface
	gen      uint64
	done     chan struct{}

	closeOnce sync.Once
}

// NewServer starts serving DNS packets from conn.
func NewServer(conn net.PacketConn, upstream Interface) *Server {
	s := &Server{conn: conn}
	s.Attach(upstream)
	ctx, cancel := context.WithCancel(context.Background())
	s.p = &provider{
		ch:     make(chan Request),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(s.p.done)
		s.serve(ctx)
	}()
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
		go s.handlePacket(ctx, pkt, addr)
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
	qctx, cancel := context.WithCancel(ctx)
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
