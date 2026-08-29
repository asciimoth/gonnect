package gonnect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var _ interface {
	Network
	UpDown
	io.Closer
	CloserSubscriber
	UpDownSubscriber
	Wrapper
} = (*Firewall)(nil)

// Firewall filters traffic that passes through a Network.
//
// Dial operations are checked against the outgoing Exclude rules. TCP
// listeners check each accepted peer against incoming Include rules. UDP
// connections check every outgoing datagram and silently discard incoming
// datagrams that are neither included nor a response to an allowed outgoing
// datagram.
//
// Lifecycle operations are delegated to the wrapped Network when it supports
// the corresponding optional interface.
// Keep this interface private so that Firewall does not expose an embedded
// Network field as part of its public API.
//
//nolint:iface // The identical method set is intentional for API encapsulation.
type firewallNetwork interface {
	Network
}

type Firewall struct {
	firewallNetwork
	config atomic.Pointer[FirewallConfig]
}

// NewFirewall creates a Firewall around network. It optimizes and clones cfg
// before it returns. A nil config allows all outgoing traffic and denies
// unsolicited incoming traffic.
func NewFirewall(network Network, cfg *FirewallConfig) *Firewall {
	firewall := &Firewall{firewallNetwork: network}
	firewall.config.Store(cfg.Optimize())
	return firewall
}

// GetWrapped returns the wrapped Network.
func (f *Firewall) GetWrapped() any { return f.firewallNetwork }

// GetNetwork returns the wrapped Network.
func (f *Firewall) GetNetwork() Network { return f.firewallNetwork }

// IsNative always returns false. Direct native access would bypass filtering.
func (f *Firewall) IsNative() bool { return false }

// SetConfig atomically installs an optimized clone of cfg. Existing response
// cache entries remain valid until their original expiration time.
func (f *Firewall) SetConfig(cfg *FirewallConfig) {
	f.config.Store(cfg.Optimize())
}

// SetCfg is an alias for SetConfig.
func (f *Firewall) SetCfg(cfg *FirewallConfig) { f.SetConfig(cfg) }

// GetConfig returns an independent copy of the active configuration.
func (f *Firewall) GetConfig() *FirewallConfig {
	return cloneFirewallConfig(f.config.Load())
}

// GetCfg is an alias for GetConfig.
func (f *Firewall) GetCfg() *FirewallConfig { return f.GetConfig() }

// Close closes the wrapped Network when it implements io.Closer.
func (f *Firewall) Close() error {
	if closer, ok := f.firewallNetwork.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SubscribeCloser delegates to the wrapped Network when supported.
func (f *Firewall) SubscribeCloser(c io.Closer) (func(), error) {
	if subscriber, ok := f.firewallNetwork.(CloserSubscriber); ok {
		return subscriber.SubscribeCloser(c)
	}
	return func() {}, nil
}

// Up brings the wrapped Network up when it implements UpDown.
func (f *Firewall) Up() error {
	if upDown, ok := f.firewallNetwork.(UpDown); ok {
		return upDown.Up()
	}
	return nil
}

// Down brings the wrapped Network down when it implements UpDown.
func (f *Firewall) Down() error {
	if upDown, ok := f.firewallNetwork.(UpDown); ok {
		return upDown.Down()
	}
	return nil
}

// IsUp reports the wrapped Network state when it implements UpDown.
func (f *Firewall) IsUp() (bool, error) {
	if upDown, ok := f.firewallNetwork.(UpDown); ok {
		return upDown.IsUp()
	}
	return true, nil
}

// SubscribeUpDown delegates to the wrapped Network when supported.
func (f *Firewall) SubscribeUpDown(u UpDown) (func(), error) {
	if subscriber, ok := f.firewallNetwork.(UpDownSubscriber); ok {
		return subscriber.SubscribeUpDown(u)
	}
	return func() {}, nil
}

// Dial checks the destination and delegates the operation.
func (f *Firewall) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if err := f.checkOutgoing("dial", network, address); err != nil {
		return nil, err
	}
	conn, err := f.firewallNetwork.Dial(ctx, network, address)
	if err != nil || !isFirewallUDPNetwork(network) {
		return conn, err
	}
	return f.wrapNetConn(conn, network), nil
}

// Listen delegates the operation and filters accepted TCP connections.
func (f *Firewall) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	listener, err := f.firewallNetwork.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &firewallListener{
		Listener: listener,
		firewall: f,
		network:  network,
	}, nil
}

// PacketDial checks the destination and returns a filtered packet connection.
func (f *Firewall) PacketDial(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	if err := f.checkOutgoing("dial", network, address); err != nil {
		return nil, err
	}
	conn, err := f.firewallNetwork.PacketDial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return f.wrapPacketConn(conn, network), nil
}

// ListenPacket returns a packet connection that filters both directions.
func (f *Firewall) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	conn, err := f.firewallNetwork.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return f.wrapPacketConn(conn, network), nil
}

// DialTCP checks the destination and delegates the operation.
func (f *Firewall) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	if err := f.checkOutgoing("dial", network, raddr); err != nil {
		return nil, err
	}
	return f.firewallNetwork.DialTCP(ctx, network, laddr, raddr)
}

// ListenTCP returns a listener that filters each accepted connection.
func (f *Firewall) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	listener, err := f.firewallNetwork.ListenTCP(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return &firewallTCPListener{
		TCPListener: listener,
		firewall:    f,
		network:     network,
	}, nil
}

// DialUDP checks the destination and returns a filtered UDP connection.
func (f *Firewall) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	if err := f.checkOutgoing("dial", network, raddr); err != nil {
		return nil, err
	}
	conn, err := f.firewallNetwork.DialUDP(ctx, network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return newFirewallUDPConn(f, conn, network), nil
}

// ListenUDP returns a UDP connection that filters both directions.
func (f *Firewall) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	conn, err := f.firewallNetwork.ListenUDP(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	return newFirewallUDPConn(f, conn, network), nil
}

// ListenPacketConfig returns a packet connection that filters both directions.
func (f *Firewall) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	conn, err := f.firewallNetwork.ListenPacketConfig(ctx, lc, network, address)
	if err != nil {
		return nil, err
	}
	return f.wrapPacketConn(conn, network), nil
}

// ListenUDPConfig returns a UDP connection that filters both directions.
func (f *Firewall) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	conn, err := f.firewallNetwork.ListenUDPConfig(ctx, lc, network, laddr)
	if err != nil {
		return nil, err
	}
	return newFirewallUDPConn(f, conn, network), nil
}

// ListenMulticastUDP returns a filtered multicast packet connection.
func (f *Firewall) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	conn, err := f.firewallNetwork.ListenMulticastUDP(
		ctx,
		network,
		address,
		opts,
	)
	if err != nil {
		return nil, err
	}
	return &firewallMulticastPacketConn{
		MulticastPacketConn: conn,
		state: &firewallPacketState{
			firewall:  f,
			network:   network,
			localAddr: conn.LocalAddr,
			remote:    func() net.Addr { return nil },
		},
	}, nil
}

func (f *Firewall) checkOutgoing(op, network, address string) error {
	if !f.config.Load().BlocksOutgoing(network, address) {
		return nil
	}
	return &net.OpError{
		Op:   op,
		Net:  network,
		Addr: &NetAddr{Net: network, Addr: address},
		Err:  ErrFirewallDenied,
	}
}

func (f *Firewall) checkOutgoingAddr(
	op, network string,
	address net.Addr,
) error {
	endpoint, ok := firewallAddrPort(address)
	if !ok {
		return f.checkOutgoing(op, network, address.String())
	}
	if !f.config.Load().BlocksOutgoingAddrPort(network, endpoint) {
		return nil
	}
	return &net.OpError{
		Op:   op,
		Net:  network,
		Addr: address,
		Err:  ErrFirewallDenied,
	}
}

func (f *Firewall) wrapNetConn(conn net.Conn, network string) net.Conn {
	if udp, ok := conn.(UDPConn); ok {
		return newFirewallUDPConn(f, udp, network)
	}
	if packet, ok := conn.(PacketConn); ok {
		return f.wrapPacketConn(packet, network)
	}
	return &firewallConn{
		Conn:  conn,
		state: newFirewallPacketState(f, network, conn),
	}
}

func (f *Firewall) wrapPacketConn(conn PacketConn, network string) PacketConn {
	if udp, ok := conn.(UDPConn); ok {
		return newFirewallUDPConn(f, udp, network)
	}
	return &firewallPacketConn{
		PacketConn: conn,
		state:      newFirewallPacketState(f, network, conn),
	}
}

type firewallListener struct {
	net.Listener
	firewall *Firewall
	network  string
}

func (l *firewallListener) GetWrapped() any { return l.Listener }

func (l *firewallListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if conn == nil {
			continue
		}
		if l.firewall.acceptsIncoming(
			l.network,
			conn.RemoteAddr(),
			conn.LocalAddr(),
		) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

type firewallTCPListener struct {
	TCPListener
	firewall *Firewall
	network  string
}

func (l *firewallTCPListener) GetWrapped() any { return l.TCPListener }

func (l *firewallTCPListener) Accept() (net.Conn, error) {
	return l.AcceptTCP()
}

func (l *firewallTCPListener) AcceptTCP() (TCPConn, error) {
	for {
		conn, err := l.TCPListener.AcceptTCP()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if conn == nil {
			continue
		}
		if l.firewall.acceptsIncoming(
			l.network,
			conn.RemoteAddr(),
			conn.LocalAddr(),
		) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

func (f *Firewall) acceptsIncoming(network string, peer, local net.Addr) bool {
	peerEndpoint, peerOK := firewallAddrPort(peer)
	localEndpoint, localOK := firewallAddrPort(local)
	if peerOK && localOK {
		return f.config.Load().AllowsIncomingAddrPort(
			network,
			netip.AddrPortFrom(
				peerEndpoint.Addr(),
				localEndpoint.Port(),
			),
		)
	}
	return f.config.Load().AllowsIncoming(
		network,
		firewallPolicyAddress(peer, local),
	)
}

type firewallPacketState struct {
	firewall    *Firewall
	network     string
	localAddr   func() net.Addr
	remote      func() net.Addr
	responsesMu sync.Mutex
	responses   map[firewallPeerKey]int64
	recorded    uint64
}

func newFirewallPacketState(
	firewall *Firewall,
	network string,
	conn interface {
		LocalAddr() net.Addr
		RemoteAddr() net.Addr
	},
) *firewallPacketState {
	return &firewallPacketState{
		firewall:  firewall,
		network:   network,
		localAddr: conn.LocalAddr,
		remote:    conn.RemoteAddr,
	}
}

func (s *firewallPacketState) checkOutgoing(addr net.Addr) error {
	if addr == nil {
		addr = s.remote()
	}
	if addr == nil {
		return nil
	}
	return s.firewall.checkOutgoingAddr("write", s.network, addr)
}

func (s *firewallPacketState) checkOutgoingAddrPort(
	addr netip.AddrPort,
) error {
	if !addr.IsValid() || !s.firewall.config.Load().BlocksOutgoingAddrPort(
		s.network,
		addr,
	) {
		return nil
	}
	return &net.OpError{
		Op:  "write",
		Net: s.network,
		Addr: &NetAddr{
			Net:  s.network,
			Addr: addr.String(),
		},
		Err: ErrFirewallDenied,
	}
}

func (s *firewallPacketState) recordResponse(addr net.Addr) {
	if addr == nil {
		addr = s.remote()
	}
	key, ok := makeFirewallPeerKey(addr)
	if !ok {
		return
	}
	s.recordResponseKey(key)
}

func (s *firewallPacketState) recordResponseAddrPort(addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	s.recordResponseKey(firewallPeerKey{addr: normalizePeerAddrPort(addr)})
}

func (s *firewallPacketState) recordResponseKey(key firewallPeerKey) {
	now := time.Now()
	expires := now.Add(
		s.firewall.config.Load().responseTTL(),
	).UnixNano()
	s.responsesMu.Lock()
	if s.responses == nil {
		s.responses = make(map[firewallPeerKey]int64)
	}
	s.responses[key] = expires
	s.recorded++
	if s.recorded%256 == 0 {
		s.deleteExpiredResponsesLocked(now.UnixNano())
	}
	s.responsesMu.Unlock()
}

func (s *firewallPacketState) allowsIncoming(addr net.Addr) bool {
	key, ok := makeFirewallPeerKey(addr)
	if ok && s.hasResponse(key) {
		return true
	}
	return s.firewall.acceptsIncoming(s.network, addr, s.localAddr())
}

func (s *firewallPacketState) allowsIncomingAddrPort(
	addr netip.AddrPort,
) bool {
	if addr.IsValid() && s.hasResponse(
		firewallPeerKey{addr: normalizePeerAddrPort(addr)},
	) {
		return true
	}
	local, ok := firewallAddrPort(s.localAddr())
	if !ok {
		return s.allowsIncoming(net.UDPAddrFromAddrPort(addr))
	}
	return s.firewall.config.Load().AllowsIncomingAddrPort(
		s.network,
		netip.AddrPortFrom(addr.Addr(), local.Port()),
	)
}

func (s *firewallPacketState) hasResponse(key firewallPeerKey) bool {
	now := time.Now().UnixNano()
	s.responsesMu.Lock()
	expires, ok := s.responses[key]
	if !ok {
		s.responsesMu.Unlock()
		return false
	}
	if expires >= now {
		s.responsesMu.Unlock()
		return true
	}
	delete(s.responses, key)
	s.responsesMu.Unlock()
	return false
}

func (s *firewallPacketState) deleteExpiredResponsesLocked(now int64) {
	for key, expires := range s.responses {
		if expires < now {
			delete(s.responses, key)
		}
	}
}

type firewallPeerKey struct {
	addr netip.AddrPort
	name string
}

func makeFirewallPeerKey(addr net.Addr) (firewallPeerKey, bool) {
	if addr == nil {
		return firewallPeerKey{}, false
	}
	if endpoint, ok := firewallAddrPort(addr); ok {
		return firewallPeerKey{addr: normalizePeerAddrPort(endpoint)}, true
	}
	name := strings.ToLower(addr.String())
	return firewallPeerKey{name: name}, name != ""
}

func firewallAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	if provider, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		endpoint := provider.AddrPort()
		return endpoint, endpoint.IsValid()
	}
	endpoint, err := netip.ParseAddrPort(addr.String())
	return endpoint, err == nil
}

func normalizePeerAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func firewallPolicyAddress(peer, local net.Addr) string {
	host, _ := splitAddrHostPort(peer)
	_, port := splitAddrHostPort(local)
	return net.JoinHostPort(host, port)
}

func splitAddrHostPort(addr net.Addr) (string, string) {
	if addr == nil {
		return "", ""
	}
	if host, port, err := net.SplitHostPort(addr.String()); err == nil {
		return host, port
	}
	return addr.String(), ""
}

type firewallConn struct {
	net.Conn
	state *firewallPacketState
}

func (c *firewallConn) GetWrapped() any { return c.Conn }

func (c *firewallConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if c.state.allowsIncoming(c.RemoteAddr()) {
			return n, err
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *firewallConn) Write(p []byte) (int, error) {
	if err := c.state.checkOutgoing(nil); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	if err == nil {
		c.state.recordResponse(nil)
	}
	return n, err
}

type firewallPacketConn struct {
	PacketConn
	state *firewallPacketState
}

func (c *firewallPacketConn) GetWrapped() any { return c.PacketConn }

func (c *firewallPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *firewallPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if c.state.allowsIncoming(addr) {
			return n, addr, err
		}
		if err != nil {
			return 0, addr, err
		}
	}
}

func (c *firewallPacketConn) Write(p []byte) (int, error) {
	if err := c.state.checkOutgoing(nil); err != nil {
		return 0, err
	}
	n, err := c.PacketConn.Write(p)
	if err == nil {
		c.state.recordResponse(nil)
	}
	return n, err
}

func (c *firewallPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.state.checkOutgoing(addr); err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return n, err
}

type firewallUDPConn struct {
	UDPConn
	state *firewallPacketState
}

func (c *firewallUDPConn) GetWrapped() any { return c.UDPConn }

func newFirewallUDPConn(
	firewall *Firewall,
	conn UDPConn,
	network string,
) *firewallUDPConn {
	return &firewallUDPConn{
		UDPConn: conn,
		state:   newFirewallPacketState(firewall, network, conn),
	}
}

func (c *firewallUDPConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *firewallUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, addr, err
}

func (c *firewallUDPConn) ReadFromUDP(
	p []byte,
) (int, *net.UDPAddr, error) {
	for {
		n, addr, err := c.UDPConn.ReadFromUDP(p)
		if c.state.allowsIncoming(addr) {
			return n, addr, err
		}
		if err != nil {
			return 0, addr, err
		}
	}
}

func (c *firewallUDPConn) ReadFromUDPAddrPort(
	p []byte,
) (int, netip.AddrPort, error) {
	for {
		n, addr, err := c.UDPConn.ReadFromUDPAddrPort(p)
		if c.state.allowsIncomingAddrPort(addr) {
			return n, addr, err
		}
		if err != nil {
			return 0, addr, err
		}
	}
}

func (c *firewallUDPConn) ReadMsgUDP(
	b, oob []byte,
) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
		if c.state.allowsIncoming(addr) {
			return
		}
		if err != nil {
			n, oobn = 0, 0
			return
		}
	}
}

func (c *firewallUDPConn) ReadMsgUDPAddrPort(
	b, oob []byte,
) (n, oobn, flags int, addr netip.AddrPort, err error) {
	for {
		n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDPAddrPort(b, oob)
		if c.state.allowsIncomingAddrPort(addr) {
			return
		}
		if err != nil {
			n, oobn = 0, 0
			return
		}
	}
}

func (c *firewallUDPConn) Write(p []byte) (int, error) {
	if err := c.state.checkOutgoing(nil); err != nil {
		return 0, err
	}
	n, err := c.UDPConn.Write(p)
	if err == nil {
		c.state.recordResponse(nil)
	}
	return n, err
}

func (c *firewallUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.state.checkOutgoing(addr); err != nil {
		return 0, err
	}
	n, err := c.UDPConn.WriteTo(p, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return n, err
}

func (c *firewallUDPConn) WriteToUDP(
	p []byte,
	addr *net.UDPAddr,
) (int, error) {
	if err := c.state.checkOutgoing(addr); err != nil {
		return 0, err
	}
	n, err := c.UDPConn.WriteToUDP(p, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return n, err
}

func (c *firewallUDPConn) WriteToUDPAddrPort(
	p []byte,
	addr netip.AddrPort,
) (int, error) {
	if err := c.state.checkOutgoingAddrPort(addr); err != nil {
		return 0, err
	}
	n, err := c.UDPConn.WriteToUDPAddrPort(p, addr)
	if err == nil {
		c.state.recordResponseAddrPort(addr)
	}
	return n, err
}

func (c *firewallUDPConn) WriteMsgUDP(
	b, oob []byte,
	addr *net.UDPAddr,
) (n, oobn int, err error) {
	if err = c.state.checkOutgoing(addr); err != nil {
		return 0, 0, err
	}
	n, oobn, err = c.UDPConn.WriteMsgUDP(b, oob, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return
}

func (c *firewallUDPConn) WriteMsgUDPAddrPort(
	b, oob []byte,
	addr netip.AddrPort,
) (n, oobn int, err error) {
	if err = c.state.checkOutgoingAddrPort(addr); err != nil {
		return 0, 0, err
	}
	n, oobn, err = c.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
	if err == nil {
		c.state.recordResponseAddrPort(addr)
	}
	return
}

type firewallMulticastPacketConn struct {
	MulticastPacketConn
	state *firewallPacketState
}

func (c *firewallMulticastPacketConn) GetWrapped() any {
	return c.MulticastPacketConn
}

func (c *firewallMulticastPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	for {
		n, addr, err := c.MulticastPacketConn.ReadFrom(p)
		if c.state.allowsIncoming(addr) {
			return n, addr, err
		}
		if err != nil {
			return 0, addr, err
		}
	}
}

func (c *firewallMulticastPacketConn) ReadFromControl(
	p []byte,
) (int, ControlMessage, net.Addr, error) {
	for {
		n, control, addr, err := c.MulticastPacketConn.ReadFromControl(p)
		if c.state.allowsIncoming(addr) {
			return n, control, addr, err
		}
		if err != nil {
			return 0, ControlMessage{}, addr, err
		}
	}
}

func (c *firewallMulticastPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	if err := c.state.checkOutgoing(addr); err != nil {
		return 0, err
	}
	n, err := c.MulticastPacketConn.WriteTo(p, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return n, err
}

func (c *firewallMulticastPacketConn) WriteToControl(
	p []byte,
	control ControlMessage,
	addr net.Addr,
) (int, error) {
	if err := c.state.checkOutgoing(addr); err != nil {
		return 0, err
	}
	n, err := c.MulticastPacketConn.WriteToControl(p, control, addr)
	if err == nil {
		c.state.recordResponse(addr)
	}
	return n, err
}

func isFirewallUDPNetwork(network string) bool {
	return strings.HasPrefix(strings.ToLower(network), "udp")
}
