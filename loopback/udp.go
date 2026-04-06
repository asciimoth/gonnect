package loopback

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	ge "github.com/asciimoth/gonnect/errors"
	"github.com/asciimoth/gonnect/helpers"
)

var (
	_ gonnect.UDPConn = &loopbackUDPConn{}
	_ io.Closer       = &loopbackUDPConn{}
)

// loopbackUDPPacket represents a single UDP packet with its data and source address.
type loopbackUDPPacket struct {
	data    []byte
	srcAddr net.Addr
}

// loopbackUDPRegistry manages UDP connections for a specific network type (udp4 or udp6).
// It handles port allocation and tracks active connections by address.
type loopbackUDPRegistry struct {
	Network, Host string
	mu            sync.RWMutex
	conns         map[string]*loopbackUDPConn
	alloc         loopbackPortAllocator
}

// IsVoid returns true if the registry has no active connections or allocated ports.
func (r *loopbackUDPRegistry) IsVoid() bool {
	if r == nil {
		return true
	}
	if len(r.conns) > 0 {
		return false
	}
	return r.alloc.isVoid()
}

// reg registers a UDP connection with the given port.
// If port is nil, it allocates an ephemeral port from the dynamic port range.
// Returns an error if the port is already in use.
func (r *loopbackUDPRegistry) reg(
	port *uint16,
	conn *loopbackUDPConn,
) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		r.conns = make(map[string]*loopbackUDPConn)
	}
	p, err := r.alloc.alloc(port)
	if err != nil {
		return err
	}
	addr := &helpers.NetAddr{
		Net:  r.Network,
		Addr: net.JoinHostPort(r.Host, strconv.Itoa(int(p))),
	}
	conn.port = p
	conn.laddr = addr
	r.conns[addr.String()] = conn
	return nil
}

// unreg unregisters a UDP connection from the registry.
// It frees the allocated port and removes the connection from the map.
func (r *loopbackUDPRegistry) unreg(conn *loopbackUDPConn) {
	if conn == nil {
		return
	}
	if conn.laddr.Network() != r.Network {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		return
	}
	c := r.conns[conn.laddr.String()]
	if c != conn {
		return
	}
	delete(r.conns, conn.laddr.String())
	r.alloc.free(conn.port)
}

// lookup finds a UDP connection by address.
// Returns nil if the network doesn't match or if no connection is found.
func (r *loopbackUDPRegistry) lookup(addr net.Addr) *loopbackUDPConn {
	if addr.Network() != r.Network {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[addr.String()]
}

// loopbackUDPConn is an in-memory UDP connection that communicates via buffered channels.
// It supports both connected (raddr set) and unconnected modes.
type loopbackUDPConn struct {
	laddr, raddr net.Addr // raddr can be nil, laddr always has value
	port         uint16
	reg          *loopbackUDPRegistry

	mu sync.Mutex
	in chan loopbackUDPPacket

	closed    bool
	closeCh   chan struct{}
	closeOnce sync.Once

	readDeadline  time.Time
	writeDeadline time.Time

	// directSend is used for PipeUDP() to send directly to paired connection
	// without going through registry lookup
	directSend  chan loopbackUDPPacket
	peerCloseCh chan struct{}

	// cb is the callback invoked on events.
	cb *gonnect.Callbacks
}

// newLoopbackUDPConn creates a new UDP connection and registers it with the given registry.
// The lport parameter can be nil for ephemeral port allocation.
// If rport is not nil, the connection is set to connected mode with the specified remote port.
func newLoopbackUDPConn(
	reg *loopbackUDPRegistry,
	lport, rport *uint16,
) (*loopbackUDPConn, error) {
	c := &loopbackUDPConn{
		reg:     reg,
		in:      make(chan loopbackUDPPacket, 1024),
		closeCh: make(chan struct{}),
	}
	if rport != nil {
		c.raddr = &helpers.NetAddr{
			Net:  reg.Network,
			Addr: net.JoinHostPort(reg.Host, strconv.Itoa(int(*rport))),
		}
	}
	err := reg.reg(lport, c)
	return c, err
}

// Close closes the UDP connection, freeing the registered port and closing all channels.
// It uses sync.Once to ensure the close operation is performed only once.
func (c *loopbackUDPConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed {
			if c.cb != nil {
				c.cb.RunBeforeClose()
			}
			c.closed = true
			if c.reg != nil {
				c.reg.unreg(c)
			}
			close(c.in)
			close(c.closeCh)
		}
	})
	return nil
}

// LocalAddr returns the local address of the UDP connection.
func (c *loopbackUDPConn) LocalAddr() net.Addr {
	return c.laddr
}

// RemoteAddr returns the remote address of the UDP connection.
// Returns nil if the connection is not in connected mode.
func (c *loopbackUDPConn) RemoteAddr() net.Addr {
	return c.raddr
}

// ReadFrom reads a UDP packet from the connection.
// It returns the number of bytes copied, the source address, and any error.
// The method respects the read deadline if set.
func (c *loopbackUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, ge.ConnClosed(
			"read",
			c.laddr.Network(),
			c.laddr,
			c.raddr,
		)
	}
	rd := c.readDeadline
	in := c.in
	c.mu.Unlock()

	var timer <-chan time.Time
	if !rd.IsZero() {
		timer = timerForDeadline(rd)
	}

	select {
	case pkt, ok := <-in:
		if !ok {
			return 0, nil, ge.ConnClosed(
				"read",
				c.laddr.Network(),
				c.laddr,
				c.raddr,
			)
		}
		copied := copy(p, pkt.data)
		return copied, pkt.srcAddr, nil
	case <-timer:
		return 0, nil, &net.OpError{
			Op:  "read",
			Net: "memudp",
			Err: errors.New("i/o timeout"),
		}
	case <-c.closeCh:
		return 0, nil, ge.ConnClosed(
			"read",
			c.laddr.Network(),
			c.laddr,
			c.raddr,
		)
	}
}

// Read reads a UDP packet from the connection.
// It delegates to ReadFrom and discards the source address.
func (c *loopbackUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// ReadFromUDP reads a UDP packet from the connection.
// It delegates to ReadFrom and converts the address to *net.UDPAddr.
func (luc *loopbackUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := luc.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
	if err != nil {
		return 0, nil, err
	}
	return n, udpAddr, nil
}

// ReadFromUDPAddrPort reads a UDP packet from the connection.
// It delegates to ReadFrom and converts the address to netip.AddrPort.
func (c *loopbackUDPConn) ReadFromUDPAddrPort(
	b []byte,
) (int, netip.AddrPort, error) {
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, ap, nil
}

// SetDeadline sets both read and write deadlines for the connection.
func (c *loopbackUDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline for the connection.
func (c *loopbackUDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (c *loopbackUDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// WriteTo writes a UDP packet to the specified address.
// It creates a copy of the data and sends it via sendTo.
// Returns the number of bytes written or an error.
func (c *loopbackUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
	}
	wd := c.writeDeadline
	c.mu.Unlock()

	data := make([]byte, len(b))
	copy(data, b)

	pkg := loopbackUDPPacket{
		data:    data,
		srcAddr: c.laddr,
	}

	err := c.sendTo(addr, pkg, wd)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Write writes a UDP packet to the remote address.
// Returns an error if the connection is not in connected mode (raddr is nil).
func (c *loopbackUDPConn) Write(b []byte) (int, error) {
	if c.raddr == nil {
		return 0, &net.OpError{
			Op:  "write",
			Net: "memudp",
			Err: errors.New("not connected"),
		}
	}
	return c.WriteTo(b, c.raddr)
}

// WriteToUDP writes a UDP packet to the specified UDP address.
// It delegates to WriteTo.
func (luc *loopbackUDPConn) WriteToUDP(
	b []byte,
	addr *net.UDPAddr,
) (int, error) {
	return luc.WriteTo(b, addr)
}

// WriteToUDPAddrPort writes a UDP packet to the specified netip.AddrPort.
// It delegates to WriteTo after converting the address.
func (luc *loopbackUDPConn) WriteToUDPAddrPort(
	b []byte,
	addr netip.AddrPort,
) (int, error) {
	return luc.WriteTo(b, &helpers.NetAddr{
		Net:  luc.laddr.Network(),
		Addr: addr.String(),
	})
}

// ReadMsgUDP reads a UDP message with out-of-band data.
// This is a stub implementation that delegates to ReadFromUDP.
// The oob buffer and flags are not used.
func (luc *loopbackUDPConn) ReadMsgUDP(
	b, oob []byte,
) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, addr, err = luc.ReadFromUDP(b)
	return
}

// ReadMsgUDPAddrPort reads a UDP message with out-of-band data.
// This is a stub implementation that delegates to ReadFromUDPAddrPort.
// The oob buffer and flags are not used.
func (luc *loopbackUDPConn) ReadMsgUDPAddrPort(
	b, oob []byte,
) (n, oobn, flags int, addr netip.AddrPort, err error) {
	n, addr, err = luc.ReadFromUDPAddrPort(b)
	return
}

// WriteMsgUDP writes a UDP message with out-of-band data.
// This is a stub implementation that delegates to WriteToUDP.
// The oob buffer is not used.
func (luc *loopbackUDPConn) WriteMsgUDP(
	b, oob []byte,
	addr *net.UDPAddr,
) (n, oobn int, err error) {
	n, err = luc.WriteToUDP(b, addr)
	return
}

// WriteMsgUDPAddrPort writes a UDP message with out-of-band data.
// This is a stub implementation that delegates to WriteToUDPAddrPort.
// The oob buffer is not used.
func (luc *loopbackUDPConn) WriteMsgUDPAddrPort(
	b, oob []byte,
	addr netip.AddrPort,
) (n, oobn int, err error) {
	n, err = luc.WriteToUDPAddrPort(b, addr)
	return
}

// sendTo sends a UDP packet to the specified address.
// If directSend is set (for PipeUDP()), it sends directly to the paired connection.
// Otherwise, it looks up the destination connection in the registry and queues the packet.
// The method respects the write deadline if set.
func (c *loopbackUDPConn) sendTo(
	addr net.Addr,
	pkg loopbackUDPPacket,
	wd time.Time,
) error {
	pkg.srcAddr = c.laddr

	// Use direct send for PipeUDP() connections
	if c.directSend != nil {
		// Check if peer is closed before attempting to send
		select {
		case <-c.peerCloseCh:
			return ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
		default:
		}

		var timer <-chan time.Time
		if !wd.IsZero() {
			timer = timerForDeadline(wd)
		}

		select {
		case c.directSend <- pkg:
			return nil
		case <-c.peerCloseCh:
			return ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
		case <-timer:
			return &net.OpError{
				Op:  "write",
				Net: "memudp",
				Err: errors.New("i/o timeout"),
			}
		case <-c.closeCh:
			return ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
		}
	}

	dst := c.reg.lookup(addr)
	if dst == nil {
		return &net.OpError{
			Op:  "write",
			Net: "memudp",
			Err: errors.New("no route to host"),
		}
	}

	var timer <-chan time.Time
	if !wd.IsZero() {
		timer = timerForDeadline(wd)
	}

	select {
	case dst.in <- pkg:
		return nil
	case <-timer:
		return &net.OpError{
			Op:  "write",
			Net: "memudp",
			Err: errors.New("i/o timeout"),
		}
	case <-dst.closeCh:
		return ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
	case <-c.closeCh:
		return ge.ConnClosed("write", c.laddr.Network(), c.laddr, c.raddr)
	}
}

// PipeUDP creates a pair of connected loopbackUDPConn that communicate
// via buffered channels. The connections are set up to send packets to
// each other directly without using actual network sockets or registry lookup.
// This is analogous to net.Pipe() but for UDP-style packet communication.
func PipeUDP() (conn1, conn2 gonnect.UDPConn) {
	// Create two channels for bidirectional communication
	ch1to2 := make(chan loopbackUDPPacket, 1024)
	ch2to1 := make(chan loopbackUDPPacket, 1024)
	closeCh1 := make(chan struct{})
	closeCh2 := make(chan struct{})

	addr1 := &helpers.NetAddr{
		Net:  "udp",
		Addr: "pipe:conn1",
	}
	addr2 := &helpers.NetAddr{
		Net:  "udp",
		Addr: "pipe:conn2",
	}

	// conn1 sends to conn2 via ch1to2, receives from conn2 via ch2to1
	conn1 = &loopbackUDPConn{
		laddr:       addr1,
		raddr:       addr2,
		in:          ch2to1,
		closeCh:     closeCh1,
		directSend:  ch1to2,
		peerCloseCh: closeCh2,
	}

	// conn2 sends to conn1 via ch2to1, receives from conn1 via ch1to2
	conn2 = &loopbackUDPConn{
		laddr:       addr2,
		raddr:       addr1,
		in:          ch1to2,
		closeCh:     closeCh2,
		directSend:  ch2to1,
		peerCloseCh: closeCh1,
	}

	return conn1, conn2
}
