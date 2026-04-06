package loopback

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
)

var (
	_ gonnect.TCPConn     = &loopbackTCPConn{}
	_ net.Conn            = &loopbackTCPConn{}
	_ gonnect.TCPListener = &loopbackTCPListener{}
	_ io.Closer           = &loopbackTCPListener{}
	_ io.Closer           = &loopbackTCPConn{}
)

// loopbackTCPRegistry manages TCP listeners and connections for a specific
// network type (tcp4 or tcp6). It handles port allocation and tracks active
// listeners by address.
type loopbackTCPRegistry struct {
	Network, Host string
	mu            sync.RWMutex
	listeners     map[string]*loopbackTCPListener
	alloc         loopbackPortAllocator
}

// IsVoid returns true if the registry has no active listeners or allocated ports.
func (r *loopbackTCPRegistry) IsVoid() bool {
	if r == nil {
		return true
	}
	if len(r.listeners) > 0 {
		return false
	}
	return r.alloc.isVoid()
}

// RegListener registers a TCP listener with the given port.
// If port is nil, it allocates an ephemeral port from the dynamic port range.
// Returns an error if the port is already in use.
func (r *loopbackTCPRegistry) RegListener(
	port *uint16,
	listener *loopbackTCPListener,
) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listeners == nil {
		r.listeners = make(map[string]*loopbackTCPListener)
	}
	p, err := r.alloc.alloc(port)
	if err != nil {
		return err
	}
	addr := &helpers.NetAddr{
		Net:  r.Network,
		Addr: net.JoinHostPort(r.Host, strconv.Itoa(int(p))),
	}
	listener.reg = r
	listener.Port = p
	listener.Laddr = addr
	r.listeners[addr.String()] = listener
	return nil
}

// UnregListener unregisters a TCP listener from the registry.
// It frees the allocated port and removes the listener from the map.
func (r *loopbackTCPRegistry) UnregListener(listener *loopbackTCPListener) {
	if r == nil || listener == nil {
		return
	}
	if listener.Laddr != nil && listener.Laddr.Network() != r.Network {
		return
	}
	if listener.Port == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listeners == nil {
		return
	}
	c := r.listeners[listener.Laddr.String()]
	if c != listener {
		return
	}
	delete(r.listeners, listener.Laddr.String())
	r.alloc.free(listener.Port)
}

// RegConn registers a TCP connection with the given port.
// If port is nil, it allocates an ephemeral port from the dynamic port range.
// Returns an error if the port is already in use.
func (r *loopbackTCPRegistry) RegConn(
	port *uint16,
	conn *loopbackTCPConn,
) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.alloc.alloc(port)
	if err != nil {
		return err
	}
	addr := &helpers.NetAddr{
		Net:  r.Network,
		Addr: net.JoinHostPort(r.Host, strconv.Itoa(int(p))),
	}
	conn.reg = r
	conn.Port = p
	conn.Laddr = addr
	return nil
}

// UnregConn unregisters a TCP connection from the registry.
// It frees the allocated port associated with the connection.
func (r *loopbackTCPRegistry) UnregConn(conn *loopbackTCPConn) {
	if r == nil || conn == nil {
		return
	}
	if conn.Laddr != nil && conn.Laddr.Network() != r.Network {
		return
	}
	if conn.Port == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alloc.free(conn.Port)
}

// Lookup finds a TCP listener by address.
// Returns nil if the network doesn't match or if no listener is found.
func (r *loopbackTCPRegistry) Lookup(addr net.Addr) *loopbackTCPListener {
	if addr.Network() != r.Network {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.listeners[addr.String()]
}

// loopbackTCPListener implements gonnect.TCPListener and provides Accept
// via a buffered channel. It queues incoming connections in acceptQ and
// signals closure via the closed channel.
type loopbackTCPListener struct {
	reg     *loopbackTCPRegistry
	Laddr   net.Addr
	Port    uint16
	acceptQ chan *loopbackTCPConn
	closed  chan struct{}
	closeMu sync.Mutex

	deadlineMu sync.Mutex
	deadline   time.Time

	// cb is the callback invoked on events.
	cb *gonnect.Callbacks
}

// newLoopbackTCPListener creates a new TCP listener and registers it with the given registry.
// The lport parameter can be nil for ephemeral port allocation.
func newLoopbackTCPListener(
	reg *loopbackTCPRegistry,
	lport *uint16,
) (*loopbackTCPListener, error) {
	listener := &loopbackTCPListener{
		reg:     reg,
		acceptQ: make(chan *loopbackTCPConn, runtime.NumCPU()),
		closed:  make(chan struct{}),
	}
	err := reg.RegListener(lport, listener)
	return listener, err
}

// NewConn queues an incoming connection for acceptance.
// Returns an error if the listener has been closed.
func (l *loopbackTCPListener) NewConn(c *loopbackTCPConn) error {
	select {
	case l.acceptQ <- c:
		return nil
	case <-l.closed:
		return &net.OpError{
			Op:  "accept",
			Net: l.Laddr.Network(),
			Err: errors.New("use of closed network connection"),
		}
	}
}

// Close closes the listener, freeing the registered port and draining the accept queue.
// Any pending connections in the queue are closed.
func (l *loopbackTCPListener) Close() error {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	select {
	case <-l.closed:
	default:
		if l.cb != nil {
			l.cb.RunBeforeClose()
		}
		l.reg.UnregListener(l)
		close(l.closed)
		// drain acceptQ to avoid leaks
		go func() {
			for {
				select {
				case c := <-l.acceptQ:
					_ = c.Close()
				default:
					return
				}
			}
		}()
	}
	return nil
}

// Addr returns the listener's network address.
func (l *loopbackTCPListener) Addr() net.Addr {
	return l.Laddr
}

// AcceptTCP accepts the next incoming connection from the queue.
// Returns an error if the listener has been closed.
func (l *loopbackTCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	l.deadlineMu.Lock()
	deadline := l.deadline
	l.deadlineMu.Unlock()

	var timer *time.Timer
	var deadlineCh <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		deadlineCh = timer.C
	}

	select {
	case c := <-l.acceptQ:
		if timer != nil {
			timer.Stop()
		}
		c.Laddr = l.Laddr
		c.Port = l.Port
		if l.cb != nil {
			var wrapped gonnect.TCPConn
			var err error
			wrapped, err = l.cb.RunOnAcceptTCP(c)
			if err != nil {
				return nil, err
			}
			return wrapped, nil
		}
		return c, nil
	case <-l.closed:
		if timer != nil {
			timer.Stop()
		}
		return nil, &net.OpError{
			Op:  "accept",
			Net: l.Laddr.Network(),
			Err: errors.New("use of closed network connection"),
		}
	case <-deadlineCh:
		return nil, &net.OpError{
			Op:  "accept",
			Net: l.Laddr.Network(),
			Err: errors.New("i/o timeout"),
		}
	}
}

// Accept accepts the next incoming connection from the queue.
// It delegates to AcceptTCP.
func (l *loopbackTCPListener) Accept() (net.Conn, error) {
	return l.AcceptTCP()
}

// SetDeadline sets the deadline associated with the listener's Accept method.
// A zero time value disables the deadline.
func (l *loopbackTCPListener) SetDeadline(t time.Time) error {
	l.deadlineMu.Lock()
	defer l.deadlineMu.Unlock()
	l.deadline = t
	return nil
}

// loopbackTCPConn is an in-memory TCP connection implemented using net.Pipe.
// It wraps a net.Conn and adds loopback-specific address and port tracking.
type loopbackTCPConn struct {
	net.Conn
	reg          *loopbackTCPRegistry
	Laddr, Raddr net.Addr
	Port         uint16

	closeOnce sync.Once

	// cb is the callback invoked on events.
	cb *gonnect.Callbacks
}

// LocalAddr returns the local address of the connection.
// If Laddr is set, it returns Laddr; otherwise it delegates to the underlying Conn.
func (ltc *loopbackTCPConn) LocalAddr() net.Addr {
	if ltc.Laddr == nil {
		return ltc.Conn.LocalAddr()
	}
	return ltc.Laddr
}

// RemoteAddr returns the remote address of the connection.
// If Raddr is set, it returns Raddr; otherwise it delegates to the underlying Conn.
func (ltc *loopbackTCPConn) RemoteAddr() net.Addr {
	if ltc.Raddr == nil {
		return ltc.Conn.RemoteAddr()
	}
	return ltc.Raddr
}

// Close closes the connection and unregisters it from the registry.
// It uses sync.Once to ensure the close operation is performed only once.
func (ltc *loopbackTCPConn) Close() error {
	var err error
	ltc.closeOnce.Do(func() {
		if ltc.cb != nil {
			ltc.cb.RunBeforeClose()
		}
		if ltc.reg != nil {
			ltc.reg.UnregConn(ltc)
		}
		err = ltc.Conn.Close()
	})
	return err
}

// Read reads data from the connection with read deadline support.
func (ltc *loopbackTCPConn) Read(b []byte) (n int, err error) {
	return ltc.Conn.Read(b)
}

// Write writes data to the connection with write deadline support.
func (ltc *loopbackTCPConn) Write(b []byte) (n int, err error) {
	return ltc.Conn.Write(b)
}

// ReadFrom copies data from the provided reader to the connection.
// It delegates to io.Copy.
func (ltc *loopbackTCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(ltc.Conn, r)
}

// WriteTo copies data from the connection to the provided writer.
// It delegates to io.Copy.
func (ltc *loopbackTCPConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, ltc.Conn)
}

// SetKeepAlive is a no-op for loopback connections.
func (ltc *loopbackTCPConn) SetKeepAlive(_ bool) error { return nil }

// SetKeepAliveConfig is a no-op for loopback connections.
func (ltc *loopbackTCPConn) SetKeepAliveConfig(
	_ net.KeepAliveConfig,
) error {
	return nil
}

// SetKeepAlivePeriod is a no-op for loopback connections.
func (ltc *loopbackTCPConn) SetKeepAlivePeriod(
	_ time.Duration,
) error {
	return nil
}

// SetLinger is a no-op for loopback connections.
func (ltc *loopbackTCPConn) SetLinger(sec int) error { return nil }

// SetNoDelay is a no-op for loopback connections.
func (ltc *loopbackTCPConn) SetNoDelay(_ bool) error { return nil }

// CloseRead closes the read side of the connection.
// It delegates to Close.
func (ltc *loopbackTCPConn) CloseRead() error {
	return ltc.Close()
}

// CloseWrite closes the write side of the connection.
// It delegates to Close.
func (ltc *loopbackTCPConn) CloseWrite() error {
	return ltc.Close()
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero time value disables the deadline.
func (ltc *loopbackTCPConn) SetReadDeadline(t time.Time) error {
	return ltc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// A zero time value disables the deadline.
func (ltc *loopbackTCPConn) SetWriteDeadline(t time.Time) error {
	return ltc.Conn.SetWriteDeadline(t)
}

// SetDeadline sets both read and write deadlines.
// A zero time value disables the deadline.
func (ltc *loopbackTCPConn) SetDeadline(t time.Time) error {
	return ltc.Conn.SetDeadline(t)
}

// PipeTCP creates a pair of connected loopbackTCPConn using net.Pipe.
// The connections communicate directly through an in-memory pipe without
// using actual network sockets. Both connections have their local and
// remote addresses set to point to each other.
// This is analogous to net.Pipe() but returns loopbackTCPConn instances.
func PipeTCP() (client, server gonnect.TCPConn) {
	serverPipe, clientPipe := net.Pipe()

	serverAddr := &helpers.NetAddr{
		Net:  "tcp",
		Addr: "pipe:server",
	}
	clientAddr := &helpers.NetAddr{
		Net:  "tcp",
		Addr: "pipe:client",
	}

	serverConn := &loopbackTCPConn{
		Conn:  serverPipe,
		Laddr: serverAddr,
		Raddr: clientAddr,
	}

	clientConn := &loopbackTCPConn{
		Conn:  clientPipe,
		Laddr: clientAddr,
		Raddr: serverAddr,
	}

	return clientConn, serverConn
}
