package gonnect

import (
	"net"
	"os"
	"syscall"
)

// Type assertions to ensure all callback types implement Wrapper.
var (
	_ Wrapper = &CallbackConn{}
	_ Wrapper = &CallbackPacketConn{}
	_ Wrapper = &CallbackNetPacketConn{}
	_ Wrapper = &CallbackListener{}
	_ Wrapper = &CallbackTCPConn{}
	_ Wrapper = &CallbackTCPListener{}
	_ Wrapper = &CallbackUDPConn{}
)

// Callbacks holds callback functions invoked on various network events.
type Callbacks struct {
	// BeforeClose is called before the connection or listener is closed.
	BeforeClose func()
	// OnAccept is called when a listener accepts a new connection.
	// The callback can return a different connection or an error to reject it.
	OnAccept func(net.Conn) (net.Conn, error)
	// OnAcceptTCP is called when a TCP listener accepts a new TCP connection.
	// The callback can return a different TCP connection or an error to reject it.
	OnAcceptTCP func(TCPConn) (TCPConn, error)

	// TODO: More callbacks for more events and more types
}

func (c *Callbacks) RunBeforeClose() {
	if c == nil || c.BeforeClose == nil {
		return
	}
	c.BeforeClose()
}

func (c *Callbacks) RunOnAccept(conn net.Conn) (net.Conn, error) {
	if c == nil || c.OnAccept == nil {
		return conn, nil
	}
	return c.OnAccept(conn)
}

func (c *Callbacks) RunOnAcceptTCP(conn TCPConn) (TCPConn, error) {
	if c == nil || c.OnAcceptTCP == nil {
		return conn, nil
	}
	return c.OnAcceptTCP(conn)
}

// ConnWithCallbacks wraps a net.Conn with callbacks, using the most specific
// wrapper type based on the underlying connection type.
func ConnWithCallbacks(c net.Conn, cb *Callbacks) net.Conn {
	if tc, ok := c.(TCPConn); ok {
		return &CallbackTCPConn{
			TCPConn: tc,
			CB:      cb,
		}
	}
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			CB:          cb,
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			CB:      cb,
		}
	}
	if pc, ok := c.(PacketConn); ok {
		return &CallbackPacketConn{
			PacketConn: pc,
			CB:         cb,
		}
	}
	return &CallbackConn{
		Conn: c,
		CB:   cb,
	}
}

// NetPacketConnWithCallbacks wraps a net.PacketConn with callbacks, using the
// most specific wrapper type based on the underlying connection type.
func NetPacketConnWithCallbacks(
	c net.PacketConn,
	cb *Callbacks,
) net.PacketConn {
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			CB:          cb,
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			CB:      cb,
		}
	}
	if pc, ok := c.(PacketConn); ok {
		return &CallbackPacketConn{
			PacketConn: pc,
			CB:         cb,
		}
	}
	return &CallbackNetPacketConn{
		PacketConn: c,
		CB:         cb,
	}
}

// PacketConnWithCallbacks wraps a PacketConn with callbacks, using the most
// specific wrapper type based on the underlying connection type.
func PacketConnWithCallbacks(c PacketConn, cb *Callbacks) PacketConn {
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			CB:          cb,
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			CB:      cb,
		}
	}
	return &CallbackPacketConn{
		PacketConn: c,
		CB:         cb,
	}
}

// UDPConnWithCallbacks wraps a UDPConn with callbacks, using the most
// specific wrapper type based on the underlying connection type.
func UDPConnWithCallbacks(c UDPConn, cb *Callbacks) UDPConn {
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			CB:          cb,
		}
	}
	return &CallbackUDPConn{
		UDPConn: c,
		CB:      cb,
	}
}

// ListenerWithCallbacks wraps a net.Listener with callbacks, using the most
// specific wrapper type based on the underlying listener type.
func ListenerWithCallbacks(l net.Listener, cb *Callbacks) net.Listener {
	if tl, ok := l.(TCPListener); ok {
		return &CallbackTCPListener{
			TCPListener: tl,
			CB:          cb,
		}
	}
	return &CallbackListener{
		Listener: l,
		CB:       cb,
	}
}

// CallbackConn wraps a net.Conn and invokes callbacks on events.
type CallbackConn struct {
	net.Conn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackConn) Close() error {
	c.CB.RunBeforeClose()
	return c.Conn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackConn) GetWrapped() any {
	return c.Conn
}

// CallbackPacketConn wraps a PacketConn and invokes callbacks on events.
type CallbackPacketConn struct {
	PacketConn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackPacketConn) Close() error {
	c.CB.RunBeforeClose()
	return c.PacketConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackPacketConn) GetWrapped() any {
	return c.PacketConn
}

// CallbackNetPacketConn wraps a net.PacketConn and invokes callbacks on events.
type CallbackNetPacketConn struct {
	net.PacketConn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackNetPacketConn) Close() error {
	c.CB.RunBeforeClose()
	return c.PacketConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackNetPacketConn) GetWrapped() any {
	return c.PacketConn
}

// CallbackListener wraps a net.Listener and invokes callbacks on events.
type CallbackListener struct {
	net.Listener
	CB *Callbacks
}

// Accept accepts a connection and invokes OnAccept if the callback is set.
func (c *CallbackListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil && conn != nil {
		conn, err = c.CB.RunOnAccept(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, err
}

// Close calls the BeforeClose callback, then closes the underlying listener.
func (c *CallbackListener) Close() error {
	c.CB.RunBeforeClose()
	return c.Listener.Close()
}

// GetWrapped returns the underlying wrapped listener.
func (c *CallbackListener) GetWrapped() any {
	return c.Listener
}

// CallbackTCPConn wraps a net.TCPConn and invokes callbacks on events.
type CallbackTCPConn struct {
	TCPConn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackTCPConn) Close() error {
	c.CB.RunBeforeClose()
	return c.TCPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackTCPConn) GetWrapped() any {
	return c.TCPConn
}

// CallbackTCPListener wraps a net.TCPListener and invokes callbacks on events.
type CallbackTCPListener struct {
	TCPListener
	CB *Callbacks
}

// Accept accepts a connection and invokes OnAccept if the callback is set.
func (c *CallbackTCPListener) Accept() (net.Conn, error) {
	conn, err := c.TCPListener.Accept()
	if err == nil && conn != nil {
		conn, err = c.CB.RunOnAccept(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, err
}

// AcceptTCP accepts a TCP connection and invokes OnAcceptTCP if the callback is set.
func (c *CallbackTCPListener) AcceptTCP() (TCPConn, error) {
	conn, err := c.TCPListener.AcceptTCP()
	if err == nil && conn != nil {
		conn, err = c.CB.RunOnAcceptTCP(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, err
}

// Close calls the BeforeClose callback, then closes the underlying listener.
func (c *CallbackTCPListener) Close() error {
	c.CB.RunBeforeClose()
	return c.TCPListener.Close()
}

// GetWrapped returns the underlying wrapped listener.
func (c *CallbackTCPListener) GetWrapped() any {
	return c.TCPListener
}

// CallbackUDPConn wraps a net.UDPConn and invokes callbacks on events.
type CallbackUDPConn struct {
	UDPConn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackUDPConn) Close() error {
	c.CB.RunBeforeClose()
	return c.UDPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackUDPConn) GetWrapped() any {
	return c.UDPConn
}

type fullUDPConn interface {
	UDPConn

	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error

	// May return nil, nil
	SyscallConn() (syscall.RawConn, error)
	// May return nil, nil
	File() (f *os.File, err error)
}

type callbackFullUDPConn struct {
	fullUDPConn
	CB *Callbacks
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *callbackFullUDPConn) Close() error {
	c.CB.RunBeforeClose()
	return c.fullUDPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *callbackFullUDPConn) GetWrapped() any {
	return c.fullUDPConn
}
