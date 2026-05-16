package gonnect

import (
	"net"
	"os"
	"sync"
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

type callbackSet struct {
	mu          sync.Mutex
	stopped     bool
	beforeClose []func()
	onAccept    []func(net.Conn) (net.Conn, error)
	onAcceptTCP []func(TCPConn) (TCPConn, error)
}

func newCallbackSet(cb *Callbacks) *callbackSet {
	cbs := &callbackSet{}
	cbs.add(cb)
	return cbs
}

func (c *callbackSet) add(cb *Callbacks) {
	if c == nil || cb == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	if cb.BeforeClose != nil {
		c.beforeClose = append(c.beforeClose, cb.BeforeClose)
	}
	if cb.OnAccept != nil {
		c.onAccept = append(c.onAccept, cb.OnAccept)
	}
	if cb.OnAcceptTCP != nil {
		c.onAcceptTCP = append(c.onAcceptTCP, cb.OnAcceptTCP)
	}
}

func (c *callbackSet) runBeforeClose() {
	if c == nil {
		return
	}
	c.mu.Lock()
	callbacks := c.beforeClose
	c.beforeClose = nil
	c.onAccept = nil
	c.onAcceptTCP = nil
	c.stopped = true
	c.mu.Unlock()

	for _, cb := range callbacks {
		cb()
	}
}

func (c *callbackSet) runOnAccept(conn net.Conn) (net.Conn, error) {
	if c == nil {
		return conn, nil
	}
	c.mu.Lock()
	stopped := c.stopped
	callbacks := append([]func(net.Conn) (net.Conn, error)(nil), c.onAccept...)
	c.mu.Unlock()
	if stopped {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, net.ErrClosed
	}
	var err error
	for _, cb := range callbacks {
		conn, err = cb(conn)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
	}
	return conn, nil
}

func (c *callbackSet) runOnAcceptTCP(conn TCPConn) (TCPConn, error) {
	if c == nil {
		return conn, nil
	}
	c.mu.Lock()
	stopped := c.stopped
	callbacks := append([]func(TCPConn) (TCPConn, error)(nil), c.onAcceptTCP...)
	c.mu.Unlock()
	if stopped {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, net.ErrClosed
	}
	var err error
	for _, cb := range callbacks {
		conn, err = cb(conn)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
	}
	return conn, nil
}

type callbackWrapper interface {
	callbacks() *callbackSet
}

// ConnWithCallbacks wraps a net.Conn with callbacks, using the most specific
// wrapper type based on the underlying connection type.
func ConnWithCallbacks(c net.Conn, cb *Callbacks) net.Conn {
	if cc, ok := c.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return c
	}
	if tc, ok := c.(TCPConn); ok {
		return &CallbackTCPConn{
			TCPConn: tc,
			cb:      newCallbackSet(cb),
		}
	}
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			cb:          newCallbackSet(cb),
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			cb:      newCallbackSet(cb),
		}
	}
	if pc, ok := c.(PacketConn); ok {
		return &CallbackPacketConn{
			PacketConn: pc,
			cb:         newCallbackSet(cb),
		}
	}
	return &CallbackConn{
		Conn: c,
		cb:   newCallbackSet(cb),
	}
}

// TCPConnWithCallbacks wraps a TCPConn with callbacks.
func TCPConnWithCallbacks(c TCPConn, cb *Callbacks) TCPConn {
	if cc, ok := c.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return c
	}
	return &CallbackTCPConn{
		TCPConn: c,
		cb:      newCallbackSet(cb),
	}
}

// NetPacketConnWithCallbacks wraps a net.PacketConn with callbacks, using the
// most specific wrapper type based on the underlying connection type.
func NetPacketConnWithCallbacks(
	c net.PacketConn,
	cb *Callbacks,
) net.PacketConn {
	if cc, ok := c.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return c
	}
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			cb:          newCallbackSet(cb),
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			cb:      newCallbackSet(cb),
		}
	}
	if pc, ok := c.(PacketConn); ok {
		return &CallbackPacketConn{
			PacketConn: pc,
			cb:         newCallbackSet(cb),
		}
	}
	return &CallbackNetPacketConn{
		PacketConn: c,
		cb:         newCallbackSet(cb),
	}
}

// PacketConnWithCallbacks wraps a PacketConn with callbacks, using the most
// specific wrapper type based on the underlying connection type.
func PacketConnWithCallbacks(c PacketConn, cb *Callbacks) PacketConn {
	if cc, ok := c.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return c
	}
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			cb:          newCallbackSet(cb),
		}
	}
	if uc, ok := c.(UDPConn); ok {
		return &CallbackUDPConn{
			UDPConn: uc,
			cb:      newCallbackSet(cb),
		}
	}
	return &CallbackPacketConn{
		PacketConn: c,
		cb:         newCallbackSet(cb),
	}
}

// UDPConnWithCallbacks wraps a UDPConn with callbacks, using the most
// specific wrapper type based on the underlying connection type.
func UDPConnWithCallbacks(c UDPConn, cb *Callbacks) UDPConn {
	if cc, ok := c.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return c
	}
	if uc, ok := c.(fullUDPConn); ok {
		return &callbackFullUDPConn{
			fullUDPConn: uc,
			cb:          newCallbackSet(cb),
		}
	}
	return &CallbackUDPConn{
		UDPConn: c,
		cb:      newCallbackSet(cb),
	}
}

// ListenerWithCallbacks wraps a net.Listener with callbacks, using the most
// specific wrapper type based on the underlying listener type.
func ListenerWithCallbacks(l net.Listener, cb *Callbacks) net.Listener {
	if cc, ok := l.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return l
	}
	if tl, ok := l.(TCPListener); ok {
		return &CallbackTCPListener{
			TCPListener: tl,
			cb:          newCallbackSet(cb),
		}
	}
	return &CallbackListener{
		Listener: l,
		cb:       newCallbackSet(cb),
	}
}

// TCPListenerWithCallbacks wraps a TCPListener with callbacks.
func TCPListenerWithCallbacks(l TCPListener, cb *Callbacks) TCPListener {
	if cc, ok := l.(callbackWrapper); ok {
		cc.callbacks().add(cb)
		return l
	}
	return &CallbackTCPListener{
		TCPListener: l,
		cb:          newCallbackSet(cb),
	}
}

// CallbackConn wraps a net.Conn and invokes callbacks on events.
type CallbackConn struct {
	net.Conn
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackConn) Close() error {
	c.cb.runBeforeClose()
	return c.Conn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackConn) GetWrapped() any {
	return c.Conn
}

func (c *CallbackConn) callbacks() *callbackSet {
	return c.cb
}

// CallbackPacketConn wraps a PacketConn and invokes callbacks on events.
type CallbackPacketConn struct {
	PacketConn
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackPacketConn) Close() error {
	c.cb.runBeforeClose()
	return c.PacketConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackPacketConn) GetWrapped() any {
	return c.PacketConn
}

func (c *CallbackPacketConn) callbacks() *callbackSet {
	return c.cb
}

// CallbackNetPacketConn wraps a net.PacketConn and invokes callbacks on events.
type CallbackNetPacketConn struct {
	net.PacketConn
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackNetPacketConn) Close() error {
	c.cb.runBeforeClose()
	return c.PacketConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackNetPacketConn) GetWrapped() any {
	return c.PacketConn
}

func (c *CallbackNetPacketConn) callbacks() *callbackSet {
	return c.cb
}

// CallbackListener wraps a net.Listener and invokes callbacks on events.
type CallbackListener struct {
	net.Listener
	cb *callbackSet
}

// Accept accepts a connection and invokes OnAccept if the callback is set.
func (c *CallbackListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil && conn != nil {
		conn, err = c.cb.runOnAccept(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, err
}

// Close calls the BeforeClose callback, then closes the underlying listener.
func (c *CallbackListener) Close() error {
	c.cb.runBeforeClose()
	return c.Listener.Close()
}

// GetWrapped returns the underlying wrapped listener.
func (c *CallbackListener) GetWrapped() any {
	return c.Listener
}

func (c *CallbackListener) callbacks() *callbackSet {
	return c.cb
}

// CallbackTCPConn wraps a net.TCPConn and invokes callbacks on events.
type CallbackTCPConn struct {
	TCPConn
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackTCPConn) Close() error {
	c.cb.runBeforeClose()
	return c.TCPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackTCPConn) GetWrapped() any {
	return c.TCPConn
}

func (c *CallbackTCPConn) callbacks() *callbackSet {
	return c.cb
}

// CallbackTCPListener wraps a net.TCPListener and invokes callbacks on events.
type CallbackTCPListener struct {
	TCPListener
	cb *callbackSet
}

// Accept accepts a connection and invokes OnAccept if the callback is set.
func (c *CallbackTCPListener) Accept() (net.Conn, error) {
	conn, err := c.TCPListener.Accept()
	if err == nil && conn != nil {
		conn, err = c.cb.runOnAccept(conn)
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
		conn, err = c.cb.runOnAcceptTCP(conn)
		if err != nil {
			return nil, err
		}
	}
	return conn, err
}

// Close calls the BeforeClose callback, then closes the underlying listener.
func (c *CallbackTCPListener) Close() error {
	c.cb.runBeforeClose()
	return c.TCPListener.Close()
}

// GetWrapped returns the underlying wrapped listener.
func (c *CallbackTCPListener) GetWrapped() any {
	return c.TCPListener
}

func (c *CallbackTCPListener) callbacks() *callbackSet {
	return c.cb
}

// CallbackUDPConn wraps a net.UDPConn and invokes callbacks on events.
type CallbackUDPConn struct {
	UDPConn
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *CallbackUDPConn) Close() error {
	c.cb.runBeforeClose()
	return c.UDPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *CallbackUDPConn) GetWrapped() any {
	return c.UDPConn
}

func (c *CallbackUDPConn) callbacks() *callbackSet {
	return c.cb
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
	cb *callbackSet
}

// Close calls the BeforeClose callback, then closes the underlying connection.
func (c *callbackFullUDPConn) Close() error {
	c.cb.runBeforeClose()
	return c.fullUDPConn.Close()
}

// GetWrapped returns the underlying wrapped connection.
func (c *callbackFullUDPConn) GetWrapped() any {
	return c.fullUDPConn
}

func (c *callbackFullUDPConn) callbacks() *callbackSet {
	return c.cb
}
