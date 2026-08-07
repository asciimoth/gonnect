package putback

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
)

// Conn wraps a net.Conn and allows bytes to be prepended to its unread input.
//
// Conn is not safe for concurrent read-side operations. Do not call Read,
// PutBack, or Buffered concurrently with each other. Like a normal net.Conn,
// Conn can still be used concurrently by one goroutine that reads and one
// goroutine that writes, subject to the underlying connection's guarantees. For
// TCPConn, WriteTo is also a read-side operation.
type Conn interface {
	net.Conn

	// PutBack copies p and prepends it to the unread byte stream.
	//
	// Bytes within p retain their order. If PutBack is called more than once,
	// bytes from the most recent call are read first. For example, putting back
	// "one" and then "two" causes subsequent reads to produce "twoone" before any
	// bytes obtained from the underlying connection.
	//
	// PutBack with an empty slice has no effect.
	//
	// PutBack is not safe for concurrent use with Read, Buffered, or another
	// PutBack call.
	PutBack(p []byte)

	// Buffered reports the number of bytes currently waiting in the put-back
	// buffer. It does not include bytes waiting in the operating system or a
	// deferred read error.
	//
	// Buffered is not safe for concurrent use with Read or PutBack.
	Buffered() int

	GetWrapped() any
}

// TCPConn wraps a gonnect.TCPConn and allows bytes to be prepended to its
// unread input.
type TCPConn interface {
	Conn
	gonnect.TCPConn
}

// conn implements Conn.
//
// Use New to construct a Conn. The zero value is not usable.
type conn struct {
	conn net.Conn
	pool bufpool.Pool

	extraBuf []byte
	extra    []byte

	// deferredErr holds an error returned together with bytes by the
	// underlying connection. Read returns those bytes first and reports this
	// error on the next read after all put-back bytes have been drained.
	deferredErr error
}

var _ Conn = (*conn)(nil)
var _ TCPConn = (*tcpConn)(nil)
var _ netTCPConn = (*tcpNetConn)(nil)

// New wraps nc and uses pool to allocate copied put-back buffers. If pool is
// nil, each put-back copy is allocated with make. Pooled buffers are returned
// when buffered bytes are drained, replaced by a later PutBack, written by
// TCPConn.WriteTo, or discarded by Close.
//
// If nc implements gonnect.TCPConn, the returned value also implements TCPConn
// and gonnect.TCPConn.
//
// New returns nil if nc is nil.
func New(nc net.Conn, pool bufpool.Pool) Conn {
	if nc == nil {
		return nil
	}
	if tc, ok := nc.(rawNetTCPConn); ok {
		return &tcpNetConn{
			tcpConn: newTCPConn(tc, pool),
			tcp:     tc,
		}
	}
	if tc, ok := nc.(gonnect.TCPConn); ok {
		return newTCPConn(tc, pool)
	}
	return &conn{conn: nc, pool: pool}
}

func newTCPConn(tc gonnect.TCPConn, pool bufpool.Pool) *tcpConn {
	return &tcpConn{
		conn: &conn{conn: tc, pool: pool},
		tcp:  tc,
	}
}

func (c *conn) PutBack(p []byte) {
	if len(p) == 0 {
		return
	}

	if len(c.extra) == 0 {
		c.setExtra(c.copyExtra(p))
		return
	}

	combinedLen := len(p) + len(c.extra)
	combined := bufpool.GetBuffer(c.pool, combinedLen)
	copy(combined, p)
	copy(combined[len(p):combinedLen], c.extra)
	c.releaseExtra()
	c.setExtra(combined[:combinedLen])
}

func (c *conn) Buffered() int {
	return len(c.extra)
}

func (c *conn) copyExtra(p []byte) []byte {
	buf := bufpool.GetBuffer(c.pool, len(p))
	copy(buf, p)
	return buf[:len(p)]
}

func (c *conn) setExtra(buf []byte) {
	c.extraBuf = buf
	c.extra = buf
}

func (c *conn) releaseExtra() {
	if c.extraBuf == nil {
		c.extra = nil
		return
	}
	buf := c.extraBuf
	c.extraBuf = nil
	c.extra = nil
	bufpool.PutBuffer(c.pool, buf)
}

// Read reads from the put-back buffer first. If buffered bytes are available,
// Read returns them immediately and does not also read from the underlying
// connection in the same call. Once the buffer is empty, Read delegates to the
// underlying connection.
//
// If the underlying connection returns n > 0 together with a non-nil error, Read
// returns the bytes with a nil error and defers the error until the next Read
// after all put-back bytes have been consumed.
//
// Read is not safe for concurrent use with another Read, PutBack, or Buffered.
func (c *conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(c.extra) != 0 {
		n := copy(p, c.extra)
		if n == len(c.extra) {
			c.releaseExtra()
		} else {
			c.extra = c.extra[n:]
		}
		return n, nil
	}

	if c.deferredErr != nil {
		err := c.deferredErr
		c.deferredErr = nil
		return 0, err
	}

	n, err := c.conn.Read(p)
	if n > 0 && err != nil {
		c.deferredErr = err
		err = nil
	}
	return n, err
}

// Write delegates to the underlying connection.
func (c *conn) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

// Close returns any pooled put-back buffer and delegates to the underlying
// connection.
func (c *conn) Close() error {
	c.releaseExtra()
	return c.conn.Close()
}

// LocalAddr delegates to the underlying connection.
func (c *conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr delegates to the underlying connection.
func (c *conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline delegates to the underlying connection.
func (c *conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline delegates to the underlying connection.
func (c *conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline delegates to the underlying connection.
func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *conn) GetWrapped() any {
	return c.conn
}

func (c *conn) writeBufferedTo(
	w io.Writer,
) (written int64, done bool, err error) {
	for len(c.extra) != 0 {
		n, err := w.Write(c.extra)
		if n < 0 || n > len(c.extra) {
			return written, true, io.ErrShortWrite
		}
		if n > 0 {
			c.extra = c.extra[n:]
			written += int64(n)
			if len(c.extra) == 0 {
				c.releaseExtra()
			}
		}
		if err != nil {
			return written, true, err
		}
		if n == 0 {
			return written, true, io.ErrShortWrite
		}
	}

	if c.deferredErr != nil {
		err := c.deferredErr
		c.deferredErr = nil
		if errors.Is(err, io.EOF) {
			return written, true, nil
		}
		return written, true, err
	}
	return written, false, nil
}

type tcpConn struct {
	*conn
	tcp gonnect.TCPConn
}

// ReadFrom delegates to the underlying TCP connection.
func (c *tcpConn) ReadFrom(r io.Reader) (int64, error) {
	return c.tcp.ReadFrom(r)
}

// WriteTo writes buffered bytes first, then reads from the underlying
// connection through the underlying TCP WriteTo method.
func (c *tcpConn) WriteTo(w io.Writer) (int64, error) {
	n, done, err := c.writeBufferedTo(w)
	if err != nil || done {
		return n, err
	}
	m, err := c.tcp.WriteTo(w)
	return n + m, err
}

// SetKeepAlive delegates to the underlying TCP connection.
func (c *tcpConn) SetKeepAlive(keepalive bool) error {
	return c.tcp.SetKeepAlive(keepalive)
}

// SetKeepAliveConfig delegates to the underlying TCP connection.
func (c *tcpConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	return c.tcp.SetKeepAliveConfig(config)
}

// SetKeepAlivePeriod delegates to the underlying TCP connection.
func (c *tcpConn) SetKeepAlivePeriod(d time.Duration) error {
	return c.tcp.SetKeepAlivePeriod(d)
}

// SetLinger delegates to the underlying TCP connection.
func (c *tcpConn) SetLinger(sec int) error {
	return c.tcp.SetLinger(sec)
}

// SetNoDelay delegates to the underlying TCP connection.
func (c *tcpConn) SetNoDelay(noDelay bool) error {
	return c.tcp.SetNoDelay(noDelay)
}

// CloseRead delegates to the underlying TCP connection.
func (c *tcpConn) CloseRead() error {
	return c.tcp.CloseRead()
}

// CloseWrite delegates to the underlying TCP connection.
func (c *tcpConn) CloseWrite() error {
	return c.tcp.CloseWrite()
}

type tcpNetConnMethods interface {
	MultipathTCP() (bool, error)
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	SyscallConn() (syscall.RawConn, error)
	File() (*os.File, error)
}

type rawNetTCPConn interface {
	gonnect.TCPConn
	tcpNetConnMethods
}

type netTCPConn interface {
	TCPConn
	tcpNetConnMethods
}

type tcpNetConn struct {
	*tcpConn
	tcp rawNetTCPConn
}

// MultipathTCP delegates to the underlying TCP connection.
func (c *tcpNetConn) MultipathTCP() (bool, error) {
	return c.tcp.MultipathTCP()
}

// SetReadBuffer delegates to the underlying TCP connection.
func (c *tcpNetConn) SetReadBuffer(bytes int) error {
	return c.tcp.SetReadBuffer(bytes)
}

// SetWriteBuffer delegates to the underlying TCP connection.
func (c *tcpNetConn) SetWriteBuffer(bytes int) error {
	return c.tcp.SetWriteBuffer(bytes)
}

// SyscallConn delegates to the underlying TCP connection.
func (c *tcpNetConn) SyscallConn() (syscall.RawConn, error) {
	return c.tcp.SyscallConn()
}

// File delegates to the underlying TCP connection.
func (c *tcpNetConn) File() (*os.File, error) {
	return c.tcp.File()
}
