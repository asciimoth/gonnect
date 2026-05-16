// nolint
package gonnect

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnWithCallbacksAddsCallbacksToExistingWrapper(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	var calls atomic.Int32
	wrapped := ConnWithCallbacks(c1, &Callbacks{
		BeforeClose: func() { calls.Add(1) },
	})
	again := ConnWithCallbacks(wrapped, &Callbacks{
		BeforeClose: func() { calls.Add(1) },
	})
	if wrapped != again {
		t.Fatal("ConnWithCallbacks wrapped an existing callback conn again")
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("BeforeClose calls = %d, want 2", got)
	}
}

func TestCallbacksCloseStopsAndDrainsCallbacks(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	var calls atomic.Int32
	wrapped := ConnWithCallbacks(c1, &Callbacks{})
	wrapped = ConnWithCallbacks(wrapped, &Callbacks{
		BeforeClose: func() {
			calls.Add(1)
			ConnWithCallbacks(wrapped, &Callbacks{
				BeforeClose: func() { calls.Add(100) },
			})
		},
	})

	done := make(chan error, 1)
	go func() { done <- wrapped.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked while a callback registered another callback")
	}

	ConnWithCallbacks(wrapped, &Callbacks{
		BeforeClose: func() { calls.Add(1000) },
	})
	_ = wrapped.Close()

	if got := calls.Load(); got != 1 {
		t.Fatalf("BeforeClose calls = %d, want 1", got)
	}
}

func TestListenerWithCallbacksRunsMultipleAcceptCallbacks(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	ln := newCallbackTestListener()
	wrapped := ListenerWithCallbacks(ln, &Callbacks{
		OnAccept: func(conn net.Conn) (net.Conn, error) {
			return &callbackTestConn{Conn: conn}, nil
		},
	})
	again := ListenerWithCallbacks(wrapped, &Callbacks{
		OnAccept: func(conn net.Conn) (net.Conn, error) {
			if _, ok := conn.(*callbackTestConn); !ok {
				t.Fatalf("second callback received %T, want *callbackTestConn", conn)
			}
			return conn, nil
		},
	})
	if wrapped != again {
		t.Fatal("ListenerWithCallbacks wrapped an existing callback listener again")
	}

	ln.accept <- c1
	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*callbackTestConn); !ok {
		t.Fatalf("Accept() conn = %T, want *callbackTestConn", conn)
	}
}

func TestListenerWithCallbacksClosesAcceptedConnAfterStop(t *testing.T) {
	ln := newCallbackTestListener()
	wrapped := ListenerWithCallbacks(ln, &Callbacks{
		OnAccept: func(conn net.Conn) (net.Conn, error) {
			return conn, nil
		},
	})
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	conn := &callbackTestConn{}
	ln.accept <- conn
	got, err := wrapped.Accept()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want net.ErrClosed", err)
	}
	if got != nil {
		t.Fatalf("Accept() conn = %v, want nil", got)
	}
	if conn.closeCount.Load() != 1 {
		t.Fatalf("accepted conn close count = %d, want 1", conn.closeCount.Load())
	}
}

func TestTCPListenerWithCallbacksClosesAcceptedTCPConnAfterStop(t *testing.T) {
	ln := newCallbackTestTCPListener()
	wrapped := ListenerWithCallbacks(ln, &Callbacks{
		OnAcceptTCP: func(conn TCPConn) (TCPConn, error) {
			return conn, nil
		},
	}).(TCPListener)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	conn := &callbackTestTCPConn{callbackTestConn: callbackTestConn{}}
	ln.accept <- conn
	got, err := wrapped.AcceptTCP()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptTCP() error = %v, want net.ErrClosed", err)
	}
	if got != nil {
		t.Fatalf("AcceptTCP() conn = %v, want nil", got)
	}
	if conn.closeCount.Load() != 1 {
		t.Fatalf("accepted TCP conn close count = %d, want 1", conn.closeCount.Load())
	}
}

func TestCallbacksConcurrentRegisterAcceptAndClose(t *testing.T) {
	ln := newCallbackTestListener()
	wrapped := ListenerWithCallbacks(ln, &Callbacks{})

	var callbacks atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				ListenerWithCallbacks(wrapped, &Callbacks{
					BeforeClose: func() { callbacks.Add(1) },
					OnAccept: func(conn net.Conn) (net.Conn, error) {
						return conn, nil
					},
				})
			}
		}()
	}

	for range 32 {
		c1, c2 := net.Pipe()
		defer c2.Close()
		ln.accept <- c1
		conn, err := wrapped.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wg.Wait()
}

type callbackTestConn struct {
	net.Conn
	closeCount atomic.Int32
}

func (c *callbackTestConn) Close() error {
	c.closeCount.Add(1)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

type callbackTestListener struct {
	accept chan net.Conn
}

func newCallbackTestListener() *callbackTestListener {
	return &callbackTestListener{accept: make(chan net.Conn, 128)}
}

func (l *callbackTestListener) Accept() (net.Conn, error) {
	return <-l.accept, nil
}

func (l *callbackTestListener) Close() error {
	return nil
}

func (l *callbackTestListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

type callbackTestTCPConn struct {
	callbackTestConn
}

func (c *callbackTestTCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.callbackTestConn.Conn, r)
}

func (c *callbackTestTCPConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, c.callbackTestConn.Conn)
}

func (c *callbackTestTCPConn) SetKeepAlive(bool) error {
	return nil
}

func (c *callbackTestTCPConn) SetKeepAliveConfig(net.KeepAliveConfig) error {
	return nil
}

func (c *callbackTestTCPConn) SetKeepAlivePeriod(time.Duration) error {
	return nil
}

func (c *callbackTestTCPConn) SetLinger(int) error {
	return nil
}

func (c *callbackTestTCPConn) SetNoDelay(bool) error {
	return nil
}

func (c *callbackTestTCPConn) CloseRead() error {
	return c.Close()
}

func (c *callbackTestTCPConn) CloseWrite() error {
	return c.Close()
}

type callbackTestTCPListener struct {
	accept chan TCPConn
}

func newCallbackTestTCPListener() *callbackTestTCPListener {
	return &callbackTestTCPListener{accept: make(chan TCPConn, 128)}
}

func (l *callbackTestTCPListener) Accept() (net.Conn, error) {
	return l.AcceptTCP()
}

func (l *callbackTestTCPListener) AcceptTCP() (TCPConn, error) {
	return <-l.accept, nil
}

func (l *callbackTestTCPListener) Close() error {
	return nil
}

func (l *callbackTestTCPListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (l *callbackTestTCPListener) SetDeadline(time.Time) error {
	return nil
}
