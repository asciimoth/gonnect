package tls

import (
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type testTCPConn struct {
	local  net.Addr
	remote net.Addr

	closeCalls        int
	setKeepAlive      bool
	setKeepAliveCfg   net.KeepAliveConfig
	setKeepAliveAfter time.Duration
	setLinger         int
	setNoDelay        bool
	closeReadCalls    int
	closeWriteCalls   int
}

type errorListener struct {
	err error
}

func (l errorListener) Accept() (net.Conn, error) { return nil, l.err }

func (l errorListener) Close() error { return nil }

func (l errorListener) Addr() net.Addr {
	return testAddr("listener")
}

type errorTCPListener struct {
	err error
}

func (l errorTCPListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l errorTCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	return nil, l.err
}

func (l errorTCPListener) Close() error { return nil }

func (l errorTCPListener) Addr() net.Addr {
	return testAddr("tcp-listener")
}

func (l errorTCPListener) SetDeadline(time.Time) error { return nil }

func (c *testTCPConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *testTCPConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *testTCPConn) Close() error {
	c.closeCalls++
	return nil
}

func (c *testTCPConn) LocalAddr() net.Addr { return c.local }

func (c *testTCPConn) RemoteAddr() net.Addr { return c.remote }

func (c *testTCPConn) SetDeadline(time.Time) error { return nil }

func (c *testTCPConn) SetReadDeadline(time.Time) error { return nil }

func (c *testTCPConn) SetWriteDeadline(time.Time) error { return nil }

func (c *testTCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(io.Discard, r)
}

func (c *testTCPConn) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte("test"))
	return int64(n), err
}

func (c *testTCPConn) SetKeepAlive(keepalive bool) error {
	c.setKeepAlive = keepalive
	return nil
}

func (c *testTCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	c.setKeepAliveCfg = config
	return nil
}

func (c *testTCPConn) SetKeepAlivePeriod(d time.Duration) error {
	c.setKeepAliveAfter = d
	return nil
}

func (c *testTCPConn) SetLinger(sec int) error {
	c.setLinger = sec
	return nil
}

func (c *testTCPConn) SetNoDelay(noDelay bool) error {
	c.setNoDelay = noDelay
	return nil
}

func (c *testTCPConn) CloseRead() error {
	c.closeReadCalls++
	return nil
}

func (c *testTCPConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

func TestTLSNetworkTCPConnDelegatesAndOverridesAddrs(t *testing.T) {
	base := &testTCPConn{
		local:  &gonnect.NetAddr{Net: "tcp", Addr: "base-local"},
		remote: &gonnect.NetAddr{Net: "tcp", Addr: "base-remote"},
	}
	upstream := &testTCPConn{}
	conn := &tcpConn{
		TCPConn:     base,
		upstream:    upstream,
		upstreamTCP: upstream,
		local:       &gonnect.NetAddr{Net: "tcp", Addr: "override-local"},
		remote:      &gonnect.NetAddr{Net: "tcp", Addr: "override-remote"},
	}

	if conn.GetWrapped() != base {
		t.Fatal("GetWrapped() returned wrong connection")
	}
	if conn.LocalAddr().String() != "override-local" {
		t.Fatalf("LocalAddr() = %v, want override-local", conn.LocalAddr())
	}
	if conn.RemoteAddr().String() != "override-remote" {
		t.Fatalf("RemoteAddr() = %v, want override-remote", conn.RemoteAddr())
	}
	if err := conn.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive() error = %v", err)
	}
	cfg := net.KeepAliveConfig{Enable: true, Idle: time.Second}
	if err := conn.SetKeepAliveConfig(cfg); err != nil {
		t.Fatalf("SetKeepAliveConfig() error = %v", err)
	}
	if err := conn.SetKeepAlivePeriod(2 * time.Second); err != nil {
		t.Fatalf("SetKeepAlivePeriod() error = %v", err)
	}
	if err := conn.SetLinger(3); err != nil {
		t.Fatalf("SetLinger() error = %v", err)
	}
	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay() error = %v", err)
	}
	if !upstream.setKeepAlive || upstream.setKeepAliveCfg != cfg ||
		upstream.setKeepAliveAfter != 2*time.Second ||
		upstream.setLinger != 3 || !upstream.setNoDelay {
		t.Fatalf("upstream delegates = %+v, want configured values", upstream)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if base.closeCalls != 1 || upstream.closeCalls != 1 {
		t.Fatalf(
			"close calls = base %d upstream %d, want 1 each",
			base.closeCalls,
			upstream.closeCalls,
		)
	}
}

func TestTLSNetworkTCPConnFallsBackToBase(t *testing.T) {
	base := &testTCPConn{
		local:  &gonnect.NetAddr{Net: "tcp", Addr: "base-local"},
		remote: &gonnect.NetAddr{Net: "tcp", Addr: "base-remote"},
	}
	conn := &tcpConn{TCPConn: base, upstream: &testTCPConn{}}

	if conn.LocalAddr().String() != "base-local" {
		t.Fatalf("LocalAddr() = %v, want base-local", conn.LocalAddr())
	}
	if conn.RemoteAddr().String() != "base-remote" {
		t.Fatalf("RemoteAddr() = %v, want base-remote", conn.RemoteAddr())
	}
	if err := conn.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive() error = %v", err)
	}
	if !base.setKeepAlive {
		t.Fatal("SetKeepAlive() did not fall back to base")
	}
}

func TestTerminatorTCPConnDelegatesAndOverridesAddrs(t *testing.T) {
	base := &testTCPConn{
		local:  &gonnect.NetAddr{Net: "tcp", Addr: "base-local"},
		remote: &gonnect.NetAddr{Net: "tcp", Addr: "base-remote"},
	}
	cancelled := false
	conn := &terminatorTCPConn{
		TCPConn: base,
		cancelBridge: func() {
			cancelled = true
		},
	}
	conn.setAddrs(
		&gonnect.NetAddr{Net: "tcp", Addr: "override-local"},
		&gonnect.NetAddr{Net: "tcp", Addr: "override-remote"},
	)

	if conn.GetWrapped() != base {
		t.Fatal("GetWrapped() returned wrong connection")
	}
	if conn.LocalAddr().String() != "override-local" {
		t.Fatalf("LocalAddr() = %v, want override-local", conn.LocalAddr())
	}
	if conn.RemoteAddr().String() != "override-remote" {
		t.Fatalf("RemoteAddr() = %v, want override-remote", conn.RemoteAddr())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !cancelled || base.closeCalls != 1 {
		t.Fatalf(
			"cancelled=%v closeCalls=%d, want true and 1",
			cancelled,
			base.closeCalls,
		)
	}
}

func TestClientServerTCPConnDelegates(t *testing.T) {
	wrapped := &testTCPConn{}
	conn := &clientServerTCPConn{wrapped: wrapped}

	if conn.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() returned wrong connection")
	}
	if err := conn.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive() error = %v", err)
	}
	cfg := net.KeepAliveConfig{Enable: true, Idle: time.Second}
	if err := conn.SetKeepAliveConfig(cfg); err != nil {
		t.Fatalf("SetKeepAliveConfig() error = %v", err)
	}
	if err := conn.SetKeepAlivePeriod(time.Second); err != nil {
		t.Fatalf("SetKeepAlivePeriod() error = %v", err)
	}
	if err := conn.SetLinger(4); err != nil {
		t.Fatalf("SetLinger() error = %v", err)
	}
	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay() error = %v", err)
	}
	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v", err)
	}
	if !wrapped.setKeepAlive || wrapped.setKeepAliveCfg != cfg ||
		wrapped.setKeepAliveAfter != time.Second ||
		wrapped.setLinger != 4 || !wrapped.setNoDelay ||
		wrapped.closeReadCalls != 1 {
		t.Fatalf("wrapped delegates = %+v, want configured values", wrapped)
	}
}

func TestClientServerTCPConnTLSIOAndCloseWrite(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer func() { _ = serverEnd.Close() }()
	_ = clientEnd.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_ = serverEnd.SetDeadline(time.Now().Add(100 * time.Millisecond))

	wrapped := &testTCPConn{}
	conn := &clientServerTCPConn{
		Conn: stdtls.Client(clientEnd, &stdtls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}),
		wrapped: wrapped,
	}

	if _, err := conn.ReadFrom(strings.NewReader("data")); err == nil {
		t.Fatal("ReadFrom() error = nil, want handshake error")
	}
	if _, err := conn.WriteTo(io.Discard); err == nil {
		t.Fatal("WriteTo() error = nil, want handshake error")
	}
	if err := conn.CloseWrite(); err == nil {
		t.Fatal("CloseWrite() error = nil, want handshake error")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestClientServerListenerWrappersPropagateAcceptErrors(t *testing.T) {
	acceptErr := errors.New("accept")
	baseListener := errorListener{err: acceptErr}
	listener := &clientServerListener{Listener: baseListener}

	if listener.GetWrapped() != baseListener {
		t.Fatal("clientServerListener GetWrapped() returned wrong listener")
	}
	if _, err := listener.Accept(); !errors.Is(err, acceptErr) {
		t.Fatalf("Accept() error = %v, want accept error", err)
	}

	baseTCPListener := errorTCPListener{err: acceptErr}
	tcpListener := &clientServerTCPListener{TCPListener: baseTCPListener}
	if tcpListener.GetWrapped() != baseTCPListener {
		t.Fatal("clientServerTCPListener GetWrapped() returned wrong listener")
	}
	if _, err := tcpListener.Accept(); !errors.Is(err, acceptErr) {
		t.Fatalf("Accept() error = %v, want accept error", err)
	}
	if _, err := tcpListener.AcceptTCP(); !errors.Is(err, acceptErr) {
		t.Fatalf("AcceptTCP() error = %v, want accept error", err)
	}
}

func TestTerminatorUnsupportedOpAddress(t *testing.T) {
	err := terminatorUnsupportedOp("dial", "tcp", "example.test:443")
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Addr.String() != "example.test:443" {
		t.Fatalf("terminatorUnsupportedOp() = %v, want address", err)
	}
	if got := netAddrOrNil("tcp", ""); got != nil {
		t.Fatalf("netAddrOrNil(empty) = %v, want nil", got)
	}
	if got := netAddrOrNil("tcp", "example.test:443"); got == nil ||
		got.String() != "example.test:443" {
		t.Fatalf("netAddrOrNil(address) = %v, want example.test:443", got)
	}
}
