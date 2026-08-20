// nolint
package protected

import (
	"errors"
	"io"
	"net"
	"os/user"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sockowner"
)

func TestAllowOwnerMatchesUIDGIDAndUsername(t *testing.T) {
	oldLookupUser := lookupUser
	defer func() { lookupUser = oldLookupUser }()

	lookupUser = func(username string) (*user.User, error) {
		if username != "alice" {
			return nil, errors.New("not found")
		}
		return &user.User{Username: username, Uid: "1001"}, nil
	}

	c, err := newChecker(Rules{
		UIDs:      []uint32{1000},
		GIDs:      []uint32{100},
		Usernames: []string{"alice"},
	})
	if err != nil {
		t.Fatalf("newChecker() error = %v", err)
	}

	uid := uint32(1000)
	if !c.allowOwner(&sockowner.SocketOwner{UID: &uid}) {
		t.Fatal("UID rule did not match")
	}

	gid := uint32(100)
	if !c.allowOwner(&sockowner.SocketOwner{GID: &gid}) {
		t.Fatal("GID rule did not match")
	}

	uid = 1001
	if !c.allowOwner(&sockowner.SocketOwner{UID: &uid}) {
		t.Fatal("username rule did not match")
	}
}

func TestUsernameRuleRequiresStableUID(t *testing.T) {
	oldLookupUser := lookupUser
	defer func() { lookupUser = oldLookupUser }()

	uid := "1001"
	lookupUser = func(username string) (*user.User, error) {
		return &user.User{Username: username, Uid: uid}, nil
	}

	c, err := newChecker(Rules{Usernames: []string{"alice"}})
	if err != nil {
		t.Fatalf("newChecker() error = %v", err)
	}

	uid = "1002"
	ownerUID := uint32(1002)
	if c.allowOwner(&sockowner.SocketOwner{UID: &ownerUID}) {
		t.Fatal("username rule matched after UID changed")
	}
}

func TestListenerRejectsUntilAllowed(t *testing.T) {
	oldOwner := getIncomingConnOwner
	defer func() { getIncomingConnOwner = oldOwner }()

	rejected := newFakeConn()
	accepted := newFakeConn()

	allowedUID := uint32(42)
	getIncomingConnOwner = func(conn net.Conn) (*sockowner.SocketOwner, error) {
		if conn == accepted {
			return &sockowner.SocketOwner{UID: &allowedUID}, nil
		}
		otherUID := uint32(7)
		return &sockowner.SocketOwner{UID: &otherUID}, nil
	}

	base := &fakeListener{
		conns: make(chan net.Conn, 2),
	}
	base.conns <- rejected
	base.conns <- accepted

	wrapped, err := NewListener(base, Rules{UIDs: []uint32{allowedUID}})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if conn != accepted {
		t.Fatalf("Accept() conn = %p, want %p", conn, accepted)
	}
	if !rejected.closed {
		t.Fatal("rejected connection was not closed")
	}
	if accepted.closed {
		t.Fatal("accepted connection was closed")
	}
	if wrapped.(*Listener).GetWrapped() != base {
		t.Fatal("GetWrapped() did not return base listener")
	}
}

func TestNewListenerRejectsNilAndWrapsTCPListener(t *testing.T) {
	if _, err := NewListener(nil, Rules{}); !errors.Is(err, errNilListener) {
		t.Fatalf("NewListener(nil) error = %v, want errNilListener", err)
	}

	base := &fakeTCPListener{fakeListener: fakeListener{
		conns: make(chan net.Conn, 1),
	}}
	wrapped, err := NewListener(base, Rules{})
	if err != nil {
		t.Fatalf("NewListener(TCPListener) error = %v", err)
	}
	if _, ok := wrapped.(*TCPListener); !ok {
		t.Fatalf(
			"NewListener(TCPListener) type = %T, want *TCPListener",
			wrapped,
		)
	}
	if wrapped.(*TCPListener).GetWrapped() != base {
		t.Fatal("GetWrapped() did not return base TCP listener")
	}
}

func TestNewCheckerUsernameErrors(t *testing.T) {
	oldLookupUser := lookupUser
	defer func() { lookupUser = oldLookupUser }()

	lookupUser = func(username string) (*user.User, error) {
		return nil, errors.New("lookup failed")
	}
	if _, err := newChecker(Rules{Usernames: []string{"missing"}}); err == nil {
		t.Fatal("newChecker() error = nil, want lookup error")
	}

	lookupUser = func(username string) (*user.User, error) {
		return &user.User{Username: username, Uid: "not-a-number"}, nil
	}
	if _, err := newChecker(Rules{Usernames: []string{"bad"}}); err == nil {
		t.Fatal("newChecker() error = nil, want parse error")
	}
}

func TestNewTCPListenerUsernameError(t *testing.T) {
	oldLookupUser := lookupUser
	defer func() { lookupUser = oldLookupUser }()

	lookupUser = func(username string) (*user.User, error) {
		return nil, errors.New("lookup failed")
	}

	base := &fakeTCPListener{tcpConns: make(chan gonnect.TCPConn)}
	if _, err := NewTCPListener(base, Rules{
		Usernames: []string{"missing"},
	}); err == nil {
		t.Fatal("NewTCPListener() error = nil, want lookup error")
	}
}

func TestAllowRejectsNilOwnerAndLookupError(t *testing.T) {
	oldOwner := getIncomingConnOwner
	defer func() { getIncomingConnOwner = oldOwner }()

	c, err := newChecker(Rules{UIDs: []uint32{1}})
	if err != nil {
		t.Fatalf("newChecker() error = %v", err)
	}
	if c.allowOwner(nil) {
		t.Fatal("allowOwner(nil) = true, want false")
	}

	getIncomingConnOwner = func(net.Conn) (*sockowner.SocketOwner, error) {
		return nil, errors.New("lookup failed")
	}
	if c.allow(newFakeConn()) {
		t.Fatal("allow() = true for lookup error")
	}

	getIncomingConnOwner = func(net.Conn) (*sockowner.SocketOwner, error) {
		return nil, nil
	}
	if c.allow(newFakeConn()) {
		t.Fatal("allow() = true for nil owner")
	}
}

func TestListenerSkipsNilConnThenReturnsAcceptError(t *testing.T) {
	base := &fakeListener{conns: make(chan net.Conn, 1)}
	base.conns <- nil
	close(base.conns)

	wrapped, err := NewListener(base, Rules{})
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	if _, err := wrapped.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want net.ErrClosed", err)
	}
}

func TestTCPListenerRejectsUntilAllowed(t *testing.T) {
	oldOwner := getIncomingConnOwner
	defer func() { getIncomingConnOwner = oldOwner }()

	rejected := &fakeTCPConn{}
	accepted := &fakeTCPConn{}

	allowedUID := uint32(42)
	getIncomingConnOwner = func(conn net.Conn) (*sockowner.SocketOwner, error) {
		if conn == accepted {
			return &sockowner.SocketOwner{UID: &allowedUID}, nil
		}
		otherUID := uint32(7)
		return &sockowner.SocketOwner{UID: &otherUID}, nil
	}

	base := &fakeTCPListener{tcpConns: make(chan gonnect.TCPConn, 2)}
	base.tcpConns <- rejected
	base.tcpConns <- accepted

	wrapped, err := NewTCPListener(base, Rules{UIDs: []uint32{allowedUID}})
	if err != nil {
		t.Fatalf("NewTCPListener() error = %v", err)
	}

	conn, err := wrapped.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP() error = %v", err)
	}
	if conn != accepted {
		t.Fatalf("AcceptTCP() conn = %p, want %p", conn, accepted)
	}
	if !rejected.closed {
		t.Fatal("rejected TCP connection was not closed")
	}
	if accepted.closed {
		t.Fatal("accepted TCP connection was closed")
	}

	deadline := time.Unix(1, 0)
	if err := wrapped.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if !base.deadline.Equal(deadline) {
		t.Fatalf("base deadline = %v, want %v", base.deadline, deadline)
	}

	next := &fakeTCPConn{}
	base.tcpConns <- next
	getIncomingConnOwner = func(conn net.Conn) (*sockowner.SocketOwner, error) {
		if conn != next {
			t.Fatalf("owner lookup conn = %p, want %p", conn, next)
		}
		return &sockowner.SocketOwner{UID: &allowedUID}, nil
	}
	netConn, err := wrapped.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if netConn != next {
		t.Fatalf("Accept() conn = %p, want %p", netConn, next)
	}
}

func TestTCPListenerSkipsNilConnThenReturnsAcceptError(t *testing.T) {
	base := &fakeTCPListener{tcpConns: make(chan gonnect.TCPConn, 1)}
	base.tcpConns <- nil
	close(base.tcpConns)

	wrapped, err := NewTCPListener(base, Rules{})
	if err != nil {
		t.Fatalf("NewTCPListener() error = %v", err)
	}
	if _, err := wrapped.AcceptTCP(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptTCP() error = %v, want net.ErrClosed", err)
	}
}

func TestTCPListenerNil(t *testing.T) {
	if _, err := NewTCPListener(nil, Rules{}); !errors.Is(err, errNilListener) {
		t.Fatalf("NewTCPListener(nil) error = %v, want errNilListener", err)
	}
}

func TestListenHelpers(t *testing.T) {
	listener, err := Listen("tcp", "127.0.0.1:0", Rules{})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("listener Close() error = %v", err)
	}

	listener, err = ListenCtx(
		t.Context(),
		"tcp",
		"127.0.0.1:0",
		Rules{},
	)
	if err != nil {
		t.Fatalf("ListenCtx() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("ctx listener Close() error = %v", err)
	}

	if _, err := Listen("bad-network", "127.0.0.1:0", Rules{}); err == nil {
		t.Fatal("Listen(bad-network) error = nil")
	}
	if _, err := ListenCtx(
		t.Context(),
		"bad-network",
		"127.0.0.1:0",
		Rules{},
	); err == nil {
		t.Fatal("ListenCtx(bad-network) error = nil")
	}
}

func TestListenHelpersCloseBaseOnWrapError(t *testing.T) {
	oldLookupUser := lookupUser
	defer func() { lookupUser = oldLookupUser }()

	lookupUser = func(username string) (*user.User, error) {
		return nil, errors.New("lookup failed")
	}

	if _, err := Listen("tcp", "127.0.0.1:0", Rules{
		Usernames: []string{"missing"},
	}); err == nil {
		t.Fatal("Listen() with username lookup failure error = nil")
	}
	if _, err := ListenCtx(t.Context(), "tcp", "127.0.0.1:0", Rules{
		Usernames: []string{"missing"},
	}); err == nil {
		t.Fatal("ListenCtx() with username lookup failure error = nil")
	}
}

type fakeListener struct {
	conns chan net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	conn, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *fakeListener) Close() error {
	close(l.conns)
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	return fakeAddr("listener")
}

type fakeConn struct {
	closed bool
}

func newFakeConn() *fakeConn { return &fakeConn{} }

func (c *fakeConn) Read(
	[]byte,
) (int, error) {
	return 0, errors.New("unused")
}

func (c *fakeConn) Write(
	[]byte,
) (int, error) {
	return 0, errors.New("unused")
}

func (c *fakeConn) Close() error { c.closed = true; return nil }

func (c *fakeConn) LocalAddr() net.Addr { return fakeAddr("local") }

func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

type fakeTCPListener struct {
	fakeListener
	tcpConns chan gonnect.TCPConn
	deadline time.Time
}

func (l *fakeTCPListener) AcceptTCP() (gonnect.TCPConn, error) {
	conn, ok := <-l.tcpConns
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *fakeTCPListener) SetDeadline(t time.Time) error {
	l.deadline = t
	return nil
}

type fakeTCPConn struct {
	fakeConn
}

func (*fakeTCPConn) ReadFrom(io.Reader) (int64, error) {
	return 0, errors.New("unused")
}

func (*fakeTCPConn) WriteTo(io.Writer) (int64, error) {
	return 0, errors.New("unused")
}

func (*fakeTCPConn) SetKeepAlive(bool) error { return nil }

func (*fakeTCPConn) SetKeepAliveConfig(net.KeepAliveConfig) error { return nil }

func (*fakeTCPConn) SetKeepAlivePeriod(time.Duration) error { return nil }

func (*fakeTCPConn) SetLinger(int) error { return nil }

func (*fakeTCPConn) SetNoDelay(bool) error { return nil }

func (*fakeTCPConn) CloseRead() error { return nil }

func (*fakeTCPConn) CloseWrite() error { return nil }
