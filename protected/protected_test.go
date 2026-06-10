// nolint
package protected

import (
	"errors"
	"net"
	"os/user"
	"testing"
	"time"

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
