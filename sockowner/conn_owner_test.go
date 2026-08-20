package sockowner_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestGetIncomingConnOwnerUsesWrappedConn(t *testing.T) {
	conn := connOwnerTestWrapper{
		wrapped: connOwnerTestConn{
			local:  &net.TCPAddr{IP: nil, Port: 443},
			remote: &net.TCPAddr{IP: nil, Port: 12345},
		},
	}

	_, err := sockowner.GetIncomingConnOwner(conn)
	if !errors.Is(err, sockowner.ErrInvIP) {
		t.Fatalf(
			"GetIncomingConnOwner() error = %v, want %v",
			err,
			sockowner.ErrInvIP,
		)
	}
}

type connOwnerTestWrapper struct {
	wrapped net.Conn
}

func (c connOwnerTestWrapper) GetWrapped() any { return c.wrapped }

func (c connOwnerTestWrapper) Read(
	[]byte,
) (int, error) {
	return 0, net.ErrClosed
}

func (c connOwnerTestWrapper) Write(
	[]byte,
) (int, error) {
	return 0, net.ErrClosed
}

func (c connOwnerTestWrapper) Close() error { return nil }

func (c connOwnerTestWrapper) LocalAddr() net.Addr { return nil }

func (c connOwnerTestWrapper) RemoteAddr() net.Addr { return nil }

func (c connOwnerTestWrapper) SetDeadline(time.Time) error { return nil }

func (c connOwnerTestWrapper) SetReadDeadline(time.Time) error { return nil }

func (c connOwnerTestWrapper) SetWriteDeadline(time.Time) error { return nil }

type connOwnerTestConn struct {
	local  net.Addr
	remote net.Addr
}

func (c connOwnerTestConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c connOwnerTestConn) Write(
	[]byte,
) (int, error) {
	return 0, net.ErrClosed
}

func (c connOwnerTestConn) Close() error { return nil }

func (c connOwnerTestConn) LocalAddr() net.Addr { return c.local }

func (c connOwnerTestConn) RemoteAddr() net.Addr { return c.remote }

func (c connOwnerTestConn) SetDeadline(time.Time) error { return nil }

func (c connOwnerTestConn) SetReadDeadline(time.Time) error { return nil }

func (c connOwnerTestConn) SetWriteDeadline(time.Time) error { return nil }
