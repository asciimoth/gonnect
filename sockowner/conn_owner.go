package sockowner

import (
	"net"

	"github.com/asciimoth/gonnect"
)

// GetIncomingConnOwner returns the best-effort owner of the peer side of an
// incoming connection accepted by a local listener.
//
// This function is intentionally opportunistic:
//
//   - For Unix-domain sockets, platform backends may use direct peer credential
//     APIs such as Linux SO_PEERCRED. This is the most reliable case.
//   - For TCP, this function reverses conn.LocalAddr()/conn.RemoteAddr() and
//     asks GetSockOwner for the owner of the client-side socket.
//   - For UDP, this does the same when conn exposes *net.UDPAddr endpoints.
//     Plain UDP listeners usually do not produce accepted net.Conn values, but
//     custom wrappers or connected UDP sockets may.
//   - For virtual net.Conn implementations without real OS sockets, or wrappers
//     that do not expose usable endpoint addresses or raw socket access, this
//     returns ErrNoOwner.
//
// Important:
//
// If conn is a TCP connection accepted by your server, conn.LocalAddr() is the
// server-side endpoint and conn.RemoteAddr() is the client-side endpoint. To find
// the local client process, this function intentionally builds:
//
//	LocalIP:LocalPort     = conn.RemoteAddr()
//	RemoteIP:RemotePort  = conn.LocalAddr()
//
// That asks "who owns the peer-side socket?", not "who owns my accepted server
// socket?".
//
// If the peer is remote, in another network namespace, already closed, hidden by
// procfs permissions, not representable by the platform backend, or on a
// platform that does not expose owner metadata, the returned owner can be nil.
// Callers must treat nil owner as no usable owner information, even when err is
// nil.
func GetIncomingConnOwner(conn net.Conn) (*SocketOwner, error) {
	if wrapped, ok := gonnect.GetWrapped(conn).(net.Conn); ok {
		conn = wrapped
	}

	owner, err := getIncomingUnixPeerOwner(conn)
	if err == nil && owner != nil {
		return owner, nil
	}

	flow, err := IncomingConnPeerFlow(conn)
	if err != nil {
		return nil, err
	}

	return GetSockOwner(*flow)
}

// IncomingConnPeerFlow converts an incoming TCP/UDP net.Conn into the FlowTuple
// of the peer-side socket.
//
// For an accepted TCP connection:
//
//	conn.LocalAddr()  = server endpoint
//	conn.RemoteAddr() = client endpoint
//
// The returned tuple is reversed so that Local* describes the client-side socket
// whose owner we want to resolve.
func IncomingConnPeerFlow(conn net.Conn) (*FlowTuple, error) {
	if conn == nil {
		return nil, ErrConnNil
	}

	local := conn.LocalAddr()
	remote := conn.RemoteAddr()
	if local == nil || remote == nil {
		return nil, ErrAddrNil
	}

	switch l := local.(type) {
	case *net.TCPAddr:
		r, ok := remote.(*net.TCPAddr)
		if !ok {
			return nil, ErrAddrTypeUnexpected
		}

		return flowFromIPAddrs("tcp", r.IP, r.Port, l.IP, l.Port)

	case *net.UDPAddr:
		r, ok := remote.(*net.UDPAddr)
		if !ok {
			return nil, ErrAddrTypeUnexpected
		}

		return flowFromIPAddrs("udp", r.IP, r.Port, l.IP, l.Port)

	default:
		return nil, ErrAddrTypeUnexpected
	}
}
