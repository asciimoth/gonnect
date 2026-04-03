//go:build !linux && !windows && !unix

package sockopt

import "github.com/asciimoth/gonnect"

// CheckSupport returns the set of supported socket options on this platform.
// This fallback implementation indicates no socket options are supported
// on unrecognized platforms.
func CheckSupport() Support {
	return Support{
		BufSize:         false,
		RoutingMark:     false,
		BindToInterface: false,
	}
}

// SetBufSize sets both receive and send buffer sizes for the socket.
// This operation is not supported on this platform.
func SetBufSize(_ any, _ int) error {
	return ErrUnsupported
}

// GetBuffSize returns the current receive and send buffer sizes for the socket.
// This operation is not supported on this platform.
func GetBuffSize(_ any) (recvSize, sendSize int, err error) {
	return 0, 0, ErrUnsupported
}

// SetRoutingMark sets the routing mark on the socket.
// This operation is not supported on this platform.
func SetRoutingMark(a any, mark int) error {
	return ErrUnsupported
}

// GetRoutingMark retrieves the routing mark from the socket.
// This operation is not supported on this platform.
func GetRoutingMark(a any) (mark int, err error) {
	return 0, ErrUnsupported
}

// SetBindToInterface binds the socket to a specific network interface.
// This operation is not supported on this platform.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	return ErrUnsupported
}
