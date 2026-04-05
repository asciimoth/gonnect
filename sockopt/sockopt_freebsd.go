//go:build freebsd

package sockopt

import (
	"time"

	"github.com/asciimoth/gonnect"
	"golang.org/x/sys/unix"
)

// CheckSupport returns the set of supported socket options on this platform.
// FreeBSD supports buffer size and routing marks (via SO_USER_COOKIE),
// but not interface binding.
func CheckSupport() Support {
	return Support{
		BufSize:         true,
		RoutingMark:     true,
		BindToInterface: false,
	}
}

// SetBufSize sets both receive and send buffer sizes for the socket.
// This function uses unprivileged SO_RCVBUF and SO_SNDBUF options.
func SetBufSize(a any, size int) error {
	return Control(a, func(f uintptr) {
		fd := int(f)
		// Unprivileged, unix general
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
	})
}

// GetBuffSize returns the current receive and send buffer sizes for the socket.
func GetBuffSize(a any) (recvSize, sendSize int, err error) {
	err1 := Control(a, func(f uintptr) {
		fd := int(f)
		recvSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			return
		}
		sendSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err != nil {
			return
		}
	})
	if err1 != nil {
		err = err1
	}
	return
}

// SetRoutingMark sets the routing mark (SO_USER_COOKIE) on the socket.
func SetRoutingMark(a any, mark int) error {
	return Control(a, func(fd uintptr) {
		_ = unix.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_USER_COOKIE,
			mark,
		)
	})
}

// GetRoutingMark retrieves the routing mark (SO_USER_COOKIE) from the socket.
func GetRoutingMark(a any) (mark int, err error) {
	err1 := Control(a, func(fd uintptr) {
		mark, err = unix.GetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_USER_COOKIE,
		)
	})
	if err1 != nil {
		err = err1
	}
	return
}

// SetBindToInterface binds the socket to a specific network interface.
// This operation is not supported on FreeBSD.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	return ErrUnsupported
}

// SetTCPTimeout sets the TCP user timeout.
// This operation is not supported on this platform.
func SetTCPTimeout(a any, timeout time.Duration) error {
	return ErrUnsupported
}

// GetTCPRTT returns RTT for TCPConn.
// This operation is not supported on this platform.
func GetTCPRTT(a any) (rtt time.Duration, err error) {
	return 0, ErrUnsupported
}
