//go:build linux

package sockopt

import (
	"github.com/asciimoth/gonnect"
	"golang.org/x/sys/unix"
)

// CheckSupport returns the set of supported socket options on this platform.
// Linux supports all socket options: buffer size, routing mark, and interface binding.
func CheckSupport() Support {
	return Support{
		BufSize:         true,
		RoutingMark:     true,
		BindToInterface: true,
	}
}

// SetBufSize sets both receive and send buffer sizes for the socket.
// On Linux, this uses both unprivileged (SO_RCVBUF, SO_SNDBUF) and
// privileged (SO_RCVBUFFORCE, SO_SNDBUFFORCE) options. The privileged
// options require CAP_NET_ADMIN capability.
func SetBufSize(a any, size int) error {
	return Control(a, func(f uintptr) {
		fd := int(f)
		// Unprivileged, unix general
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
		// Privileged, linux specific
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
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

// SetRoutingMark sets the routing mark (SO_MARK) on the socket.
// This requires appropriate privileges (CAP_NET_ADMIN or net_admin capability).
func SetRoutingMark(a any, mark int) error {
	return Control(a, func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
	})
}

// GetRoutingMark retrieves the routing mark (SO_MARK) from the socket.
func GetRoutingMark(a any) (mark int, err error) {
	err1 := Control(a, func(fd uintptr) {
		mark, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	})
	if err1 != nil {
		err = err1
	}
	return
}

// SetBindToInterface binds the socket to a specific network interface
// using the SO_BINDTODEVICE option. This requires appropriate privileges.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	var err2 error
	err1 := Control(a, func(fd uintptr) {
		err2 = unix.BindToDevice(int(fd), i.Name())
	})
	if err1 != nil {
		return err1
	}
	return err2
}
