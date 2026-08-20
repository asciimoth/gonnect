//go:build linux

package sockopt

import (
	"fmt"
	"time"

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
		TCPUserTimeout:  true,
		TCPRtt:          true,
	}
}

// SetBufSize sets both receive and send buffer sizes for the socket.
// On Linux, this uses both unprivileged (SO_RCVBUF, SO_SNDBUF) and
// privileged (SO_RCVBUFFORCE, SO_SNDBUFFORCE) options. The privileged
// options require CAP_NET_ADMIN capability.
func SetBufSize(a any, size int) error {
	return control(a, func(f uintptr) error {
		fd := int(f)
		// Unprivileged, unix general
		if err := unix.SetsockoptInt(
			fd,
			unix.SOL_SOCKET,
			unix.SO_RCVBUF,
			size,
		); err != nil {
			return fmt.Errorf("set SO_RCVBUF: %w", err)
		}
		if err := unix.SetsockoptInt(
			fd,
			unix.SOL_SOCKET,
			unix.SO_SNDBUF,
			size,
		); err != nil {
			return fmt.Errorf("set SO_SNDBUF: %w", err)
		}
		// Privileged, linux specific
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
		return nil
	})
}

// GetBuffSize returns the current receive and send buffer sizes for the socket.
func GetBuffSize(a any) (recvSize, sendSize int, err error) {
	err = control(a, func(f uintptr) error {
		fd := int(f)
		recvSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			return fmt.Errorf("get SO_RCVBUF: %w", err)
		}
		sendSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err != nil {
			return fmt.Errorf("get SO_SNDBUF: %w", err)
		}
		return nil
	})
	return
}

// SetRoutingMark sets the routing mark (SO_MARK) on the socket.
// This requires appropriate privileges (CAP_NET_ADMIN or net_admin capability).
func SetRoutingMark(a any, mark uint32) error {
	return control(a, func(fd uintptr) error {
		if err := unix.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_MARK,
			int(mark),
		); err != nil {
			return fmt.Errorf("set SO_MARK: %w", err)
		}
		return nil
	})
}

// GetRoutingMark retrieves the routing mark (SO_MARK) from the socket.
func GetRoutingMark(a any) (mark uint32, err error) {
	err = control(a, func(fd uintptr) error {
		var value int
		value, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if err != nil {
			return fmt.Errorf("get SO_MARK: %w", err)
		}
		mark = routingMarkFromSockoptInt(value)
		return nil
	})
	return
}

// SetBindToInterface binds the socket to a specific network interface
// using the SO_BINDTODEVICE option. This requires appropriate privileges.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	name, _, err := networkInterfaceNameIndex(i)
	if err != nil {
		return err
	}
	return control(a, func(fd uintptr) error {
		if err := unix.BindToDevice(int(fd), name); err != nil {
			return fmt.Errorf("bind SO_BINDTODEVICE %q: %w", name, err)
		}
		return nil
	})
}

// SetTCPTimeout sets the TCP_USER_TIMEOUT option on the given file descriptor.
func SetTCPTimeout(a any, timeout time.Duration) error {
	return control(a, func(fd uintptr) error {
		if err := unix.SetsockoptInt(
			int(fd),
			unix.SOL_TCP,
			unix.TCP_USER_TIMEOUT,
			int(timeout/time.Millisecond),
		); err != nil {
			return fmt.Errorf("set TCP_USER_TIMEOUT: %w", err)
		}
		return nil
	})
}

// GetTCPRTT returns RTT for TCPConn.
func GetTCPRTT(a any) (rtt time.Duration, err error) {
	err = control(a, func(fd uintptr) error {
		var info *unix.TCPInfo
		info, err = unix.GetsockoptTCPInfo(
			int(fd),
			unix.IPPROTO_TCP,
			unix.TCP_INFO,
		)
		if err != nil {
			return fmt.Errorf("get TCP_INFO: %w", err)
		}
		rtt = time.Duration(info.Rtt) * time.Microsecond
		return nil
	})
	return
}
