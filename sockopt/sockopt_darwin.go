//go:build darwin

package sockopt

import (
	"fmt"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
	"golang.org/x/sys/unix"
)

// CheckSupport returns the set of supported socket options on this platform.
// Darwin (macOS) supports buffer size and interface binding, but not routing marks.
func CheckSupport() Support {
	return Support{
		BufSize:         true,
		RoutingMark:     false,
		BindToInterface: true,
		TCPRtt:          true,
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

// SetRoutingMark sets the routing mark on the socket.
// This operation is not supported on Darwin (macOS).
func SetRoutingMark(a any, mark uint32) error {
	return ErrUnsupported
}

// GetRoutingMark retrieves the routing mark from the socket.
// This operation is not supported on Darwin (macOS).
func GetRoutingMark(a any) (mark uint32, err error) {
	return 0, ErrUnsupported
}

// SetBindToInterface binds the socket to a specific network interface.
// On Darwin, this uses IP_BOUND_IF for IPv4 and IPV6_BOUND_IF for IPv6.
// The function determines the appropriate protocol based on the connection's
// network type.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	conn, ok := a.(net.Conn)
	if !ok {
		return ErrUnsupported
	}
	_, id, err := networkInterfaceNameIndex(i)
	if err != nil {
		return err
	}

	network := ""
	if la := conn.LocalAddr(); la != nil && la.Network() != "" {
		network = la.Network()
	} else if ra := conn.RemoteAddr(); ra != nil && ra.Network() != "" {
		network = ra.Network()
	}
	if network == "" {
		return ErrUnsupported
	}

	return control(a, func(fd uintptr) error {
		switch network {
		case "ip4", "tcp4", "udp4", "ip", "tcp", "udp":
			if err := unix.SetsockoptInt(
				int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, id,
			); err != nil {
				return fmt.Errorf("set IP_BOUND_IF: %w", err)
			}
			return nil
		case "ip6", "tcp6", "udp6":
			if err := unix.SetsockoptInt(
				int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, id,
			); err != nil {
				return fmt.Errorf("set IPV6_BOUND_IF: %w", err)
			}
			return nil
		default:
			return ErrUnsupported
		}
	})
}

// SetTCPTimeout sets the TCP user timeout.
// This operation is not supported on this platform.
func SetTCPTimeout(a any, timeout time.Duration) error {
	return ErrUnsupported
}

// GetTCPRTT returns RTT for TCPConn.
func GetTCPRTT(a any) (rtt time.Duration, err error) {
	err1 := Control(a, func(fd uintptr) {
		var info *unix.TCPConnectionInfo
		info, err = unix.GetsockoptTCPConnectionInfo(
			int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO,
		)
		rtt = time.Duration(info.Rttcur) * time.Millisecond
	})
	if err1 != nil {
		err = err1
	}
	return
}
