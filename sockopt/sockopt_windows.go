//go:build windows

package sockopt

import (
	"math/bits"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
	"golang.org/x/sys/windows"
)

// CheckSupport returns the set of supported socket options on this platform.
// Windows supports buffer size and interface binding, but not routing marks.
func CheckSupport() Support {
	return Support{
		BufSize:         true,
		RoutingMark:     false,
		BindToInterface: true,
	}
}

// SetBufSize sets both receive and send buffer sizes for the socket.
func SetBufSize(a any, size int) error {
	return Control(a, func(f uintptr) {
		fd := int(f)
		_ = windows.SetsockoptInt(
			windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, size,
		)
		_ = windows.SetsockoptInt(
			windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, size,
		)
	})
}

// GetBuffSize returns the current receive and send buffer sizes for the socket.
func GetBuffSize(a any) (recvSize, sendSize int, err error) {
	err1 := Control(a, func(f uintptr) {
		fd := int(f)
		recvSize, err = windows.GetsockoptInt(
			windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF,
		)
		if err != nil {
			return
		}
		sendSize, err = windows.GetsockoptInt(
			windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF,
		)
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
// This operation is not supported on Windows.
func SetRoutingMark(a any, mark int) error {
	return ErrUnsupported
}

// GetRoutingMark retrieves the routing mark from the socket.
// This operation is not supported on Windows.
func GetRoutingMark(a any) (mark int, err error) {
	return 0, ErrUnsupported
}

// SetBindToInterface binds the socket to a specific network interface.
// On Windows, this uses IP_UNICAST_IF (option 0x1f) for IPv4 and
// IPV6_UNICAST_IF (option 0x1f) for IPv6. For IPv4, the interface index
// must be byte-swapped due to Windows API quirks.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	conn, ok := a.(net.Conn)
	if !ok {
		return nil
	}
	rc, err1 := helpers.SyscallConn(a)
	if err1 != nil {
		return err1
	}
	if rc == nil {
		return ErrUnsupported
	}

	network := ""
	if la := conn.LocalAddr(); la != nil && la.Network() != "" {
		network = la.Network()
	} else if ra := conn.RemoteAddr(); ra != nil && ra.Network() != "" {
		network = ra.Network()
	}

	if network == "" {
		return nil
	}

	var err2 error
	err1 = rc.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		switch network {
		case "ip4", "tcp4", "udp4", "ip", "tcp", "udp":
			err2 = windows.SetsockoptInt(
				h, windows.IPPROTO_IP, 0x1f,
				// Fuck winapi
				int(bits.ReverseBytes32(uint32(i.Index()))),
			)
		case "ip6", "tcp6", "udp6":
			var ip net.IP
			if la := conn.LocalAddr(); la != nil {
				host, _, err1 := net.SplitHostPort(la.String())
				if err1 != nil {
					return
				}
				ip = net.ParseIP(host)
			} else {
				return
			}
			if ip == nil || ip.IsUnspecified() {
				err2 = windows.SetsockoptInt(
					h, windows.IPPROTO_IPV6, 0x1f, i.Index(),
				)
			}
		}
	})

	if err1 != nil {
		return err1
	}

	return err2
}

// SetTCPTimeout sets the TCP user timeout.
// This operation is not supported on this platform.
func SetTCPTimeout(a any, timeout time.Duration) error {
	return ErrUnsupported
}
