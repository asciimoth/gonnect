//go:build windows

package sockopt

import (
	"fmt"
	"math/bits"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
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
//
// For compatibility with Windows socket behavior, this function ignores
// SO_RCVBUF and SO_SNDBUF errors after the raw socket is acquired. Use
// GetBuffSize to verify the applied values when the exact size matters.
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
func SetRoutingMark(a any, mark uint32) error {
	return ErrUnsupported
}

// GetRoutingMark retrieves the routing mark from the socket.
// This operation is not supported on Windows.
func GetRoutingMark(a any) (mark uint32, err error) {
	return 0, ErrUnsupported
}

// SetBindToInterface binds the socket to a specific network interface.
// On Windows, this uses IP_UNICAST_IF (option 0x1f) for IPv4 and
// IPV6_UNICAST_IF (option 0x1f) for IPv6. For IPv4, the interface index
// must be byte-swapped due to Windows API quirks.
func SetBindToInterface(a any, i gonnect.NetworkInterface) error {
	conn, ok := a.(net.Conn)
	if !ok {
		return ErrUnsupported
	}
	_, id, err := networkInterfaceNameIndex(i)
	if err != nil {
		return err
	}

	family := connIPFamily(conn)
	if family == socketIPFamilyUnknown {
		return ErrUnsupported
	}

	return control(a, func(fd uintptr) error {
		h := windows.Handle(fd)
		switch family {
		case socketIPFamily4:
			if err := windows.SetsockoptInt(
				h, windows.IPPROTO_IP, 0x1f,
				// Windows expects the IPv4 interface index in network byte order.
				int(bits.ReverseBytes32(uint32(id))),
			); err != nil {
				return fmt.Errorf("set IP_UNICAST_IF: %w", err)
			}
			return nil
		case socketIPFamily6:
			ip := addrIP(conn.LocalAddr())
			if ip == nil || ip.IsUnspecified() {
				if err := windows.SetsockoptInt(
					h, windows.IPPROTO_IPV6, 0x1f, id,
				); err != nil {
					return fmt.Errorf("set IPV6_UNICAST_IF: %w", err)
				}
				return nil
			}
			return ErrUnsupported
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
// This operation is not supported on this platform.
func GetTCPRTT(a any) (rtt time.Duration, err error) {
	return 0, ErrUnsupported
}
