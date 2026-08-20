// Package sockopt provides platform-specific socket option manipulation.
//
// This package offers a unified interface for setting and getting socket options
// across different operating systems including Linux, Darwin, FreeBSD, OpenBSD,
// other Unix-like systems and Windows. It supports buffer size configuration,
// routing marks (where available), and binding sockets to specific network interfaces.
//
// Darwin support is currently marked as broken. Do not rely on this package on
// Darwin until it is fixed and cross-compile checks pass again.
//
// Some non-Linux SetBufSize implementations ignore SO_RCVBUF and SO_SNDBUF
// errors after the raw socket was acquired. This is intentional compatibility
// behavior for platforms where one side can fail while the socket stays usable.
// Use GetBuffSize after SetBufSize when the exact applied value is important.
package sockopt

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"syscall"

	helpers "github.com/asciimoth/gonnect"
)

// Well known fwmark collection.
// Borrowed from https://github.com/fwmark/registry
const (
	// Bitwise mark masks
	FwmarkCiliumMask     = 0xFFFF1FFF
	FwmarkAWSCNIMask     = 0x00000080
	FwmarkCNIPortmapMask = 0x00002000
	FwmarkKubernetesMask = 0x0000C000
	FwmarkCalicoMask     = 0xFFFF0000
	FwmarkWeaveMask      = 0x00060000
	FwmarkTailscaleMask  = 0x000C0000

	// Non-bitwise marks (integer values)
	FwmarkAntrea     = 0x00000800
	FwmarkIstio      = 0x1337
	FwmarkAWSAppMesh = 0x1E7700CE
)

// NOFD is a sentinel value indicating an invalid or unavailable file descriptor.
const NOFD = -1

// ErrUnsupported indicates that the requested socket option is not supported
// on the current platform or for the given socket type.
var ErrUnsupported = errors.New("option unsupported")

// IgnoreUnsupported returns nil if the error is ErrUnsupported
// or contains "not supported", otherwise returns the original error.
// This is useful for optional socket options
// where unsupported platforms should be silently skipped.
func IgnoreUnsupported(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUnsupported) {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "not supported") {
		return nil
	}
	return err
}

// Support indicates which socket options are supported on the current platform.
type Support struct {
	BufSize         bool // Buffer size configuration support
	RoutingMark     bool // Routing mark (SO_MARK, SO_USER_COOKIE, etc.) support
	BindToInterface bool // Bind to device/interface support
	TCPUserTimeout  bool // TCP user timeout support
	TCPRtt          bool // TCP Round Trip Time getter
}

// Control extracts the raw file descriptor from a network connection and
// executes the provided function with it. Returns ErrUnsupported if the
// connection type does not support raw file descriptor access.
func Control(a any, f func(fd uintptr)) error {
	return control(a, func(fd uintptr) error {
		f(fd)
		return nil
	})
}

func control(a any, f func(fd uintptr) error) error {
	if rc, ok := a.(syscall.RawConn); ok {
		return controlRawConn(rc, f)
	}

	rc, err := helpers.SyscallConn(a)
	if err != nil {
		return err
	}
	if rc == nil {
		return ErrUnsupported
	}
	return controlRawConn(rc, f)
}

func controlRawConn(rc syscall.RawConn, f func(fd uintptr) error) error {
	var opErr error
	err := rc.Control(func(fd uintptr) {
		opErr = f(fd)
	})
	if err != nil {
		return err
	}
	return opErr
}

// GetFd extracts the raw file descriptor from a network connection.
// Returns NOFD if the file descriptor cannot be obtained.
//
// WARN: The file descriptor may become invalid immediately after
// this function returns. Use Control instead for safer operation.
func GetFd(a any) (fd int, err error) {
	fd = NOFD
	err = Control(a, func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		fd = NOFD
	}
	return
}

func networkInterfaceNameIndex(
	i helpers.NetworkInterface,
) (string, int, error) {
	if i == nil {
		return "", 0, ErrUnsupported
	}
	v := reflect.ValueOf(i)
	switch v.Kind() { //nolint:exhaustive // Only nilable kinds matter here.
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return "", 0, ErrUnsupported
		}
	}
	return i.Name(), i.Index(), nil
}

type socketIPFamily int

const (
	socketIPFamilyUnknown socketIPFamily = iota
	socketIPFamily4
	socketIPFamily6
)

func addrIPFamily(addr net.Addr) socketIPFamily {
	ip := addrIP(addr)
	if ip == nil {
		return socketIPFamilyUnknown
	}
	if ip.To4() != nil {
		return socketIPFamily4
	}
	if ip.To16() != nil {
		return socketIPFamily6
	}
	return socketIPFamilyUnknown
}

func connIPFamily(conn net.Conn) socketIPFamily {
	if family := addrIPFamily(
		conn.LocalAddr(),
	); family != socketIPFamilyUnknown {
		return family
	}
	return addrIPFamily(conn.RemoteAddr())
}

func addrIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}
