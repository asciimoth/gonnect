// Package sockopt provides platform-specific socket option manipulation.
//
// This package offers a unified interface for setting and getting socket options
// across different operating systems including Linux, Darwin, FreeBSD, OpenBSD,
// other Unix-like systems and Windows. It supports buffer size configuration,
// routing marks (where available), and binding sockets to specific network interfaces.
package sockopt

import (
	"errors"

	"github.com/asciimoth/gonnect/helpers"
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

// IgnoreUnsupported returns nil if the error is ErrUnsupported, otherwise
// returns the original error. This is useful for optional socket options
// where unsupported platforms should be silently skipped.
func IgnoreUnsupported(err error) error {
	if errors.Is(err, ErrUnsupported) {
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
	rc, err := helpers.SyscallConn(a)
	if err != nil {
		return err
	}
	if rc == nil {
		return ErrUnsupported
	}
	return rc.Control(f)
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
