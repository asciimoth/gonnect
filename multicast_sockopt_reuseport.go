//go:build linux || darwin || freebsd || openbsd

package gonnect

import "golang.org/x/sys/unix"

func setNativeReusePort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
