//go:build unix

package gonnect

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setNativeMulticastSockopts(
	c syscall.RawConn,
	opts MulticastOptions,
) error {
	if c == nil {
		return ErrUnsupported
	}
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if opts.ReuseAddr {
			if err := unix.SetsockoptInt(
				int(fd),
				unix.SOL_SOCKET,
				unix.SO_REUSEADDR,
				1,
			); err != nil &&
				sockErr == nil {
				sockErr = err
			}
		}
		if opts.ReusePort {
			if err := setNativeReusePort(
				int(fd),
			); err != nil &&
				sockErr == nil {
				sockErr = err
			}
		}
		if opts.RecvAnyIf {
			if err := setNativeRecvAnyIf(
				int(fd),
			); err != nil &&
				sockErr == nil {
				sockErr = err
			}
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
