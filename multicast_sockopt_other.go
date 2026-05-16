//go:build !unix

package gonnect

import "syscall"

func setNativeMulticastSockopts(
	c syscall.RawConn,
	opts MulticastOptions,
) error {
	if opts.ReuseAddr || opts.ReusePort || opts.RecvAnyIf {
		return ErrUnsupported
	}
	return nil
}
