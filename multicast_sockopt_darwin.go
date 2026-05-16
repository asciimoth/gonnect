//go:build darwin

package gonnect

import "golang.org/x/sys/unix"

func setNativeRecvAnyIf(fd int) error {
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVANYIF, 1)
}
