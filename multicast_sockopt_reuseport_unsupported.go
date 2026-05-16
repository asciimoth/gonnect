//go:build unix && !linux && !darwin && !freebsd && !openbsd

package gonnect

func setNativeReusePort(fd int) error {
	return ErrUnsupported
}
