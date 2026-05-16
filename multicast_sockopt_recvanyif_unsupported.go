//go:build unix && !darwin

package gonnect

func setNativeRecvAnyIf(fd int) error {
	return ErrUnsupported
}
