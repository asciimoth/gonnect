//go:build darwin

package gonnect

func setNativeRecvAnyIf(_ int) error {
	// Darwin support is not verified. Keep RecvAnyIf disabled until the
	// correct macOS socket option is tested.
	return ErrUnsupported
}
