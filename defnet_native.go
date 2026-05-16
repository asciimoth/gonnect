//go:build !wasm

package gonnect

// DefaultNetwork builds gonnect.NativeNetwork on compilation targets with native
// networking available (linux, windows, darwin, etc)
// and loopback network for others (wasm, etc).
// If cfg is nil, default one will be used.
// For loopback network cfg arg is ignored.
func DefaultNetwork(cfg *NativeConfig) Network {
	if cfg == nil {
		cfg = &NativeConfig{}
	}
	return cfg.Build()
}
