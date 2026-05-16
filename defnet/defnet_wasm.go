//go:build wasm

package defnet

import (
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/loopback"
)

// DefaultNetwork builds gonnect.NativeNetwork on compilation targets with native
// networking available (linux, windows, darwin, etc)
// and loopback network for others (wasm, etc).
// If cfg is nil, default one will be used.
// For loopback network cfg arg is ignored.
func DefaultNetwork(_ *gonnect.NativeConfig) Network {
	return loopback.NewLoopbackNetwok()
}
