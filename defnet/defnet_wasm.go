//go:build wasm

package defnet

import (
	"github.com/asciimoth/gonnect/loopback"
	"github.com/asciimoth/gonnect/native"
)

// DefaultNetwork builds native.Network on compilation targets with native
// networking available (linux, windows, darwin, etc)
// and loopback network for others (wasm, etc).
// If cfg is nil, default one will be used.
// For loopback network cfg arg is ignored.
func DefaultNetwork(_ *native.Config) Network {
	return loopback.NewLoopbackNetwok()
}
