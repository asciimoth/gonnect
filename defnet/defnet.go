// Package defnet provides a default network implementation that uses
// native networking on platforms that support it, and falls back
// to a loopback (in-memory) network on platforms like wasm.
package defnet

import (
	"github.com/asciimoth/gonnect"
)

// Network is the default network interface returned by this package.
// Use gonnect.DetachNetwork when independent UpDown state is required.
type Network interface {
	gonnect.Network
}
