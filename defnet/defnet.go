// Package defnet provides a default network implementation that uses
// native networking on platforms that support it, and falls back
// to a loopback (in-memory) network on platforms like wasm.
package defnet

import (
	"github.com/asciimoth/gonnect"
)

// Network combines all major gonnect interfaces into one.
type Network interface {
	gonnect.Network
	gonnect.InterfaceNetwork
	gonnect.Resolver
	gonnect.UpDown
}
