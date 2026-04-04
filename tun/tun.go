// Package tun provides a TUN (network tunnel) interface for handling virtual
// network devices. It defines the Tun interface, which is compatible with
// wireguard-go and similar projects, along with utility functions for I/O
// adaptation, testing, and bidirectional packet copying.
//
// The package includes:
//   - Tun: Core interface for reading/writing network packets in batches
//   - IO: Adapter that wraps Tun to implement io.ReadWriteCloser for single-packet operations
//   - Pipe: Creates paired connected Tun implementations for testing (similar to net.Pipe)
//   - Copy: Bidirectional packet copying between two Tun implementations
package tun

import "os"

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

// Tun interface is borrowed from wireguard-go.
// There is multiple projects that use same or similar interfaces so it is
// a good choice for a de-facto standard role.
type Tun interface {
	// File returns the file descriptor of the tun device.
	// It may be nil for virtual/mock/etc implementations.
	File() *os.File

	// Read a batch of packets from Tun.
	// If original source (e.g. linux tun interface) ruturn additional headers,
	// they are stripped under the hood.
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Tun on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write one or more packets to the tun (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (int, error)

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	// Name returns the current name of the Device.
	Name() (string, error)

	// Events returns a channel of type Event, which is fed Device events.
	Events() <-chan Event

	// Close stops the Device and closes the Event channel.
	Close() error

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int

	// TODO: Add getter for gonnect.NetworkInterface?
}
