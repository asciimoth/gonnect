// Package tun provides a TUN (network tunnel) interface for handling virtual
// network devices. It defines the Tun interface, which is compatible with
// wireguard-go and similar projects, along with utility functions for I/O
// adaptation, testing, and bidirectional packet copying.
//
// Detach wraps a Tun with wrapper-local Up, Down, and Close state. Because Tun
// has no deadline or context API, the wrapper copies packets at the boundary and
// uses internal read/write pumps so pending wrapper Read and Write calls can
// return without closing the wrapped device. If the wrapped Tun itself blocks
// without cancellation support, an internal pump may remain blocked until that
// underlying operation completes.
//
// Only one active detached wrapper for a Tun instance generally makes sense,
// or one nested stack created by wrapping an existing DetachedTun. Multiple
// parallel wrappers around the same Tun, or direct use of the wrapped Tun while
// a wrapper is active, may split reads and writes across consumers and can cause
// operations to hang. Nested detached Tun wrappers share the first wrapper's
// pumps, avoiding an extra pump and packet-copy stage per nested layer.
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
//
// Implementations should distinguish a down interface from a closed Tun. A
// down interface is reported with EventDown and may later report EventUp; the
// Tun remains open, and Read or Write calls may keep blocking or may keep
// returning packets according to the underlying implementation. Close is
// permanent: implementations should unblock pending Read and Write calls when
// possible, close the Events channel, and make future I/O fail with an error
// that matches os.ErrClosed.
//
// Read can also return non-terminal errors after which the same Tun can still
// be used. Known examples from native and third-party implementations include
// temporary errors and capacity errors such as "too many segments" or "need
// more buffers" when the caller supplied too few read buffers. IsTunTermError
// classifies errors for callers that need to decide whether to stop using a
// Tun after a Read error.
type Tun interface {
	// File returns the file descriptor of the tun device.
	// It may be nil for virtual/mock/etc implementations.
	File() *os.File

	// Read a batch of packets from Tun.
	// If original source (e.g. linux tun interface) ruturn additional headers,
	// they are stripped under the hood.
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// Callers must size bufs from the source Tun's BatchSize(); a single Read
	// may yield multiple logical packets, and some native TUN implementations
	// can require multiple buffers even for one inbound frame.
	// A nonzero offset can be used to instruct the Tun on where to begin
	// reading into each element of the bufs slice.
	// If Read returns a non-terminal error, callers may retry using the same
	// Tun. If it returns a terminal error as reported by IsTunTermError,
	// callers should stop using this Tun instance for the current data path.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write one or more packets to the tun (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice. Callers must chunk writes
	// using the destination Tun's BatchSize() and handle partial writes.
	// After Close, Write should return an error matching os.ErrClosed.
	Write(bufs [][]byte, offset int) (int, error)

	// MWO stands for Minimal Write Offset.
	// It is typically used by native tun implementations to reserver space for
	// OS specific headers.
	MWO() int

	// MRO stands for Minimal Read Offset.
	// It isn't used anywhere at the moment but added for future use.
	MRO() int

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	// Name returns the current name of the Device.
	Name() (string, error)

	// Events returns a channel of type Event, which is fed Device events.
	// EventDown means the interface is down, not that the Tun is closed. The
	// channel is closed when the Tun is closed.
	Events() <-chan Event

	// Close permanently stops the Device and closes the Event channel. After
	// Close, Read and Write should return errors matching os.ErrClosed.
	Close() error

	// BatchSize returns the preferred/max number of packets that this Tun can
	// read or write in a single read/write call. BatchSize must not change over
	// the lifetime of a Device. Callers must not assume symmetric batch
	// compatibility across two different Tun implementations: reads should be
	// sized from the source Tun, and writes should be chunked for the
	// destination Tun.
	BatchSize() int

	// TODO: Add getter for gonnect.NetworkInterface?
}
