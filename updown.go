package gonnect

import "io"

// CloserSubscriber is implemented by Network values that can attach externally
// created closers to their own lifecycle.
//
// SubscribeCloser registers c to be closed when the Network is permanently
// closed. The returned unsubscribe function removes c without closing it. If
// the Network is already closed, c is closed before SubscribeCloser returns
// net.ErrClosed.
//
// Network implementations that also implement io.Closer must implement
// CloserSubscriber.
type CloserSubscriber interface {
	SubscribeCloser(c io.Closer) (func(), error)
}

// UpDown defines an interface for managing the operational state of a resource.
type UpDown interface {
	// Up activates or brings the resource online.
	Up() error
	// Down deactivates or brings the resource offline.
	// All active connections/listeners/etc must be closed on down.
	Down() error

	IsUp() (bool, error)
}

// UpDownSubscriber is implemented by Network values that can attach external
// UpDown resources to their own operational state.
//
// SubscribeUpDown registers u to be moved down when the Network goes down or is
// closed, and moved up when the Network goes up. The subscription persists
// across repeated Down and Up calls until the returned unsubscribe function is
// called. If the Network is already down or closed, u.Down is called before
// SubscribeUpDown returns.
//
// Network implementations that also implement UpDown must implement
// UpDownSubscriber.
type UpDownSubscriber interface {
	SubscribeUpDown(u UpDown) (func(), error)
}
