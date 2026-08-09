package gonnect

import "net"

// PreCloser is implemented by connections that split shutdown into a
// concurrent phase and a final phase.
//
// PreClose can be called more than once and can be called while I/O operations
// are still active. It should do only the work that is necessary to make active
// reads or writes stop. It must not release buffers or other state that active
// I/O operations can still use.
type PreCloser interface {
	PreClose() error
}

// PostCloser is implemented by connections that split shutdown into a
// concurrent phase and a final phase.
//
// PostClose can be called more than once, but callers must not call it in
// parallel. It should run after all active I/O operations stopped. It can
// release buffers and other state that PreClose intentionally left in place.
type PostCloser interface {
	PostClose() error
}

// TwoStepCloser is implemented by connections that support PreClose and
// PostClose.
//
// Close implementations for these connections should do both phases.
type TwoStepCloser interface {
	PreCloser
	PostCloser
}

// PreClose starts closing c.
//
// If c implements PreCloser, PreClose calls c.PreClose. Otherwise it calls
// c.Close. A nil connection is accepted and returns nil.
func PreClose(c net.Conn) error {
	if c == nil {
		return nil
	}
	if closer, ok := c.(PreCloser); ok {
		return closer.PreClose()
	}
	return c.Close()
}

// PostClose finishes closing c.
//
// If c implements PostCloser, PostClose calls c.PostClose. Otherwise it calls
// c.Close. A nil connection is accepted and returns nil.
func PostClose(c net.Conn) error {
	if c == nil {
		return nil
	}
	if closer, ok := c.(PostCloser); ok {
		return closer.PostClose()
	}
	return c.Close()
}
