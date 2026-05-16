// Package gonnect provides network helper functions and common network types.
//
// DetachNetwork wraps a Network with independent Up, Down, and Close state.
// Stopping the wrapper does not stop the wrapped Network, but it cancels wrapper
// operations that honor context cancellation and closes connections, listeners,
// packet connections, and accepted connections created through that wrapper.
// Multiple detached network wrappers can be used over the same Network
// independently.
package gonnect
