// Package gonnect provides network helper functions and common network types.
// NativeConfig builds a NativeNetwork backed by Go's standard net package.
// NativeNetwork.Dial keeps Go native dial semantics. It filters the original
// address and passes that address to net.Dialer without resolving it through the
// configured gonnect Resolver first. This is intentional: native dial must keep
// local operating system name lookup behavior, including hosts files and other
// platform resolver rules. Wrap NativeNetwork with NetworkWithResolver when a
// network must receive numeric addresses resolved by a gonnect Resolver.
// NativeNetwork implements Network only; wrap it with DetachNetwork when
// independent Up, Down, or Close state is required.
//
// DetachNetwork wraps a Network with independent Up, Down, and Close state.
// Stopping the wrapper does not stop the wrapped Network, but it cancels wrapper
// operations that honor context cancellation and closes connections, listeners,
// packet connections, and accepted connections created through that wrapper.
// Multiple detached network wrappers can be used over the same Network
// independently.
package gonnect
