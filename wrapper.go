package gonnect

import "net"

// Wrapper is an interface for types that wrap underlying values.
// Implementing types should return the wrapped value via GetWrapped.
type Wrapper interface {
	GetWrapped() any
}

// withNetConn is implemented by tls.Conn
type withNetConn interface {
	NetConn() net.Conn
}

// GetWrapped extracts the wrapped value from an object.
// If obj is nil or does not implement Wrapper, returns nil.
func GetWrapped(obj any) any {
	if obj == nil {
		return nil
	}
	if wr, ok := obj.(Wrapper); ok {
		return wr.GetWrapped()
	}
	// Special case for tls.Conn
	if wn, ok := obj.(withNetConn); ok {
		return wn.NetConn()
	}
	return nil
}
