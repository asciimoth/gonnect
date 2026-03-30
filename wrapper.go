// Package gonnect provides utility functions for connection handling.
package gonnect

// Wrapper is an interface for types that wrap underlying values.
// Implementing types should return the wrapped value via GetWrapped.
type Wrapper interface {
	GetWrapped() any
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
	return nil
}
