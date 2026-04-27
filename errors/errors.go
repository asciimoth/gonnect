// Package errors provides canonical generators for frequently used network errors.
package errors

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/asciimoth/gonnect/helpers"
)

// NoSuchHost returns a net.Error representing a DNS lookup failure for the specified host.
// The host parameter is the hostname that was looked up (e.g. example.com).
// The srv parameter is the DNS server address (e.g. 8.8.8.8:53).
func NoSuchHost(host, srv string) *net.DNSError {
	return &net.DNSError{
		Err:         "no such host",
		Name:        host, // e.g. example.com
		Server:      srv,  // e.g. 8.8.8.8:53
		IsTimeout:   false,
		IsTemporary: true,
		IsNotFound:  true,
	}
}

// DnsReqErr returns a net.DNSError representing a DNS request failure.
// The host parameter is the hostname that was looked up (e.g. example.com).
// The srv parameter is the DNS server address (e.g. 8.8.8.8:53).
func DnsReqErr(host, srv string) error {
	return &net.DNSError{
		Err: fmt.Sprintf(
			"dial udp %s: connect: connection refused",
			srv,
		),
		Name:        host, // e.g. example.com
		Server:      srv,  // e.g. 8.8.8.8:53
		IsTimeout:   false,
		IsTemporary: true,
		IsNotFound:  false,
	}
}

// ConnClosed returns a net.Error representing an operation on a closed network connection.
// The op parameter is the operation being performed (e.g. "read", "write").
// The network parameter is the network type (e.g. "tcp", "udp").
// src and addr represent the source and destination addresses of the connection.
func ConnClosed(op, network string, src, addr net.Addr) net.Error {
	return &net.OpError{
		Op:     op,
		Source: src,
		Addr:   addr,
		Net:    network,
		Err:    net.ErrClosed,
	}
}

// ConnRefused returns an error representing a connection refusal.
// The n parameter is the network type (e.g. "tcp", "udp").
// The a parameter is the address that refused the connection.
func ConnRefused(n, a string) error {
	return &net.OpError{
		Op:     "dial",
		Net:    n,
		Source: nil,
		Addr: &helpers.NetAddr{
			Net:  n,
			Addr: a,
		},
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.ECONNREFUSED,
		},
	}
}

// ListenDeniedErr returns an error representing a permission denied when
// attempting to listen on an address.
// The n parameter is the network type (e.g. "tcp", "udp").
// The a parameter is the address that denied the listen attempt.
func ListenDeniedErr(n, a string) error {
	return &net.OpError{
		Op:     "listen",
		Net:    n,
		Source: nil,
		Addr: &helpers.NetAddr{
			Net:  n,
			Addr: a,
		},
		Err: &os.SyscallError{
			Syscall: "bind",
			Err:     syscall.EACCES,
		},
	}
}
