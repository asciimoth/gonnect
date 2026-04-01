// Package testing implements helpers for gonnect interfaces implementations
// testing
package testing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/asciimoth/gonnect"
)

type Network interface {
	gonnect.Network
	gonnect.InterfaceNetwork
	gonnect.Resolver
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func boolPtr(b bool) *bool { return &b }

func expectUnknownNetworkErrorWith(expectedNetwork string) func(error) error {
	return func(err error) error {
		if err == nil {
			return fmt.Errorf("expected net.UnknownNetworkError but got nil")
		}
		var u net.UnknownNetworkError
		if !errors.As(err, &u) {
			return fmt.Errorf(
				"expected net.UnknownNetworkError in chain, got: %T",
				err,
			)
		}
		// UnknownNetworkError is a string type containing network name
		if expectedNetwork != "" && string(u) != expectedNetwork {
			return fmt.Errorf(
				"network mismatch: expected %q, got %q",
				expectedNetwork,
				string(u),
			)
		}
		return nil
	}
}

func expectAddrErrorWith(
	expectedAddr, expectedErrContains string,
) func(error) error {
	return func(err error) error {
		if err == nil {
			return fmt.Errorf("expected *net.AddrError but got nil")
		}
		var a *net.AddrError
		if !errors.As(err, &a) {
			return fmt.Errorf("expected *net.AddrError in chain, got: %T", err)
		}
		if expectedAddr != "" && a.Addr != expectedAddr {
			return fmt.Errorf(
				"Addr mismatch: expected %q, got %q",
				expectedAddr,
				a.Addr,
			)
		}
		if expectedErrContains != "" &&
			!strings.Contains(a.Err, expectedErrContains) {
			return fmt.Errorf(
				"Err mismatch: expected substring %q in %q",
				expectedErrContains,
				a.Err,
			)
		}
		return nil
	}
}

func expectDNSErrorWith(
	expectedName string,
	expectIsTimeout, expectIsTemporary, expectIsNotFound *bool,
	expectedErrContains string,
) func(error) error {
	return func(err error) error {
		if err == nil {
			return fmt.Errorf("expected *net.DNSError but got nil")
		}
		var d *net.DNSError
		if !errors.As(err, &d) {
			return fmt.Errorf("expected *net.DNSError in chain, got: %T", err)
		}
		if expectedName != "" && d.Name != expectedName {
			return fmt.Errorf(
				"Name mismatch: expected %q, got %q",
				expectedName,
				d.Name,
			)
		}
		if expectIsTimeout != nil && d.IsTimeout != *expectIsTimeout {
			return fmt.Errorf(
				"IsTimeout mismatch: expected %v, got %v",
				*expectIsTimeout,
				d.IsTimeout,
			)
		}
		if expectIsTemporary != nil && d.IsTemporary != *expectIsTemporary {
			return fmt.Errorf(
				"IsTemporary mismatch: expected %v, got %v",
				*expectIsTemporary,
				d.IsTemporary,
			)
		}
		// IsNotFound exists on net.DNSError; if it's present in your go version, check it.
		if expectIsNotFound != nil {
			if d.IsNotFound != *expectIsNotFound {
				return fmt.Errorf(
					"IsNotFound mismatch: expected %v, got %v",
					*expectIsNotFound,
					d.IsNotFound,
				)
			}
		}
		if expectedErrContains != "" &&
			!strings.Contains(d.Err, expectedErrContains) {
			return fmt.Errorf(
				"Err mismatch: expected substring %q in %q",
				expectedErrContains,
				d.Err,
			)
		}
		return nil
	}
}

func expectOpErrorWith(
	expectedOp, expectedErrContains string,
) func(error) error {
	return func(err error) error {
		if err == nil {
			return fmt.Errorf("expected *net.OpError but got nil")
		}
		var op *net.OpError
		if !errors.As(err, &op) {
			return fmt.Errorf("expected *net.OpError in chain, got: %T", err)
		}
		if expectedOp != "" && op.Op != expectedOp {
			return fmt.Errorf(
				"Op mismatch: expected %q, got %q",
				expectedOp,
				op.Op,
			)
		}
		if expectedErrContains != "" {
			if op.Err == nil {
				return fmt.Errorf(
					"underlying op.Err is nil, expected substring %q",
					expectedErrContains,
				)
			}
			if !strings.Contains(op.Err.Error(), expectedErrContains) {
				return fmt.Errorf(
					"underlying error mismatch: expected substring %q in %q",
					expectedErrContains,
					op.Err.Error(),
				)
			}
		}
		return nil
	}
}

// expectInterfaceNotFound asserts that err represents a "no such interface" condition.
// Different OSes / Go versions report this differently (strings or syscall.Errno or net.OpError),
// so be lenient and accept common variants including wrapped *net.OpError messages.
func expectInterfaceNotFound() func(error) error {
	return func(err error) error {
		if err == nil {
			return fmt.Errorf("expected interface-not-found error but got nil")
		}

		low := strings.ToLower(err.Error())

		// Quick substring matches (case-insensitive)
		if strings.Contains(low, "no such") ||
			strings.Contains(low, "not found") ||
			strings.Contains(low, "no such network") ||
			strings.Contains(low, "no such network interface") ||
			strings.Contains(low, "invalid network interface index") {
			return nil
		}

		// check common errno values
		var errno syscall.Errno
		if errors.As(err, &errno) {
			switch errno { //nolint
			case syscall.ENODEV, syscall.ENOENT, syscall.EADDRNOTAVAIL:
				return nil
			}
		}

		// accept wrapped *net.OpError which some platforms return
		var op *net.OpError
		if errors.As(err, &op) {
			// If op.Err contains a helpful message, check it
			if op.Err != nil {
				oe := strings.ToLower(op.Err.Error())
				if strings.Contains(oe, "invalid network interface index") ||
					strings.Contains(oe, "no such") ||
					strings.Contains(oe, "not found") {
					return nil
				}
			}
			// Also check the full op.Error() string since some wrappers embed the message there
			if strings.Contains(
				strings.ToLower(op.Error()),
				"invalid network interface index",
			) {
				return nil
			}
		}

		return fmt.Errorf(
			"expected interface-not-found error (substring or common errno or net.OpError), got: %T: %w",
			err,
			err,
		)
	}
}

// expectInterfacesSystemErr accepts either nil error or a syscall-style error for Interfaces()/InterfaceAddrs().
// If err is non-nil we check it's plausibly a system error (errno) or contains common substrings.
func expectInterfacesSystemErr() func(error) error {
	return func(err error) error {
		if err == nil {
			return nil
		}
		// allow common substrings
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "no such") ||
			strings.Contains(low, "not found") ||
			strings.Contains(low, "permission") ||
			strings.Contains(low, "denied") {
			return nil
		}
		// allow syscall errno
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return nil
		}
		return fmt.Errorf(
			"unexpected error kind for Interfaces/InterfaceAddrs: %T: %w",
			err,
			err,
		)
	}
}

// RunNetworkErrorComplianceTests runs a set of subtests against a Network implementation.
// supply `makeNetwork` that returns a fresh Network instance for testing.
func RunNetworkErrorComplianceTests(t *testing.T, makeNetwork func() Network) {
	t.Helper()

	ctx := context.Background()
	cases := []struct {
		name     string
		got      func(n Network) error
		expected func(err error) error // returns nil if match, otherwise descriptive error
	}{
		{
			name: "Dial unknown network",
			got: func(n Network) error {
				_, err := n.Dial(ctx, "not-a-proto", "127.0.0.1:80")
				return err
			},
			expected: expectUnknownNetworkErrorWith("not-a-proto"),
		},
		{
			name: "DialTCP unknown network",
			got: func(n Network) error {
				_, err := n.DialTCP(ctx, "tcp5", "127.0.0.1:80", "127.0.0.1:80")
				return err
			},
			expected: expectUnknownNetworkErrorWith("tcp5"),
		},
		{
			name: "DialUDP unknown network",
			got: func(n Network) error {
				_, err := n.DialUDP(ctx, "udp5", "127.0.0.1:80", "127.0.0.1:80")
				return err
			},
			expected: expectUnknownNetworkErrorWith("udp5"),
		},
		{
			name: "Dial malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.Dial(ctx, "tcp", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith(
				"127.0.0.1",
				"",
			), // only check Addr field
		},
		{
			name: "DialTCP malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.DialTCP(ctx, "tcp", "127.0.0.1", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith(
				"127.0.0.1",
				"",
			), // only check Addr field
		},
		{
			name: "DialUDP malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.DialUDP(ctx, "udp", "127.0.0.1", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith(
				"127.0.0.1",
				"",
			), // only check Addr field
		},
		{
			name: "DialUDP malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.DialUDP(ctx, "udp", "127.0.0.1", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith(
				"127.0.0.1",
				"",
			), // only check Addr field
		},
		{
			name: "Dial host not found",
			got: func(n Network) error {
				_, err := n.Dial(
					ctx,
					"tcp",
					"no-such-host.example.invalid:12345",
				)
				return err
			},
			expected: expectDNSErrorWith(
				"no-such-host.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "DialTCP host not found",
			got: func(n Network) error {
				_, err := n.DialTCP(
					ctx,
					"tcp",
					"127.0.0.1:",
					"no-such-host.example.invalid:12345",
				)
				return err
			},
			expected: expectDNSErrorWith(
				"no-such-host.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "DialUDP host not found",
			got: func(n Network) error {
				_, err := n.DialUDP(
					ctx,
					"udp",
					"127.0.0.1:",
					"no-such-host.example.invalid:12345",
				)
				return err
			},
			expected: expectDNSErrorWith(
				"no-such-host.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "Listen unknown network",
			got: func(n Network) error {
				_, err := n.Listen(ctx, "not-a-proto", "127.0.0.1:0")
				return err
			},
			expected: expectUnknownNetworkErrorWith("not-a-proto"),
		},
		{
			name: "ListenPacket unknown network",
			got: func(n Network) error {
				_, err := n.ListenPacket(ctx, "not-a-proto", "127.0.0.1:0")
				return err
			},
			expected: expectUnknownNetworkErrorWith("not-a-proto"),
		},
		{
			name: "ListenTCP unknown network",
			got: func(n Network) error {
				_, err := n.ListenTCP(ctx, "not-a-proto", "127.0.0.1:0")
				return err
			},
			expected: expectUnknownNetworkErrorWith("not-a-proto"),
		},
		{
			name: "ListenUDP unknown network",
			got: func(n Network) error {
				_, err := n.ListenUDP(ctx, "not-a-proto", "127.0.0.1:0")
				return err
			},
			expected: expectUnknownNetworkErrorWith("not-a-proto"),
		},
		{
			name: "Listen malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.Listen(ctx, "tcp", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith("127.0.0.1", ""),
		},
		{
			name: "ListenPacket malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.ListenPacket(ctx, "udp", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith("127.0.0.1", ""),
		},
		{
			name: "ListenTCP malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.ListenTCP(ctx, "tcp", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith("127.0.0.1", ""),
		},
		{
			name: "ListenUDP malformed address (missing port)",
			got: func(n Network) error {
				_, err := n.ListenTCP(ctx, "tcp", "127.0.0.1")
				return err
			},
			expected: expectAddrErrorWith("127.0.0.1", ""),
		},
		{
			name: "LookupMX host not found",
			got: func(n Network) error {
				_, err := n.LookupMX(ctx, "no-such-domain.example.invalid")
				return err
			},
			expected: expectDNSErrorWith(
				"no-such-domain.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "LookupTXT host not found",
			got: func(n Network) error {
				_, err := n.LookupTXT(ctx, "no-such-domain.example.invalid")
				return err
			},
			expected: expectDNSErrorWith(
				"no-such-domain.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "LookupSRV host not found",
			got: func(n Network) error {
				_, _, err := n.LookupSRV(
					ctx,
					"svc",
					"tcp",
					"no-such-domain.example.invalid",
				)
				return err
			},
			expected: expectDNSErrorWith(
				"_svc._tcp.no-such-domain.example.invalid",
				nil,
				nil,
				boolPtr(true),
				"no such host",
			),
		},
		{
			name: "InterfacesByIndex invalid",
			got: func(n Network) error {
				// TODO: Fetch list of all interfaces and select index that guaranteed don't exists (good first issue)
				_, err := n.InterfacesByIndex(-999999) // very unlikely to exist
				return err
			},
			expected: expectInterfaceNotFound(),
		},
		{
			name: "InterfacesByName invalid",
			got: func(n Network) error {
				// TODO: Fetch list of all interfaces and select name that guaranteed don't exists (good first issue)
				_, err := n.InterfacesByName("no-such-interface-xyz-12345")
				return err
			},
			expected: expectInterfaceNotFound(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			netw := makeNetwork()
			gotErr := c.got(netw)

			if c.expected == nil {
				if gotErr != nil {
					t.Fatalf("expected nil error but got: %v", gotErr)
				}
				return
			}
			if perr := c.expected(gotErr); perr != nil {
				t.Fatalf(
					"expectation failed for %s: %v\nreturned error: %#v\nerror string: %q",
					c.name,
					perr,
					gotErr,
					errStr(gotErr),
				)
			}
		})
	}
}
