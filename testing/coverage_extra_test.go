// nolint
package testing

import (
	"errors"
	"net"
	"syscall"
	stdtesting "testing"
)

func TestErrorExpectationHelpers(t *stdtesting.T) {
	if errStr(nil) != "" || errStr(errors.New("x")) != "x" {
		t.Fatalf("errStr returned unexpected values")
	}
	if p := boolPtr(true); p == nil || !*p {
		t.Fatalf("boolPtr(true) = %v, want true pointer", p)
	}

	if err := expectUnknownNetworkErrorWith(
		"bad",
	)(
		net.UnknownNetworkError("bad"),
	); err != nil {
		t.Fatalf("unknown network expectation failed: %v", err)
	}
	if err := expectUnknownNetworkErrorWith(
		"other",
	)(
		net.UnknownNetworkError("bad"),
	); err == nil {
		t.Fatal("unknown network expectation accepted mismatched network")
	}

	addrErr := &net.AddrError{Err: "missing port in address", Addr: "127.0.0.1"}
	if err := expectAddrErrorWith(
		"127.0.0.1",
		"missing port",
	)(
		addrErr,
	); err != nil {
		t.Fatalf("addr error expectation failed: %v", err)
	}
	if err := expectAddrErrorWith("127.0.0.2", "")(addrErr); err == nil {
		t.Fatal("addr error expectation accepted mismatched addr")
	}

	dnsErr := &net.DNSError{
		Err:         "no such host",
		Name:        "example.invalid",
		IsTimeout:   true,
		IsTemporary: true,
		IsNotFound:  true,
	}
	if err := expectDNSErrorWith(
		"example.invalid",
		boolPtr(true),
		boolPtr(true),
		boolPtr(true),
		"no such",
	)(dnsErr); err != nil {
		t.Fatalf("dns error expectation failed: %v", err)
	}
	if err := expectDNSErrorWith(
		"wrong",
		nil,
		nil,
		nil,
		"",
	)(
		dnsErr,
	); err == nil {
		t.Fatal("dns error expectation accepted mismatched name")
	}

	opErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	if err := expectOpErrorWith("dial", "refused")(opErr); err != nil {
		t.Fatalf("op error expectation failed: %v", err)
	}
	if err := expectOpErrorWith("read", "")(opErr); err == nil {
		t.Fatal("op error expectation accepted mismatched op")
	}
}

func TestInterfaceErrorExpectationHelpers(t *stdtesting.T) {
	if err := expectInterfaceNotFound()(syscall.ENODEV); err != nil {
		t.Fatalf("interface not found errno expectation failed: %v", err)
	}
	if err := expectInterfaceNotFound()(
		errors.New("no such network interface"),
	); err != nil {
		t.Fatalf("interface not found string expectation failed: %v", err)
	}
	if err := expectInterfaceNotFound()(&net.OpError{
		Op:  "route",
		Err: errors.New("invalid network interface index"),
	}); err != nil {
		t.Fatalf("interface not found op expectation failed: %v", err)
	}
	if err := expectInterfaceNotFound()(errors.New("different")); err == nil {
		t.Fatal("interface not found expectation accepted unrelated error")
	}

	if err := expectInterfacesSystemErr()(nil); err != nil {
		t.Fatalf("system err expectation rejected nil: %v", err)
	}
	if err := expectInterfacesSystemErr()(syscall.EPERM); err != nil {
		t.Fatalf("system err expectation rejected errno: %v", err)
	}
	if err := expectInterfacesSystemErr()(
		errors.New("permission denied"),
	); err != nil {
		t.Fatalf("system err expectation rejected permission string: %v", err)
	}
	if err := expectInterfacesSystemErr()(
		errors.New("unexpected"),
	); err == nil {
		t.Fatal("system err expectation accepted unrelated error")
	}
}

func TestGenRandomString(t *stdtesting.T) {
	if got := genRandomString(0); got != "" {
		t.Fatalf("genRandomString(0) = %q, want empty", got)
	}
	got := genRandomString(32)
	if len(got) != 32 {
		t.Fatalf("genRandomString length = %d, want 32", len(got))
	}
	for _, r := range got {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			t.Fatalf(
				"genRandomString produced non-alphanumeric rune %q in %q",
				r,
				got,
			)
		}
	}
}
