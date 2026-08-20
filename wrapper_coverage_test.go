package gonnect_test

import (
	"net"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestCoverageGetWrappedGenericBranches(t *testing.T) {
	if got := gonnect.GetWrapped(nil); got != nil {
		t.Fatalf("GetWrapped(nil) = %#v, want nil", got)
	}
	if got := gonnect.GetWrapped("plain"); got != nil {
		t.Fatalf("GetWrapped(non-wrapper) = %#v, want nil", got)
	}

	underlying, other := net.Pipe()
	defer func() { _ = underlying.Close() }()
	defer func() { _ = other.Close() }()
	if got := gonnect.GetWrapped(
		fakeNetConnWrapper{conn: underlying},
	); got != underlying {
		t.Fatalf("GetWrapped(NetConn wrapper) = %#v, want %#v", got, underlying)
	}
}

type fakeNetConnWrapper struct {
	conn net.Conn
}

func (w fakeNetConnWrapper) NetConn() net.Conn {
	return w.conn
}
