package sockopt //nolint:testpackage // Covers unexported helper branches.

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type nilSyscallConn struct{}

func (nilSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil //nolint:nilnil // This covers a defensive nil RawConn branch.
}

func TestCoverageControlRejectsNilRawConn(t *testing.T) {
	err := control(nilSyscallConn{}, func(uintptr) error {
		t.Fatal("callback must not run for nil RawConn")
		return nil
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("control(nil RawConn) = %v, want ErrUnsupported", err)
	}
}

func TestCoverageAddrIPFamilyUnknown(t *testing.T) {
	if got := addrIPFamily(nil); got != socketIPFamilyUnknown {
		t.Fatalf("addrIPFamily(nil) = %v, want unknown", got)
	}
	if got := addrIPFamily(
		stringAddr("not an ip"),
	); got != socketIPFamilyUnknown {
		t.Fatalf("addrIPFamily(invalid string) = %v, want unknown", got)
	}
}

func TestCoverageLinuxSocketOptionErrorBranches(t *testing.T) {
	badFD := ^uintptr(0)

	if err := SetBufSize(fakeRawConn{fd: badFD}, 4096); err == nil {
		t.Fatal("SetBufSize(bad fd) = nil, want error")
	}
	if _, _, err := GetBuffSize(fakeRawConn{fd: badFD}); err == nil {
		t.Fatal("GetBuffSize(bad fd) = nil, want error")
	}
	if _, err := GetRoutingMark(fakeRawConn{fd: badFD}); err == nil {
		t.Fatal("GetRoutingMark(bad fd) = nil, want error")
	}
	if err := SetTCPTimeout(fakeRawConn{fd: badFD}, time.Second); err == nil {
		t.Fatal("SetTCPTimeout(bad fd) = nil, want error")
	}
	if _, err := GetTCPRTT(fakeRawConn{fd: badFD}); err == nil {
		t.Fatal("GetTCPRTT(bad fd) = nil, want error")
	}
	if err := SetBindToInterface(
		fakeRawConn{fd: badFD},
		&gonnect.LiteralInterface{NameVal: "lo"},
	); err == nil {
		t.Fatal("SetBindToInterface(bad fd) = nil, want error")
	}
}

func TestCoverageLinuxSetBindToInterfaceUDP(t *testing.T) {
	conn, err := (&net.ListenConfig{}).ListenPacket(
		context.Background(),
		"udp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := SetBindToInterface(
		conn,
		&gonnect.LiteralInterface{NameVal: "lo"},
	); err != nil {
		t.Logf("SetBindToInterface(lo) is not available here: %v", err)
	}
}
