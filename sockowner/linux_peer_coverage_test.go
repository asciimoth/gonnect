//go:build linux

//nolint:testpackage
package sockowner

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestGetIncomingUnixPeerOwnerEarlyReturns(t *testing.T) {
	_, err := getIncomingUnixPeerOwner(nil)
	if !errors.Is(err, ErrNoOwner) {
		t.Fatalf(
			"getIncomingUnixPeerOwner(nil) error = %v, want ErrNoOwner",
			err,
		)
	}

	_, err = getIncomingUnixPeerOwner(testConn{
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1},
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2},
	})
	if !errors.Is(err, ErrNoOwner) {
		t.Fatalf(
			"getIncomingUnixPeerOwner(tcp) error = %v, want ErrNoOwner",
			err,
		)
	}

	_, err = getIncomingUnixPeerOwner(testConn{
		local:  &net.UnixAddr{Name: "a", Net: "unix"},
		remote: &net.UnixAddr{Name: "b", Net: "unix"},
	})
	if !errors.Is(err, ErrNoOwner) {
		t.Fatalf(
			"getIncomingUnixPeerOwner(no syscall) error = %v, want ErrNoOwner",
			err,
		)
	}
}

func TestGetIncomingUnixPeerOwnerSyscallConnError(t *testing.T) {
	sysErr := errors.New("syscall conn")
	_, err := getIncomingUnixPeerOwner(syscallErrorConn{
		testConn: testConn{
			local:  &net.UnixAddr{Name: "a", Net: "unix"},
			remote: &net.UnixAddr{Name: "b", Net: "unix"},
		},
		err: sysErr,
	})
	if !errors.Is(err, sysErr) {
		t.Fatalf(
			"getIncomingUnixPeerOwner() error = %v, want syscall error",
			err,
		)
	}
}

func TestGetIncomingUnixPeerOwnerUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Skipf("skip Unix socket peer owner test: listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	acceptCh := make(chan *net.UnixConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptUnix()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conn
	}()

	client, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Skipf("skip Unix socket peer owner test: dial failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	var server *net.UnixConn
	select {
	case server = <-acceptCh:
		defer func() { _ = server.Close() }()
	case err := <-errCh:
		t.Skipf("skip Unix socket peer owner test: accept failed: %v", err)
	}

	owner, err := getIncomingUnixPeerOwner(server)
	if err != nil {
		t.Skipf("skip Unix socket peer owner test: peer lookup failed: %v", err)
	}
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())
	if owner == nil || owner.UID == nil ||
		strconv.FormatUint(uint64(*owner.UID), 10) != uid {
		t.Fatalf("owner UID = %#v, want current UID %d", owner, os.Getuid())
	}
	if owner.GID == nil || strconv.FormatUint(uint64(*owner.GID), 10) != gid {
		t.Fatalf("owner GID = %#v, want current GID %d", owner, os.Getgid())
	}
	if len(owner.PIDs) == 0 {
		t.Fatalf("owner PIDs = %#v, want current peer PID", owner.PIDs)
	}
}

type syscallErrorConn struct {
	testConn
	err error
}

func (c syscallErrorConn) SyscallConn() (syscall.RawConn, error) {
	return nil, c.err
}
