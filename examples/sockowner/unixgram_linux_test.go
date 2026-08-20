//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestOwnerFromUnixCredentials(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	oob := unix.UnixCredentials(&unix.Ucred{
		Pid: int32(os.Getpid()),
		Uid: uid,
		Gid: gid,
	})

	owner, err := ownerFromUnixCredentials(oob)
	if err != nil {
		t.Fatalf("ownerFromUnixCredentials() error = %v", err)
	}
	if owner == nil || owner.UID == nil || *owner.UID != uid {
		t.Fatalf("UID = %#v, want %d", owner, uid)
	}
	if owner.GID == nil || *owner.GID != gid {
		t.Fatalf("GID = %#v, want %d", owner.GID, gid)
	}
	if len(owner.PIDs) != 1 || owner.PIDs[0] != os.Getpid() {
		t.Fatalf("PIDs = %v, want current pid", owner.PIDs)
	}
}

func TestOwnerFromUnixCredentialsRejectsInvalidOOB(t *testing.T) {
	_, err := ownerFromUnixCredentials(nil)
	if !errors.Is(err, sockowner.ErrNoOwner) {
		t.Fatalf(
			"ownerFromUnixCredentials(nil) error = %v, want ErrNoOwner",
			err,
		)
	}

	_, err = ownerFromUnixCredentials([]byte{1, 2, 3})
	if !errors.Is(err, sockowner.ErrNoOwner) {
		t.Fatalf(
			"ownerFromUnixCredentials(short) error = %v, want ErrNoOwner",
			err,
		)
	}
}

func TestEnablePasscred(t *testing.T) {
	path := t.TempDir() + "/dgram.sock"
	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatalf("ResolveUnixAddr() error = %v", err)
	}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("ListenUnixgram() error = %v", err)
	}
	defer conn.Close()

	if err := enablePasscred(conn); err != nil {
		t.Fatalf("enablePasscred() error = %v", err)
	}
}

func TestEnrichOwnerFromProc(t *testing.T) {
	owner := &sockowner.SocketOwner{}
	enrichOwnerFromProc(owner, os.Getpid())
	if owner.Comm == "" {
		t.Fatal("enrichOwnerFromProc() left Comm empty")
	}
}
