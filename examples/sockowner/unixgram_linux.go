//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/asciimoth/gonnect/sockowner"
)

func runUnixgramServer(args []string) {
	fs := flag.NewFlagSet("unixgram-server", flag.ExitOnError)
	path := fs.String(
		"path",
		"/tmp/sockowner-dgram.sock",
		"Unix datagram socket path",
	)
	_ = fs.Parse(args)

	_ = os.Remove(*path)

	laddr, err := net.ResolveUnixAddr("unixgram", *path)
	must(err)

	conn, err := net.ListenUnixgram("unixgram", laddr)
	must(err)
	defer conn.Close()
	defer os.Remove(*path)

	must(enablePasscred(conn))

	fmt.Printf("Unix datagram server listening on %s\n", *path)
	fmt.Printf("Try:\n  %s unixgram-client -path %q\n\n", os.Args[0], *path)

	buf := make([]byte, 64*1024)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))

	for {
		n, oobn, _, peer, err := conn.ReadMsgUnix(buf, oob)
		if err != nil {
			log.Printf("unixgram read error: %v", err)
			continue
		}

		owner, err := ownerFromUnixCredentials(oob[:oobn])

		report := Report{
			Time:       time.Now().Format(time.RFC3339Nano),
			Transport:  "unix/datagram",
			LocalAddr:  addrString(conn.LocalAddr()),
			RemoteAddr: addrString(peer),
			PayloadLen: n,
			Owner:      owner,
			Err:        err,
		}

		if owner == nil {
			report.Note = "no SCM_CREDENTIALS received; SO_PASSCRED may be unsupported or disabled"
		}

		reply := prettyJSON(report)

		if peer != nil {
			if _, err := conn.WriteToUnix(reply, peer); err != nil {
				log.Printf("unixgram write error to %s: %v", peer, err)
			}
		} else {
			log.Printf("unixgram packet has no peer address; cannot reply")
		}

		logReport("unix datagram packet", report)
	}
}

func runUnixgramClient(args []string) {
	fs := flag.NewFlagSet("unixgram-client", flag.ExitOnError)
	path := fs.String(
		"path",
		"/tmp/sockowner-dgram.sock",
		"Unix datagram server socket path",
	)
	msg := fs.String("msg", "ping", "message to send")
	_ = fs.Parse(args)

	raddr, err := net.ResolveUnixAddr("unixgram", *path)
	must(err)

	clientPath := filepath.Join(
		os.TempDir(),
		fmt.Sprintf(
			"sockowner-dgram-client-%d-%d.sock",
			os.Getpid(),
			time.Now().UnixNano(),
		),
	)

	_ = os.Remove(clientPath)
	defer os.Remove(clientPath)

	laddr, err := net.ResolveUnixAddr("unixgram", clientPath)
	must(err)

	conn, err := net.DialUnix("unixgram", laddr, raddr)
	must(err)
	defer conn.Close()

	must(conn.SetDeadline(time.Now().Add(5 * time.Second)))

	_, err = conn.Write([]byte(*msg))
	must(err)

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	must(err)

	fmt.Printf("%s\n", buf[:n])
}

func enablePasscred(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error

	err = raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PASSCRED,
			1,
		)
	})
	if err != nil {
		return err
	}

	return sockErr
}

func ownerFromUnixCredentials(oob []byte) (*sockowner.SocketOwner, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, sockowner.ErrNoOwner
	}

	for _, msg := range msgs {
		cred, err := unix.ParseUnixCredentials(&msg)
		if err != nil || cred == nil {
			continue
		}

		owner := &sockowner.SocketOwner{
			UID: &cred.Uid,
			GID: &cred.Gid,
		}

		if cred.Pid > 0 {
			pid := int(cred.Pid)
			owner.PIDs = []int{pid}
			enrichOwnerFromProc(owner, pid)
		}

		return owner, nil
	}

	return nil, sockowner.ErrNoOwner
}

func enrichOwnerFromProc(owner *sockowner.SocketOwner, pid int) {
	pidStr := strconv.Itoa(pid)

	if b, err := os.ReadFile(
		filepath.Join("/proc", pidStr, "comm"),
	); err == nil {
		owner.Comm = strings.TrimSpace(string(b))
	}

	if exe, err := os.Readlink(
		filepath.Join("/proc", pidStr, "exe"),
	); err == nil {
		owner.ProcName = filepath.Base(exe)
	}
}
