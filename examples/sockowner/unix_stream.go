//go:build unix

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sockowner"
)

func runUnixStreamServer(args []string) {
	fs := flag.NewFlagSet("unix-stream-server", flag.ExitOnError)
	path := fs.String(
		"path",
		"/tmp/sockowner-stream.sock",
		"Unix stream socket path",
	)
	_ = fs.Parse(args)

	_ = os.Remove(*path)

	ln, err := net.Listen("unix", *path)
	must(err)
	defer ln.Close()
	defer os.Remove(*path)

	fmt.Printf("Unix stream server listening on %s\n", *path)
	fmt.Printf("Try:\n  %s unix-stream-client -path %q\n\n", os.Args[0], *path)

	var spawner gonnect.Spawner
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("unix stream accept error: %v", err)
			continue
		}

		if spawner == nil {
			go handleUnixStreamConn(conn)
			continue
		}
		if _, err := spawner.Spawn(func() {
			handleUnixStreamConn(conn)
		}, "sockowner.unixStream"); err != nil {
			_ = conn.Close()
			log.Printf("unix stream spawn error: %v", err)
		}
	}
}

func handleUnixStreamConn(conn net.Conn) {
	defer conn.Close()

	owner, err := sockowner.GetIncomingConnOwner(conn)

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		if err != io.EOF {
			log.Printf("unix stream read error: %v", err)
		}
		return
	}

	report := Report{
		Time:       time.Now().Format(time.RFC3339Nano),
		Transport:  "unix/stream",
		LocalAddr:  addrString(conn.LocalAddr()),
		RemoteAddr: addrString(conn.RemoteAddr()),
		PayloadLen: len(line),
		Owner:      owner,
		Err:        err,
	}

	_, _ = conn.Write(prettyJSON(report))
	_, _ = conn.Write([]byte("\n"))

	logReport("unix stream request", report)
}

func runUnixStreamClient(args []string) {
	fs := flag.NewFlagSet("unix-stream-client", flag.ExitOnError)
	path := fs.String(
		"path",
		"/tmp/sockowner-stream.sock",
		"Unix stream socket path",
	)
	msg := fs.String("msg", "ping", "message to send")
	_ = fs.Parse(args)

	conn, err := net.Dial("unix", *path)
	must(err)
	defer conn.Close()

	must(conn.SetDeadline(time.Now().Add(5 * time.Second)))

	_, err = fmt.Fprintln(conn, *msg)
	must(err)

	data, err := io.ReadAll(conn)
	must(err)

	fmt.Printf("%s", data)
}
