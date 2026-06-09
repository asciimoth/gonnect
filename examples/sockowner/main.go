// nolint
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/asciimoth/gonnect/sockowner"
)

type ctxKey string

const connInfoKey ctxKey = "conn-info"

type ConnInfo struct {
	LocalAddr  string                 `json:"local_addr,omitempty"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
	Owner      *sockowner.SocketOwner `json:"owner,omitempty"`

	Err error `json:"err,omitempty"`
}

type Report struct {
	Time       string                 `json:"time"`
	Transport  string                 `json:"transport"`
	LocalAddr  string                 `json:"local_addr,omitempty"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
	Method     string                 `json:"method,omitempty"`
	Path       string                 `json:"path,omitempty"`
	PayloadLen int                    `json:"payload_len,omitempty"`
	Owner      *sockowner.SocketOwner `json:"owner,omitempty"`
	Err        error                  `json:"err,omitempty"`
	Note       string                 `json:"note,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "http":
		runHTTP(os.Args[2:])
	case "udp-server":
		runUDPServer(os.Args[2:])
	case "udp-client":
		runUDPClient(os.Args[2:])
	case "unix-stream-server":
		runUnixStreamServer(os.Args[2:])
	case "unix-stream-client":
		runUnixStreamClient(os.Args[2:])
	case "unixgram-server":
		runUnixgramServer(os.Args[2:])
	case "unixgram-client":
		runUnixgramClient(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:

  %[1]s http                 [-addr 127.0.0.1:0]
  %[1]s udp-server           [-addr 127.0.0.1:0]
  %[1]s udp-client           -addr 127.0.0.1:PORT [-msg ping]

  %[1]s unix-stream-server   [-path /tmp/sockowner-stream.sock]
  %[1]s unix-stream-client   [-path /tmp/sockowner-stream.sock] [-msg ping]

  %[1]s unixgram-server      [-path /tmp/sockowner-dgram.sock]
  %[1]s unixgram-client      [-path /tmp/sockowner-dgram.sock] [-msg ping]

Notes:

  - TCP/UDP owner lookup is best-effort and uses the peer-side flow tuple.
  - Unix stream owner lookup uses SO_PEERCRED through sockowner.GetIncomingConnOwner.
  - Unix datagram owner lookup uses Linux SO_PASSCRED + SCM_CREDENTIALS.
  - For UDP demos, bind to a concrete address like 127.0.0.1, not 0.0.0.0,
    otherwise the socket-table tuple may not match the client socket.

`, os.Args[0])
}

func runHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "TCP listen address")
	_ = fs.Parse(args)

	ln, err := net.Listen("tcp", *addr)
	must(err)
	defer ln.Close()

	actualAddr := ln.Addr().String()
	curlURL := "http://" + printableTCPAddr(actualAddr) + "/"

	fmt.Printf("HTTP server listening on %s\n", actualAddr)
	fmt.Printf("Try:\n  curl -s %q | jq .\n\n", curlURL)

	srv := &http.Server{
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			owner, err := sockowner.GetIncomingConnOwner(conn)

			info := ConnInfo{
				LocalAddr:  addrString(conn.LocalAddr()),
				RemoteAddr: addrString(conn.RemoteAddr()),
				Owner:      owner,
				Err:        err,
			}

			return context.WithValue(ctx, connInfoKey, info)
		},

		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, _ := r.Context().Value(connInfoKey).(ConnInfo)

			report := Report{
				Time:       time.Now().Format(time.RFC3339Nano),
				Transport:  "http/tcp",
				LocalAddr:  info.LocalAddr,
				RemoteAddr: info.RemoteAddr,
				Method:     r.Method,
				Path:       r.URL.RequestURI(),
				Owner:      info.Owner,
				Err:        info.Err,
			}

			writeHTTPJSON(w, report)
			logReport("http request", report)
		}),
	}

	must(srv.Serve(ln))
}

func writeHTTPJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(prettyJSON(v))
	_, _ = w.Write([]byte("\n"))
}

func runUDPServer(args []string) {
	fs := flag.NewFlagSet("udp-server", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "UDP listen address")
	_ = fs.Parse(args)

	laddr, err := net.ResolveUDPAddr("udp", *addr)
	must(err)

	conn, err := net.ListenUDP("udp", laddr)
	must(err)
	defer conn.Close()

	actualAddr := conn.LocalAddr().String()

	fmt.Printf("UDP server listening on %s\n", actualAddr)
	fmt.Printf("Try:\n  %s udp-client -addr %q\n\n", os.Args[0], actualAddr)

	buf := make([]byte, 64*1024)

	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("udp read error: %v", err)
			continue
		}

		local, _ := conn.LocalAddr().(*net.UDPAddr)
		owner, err := udpPeerOwner(local, peer)

		report := Report{
			Time:       time.Now().Format(time.RFC3339Nano),
			Transport:  "udp",
			LocalAddr:  addrString(local),
			RemoteAddr: addrString(peer),
			PayloadLen: n,
			Owner:      owner,
			Err:        err,
		}

		reply := prettyJSON(report)
		if _, err := conn.WriteToUDP(reply, peer); err != nil {
			log.Printf("udp write error to %s: %v", peer, err)
		}

		logReport("udp packet", report)
	}
}

func runUDPClient(args []string) {
	fs := flag.NewFlagSet("udp-client", flag.ExitOnError)
	addr := fs.String("addr", "", "UDP server address")
	msg := fs.String("msg", "ping", "message to send")
	_ = fs.Parse(args)

	if *addr == "" {
		fatalf("-addr is required")
	}

	raddr, err := net.ResolveUDPAddr("udp", *addr)
	must(err)

	conn, err := net.DialUDP("udp", nil, raddr)
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

func udpPeerOwner(
	serverLocal, peer *net.UDPAddr,
) (*sockowner.SocketOwner, error) {
	if serverLocal == nil || peer == nil {
		return nil, sockowner.ErrNoOwner
	}

	serverIP := normalizeServerIP(serverLocal.IP, peer.IP)

	flow := sockowner.FlowTuple{
		Proto: "udp",

		// Reversed on purpose:
		// local endpoint of the socket we want = packet sender/client.
		LocalIP:   peer.IP,
		LocalPort: uint16(peer.Port),

		// remote endpoint from client socket perspective = server endpoint.
		RemoteIP:   serverIP,
		RemotePort: uint16(serverLocal.Port),
	}

	return sockowner.GetSockOwner(flow)
}

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

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("unix stream accept error: %v", err)
			continue
		}

		go handleUnixStreamConn(conn)
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

func prettyJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	return b
}

func logReport(prefix string, report Report) {
	log.Printf("%s:\n%s", prefix, prettyJSON(report))
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func printableTCPAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}

	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}

	return host + ":" + port
}

func normalizeServerIP(serverIP, peerIP net.IP) net.IP {
	if serverIP != nil && !serverIP.IsUnspecified() {
		return serverIP
	}

	// Best demo fallback for servers accidentally bound to wildcard.
	// Prefer binding the server to 127.0.0.1 or ::1 explicitly.
	if peerIP != nil && peerIP.IsLoopback() {
		if peerIP.To4() != nil {
			return net.ParseIP("127.0.0.1")
		}
		return net.ParseIP("::1")
	}

	return serverIP
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

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
