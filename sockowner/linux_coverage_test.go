//go:build linux

//nolint:testpackage
package sockowner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFindProcNetSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	content := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		procNetTestLine("0200007F:01BB", "1000", "12345"),
		procNetTestLine("00000000:0000", "1001", "54321"),
		procNetTestLine("0200007F:01BB", "bad", "99999"),
		"   3: 0100007F:1F90 0200007F:01BB 01",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sock, err := findProcNetSocket(
		path,
		"tcp",
		4,
		"0100007F:1F90",
		"0200007F:01BB",
	)
	if err != nil {
		t.Fatalf("findProcNetSocket() error = %v", err)
	}
	if sock == nil || sock.uid != 1000 || sock.inode != "12345" {
		t.Fatalf("findProcNetSocket() = %#v, want uid 1000 inode 12345", sock)
	}

	sock, err = findProcNetSocket(
		path,
		"udp",
		4,
		"0100007F:1F90",
		"0200007F:0035",
	)
	if err != nil {
		t.Fatalf("findProcNetSocket() wildcard error = %v", err)
	}
	if sock == nil || sock.uid != 1001 || sock.inode != "54321" {
		t.Fatalf(
			"findProcNetSocket() wildcard = %#v, want uid 1001 inode 54321",
			sock,
		)
	}

	_, err = findProcNetSocket(path, "tcp", 4, "0100007F:9999", "0200007F:01BB")
	if !errors.Is(err, ErrNoOwner) {
		t.Fatalf("findProcNetSocket() error = %v, want ErrNoOwner", err)
	}
}

func TestFindProcNetSocketAmbiguous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp")
	content := "header\n" +
		procNetTestLine(
			"00000000:0000",
			"1000",
			"12345",
		) + "\n" +
		procNetTestLine(
			"00000000:0000",
			"1000",
			"54321",
		) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := findProcNetSocket(
		path,
		"udp",
		4,
		"0100007F:1F90",
		"0200007F:0035",
	)
	if !errors.Is(err, ErrAUW) {
		t.Fatalf("findProcNetSocket() error = %v, want ErrAUW", err)
	}
}

func TestFindProcNetSocketExactAmbiguous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	content := "header\n" +
		procNetTestLine("0200007F:01BB", "1000", "12345") + "\n" +
		procNetTestLine("0200007F:01BB", "1001", "54321") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := findProcNetSocket(
		path,
		"tcp",
		4,
		"0100007F:1F90",
		"0200007F:01BB",
	)
	if !errors.Is(err, ErrAEx) {
		t.Fatalf("findProcNetSocket() error = %v, want ErrAEx", err)
	}
}

func TestReadProcNetMatchesErrors(t *testing.T) {
	if _, err := readProcNetMatches(
		filepath.Join(t.TempDir(), "missing"),
		"local",
		"remote",
	); err == nil {
		t.Fatal("readProcNetMatches(missing) error = nil, want error")
	}

	path := filepath.Join(t.TempDir(), "tcp")
	content := strings.Join([]string{
		"header",
		"0: local remote 01 0 0 0 42 0 0",
		"1: local remote 01 0 0 0 43 0 123",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matches, err := readProcNetMatches(path, "local", "remote")
	if err != nil {
		t.Fatalf("readProcNetMatches() error = %v", err)
	}
	if len(matches) != 1 || matches[0].uid != 43 || matches[0].inode != "123" {
		t.Fatalf("readProcNetMatches() = %#v, want one valid match", matches)
	}
}

func TestProcOwnerHelpersCurrentProcess(t *testing.T) {
	owner := &SocketOwner{}
	enrichOwnerFromPID(owner, os.Getpid())

	if owner.Comm == "" {
		t.Fatal("enrichOwnerFromPID() left Comm empty")
	}
	if owner.GID == nil {
		t.Fatal("enrichOwnerFromPID() left GID nil")
	}

	gid, ok := readEffectiveGID(strconv.Itoa(os.Getpid()))
	if !ok {
		t.Fatal("readEffectiveGID(current pid) ok = false")
	}
	if owner.GID == nil || *owner.GID != gid {
		t.Fatalf("GID = %v, want %d", owner.GID, gid)
	}
}

func TestPidsForSocketInodeCurrentProcess(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()

	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.TCPListener", ln)
	}

	file, err := tcpLn.File()
	if err != nil {
		t.Fatalf("File() error = %v", err)
	}
	defer func() { _ = file.Close() }()

	target, err := os.Readlink(filepath.Join(
		"/proc/self/fd",
		strconv.Itoa(int(file.Fd())),
	))
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if !strings.HasPrefix(target, "socket:[") ||
		!strings.HasSuffix(target, "]") {
		t.Skipf("listener fd target is %q, not a socket inode", target)
	}

	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	pids := pidsForSocketInode(inode)
	if len(pids) == 0 {
		t.Skipf("/proc fd scan did not expose socket inode %s", inode)
	}

	want := os.Getpid()
	for _, pid := range pids {
		if pid == want {
			return
		}
	}
	t.Fatalf(
		"pidsForSocketInode(%s) = %v, want current pid %d",
		inode,
		pids,
		want,
	)
}

func TestGetSockOwnerUDPCurrentProcess(t *testing.T) {
	server, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	)
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = server.Close() }()

	serverAddr, ok := server.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"server local addr type = %T, want *net.UDPAddr",
			server.LocalAddr(),
		)
	}
	client, err := net.DialUDP(
		"udp",
		nil,
		serverAddr,
	)
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	local, ok := client.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"client local addr type = %T, want *net.UDPAddr",
			client.LocalAddr(),
		)
	}
	remote, ok := client.RemoteAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"client remote addr type = %T, want *net.UDPAddr",
			client.RemoteAddr(),
		)
	}
	localPort, ok := uint16Port(local.Port)
	if !ok {
		t.Fatalf("local port = %d, want uint16 range", local.Port)
	}
	remotePort, ok := uint16Port(remote.Port)
	if !ok {
		t.Fatalf("remote port = %d, want uint16 range", remote.Port)
	}
	owner, err := getSockOwner(FlowTuple{
		Proto:      "udp",
		LocalIP:    local.IP,
		LocalPort:  localPort,
		RemoteIP:   remote.IP,
		RemotePort: remotePort,
	})
	if errors.Is(err, ErrNoOwner) {
		t.Skip("kernel socket table did not expose UDP owner")
	}
	if err != nil &&
		strings.Contains(err.Error(), "ambiguous exact socket match") {
		t.Skipf("kernel socket table returned ambiguous UDP owner: %v", err)
	}
	if err != nil {
		t.Fatalf("getSockOwner() error = %v", err)
	}
	if owner == nil || owner.UID == nil {
		t.Fatalf("getSockOwner() = %#v, want owner with UID", owner)
	}
}

func uint16Port(port int) (uint16, bool) {
	if port < 0 || port > 0xffff {
		return 0, false
	}
	return uint16(port), true //nolint:gosec
}

func TestProcNetAddressHelpers(t *testing.T) {
	if got := procNetPath("tcp", 4); got != "/proc/net/tcp" {
		t.Fatalf("procNetPath(tcp, 4) = %q", got)
	}
	if got := procNetPath("tcp", 6); got != "/proc/net/tcp6" {
		t.Fatalf("procNetPath(tcp, 6) = %q", got)
	}
	if got := procNetPath("udp", 4); got != "/proc/net/udp" {
		t.Fatalf("procNetPath(udp, 4) = %q", got)
	}
	if got := procNetPath("udp", 6); got != "/proc/net/udp6" {
		t.Fatalf("procNetPath(udp, 6) = %q", got)
	}
	if got := procNetPath("icmp", 4); got != "" {
		t.Fatalf("procNetPath(icmp, 4) = %q, want empty", got)
	}
	if got := procZeroAddrPort(4); got != "00000000:0000" {
		t.Fatalf("procZeroAddrPort(4) = %q", got)
	}
	if got := procZeroAddrPort(
		6,
	); got != "00000000000000000000000000000000:0000" {
		t.Fatalf("procZeroAddrPort(6) = %q", got)
	}

	if _, err := procAddrPort(net.ParseIP("127.0.0.1"), 80, 4); err != nil {
		t.Fatalf("procAddrPort(ipv4) error = %v", err)
	}
	if _, err := procAddrPort(net.ParseIP("2001:db8::1"), 80, 6); err != nil {
		t.Fatalf("procAddrPort(ipv6) error = %v", err)
	}
	if _, err := procAddrPort(net.ParseIP("2001:db8::1"), 80, 4); err == nil {
		t.Fatal("procAddrPort(ipv6 as ipv4) error = nil, want error")
	}
	if _, err := procAddrPort(net.ParseIP("127.0.0.1"), 80, 6); err == nil {
		t.Fatal("procAddrPort(ipv4 as ipv6) error = nil, want error")
	}
	if _, err := procAddrPort(net.IP{1, 2, 3}, 80, 4); err == nil {
		t.Fatal("procAddrPort(invalid ip) error = nil, want error")
	}
	if _, err := procAddrPort(net.ParseIP("127.0.0.1"), 80, 0); err == nil {
		t.Fatal("procAddrPort(bad family) error = nil, want error")
	}
}

func TestReadEffectiveGID(t *testing.T) {
	if _, ok := readEffectiveGID("-1"); ok {
		t.Fatal("readEffectiveGID(-1) ok = true, want false")
	}
}

func procNetTestLine(remote, uid, inode string) string {
	return fmt.Sprintf(
		"0: %s %s 01 00000000:00000000 00:00000000 00000000 %s 0 %s",
		"0100007F:1F90",
		remote,
		uid,
		inode,
	)
}
