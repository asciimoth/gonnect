//go:build linux

package sockowner

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Linux implementation notes:
//
// This backend uses the practical dependency-free userspace method:
//
//  1. Convert FlowTuple into the hexadecimal address format used by
//     /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, or /proc/net/udp6.
//  2. Find a matching socket entry and read its UID + socket inode.
//  3. Scan /proc/<pid>/fd/* for symlinks equal to socket:[inode].
//  4. Use the first visible owning PID to fill best-effort GID, Comm,
//     and ProcName.
//
// This is intentionally best-effort:
//
//   - /proc/net/tcp* is deprecated by the kernel in favor of tcp_diag/sock_diag,
//     but it is widely available and simple to use without netlink code.
//   - sock_diag can replace step 1 later, but it still does not remove the need
//     to map socket inode to visible processes if you want PIDs.
//   - /proc/net is network-namespace-sensitive.
//   - /proc/<pid>/fd visibility is permission- and pid-namespace-sensitive.
//   - UDP may fall back to local endpoint matching when the socket is
//     unconnected and /proc/net/udp* stores remote as 0.0.0.0:0 or [::]:0.
func getSockOwner(flow FlowTuple) (*SocketOwner, error) {
	if flow.Proto != "tcp" && flow.Proto != "udp" {
		return nil, fmt.Errorf("%w: %s", ErrProtocol, flow.Proto)
	}

	family, err := flow.FlowFamily()
	if err != nil {
		return nil, err
	}

	local, err := procAddrPort(flow.LocalIP, flow.LocalPort, family)
	if err != nil {
		return nil, err
	}

	remote, err := procAddrPort(flow.RemoteIP, flow.RemotePort, family)
	if err != nil {
		return nil, err
	}

	path := procNetPath(flow.Proto, family)
	if path == "" {
		return nil, ErrNoOwner
	}

	sock, err := findProcNetSocket(path, flow.Proto, family, local, remote)
	if err != nil || sock == nil {
		return nil, err
	}

	pids := pidsForSocketInode(sock.inode)

	owner := &SocketOwner{
		PIDs: pids,
		UID:  &sock.uid,
	}

	if len(pids) > 0 {
		enrichOwnerFromPID(owner, pids[0])
	}

	return owner, nil
}

type procNetSocket struct {
	uid   uint32
	inode string
}

func findProcNetSocket(
	path, proto string,
	family int,
	local, remote string,
) (*procNetSocket, error) {
	exact, err := readProcNetMatches(path, local, remote)
	if err != nil {
		return nil, err
	}
	if len(exact) == 1 {
		return &exact[0], nil
	}
	if len(exact) > 1 {
		return nil, ErrAEx
	}

	// UDP sockets are often unconnected, so /proc/net/udp* may contain a
	// wildcard remote endpoint even though the packet has a real destination.
	if proto == "udp" {
		wildcardRemote := procZeroAddrPort(family)
		wildcard, err := readProcNetMatches(path, local, wildcardRemote)
		if err != nil {
			return nil, err
		}
		if len(wildcard) == 1 {
			return &wildcard[0], nil
		}
		if len(wildcard) > 1 {
			return nil, ErrAUW
		}
	}

	return nil, ErrNoOwner
}

func readProcNetMatches(
	path, wantLocal, wantRemote string,
) ([]procNetSocket, error) {
	// #nosec G304 -- path comes from procNetPath's fixed /proc/net allowlist.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []procNetSocket

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue // header
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)

		// Expected fields:
		//
		// 0 sl
		// 1 local_address
		// 2 rem_address
		// 3 st
		// 4 tx_queue:rx_queue
		// 5 tr:tm->when
		// 6 retrnsmt
		// 7 uid
		// 8 timeout
		// 9 inode
		if len(fields) < 10 {
			continue
		}

		gotLocal := fields[1]
		gotRemote := fields[2]
		if !strings.EqualFold(gotLocal, wantLocal) {
			continue
		}
		if !strings.EqualFold(gotRemote, wantRemote) {
			continue
		}

		inode := fields[9]
		if inode == "" || inode == "0" {
			// TIME_WAIT and some kernel-only entries may have no useful inode.
			continue
		}

		uid64, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			continue
		}

		out = append(out, procNetSocket{
			uid:   uint32(uid64),
			inode: inode,
		})
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func pidsForSocketInode(inode string) []int {
	want := "socket:[" + inode + "]"

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	seen := make(map[int]struct{})

	for _, procEntry := range procEntries {
		if !procEntry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(procEntry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", procEntry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			linkPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if target == want {
				seen[pid] = struct{}{}
				break
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	pids := make([]int, 0, len(seen))
	for pid := range seen {
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	return pids
}

func enrichOwnerFromPID(owner *SocketOwner, pid int) {
	pidStr := strconv.Itoa(pid)

	// #nosec G304 -- pidStr is produced from an int PID, not user input.
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

	if gid, ok := readEffectiveGID(pidStr); ok {
		owner.GID = &gid
	}

	// owner.Cgroup intentionally remains 0.
	//
	// /proc/<pid>/cgroup exposes hierarchy/path data, not a portable uint32.
	// If you need Linux cgroup identity, prefer changing the struct to:
	//
	//   CgroupID   uint64
	//   CgroupPath string
}

func readEffectiveGID(pidStr string) (uint32, bool) {
	// #nosec G304 -- pidStr is produced from an int PID, not user input.
	b, err := os.ReadFile(filepath.Join("/proc", pidStr, "status"))
	if err != nil {
		return 0, false
	}

	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Gid:") {
			continue
		}

		fields := strings.Fields(line)

		// Gid: real effective saved-set filesystem
		if len(fields) < 3 {
			return 0, false
		}

		gid64, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return 0, false
		}

		return uint32(gid64), true
	}

	return 0, false
}

func procNetPath(proto string, family int) string {
	switch {
	case proto == "tcp" && family == 4:
		return "/proc/net/tcp"
	case proto == "tcp" && family == 6:
		return "/proc/net/tcp6"
	case proto == "udp" && family == 4:
		return "/proc/net/udp"
	case proto == "udp" && family == 6:
		return "/proc/net/udp6"
	default:
		return ""
	}
}

func procAddrPort(ip net.IP, port uint16, family int) (string, error) {
	switch family {
	case 4:
		ip4 := ip.To4()
		if ip4 == nil {
			return "", errors.New("not IPv4")
		}

		// /proc/net/tcp stores IPv4 address as native-endian uint32 hex.
		return fmt.Sprintf(
			"%08X:%04X",
			binary.NativeEndian.Uint32(ip4),
			port,
		), nil

	case 6:
		if ip.To4() != nil {
			return "", errors.New("IPv4-mapped address passed as IPv6")
		}

		ip16 := ip.To16()
		if ip16 == nil {
			return "", errors.New("not IPv6")
		}

		// /proc/net/tcp6 stores IPv6 as four native-endian uint32 words.
		var b strings.Builder
		for i := 0; i < net.IPv6len; i += 4 {
			_, _ = fmt.Fprintf(
				&b,
				"%08X",
				binary.NativeEndian.Uint32(ip16[i:i+4]),
			)
		}
		_, _ = fmt.Fprintf(&b, ":%04X", port)

		return b.String(), nil

	default:
		return "", errors.New("unknown address family")
	}
}

func procZeroAddrPort(family int) string {
	if family == 4 {
		return "00000000:0000"
	}
	return "00000000000000000000000000000000:0000"
}
