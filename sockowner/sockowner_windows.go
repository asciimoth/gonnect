//go:build windows

package sockowner

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

// Windows implementation notes:
//
// This backend follows the same shape used by sing-box and Xray:
//
//  1. Query the IP Helper API owner tables with GetExtendedTcpTable or
//     GetExtendedUdpTable.
//  2. Match the flow tuple against the table rows.
//  3. Use the owning PID to fill SocketOwner, and best-effort resolve the
//     executable basename with QueryFullProcessImageName.
//
// The Windows UDP owner table does not expose a remote endpoint, so UDP lookup
// matches only the local address and port.
func getSockOwner(flow FlowTuple) (*SocketOwner, error) {
	if flow.Proto != "tcp" && flow.Proto != "udp" {
		return nil, fmt.Errorf("%w: %s", ErrProtocol, flow.Proto)
	}

	family, err := flow.FlowFamily()
	if err != nil {
		return nil, err
	}

	var pid uint32
	switch flow.Proto {
	case "tcp":
		pid, err = findWindowsTCPOwnerPID(flow, family)
	case "udp":
		pid, err = findWindowsUDPOwnerPID(flow, family)
	}
	if err != nil {
		return nil, err
	}

	owner := &SocketOwner{PIDs: []int{int(pid)}} //nolint:gosec
	enrichWindowsOwnerFromPID(owner, pid)

	return owner, nil
}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func findWindowsTCPOwnerPID(flow FlowTuple, family int) (uint32, error) {
	buf, err := getExtendedTCPTableBuffer(family)
	if err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, ErrNoOwner
	}

	count, ok := windowsTableRowCount[mibTCPRowOwnerPID](buf)
	if !ok {
		return 0, ErrNoOwner
	}
	rowsPtr := unsafe.Pointer(&buf[4])

	switch family {
	case 4:
		localIP := binary.LittleEndian.Uint32(flow.LocalIP.To4())
		remoteIP := binary.LittleEndian.Uint32(flow.RemoteIP.To4())
		rows := unsafe.Slice((*mibTCPRowOwnerPID)(rowsPtr), count)

		for _, row := range rows {
			if row.LocalAddr == localIP &&
				windowsPort(row.LocalPort) == flow.LocalPort &&
				row.RemoteAddr == remoteIP &&
				windowsPort(row.RemotePort) == flow.RemotePort {
				return row.OwningPID, nil
			}
		}

	case 6:
		localIP := ip16Array(flow.LocalIP)
		remoteIP := ip16Array(flow.RemoteIP)
		count, ok := windowsTableRowCount[mibTCP6RowOwnerPID](buf)
		if !ok {
			return 0, ErrNoOwner
		}
		rows := unsafe.Slice((*mibTCP6RowOwnerPID)(rowsPtr), count)

		for _, row := range rows {
			if row.LocalAddr == localIP &&
				windowsPort(row.LocalPort) == flow.LocalPort &&
				row.RemoteAddr == remoteIP &&
				windowsPort(row.RemotePort) == flow.RemotePort {
				return row.OwningPID, nil
			}
		}
	}

	return 0, ErrNoOwner
}

func findWindowsUDPOwnerPID(flow FlowTuple, family int) (uint32, error) {
	buf, err := getExtendedUDPTableBuffer(family)
	if err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, ErrNoOwner
	}

	count, ok := windowsTableRowCount[mibUDPRowOwnerPID](buf)
	if !ok {
		return 0, ErrNoOwner
	}
	rowsPtr := unsafe.Pointer(&buf[4])

	switch family {
	case 4:
		rows := unsafe.Slice((*mibUDPRowOwnerPID)(rowsPtr), count)
		return findWindowsUDP4OwnerPID(flow, rows)

	case 6:
		count, ok := windowsTableRowCount[mibUDP6RowOwnerPID](buf)
		if !ok {
			return 0, ErrNoOwner
		}
		rows := unsafe.Slice((*mibUDP6RowOwnerPID)(rowsPtr), count)
		return findWindowsUDP6OwnerPID(flow, rows)
	}

	return 0, ErrNoOwner
}

func findWindowsUDP4OwnerPID(
	flow FlowTuple,
	rows []mibUDPRowOwnerPID,
) (uint32, error) {
	localIP := binary.LittleEndian.Uint32(flow.LocalIP.To4())

	var pid uint32
	matched := false
	for _, row := range rows {
		if row.LocalAddr == localIP &&
			windowsPort(row.LocalPort) == flow.LocalPort {
			if matched && row.OwningPID != pid {
				return 0, ErrAUW
			}
			pid = row.OwningPID
			matched = true
		}
	}
	if matched {
		return pid, nil
	}

	return 0, ErrNoOwner
}

func findWindowsUDP6OwnerPID(
	flow FlowTuple,
	rows []mibUDP6RowOwnerPID,
) (uint32, error) {
	localIP := ip16Array(flow.LocalIP)

	var pid uint32
	matched := false
	for _, row := range rows {
		if row.LocalAddr == localIP &&
			windowsPort(row.LocalPort) == flow.LocalPort {
			if matched && row.OwningPID != pid {
				return 0, ErrAUW
			}
			pid = row.OwningPID
			matched = true
		}
	}
	if matched {
		return pid, nil
	}

	return 0, ErrNoOwner
}

func getExtendedTCPTableBuffer(family int) ([]byte, error) {
	return getExtendedIPTableBuffer(
		procGetExtendedTcpTable,
		family,
		tcpTableOwnerPIDAll,
	)
}

func getExtendedUDPTableBuffer(family int) ([]byte, error) {
	return getExtendedIPTableBuffer(
		procGetExtendedUdpTable,
		family,
		udpTableOwnerPID,
	)
}

func getExtendedIPTableBuffer(
	proc *windows.LazyProc,
	family int,
	tableClass uint32,
) ([]byte, error) {
	af, err := windowsAddressFamily(family)
	if err != nil {
		return nil, err
	}

	var size uint32
	r1, _, _ := proc.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(af),
		uintptr(tableClass),
		0,
	)
	if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r1 != 0 {
		return nil, windows.Errno(r1)
	}
	if size == 0 {
		return nil, ErrNoOwner
	}

	buf := make([]byte, size)
	r1, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(af),
		uintptr(tableClass),
		0,
	)
	if r1 != 0 {
		return nil, windows.Errno(r1)
	}

	return buf[:size], nil
}

func windowsAddressFamily(family int) (uint32, error) {
	switch family {
	case 4:
		return windows.AF_INET, nil
	case 6:
		return windows.AF_INET6, nil
	default:
		return 0, ErrInvIP
	}
}

func windowsTableRowCount[T any](buf []byte) (int, bool) {
	if len(buf) < 4 {
		return 0, false
	}

	count64 := uint64(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := uint64(unsafe.Sizeof(*new(T)))
	if rowSize == 0 || count64 > uint64(^uint(0)>>1) {
		return 0, false
	}
	if count64*rowSize > uint64(len(buf)-4) {
		return 0, false
	}

	return int(count64), true
}

func windowsPort(port uint32) uint16 {
	return binary.BigEndian.Uint16((*[4]byte)(unsafe.Pointer(&port))[:2])
}

func ip16Array(ip net.IP) [16]byte {
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

func enrichWindowsOwnerFromPID(owner *SocketOwner, pid uint32) {
	name, err := windowsProcessImageName(pid)
	if err != nil {
		return
	}

	owner.ProcName = filepath.Base(name)
}

func windowsProcessImageName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	for size := uint32(windows.MAX_PATH); size <= 32768; size *= 2 {
		buf := make([]uint16, size)
		n := size
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", err
		}
	}

	return "", windows.ERROR_INSUFFICIENT_BUFFER
}
