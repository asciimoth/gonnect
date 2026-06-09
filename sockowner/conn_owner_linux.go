//go:build linux

package sockowner

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Linux incoming-connection owner implementation.
//
// Unix-domain sockets are handled with SO_PEERCRED. This is much better than
// tuple lookup because the kernel directly reports the connected peer's PID,
// UID, and GID.
//
// TCP/UDP are not handled in this file. They fall back to IncomingConnPeerFlow
// + GetSockOwner, which uses the platform socket-table backend.
//
// SO_PEERCRED only applies to Unix-domain sockets. For TCP loopback
// connections, Linux has no equivalent "give me the peer PID" getsockopt.
func getIncomingUnixPeerOwner(conn net.Conn) (*SocketOwner, error) {
	if conn == nil {
		return nil, ErrNoOwner
	}

	// Avoid calling SO_PEERCRED on unrelated sockets. It would just fail, but
	// checking addresses keeps the intent clear and avoids surprising behavior
	// for virtual connections that happen to expose SyscallConn.
	if !addrLooksUnix(conn.LocalAddr()) && !addrLooksUnix(conn.RemoteAddr()) {
		return nil, ErrNoOwner
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, ErrNoOwner
	}

	raw, err := sysConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var cred *unix.Ucred
	var sockErr error

	err = raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	})
	if err != nil {
		return nil, err
	}
	if sockErr != nil {
		return nil, sockErr
	}
	if cred == nil {
		return nil, ErrNoOwner
	}

	owner := &SocketOwner{
		UID: &cred.Uid,
		GID: &cred.Gid,
	}

	if cred.Pid > 0 {
		pid := int(cred.Pid)
		owner.PIDs = []int{pid}

		// Reuse the helper from the Linux GetSockOwner implementation.
		// It fills Comm, ProcName, and best-effort GID from /proc/<pid>.
		enrichOwnerFromPID(owner, pid)

		// Preserve the direct SO_PEERCRED GID if /proc enrichment failed or
		// reported something unexpected.
		if owner.GID == nil && cred.Gid != 0 {
			owner.GID = &cred.Gid
		}
	}

	return owner, nil
}
