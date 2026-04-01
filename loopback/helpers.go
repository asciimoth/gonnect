package loopback

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
)

// loopbackNetHostTable maps network family combinations to loopback host addresses.
// The key format is "network_family+host_family" (e.g., "ip+ip4" -> "127.0.0.1").
var loopbackNetHostTable = map[string]string{
	"ip+ip":   "127.0.0.1",
	"ip+ip4":  "127.0.0.1",
	"ip+ip6":  "::1",
	"ip4+ip":  "127.0.0.1",
	"ip4+ip4": "127.0.0.1",
	"ip6+ip":  "::1",
	"ip6+ip6": "::1",
}

// loopbackNetHost2Table maps three-party network family combinations to loopback host addresses.
// The key format is "network_family+local_host_family+remote_host_family".
// This table is used for dial operations where both local and remote addresses need normalization.
var loopbackNetHost2Table = map[string]string{
	"ip+ip+ip":    "127.0.0.1",
	"ip+ip+ip4":   "127.0.0.1",
	"ip+ip4+ip":   "127.0.0.1",
	"ip+ip4+ip4":  "127.0.0.1",
	"ip4+ip+ip":   "127.0.0.1",
	"ip4+ip+ip4":  "127.0.0.1",
	"ip4+ip4+ip":  "127.0.0.1",
	"ip4+ip4+ip4": "127.0.0.1",
	"ip+ip+ip6":   "::1",
	"ip+ip6+ip":   "::1",
	"ip+ip6+ip6":  "::1",
	"ip6+ip+ip":   "::1",
	"ip6+ip+ip6":  "::1",
	"ip6+ip6+ip":  "::1",
	"ip6+ip6+ip6": "::1",
}

// loopbackDnsReqErr creates a DNSError for DNS request failures in the loopback network.
// The error indicates the host was not found and is marked as temporary.
func loopbackDnsReqErr(name string) error {
	return &net.DNSError{
		Err:         "no such host",
		Name:        name,
		Server:      "loopbackdns:53",
		IsTimeout:   false,
		IsTemporary: true,
		IsNotFound:  true,
	}
}

// loopbackPortAllocator manages dynamic port allocation for the loopback network.
// It allocates ports from the ephemeral port range (49152-65535) and tracks
// which ports are currently in use.
// WARN: Not thread safe - caller must hold appropriate locks.
type loopbackPortAllocator struct {
	next      uint16
	allocated uint16
	inUse     map[uint16]struct{}
}

// isVoid returns true if no ports have been allocated or are in use.
func (pa *loopbackPortAllocator) isVoid() bool {
	if pa.allocated > 0 {
		return false
	}
	if len(pa.inUse) > 0 {
		return false
	}
	return true
}

// reserve marks a port as used.
// Returns an EADDRINUSE error if the port is already in use.
func (pa *loopbackPortAllocator) reserve(port uint16) error {
	if pa.inUse == nil {
		pa.inUse = make(map[uint16]struct{})
	}
	_, ok := pa.inUse[port]
	if ok {
		return &os.SyscallError{
			Syscall: "bind",
			Err:     syscall.EADDRINUSE,
		}
	}
	pa.inUse[port] = struct{}{}
	if port >= 49152 {
		pa.allocated += 1
	}
	return nil
}

// free releases a port from use.
// It decrements the allocated counter if the port is in the ephemeral range.
func (pa *loopbackPortAllocator) free(port uint16) {
	if pa.inUse == nil {
		return
	}
	if _, ok := pa.inUse[port]; !ok {
		return
	}
	if port >= 49152 {
		pa.allocated -= 1
	}
	delete(pa.inUse, port)
}

// alloc allocates a port.
// If port is not nil, it reserves that specific port.
// Otherwise, it allocates the next available ephemeral port.
// Returns ECONNREFUSED if all ephemeral ports are exhausted.
func (pa *loopbackPortAllocator) alloc(port *uint16) (uint16, error) {
	if port != nil {
		err := pa.reserve(*port)
		return *port, err
	}
	if pa.inUse == nil {
		pa.inUse = make(map[uint16]struct{})
	}
	if pa.allocated >= 16382 /* 65535 - 49152 - 1 */ {
		return 0, &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.ECONNREFUSED,
		}
	}
	if pa.next < 49152 {
		pa.next = 49152
	}
	for {
		if _, ok := pa.inUse[pa.next]; !ok {
			p := pa.next
			pa.next += 1
			pa.allocated += 1
			pa.inUse[p] = struct{}{}
			return p, nil
		}
		if pa.next < 65535 {
			pa.next += 1
		} else {
			pa.next = 49152
		}
	}
}

// loopbackHostToFamily determines the IP family of a host address.
// Returns "ip4" for IPv4 addresses, "ip6" for IPv6 addresses, or "ip" for unknown.
func loopbackHostToFamily(host string) string {
	if host == "::1" || host == "::" {
		return "ip6"
	}
	if host == "127.0.0.1" || host == "0.0.0.0" {
		return "ip4"
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return "ip4"
		}
		if ip.To16() != nil {
			return "ip6"
		}
	}
	return "ip"
}

// normalizeLoopbackHosts normalizes the host addresses for a dial operation.
// It resolves the network and host family combinations to appropriate loopback addresses.
// Returns an error if any host cannot be resolved.
func normalizeLoopbackHosts(network, lhost, rhost string) (string, error) {
	lhostFam := loopbackHostToFamily(lhost)
	if lhostFam == "" {
		return "", loopbackDnsReqErr(lhost)
	}
	// If lhost is not a loopback IP or "localhost", it's not resolvable in loopback network
	if lhostFam == "ip" && !helpers.IsLocal(lhost) {
		return "", loopbackDnsReqErr(lhost)
	}
	rhostFam := loopbackHostToFamily(rhost)
	if rhostFam == "" {
		return "", loopbackDnsReqErr(rhost)
	}
	// If rhost is not a loopback IP or "localhost", it's not resolvable in loopback network
	if rhostFam == "ip" && !helpers.IsLocal(rhost) {
		return "", loopbackDnsReqErr(rhost)
	}
	netFam := helpers.FamilyFromNetwork(network)
	if netFam == "ip" {
		if lhostFam != "ip" {
			netFam = lhostFam
		} else if rhostFam != "ip" {
			netFam = rhostFam
		}
	}
	norm := loopbackNetHost2Table[netFam+"+"+lhostFam+"+"+rhostFam]
	if norm == "" {
		return "", &net.AddrError{
			Err:  "no suitable address found",
			Addr: lhost,
		}
	}
	return norm, nil
}

// normalizeLoopbackHost normalizes a single host address for a listen operation.
// It resolves the network and host family combinations to appropriate loopback addresses.
// Returns an error if the host cannot be resolved.
func normalizeLoopbackHost(network, host string) (string, error) {
	hostFam := loopbackHostToFamily(host)
	if hostFam == "" {
		return "", loopbackDnsReqErr(host)
	}
	// If host is not a loopback IP or "localhost", it's not resolvable in loopback network
	if hostFam == "ip" && !helpers.IsLocal(host) {
		return "", loopbackDnsReqErr(host)
	}
	netFam := helpers.FamilyFromNetwork(network)
	norm := loopbackNetHostTable[netFam+"+"+hostFam]
	if norm == "" {
		return "", &net.AddrError{
			Err:  "no suitable address found",
			Addr: host,
		}
	}
	return norm, nil
}

// loopbackListenPrep prepares the network and address for a listen operation.
// It normalizes the host, parses the port, and returns the host and port.
// If laddr is empty, it defaults to "localhost:".
func loopbackListenPrep(network, laddr string) (string, *uint16, error) {
	if laddr == "" {
		laddr = "localhost:"
	}

	host, portStr, err := net.SplitHostPort(laddr)
	if err != nil {
		return "", nil, err
	}

	host, err = normalizeLoopbackHost(network, host)
	if err != nil {
		return "", nil, err
	}

	var port *uint16
	if portStr != "" && portStr != "0" {
		iport, err := gonnect.LookupPortOffline(network, portStr)

		if err != nil {
			return "", nil, err
		}

		if iport < 0 || iport > 65535 {
			return "", nil, &net.AddrError{
				Err:  "invalid port",
				Addr: portStr,
			}
		}
		uport := uint16(iport)
		port = &uport
	}

	return host, port, nil
}

// loopbackDialPrep prepares the network and addresses for a dial operation.
// It normalizes both local and remote hosts, parses the ports, and returns
// the resolved host, local port (may be nil for ephemeral), and remote port.
// If laddr or raddr is empty, they default to "localhost:".
func loopbackDialPrep(
	network, laddr, raddr string,
) (string, *uint16, int, error) {
	if raddr == "" {
		raddr = "localhost:"
	}

	if laddr == "" {
		laddr = "localhost:"
	}

	// parse rhost:port
	rhost, rportStr, err := net.SplitHostPort(raddr)

	if err != nil {
		return "", nil, 0, err
	}

	lhost, lportStr, err := net.SplitHostPort(laddr)

	if err != nil {
		return "", nil, 0, err
	}

	host, err := normalizeLoopbackHosts(network, lhost, rhost)

	if err != nil {
		return "", nil, 0, err
	}

	var lport *uint16
	if lportStr != "" && lportStr != "0" {
		iport, err := gonnect.LookupPortOffline(network, lportStr)

		if err != nil {
			return "", nil, 0, err
		}
		if iport < 0 || iport > 65535 {
			return "", nil, 0, &net.AddrError{
				Err:  "invalid port",
				Addr: lportStr,
			}
		}
		uport := uint16(iport)
		lport = &uport
	}

	rport, err := gonnect.LookupPortOffline(network, rportStr)
	if err != nil {
		return "", nil, 0, err
	}
	return host, lport, rport, nil
}

// loopbackListenErrWrap wraps an error from a listen operation with network context.
// It returns an *net.OpError with the operation set to "listen".
func loopbackListenErrWrap(err error, network, laddr string) error {
	if err == nil {
		return nil
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return &net.OpError{
			Op:  "listen",
			Net: network,
			Addr: &helpers.NetAddr{
				Net:  network,
				Addr: laddr,
			},
			Err: err,
		}
	}
	return err
}

// loopbackDialErrWrap wraps an error from a dial operation with network context.
// It returns an *net.OpError with the operation set to "dial", including source and destination addresses.
// raddr can be "" for unconnected sockets.
func loopbackDialErrWrap(err error, network, laddr, raddr string) error {
	if err == nil {
		return nil
	}
	var addr net.Addr
	if raddr != "" {
		addr = &helpers.NetAddr{
			Net:  network,
			Addr: raddr,
		}
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return &net.OpError{
			Op:  "dial",
			Net: network,
			Source: &helpers.NetAddr{
				Net:  network,
				Addr: laddr,
			},
			Addr: addr,
			Err:  err,
		}
	}
	return err
}

// timerForDeadline creates a timer channel for a given deadline.
// Returns nil if the deadline is zero, or an already-expired timer if the deadline has passed.
func timerForDeadline(d time.Time) <-chan time.Time {
	if d.IsZero() {
		return nil
	}
	now := time.Now()
	if !d.After(now) {
		return time.After(0)
	}
	return time.After(time.Until(d))
}
