// Package helpers provides utility functions for network operations.
package helpers

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
)

var (
	ip4nets = []string{"ip4", "tcp4", "udp4"}
	ip6nets = []string{"ip6", "tcp6", "udp6"}
)

var (
	ErrNoDefaultInterface = errors.New("failed to found default interface")
)

// NetAddr is a simple implementation of net.Addr using a network string and address string.
type NetAddr struct {
	Net  string
	Addr string
}

func (na *NetAddr) Network() string {
	return na.Net
}

func (na *NetAddr) String() string {
	return na.Addr
}

// JointIPPort joins an IP address and port into a host:port string.
func JointIPPort(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

// IsTCPNetwork reports whether network is a TCP-based network (tcp, tcp4, or tcp6).
func IsTCPNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

// IsUDPNetwork reports whether network is a UDP-based network (udp, udp4, or udp6).
func IsUDPNetwork(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

// IsIPNetwork reports whether network is an IP-based network (ip, ip4, or ip6).
func IsIPNetwork(network string) bool {
	switch network {
	case "ip", "ip4", "ip6":
		return true
	default:
		return false
	}
}

// FamilyFromNetwork returns the IP family ("ip", "ip4", or "ip6") for a given network string.
// For example, "tcp", "udp", or "ip" all return "ip", while "tcp4", "udp4", "ip4" return "ip4".
func FamilyFromNetwork(network string) string {
	for _, n := range ip4nets {
		if strings.HasPrefix(network, n) {
			return "ip4"
		}
	}
	for _, n := range ip6nets {
		if strings.HasPrefix(network, n) {
			return "ip6"
		}
	}
	return "ip"
}

// NormalNet normalizes a network string by removing the IP version suffix.
// For example, "tcp4" becomes "tcp", "udp6" becomes "udp", and "ip4" becomes "ip".
func NormalNet(network string) string {
	if network == "" {
		return ""
	}
	if strings.HasSuffix(network, "4") {
		return strings.TrimRight(network, "4")
	}
	if strings.HasSuffix(network, "6") {
		return strings.TrimRight(network, "6")
	}
	return network
}

// SplitHostPort splits a host:port string into host and port components.
// If no port is present or the port is invalid, defport is used as the default.
// The network parameter is used for service name lookup via LookupPortOffline.
func SplitHostPort(
	network, hostport string,
	defport uint16,
) (host string, port uint16) {
	host, strPort, err := net.SplitHostPort(hostport)
	if err != nil {
		// There is no port in hostport, only host
		return hostport, defport
	}

	// defport will be used as port if there is no port in hostport or it is invalid.
	port = defport
	intPort, err := strconv.Atoi(strPort)
	if err != nil {
		intPort, err = gonnect.LookupPortOffline(network, strPort)
	}
	if err == nil && intPort <= math.MaxUint16 && intPort >= 0 {
		port = uint16(intPort) //nolint
	}

	return host, port
}

// PickIP selects an IP address from the given list based on preference.
// If prefer is 4, IPv4 addresses are preferred; if 6, IPv6 addresses are preferred.
// If no preference is specified (prefer != 4 && prefer != 6), a random IP is returned.
// If the preferred family is not available, an IP from the other family is returned.
func PickIP(ips []net.IP, prefer int) net.IP {
	if len(ips) < 1 {
		return nil
	}

	// No specific preferences.
	// Just selecting a random one
	if prefer != 4 && prefer != 6 {
		return ips[rand.Intn(len(ips))] //nolint gosec
	}

	var pool4 = make([]net.IP, 0, len(ips))
	var pool6 = make([]net.IP, 0, len(ips))
	var prefOccur bool

	for _, ip := range ips {
		if ip.To4() != nil {
			switch prefer {
			case 4:
				prefOccur = true
			case 6:
				if prefOccur {
					continue
				}
			}
			pool4 = append(pool4, ip)
		} else {
			switch prefer {
			case 6:
				prefOccur = true
			case 4:
				if prefOccur {
					continue
				}
			}
			pool6 = append(pool6, ip)
		}
	}

	var pool []net.IP
	if prefOccur {
		switch prefer {
		case 4:
			pool = pool4
		case 6:
			pool = pool6
		}
	} else {
		switch prefer {
		case 4:
			pool = pool6
		case 6:
			pool = pool4
		}
	}

	return pool[rand.Intn(len(pool))] //nolint gosec
}

// ReadNullTerminatedString reads bytes from r until a null byte (0x00) is encountered.
// It returns the resulting string (excluding the null terminator).
// An error is returned if the string exceeds buf's capacity or if reading fails.
func ReadNullTerminatedString(r io.Reader, buf []byte) (string, error) {
	// Should be cap(buf) >= 1
	buf = buf[:1]
	for {
		n, err := r.Read(buf[len(buf)-1:])
		if err != nil {
			return "", err
		}
		if n > 0 {
			if buf[len(buf)-1] == 0 {
				buf = buf[:len(buf)-1]
				break
			}
			if len(buf) == cap(buf) {
				return "", errors.New("string is too long")
			}
			buf = buf[:len(buf)+1] // grow
		}
	}
	return string(buf), nil
}

// ClosedNetworkErrToNil returns nil if err represents a closed network connection error.
// It unwraps err to find the root cause and checks for common closed connection messages.
// Returns the original error if it is not a closed connection error.
func ClosedNetworkErrToNil(err error) error {
	var unwrapped = err
	for {
		u := errors.Unwrap(unwrapped)
		if u == nil {
			break
		}
		unwrapped = u
	}
	if unwrapped != nil {
		str := unwrapped.Error()
		if str == "use of closed network connection" || str == "EOF" ||
			str == "unexpected EOF" ||
			str == "io: read/write on closed pipe" {
			return nil
		}
	}
	return err
}

// ReadUntilClose reads from rc until an error occurs, then closes rc.
// This function is useful for draining a connection before closing it.
func ReadUntilClose(rc io.ReadCloser) {
	// Try to read until read fails, close rc, returns
	defer func() { _ = rc.Close() }()
	b := []byte{0}
	for {
		_, err := rc.Read(b)
		if err != nil {
			return
		}
	}
}

// AddrsSameHost reports whether a and b represent addresses on the same host.
// It compares IP addresses for TCP/UDP addr types, or host strings for other types.
// Port numbers are ignored in the comparison.
func AddrsSameHost(a, b net.Addr) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch aa := a.(type) {
	case *net.TCPAddr:
		if bb, ok := b.(*net.TCPAddr); ok {
			return IpEqual(aa.IP, bb.IP)
		}
	case *net.UDPAddr:
		if bb, ok := b.(*net.UDPAddr); ok {
			return IpEqual(aa.IP, bb.IP)
		}
	}

	ahost := a.String()
	bhost := b.String()

	if host, _, err := net.SplitHostPort(ahost); err == nil {
		ahost = host
	}
	if host, _, err := net.SplitHostPort(bhost); err == nil {
		bhost = host
	}

	return ahost == bhost
}

// AddrsEq reports whether a and b are equal addresses (same host and port).
// It compares IP addresses and ports for TCP/UDP addr types, or string representation for other types.
func AddrsEq(a, b net.Addr) bool {
	// Fast net.Addr comparison
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch aa := a.(type) {
	case *net.TCPAddr:
		if bb, ok := b.(*net.TCPAddr); ok {
			return tcpUDPAddrEqual(aa.IP, aa.Port, bb.IP, bb.Port)
		}
	case *net.UDPAddr:
		if bb, ok := b.(*net.UDPAddr); ok {
			return tcpUDPAddrEqual(aa.IP, aa.Port, bb.IP, bb.Port)
		}
	}

	// Fallback: compare string representation
	return a.String() == b.String()
}

// IpEqual reports whether a and b are equal IP addresses.
// Nil IPs are considered equal to each other, and not equal to non-nil IPs.
func IpEqual(a, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

// tcpUDPAddrEqual compares IP addresses and ports for equality.
func tcpUDPAddrEqual(aIP net.IP, aPort int, bIP net.IP, bPort int) bool {
	if aPort != bPort {
		return false
	}
	return IpEqual(aIP, bIP)
}

// CheckURLBoolKey checks if a key exists in a URL values map and interprets its value as a boolean.
// It returns two booleans: f is true if the key exists with a truthy value, s is true if the key exists at all.
// Truthy values include: "true", "yes", "ok", "1", or an empty string.
func CheckURLBoolKey(values map[string][]string, key string) (f bool, s bool) {
	val, ok := values[key]
	if ok {
		if len(val) == 0 {
			return true, true
		}
		v := val[0]
		return v == "true" || v == "yes" || v == "ok" || v == "1" ||
			v == "", true
	}
	return false, false
}

type withMultipathTCP interface {
	MultipathTCP() (bool, error)
}

// MultipathTCP reports whether the connection uses Multipath TCP (MPTCP).
// It checks if the connection implements the withMultipathTCP interface,
// or unwraps the connection to find one that does.
func MultipathTCP(c net.Conn) (bool, error) {
	if wm, ok := c.(withMultipathTCP); ok {
		return wm.MultipathTCP()
	}
	u := gonnect.GetWrapped(c)
	if c, ok := u.(net.Conn); ok {
		return MultipathTCP(c)
	}
	return false, nil
}

type withSyscall interface {
	SyscallConn() (syscall.RawConn, error)
}

// SyscallConn returns the underlying syscall.RawConn from a connection.
// It checks if the value implements the withSyscall interface,
// or unwraps the value to find one that does.
// Returns nil if the value is nil or doesn't implement the interface.
func SyscallConn(a any) (syscall.RawConn, error) {
	if a == nil {
		return nil, nil //nolint nilnil
	}
	if ws, ok := a.(withSyscall); ok {
		return ws.SyscallConn()
	}
	return SyscallConn(gonnect.GetWrapped(a))
}

type withFile interface {
	File() (f *os.File, err error)
}

// File returns the underlying *os.File from a connection.
// It checks if the value implements the withFile interface,
// or unwraps the value to find one that does.
// Returns nil if the value is nil or doesn't implement the interface.
func File(a any) (f *os.File, err error) {
	if a == nil {
		return nil, nil //nolint gosec
	}
	if wf, ok := a.(withFile); ok {
		return wf.File()
	}
	return File(gonnect.GetWrapped(a))
}

func joinNetErrors(a, b error) (err error) {
	a = ClosedNetworkErrToNil(a)
	b = ClosedNetworkErrToNil(b)
	switch {
	case a != nil && b == nil:
		err = a
	case b != nil && a == nil:
		err = b
	case a != nil && b != nil:
		err = errors.Join(a, b)
	}
	return
}

// PipeConn copies data bidirectionally between two connections.
//
// PipeConn establishes a full-duplex pipe between two connections,
// copying data from inc->out and out->inc concurrently. It blocks until
// both directions complete or an error occurs
// and returns the first error encountered (if any).
func PipeConn(inc, out net.Conn) (err error) {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(inc, out)
		_ = inc.Close()
		_ = out.Close()
		done <- ClosedNetworkErrToNil(err)
	}()

	_, err = io.Copy(out, inc)
	_ = inc.Close()
	_ = out.Close()

	return joinNetErrors(err, <-done)
}

// PipePacketConn copies packets bidirectionally between two packet connections.
//
// PipePacketConn establishes a full-duplex pipe between two packet connections,
// copying packets from inc->out and out->inc concurrently. Unlike PipeConn,
// this function preserves packet boundaries by reading and writing individual
// datagrams. It blocks until both directions complete or an error occurs
// and returns the first error encountered (if any).
func PipePacketConn(
	inc, out net.PacketConn,
	bufSize int,
	pool bufpool.Pool,
) (err error) {
	done := make(chan error, 1)
	go func() {
		_, err := CopyPacket(inc, out, bufSize, pool)
		_ = inc.Close()
		_ = out.Close()
		done <- ClosedNetworkErrToNil(err)
	}()

	_, err = CopyPacket(out, inc, bufSize, pool)
	_ = inc.Close()
	_ = out.Close()

	return joinNetErrors(err, <-done)
}

// CopyPacket copies packets from src to dst, preserving packet boundaries.
// It reads individual datagrams from src and writes them to dst.
// bufSize specifies the buffer size to use, and pool is used for buffer allocation.
func CopyPacket(
	dst, src net.PacketConn,
	bufSize int,
	pool bufpool.Pool,
) (written int64, err error) {
	buf := bufpool.GetBuffer(pool, bufSize)
	defer bufpool.PutBuffer(pool, buf)
	for {
		n, addr, readErr := src.ReadFrom(buf)
		if readErr != nil {
			return written, readErr
		}
		if n > 0 {
			_, writeErr := dst.WriteTo(buf[:n], addr)
			if writeErr != nil {
				return written, writeErr
			}
			written += int64(n)
		}
	}
}

// IsLocal reports whether addr is a local address ("localhost" or a loopback IP).
// It returns true for "localhost", "127.0.0.1", "::1", or any IP in the 127.0.0.0/8 range.
func IsLocal(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func NetworkFromConn(c net.Conn) string {
	la := c.LocalAddr()
	if la != nil {
		return la.Network()
	}
	ra := c.RemoteAddr()
	if ra != nil {
		return ra.Network()
	}
	if _, ok := c.(net.PacketConn); ok {
		return "udp"
	}
	return "tcp"
}

func CloseAll(closers []io.Closer) {
	for _, c := range closers {
		_ = c.Close()
	}
}

type NetDefIface interface {
	Dial(
		ctx context.Context,
		network, address string,
	) (net.Conn, error)
	Interfaces() ([]gonnect.NetworkInterface, error)
}

func DefaultInterface(
	ctx context.Context,
	n NetDefIface,
) (gonnect.NetworkInterface, error) {
	// Dirty hack but somehow it is a de-facto standard way to do it
	var laddr *net.UDPAddr
	addrs := []struct {
		Net  string
		Addr string
	}{
		// TODO: More addrs
		{"udp4", "8.8.8.8:53"},
		{"udp4", "8.8.4.4:53"},
		{"udp4", "1.1.1.1:53"},
		{"udp4", "1.0.0.1:53"},
		{"udp4", "9.9.9.9:53"},

		{"udp6", "2001:4860:4860::8888:53"},
		{"udp6", "2001:4860:4860::8844:53"},
		{"udp6", "2606:4700:4700::1111:53"},
		{"udp6", "2606:4700:4700::1001:53"},
		{"udp6", "2620:fe::fe:53"},
		{"udp6", "2620:fe::9:53"},
	}
	for _, addr := range addrs {
		c, err := n.Dial(ctx, addr.Net, addr.Addr)
		if err != nil {
			return nil, err
		}
		if l, ok := c.LocalAddr().(*net.UDPAddr); ok && l != nil {
			laddr = l
			_ = c.Close()
			break
		}
		_ = c.Close()
	}
	if laddr == nil {
		return nil, ErrNoDefaultInterface
	}

	ifaces, err := n.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPNet); ok {
				if ip.Contains(laddr.IP) {
					return iface, nil
				}
			}
		}
	}
	return nil, ErrNoDefaultInterface
}
