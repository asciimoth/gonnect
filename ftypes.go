package gonnect

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"
)

// Static type assertions
var (
	_ Dial         = (&net.Dialer{}).DialContext
	_ Listen       = (&net.ListenConfig{}).Listen
	_ LookupIP     = (&net.Resolver{}).LookupIP
	_ LookupIPAddr = (&net.Resolver{}).LookupIPAddr
	_ LookupNetIP  = (&net.Resolver{}).LookupNetIP
	_ LookupHost   = (&net.Resolver{}).LookupHost
	_ LookupAddr   = (&net.Resolver{}).LookupAddr
	_ LookupCNAME  = (&net.Resolver{}).LookupCNAME
	_ LookupPort   = (&net.Resolver{}).LookupPort
	_ LookupTXT    = (&net.Resolver{}).LookupTXT
	_ LookupMX     = (&net.Resolver{}).LookupMX
	_ LookupNS     = (&net.Resolver{}).LookupNS
	_ LookupSRV    = (&net.Resolver{}).LookupSRV

	_ TCPConn = &net.TCPConn{}
	_ UDPConn = &net.UDPConn{}
)

// PacketConn is an interface for UDP-like packet connections.
type PacketConn interface {
	net.PacketConn
	net.Conn
}

type TCPConn interface {
	// Read(b []byte) (n int, err error)
	// Write(b []byte) (n int, err error)
	// Close() error
	// LocalAddr() Addr
	// RemoteAddr() Addr
	// SetDeadline(t time.Time) error
	// SetReadDeadline(t time.Time) error
	// SetWriteDeadline(t time.Time) error
	net.Conn

	// ReadFrom(r io.Reader) (int64, error)
	io.ReaderFrom

	// WriteTo(w io.Writer) (int64, error)
	io.WriterTo

	SetKeepAlive(keepalive bool) error
	SetKeepAliveConfig(config net.KeepAliveConfig) error
	SetKeepAlivePeriod(d time.Duration) error
	SetLinger(sec int) error
	SetNoDelay(noDelay bool) error

	CloseRead() error
	CloseWrite() error
}

type UDPConn interface {
	// Read(b []byte) (n int, err error)
	// Write(b []byte) (n int, err error)
	// Close() error
	// LocalAddr() Addr
	// RemoteAddr() Addr
	// SetDeadline(t time.Time) error
	// SetReadDeadline(t time.Time) error
	// SetWriteDeadline(t time.Time) error
	net.Conn

	// ReadFrom(p []byte) (n int, addr Addr, err error)
	// WriteTo(p []byte, addr Addr) (n int, err error)
	net.PacketConn

	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)

	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)

	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error)

	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error)
}

type TCPListener interface {
	// Accept() (Conn, error)
	// Close() error
	// Addr() Addr
	net.Listener

	AcceptTCP() (TCPConn, error)
	SetDeadline(t time.Time) error
}

// Dialer is a function type for establishing TCP-like connections.
// It matches the signature of net.Dialer.DialContext.
type Dial = func(ctx context.Context, network, address string) (net.Conn, error)

// PacketDialer is a function type for establishing UDP-like packet connections.
type PacketDial = func(ctx context.Context, network, address string) (PacketConn, error)

// Listener is a function type for creating TCP-like listeners.
type Listen = func(ctx context.Context, network, address string) (net.Listener, error)

// PacketListener is a function type for creating UDP-like packet listeners.
type PacketListen = func(ctx context.Context, network, address string) (PacketConn, error)

// LookupIP looks up host. It returns a slice of that host's IPv4 and IPv6 addresses.
type LookupIP = func(ctx context.Context, network, address string) ([]net.IP, error)

// LookupIPAddr looks up host just like LookupIP but unlike it returns slice of net.IPAddr.
type LookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error)

// LookupNetIP looks up host just like LookupIP but unlike it returns slice of netip.Addr.
type LookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error)

// LookupHost looks up host just like LookupIP but unlike it returns slice of IP strings.
type LookupHost = func(ctx context.Context, host string) (addrs []string, err error)

// LookupAddr performs a reverse lookup for the given address,
// returning a list of names mapping to that address.
type LookupAddr = func(ctx context.Context, addr string) (names []string, err error)

// LookupCNAME returns the canonical name for the given host.
type LookupCNAME = func(ctx context.Context, host string) (cname string, err error)

// LookupPort looks up the port for the given network and service.
type LookupPort = func(ctx context.Context, network, service string) (port int, err error)

// LookupTXT returns the DNS TXT records for the given domain name.
// If a DNS TXT record holds multiple strings, they are concatenated as a single string.
type LookupTXT = func(ctx context.Context, name string) ([]string, error)

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
type LookupMX = func(ctx context.Context, name string) ([]*net.MX, error)

// LookupNS returns the DNS NS records for the given domain name.
type LookupNS = func(ctx context.Context, name string) ([]*net.NS, error)

// LookupSRV tries to resolve an SRV query of the given service, protocol, and domain name.
// The proto is "tcp" or "udp".
type LookupSRV = func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
