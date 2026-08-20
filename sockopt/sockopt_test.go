// nolint
package sockopt

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type fakeRawConn struct {
	fd      uintptr
	control func(fd uintptr)
	err     error
}

func (c fakeRawConn) Control(f func(fd uintptr)) error {
	if c.control != nil {
		c.control(c.fd)
	}
	if c.err != nil {
		return c.err
	}
	f(c.fd)
	return nil
}

func (c fakeRawConn) Read(func(fd uintptr) bool) error {
	return c.err
}

func (c fakeRawConn) Write(func(fd uintptr) bool) error {
	return c.err
}

type fakeNetConn struct {
	local  net.Addr
	remote net.Addr
}

func (c fakeNetConn) Read([]byte) (int, error) {
	return 0, ErrUnsupported
}

func (c fakeNetConn) Write([]byte) (int, error) {
	return 0, ErrUnsupported
}

func (c fakeNetConn) Close() error {
	return nil
}

func (c fakeNetConn) LocalAddr() net.Addr {
	return c.local
}

func (c fakeNetConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c fakeNetConn) SetDeadline(time.Time) error {
	return nil
}

func (c fakeNetConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c fakeNetConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestIgnoreUnsupported(t *testing.T) {
	if err := IgnoreUnsupported(nil); err != nil {
		t.Fatalf("IgnoreUnsupported(nil) = %v, want nil", err)
	}
	if err := IgnoreUnsupported(ErrUnsupported); err != nil {
		t.Fatalf("IgnoreUnsupported(ErrUnsupported) = %v, want nil", err)
	}
	if err := IgnoreUnsupported(
		errors.New("feature is not supported here"),
	); err != nil {
		t.Fatalf("IgnoreUnsupported(not supported) = %v, want nil", err)
	}
	want := errors.New("other")
	if err := IgnoreUnsupported(want); !errors.Is(err, want) {
		t.Fatalf("IgnoreUnsupported(other) = %v, want %v", err, want)
	}
}

func TestConnIPFamilyUsesAddressIP(t *testing.T) {
	tests := []struct {
		name string
		conn net.Conn
		want socketIPFamily
	}{
		{
			name: "tcp network with ipv4 local address",
			conn: fakeNetConn{
				local: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
			},
			want: socketIPFamily4,
		},
		{
			name: "tcp network with ipv6 local address",
			conn: fakeNetConn{
				local: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
			},
			want: socketIPFamily6,
		},
		{
			name: "udp network with ipv6 local address",
			conn: fakeNetConn{
				local: &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 53},
			},
			want: socketIPFamily6,
		},
		{
			name: "remote fallback",
			conn: fakeNetConn{
				remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::3"), Port: 443},
			},
			want: socketIPFamily6,
		},
		{
			name: "unknown address family",
			conn: fakeNetConn{},
			want: socketIPFamilyUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connIPFamily(tt.conn); got != tt.want {
				t.Fatalf("connIPFamily() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoutingMarkFromSockoptInt(t *testing.T) {
	type testCase struct {
		name  string
		value int
		want  uint32
	}

	tests := []testCase{
		{
			name:  "zero",
			value: 0,
			want:  0,
		},
		{
			name:  "positive mark",
			value: FwmarkIstio,
			want:  FwmarkIstio,
		},
		{
			name:  "max signed int32",
			value: routingMarkSignBit - 1,
			want:  routingMarkSignBit - 1,
		},
		{
			name:  "uint32 high bit",
			value: -routingMarkSignBit,
			want:  routingMarkSignBit,
		},
		{
			name:  "max uint32",
			value: -1,
			want:  maxRoutingMark,
		},
	}
	if strconv.IntSize == 64 {
		minMark := int64(minRoutingMarkInt)
		maxMark := int64(maxRoutingMark)
		tests = append(
			tests,
			testCase{
				name:  "below signed int32",
				value: int(minMark - 1),
				want:  0,
			},
			testCase{
				name:  "above uint32",
				value: int(maxMark + 1),
				want:  0,
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routingMarkFromSockoptInt(tt.value); got != tt.want {
				t.Fatalf(
					"routingMarkFromSockoptInt(%d) = %#x, want %#x",
					tt.value,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestControlAndGetFd(t *testing.T) {
	if err := Control(
		struct{}{},
		func(uintptr) {},
	); !errors.Is(
		err,
		ErrUnsupported,
	) {
		t.Fatalf("Control(unsupported) = %v, want ErrUnsupported", err)
	}
	fd, err := GetFd(struct{}{})
	if !errors.Is(err, ErrUnsupported) || fd != NOFD {
		t.Fatalf(
			"GetFd(unsupported) = %d, %v, want NOFD ErrUnsupported",
			fd,
			err,
		)
	}

	raw := fakeRawConn{fd: 42}
	var rawFD uintptr
	if err := Control(raw, func(fd uintptr) {
		rawFD = fd
	}); err != nil {
		t.Fatalf("Control(raw conn) error = %v", err)
	}
	if rawFD != raw.fd {
		t.Fatalf("Control(raw conn) fd = %d, want %d", rawFD, raw.fd)
	}

	wantErr := syscall.EBADF
	err = control(raw, func(uintptr) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("control(callback error) = %v, want %v", err, wantErr)
	}

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer conn.Close()
	var called bool
	if err := Control(conn, func(fd uintptr) {
		called = true
		if int(fd) == NOFD {
			t.Fatalf("fd = NOFD")
		}
	}); err != nil {
		t.Fatalf("Control(udp) error = %v", err)
	}
	if !called {
		t.Fatal("Control callback was not called")
	}
	fd, err = GetFd(conn)
	if err != nil || fd == NOFD {
		t.Fatalf("GetFd(udp) = %d, %v, want valid fd nil", fd, err)
	}
}

func TestControlRawConnReturnsRawConnError(t *testing.T) {
	want := syscall.EBADF
	err := controlRawConn(fakeRawConn{err: want}, func(uintptr) error {
		t.Fatal("callback must not run when RawConn.Control fails")
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("controlRawConn() = %v, want %v", err, want)
	}
}

func TestNetworkInterfaceNameIndexRejectsTypedNil(t *testing.T) {
	var iface *gonnect.LiteralInterface
	if _, _, err := networkInterfaceNameIndex(
		iface,
	); !errors.Is(
		err,
		ErrUnsupported,
	) {
		t.Fatalf(
			"networkInterfaceNameIndex(typed nil) = %v, want ErrUnsupported",
			err,
		)
	}

	name, index, err := networkInterfaceNameIndex(&gonnect.LiteralInterface{
		NameVal:  "lo",
		IndexVal: 7,
	})
	if err != nil {
		t.Fatalf("networkInterfaceNameIndex(valid) error = %v", err)
	}
	if name != "lo" || index != 7 {
		t.Fatalf(
			"networkInterfaceNameIndex(valid) = %q, %d, want lo, 7",
			name,
			index,
		)
	}
}

func TestAddrIPParsesStringAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want net.IP
	}{
		{
			name: "ip addr",
			addr: &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)},
			want: net.IPv4(192, 0, 2, 1),
		},
		{
			name: "host port string",
			addr: stringAddr("198.51.100.2:443"),
			want: net.IPv4(198, 51, 100, 2),
		},
		{
			name: "plain ip string",
			addr: stringAddr("203.0.113.3"),
			want: net.IPv4(203, 0, 113, 3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrIP(tt.addr); !got.Equal(tt.want) {
				t.Fatalf("addrIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

type stringAddr string

func (a stringAddr) Network() string { return "test" }

func (a stringAddr) String() string { return string(a) }

func TestLinuxSocketOptions(t *testing.T) {
	support := CheckSupport()
	if !support.BufSize || !support.RoutingMark || !support.BindToInterface ||
		!support.TCPUserTimeout || !support.TCPRtt {
		t.Fatalf("CheckSupport() = %#v, want all true on linux", support)
	}

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket error = %v", err)
	}
	defer conn.Close()
	if err := SetBufSize(conn, 4096); err != nil {
		t.Fatalf("SetBufSize error = %v", err)
	}
	recv, send, err := GetBuffSize(conn)
	if err != nil {
		t.Fatalf("GetBuffSize error = %v", err)
	}
	if recv <= 0 || send <= 0 {
		t.Fatalf("GetBuffSize = %d/%d, want positive sizes", recv, send)
	}
	if err := SetRoutingMark(conn, FwmarkIstio); err != nil {
		t.Logf(
			"SetRoutingMark unsupported in this environment: %v",
			err,
		)
	}
	if _, err := GetRoutingMark(conn); err != nil {
		t.Fatalf("GetRoutingMark error = %v", err)
	}
}

func TestLinuxSocketOptionErrors(t *testing.T) {
	badFD := ^uintptr(0)

	err := SetRoutingMark(fakeRawConn{fd: badFD}, FwmarkIstio)
	if err == nil {
		t.Fatal("SetRoutingMark(bad fd) = nil, want error")
	}

	err = SetBindToInterface(fakeRawConn{fd: badFD}, nil)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf(
			"SetBindToInterface(nil interface) = %v, want ErrUnsupported",
			err,
		)
	}

	err = SetBindToInterface(
		struct{}{},
		&gonnect.LiteralInterface{NameVal: "lo"},
	)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf(
			"SetBindToInterface(unsupported input) = %v, want ErrUnsupported",
			err,
		)
	}
}

func TestLinuxTCPOptions(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPConn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptTCP()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP error = %v", err)
	}
	defer client.Close()

	var server *net.TCPConn
	select {
	case err := <-errs:
		t.Fatalf("AcceptTCP error = %v", err)
	case server = <-accepted:
		defer server.Close()
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP timed out")
	}

	if err := SetTCPTimeout(client, time.Second); err != nil {
		t.Fatalf("SetTCPTimeout error = %v", err)
	}
	if _, err := GetTCPRTT(client); err != nil {
		t.Fatalf("GetTCPRTT(client) error = %v", err)
	}
	if err := SetBindToInterface(
		client,
		&gonnect.LiteralInterface{NameVal: "lo"},
	); err != nil {
		t.Logf(
			"SetBindToInterface(lo) unsupported in this environment: %v",
			err,
		)
	}
}
