//nolint:testpackage
package sockowner

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestFlowFamily(t *testing.T) {
	tests := []struct {
		name    string
		flow    FlowTuple
		want    int
		wantErr error
	}{
		{
			name:    "nil local",
			flow:    FlowTuple{RemoteIP: net.ParseIP("127.0.0.1")},
			wantErr: ErrNilIP,
		},
		{
			name: "ipv4",
			flow: FlowTuple{
				LocalIP:  net.ParseIP("127.0.0.1"),
				RemoteIP: net.ParseIP("192.0.2.1"),
			},
			want: 4,
		},
		{
			name: "ipv6",
			flow: FlowTuple{
				LocalIP:  net.ParseIP("2001:db8::1"),
				RemoteIP: net.ParseIP("2001:db8::2"),
			},
			want: 6,
		},
		{
			name: "mixed",
			flow: FlowTuple{
				LocalIP:  net.ParseIP("127.0.0.1"),
				RemoteIP: net.ParseIP("2001:db8::2"),
			},
			wantErr: ErrInvIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.flow.FlowFamily()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FlowFamily() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("FlowFamily() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFlowFromIPAddrs(t *testing.T) {
	flow, err := flowFromIPAddrs(
		"tcp",
		net.ParseIP("127.0.0.1"),
		1234,
		net.ParseIP("192.0.2.1"),
		443,
	)
	if err != nil {
		t.Fatalf("flowFromIPAddrs() error = %v", err)
	}
	if flow.Proto != "tcp" || flow.LocalPort != 1234 || flow.RemotePort != 443 {
		t.Fatalf("flowFromIPAddrs() = %#v, want tcp ports", flow)
	}

	badCases := []struct {
		name       string
		localIP    net.IP
		localPort  int
		remoteIP   net.IP
		remotePort int
	}{
		{
			name:       "bad local ip",
			localIP:    net.IP{1, 2, 3},
			localPort:  1,
			remoteIP:   net.ParseIP("127.0.0.1"),
			remotePort: 1,
		},
		{
			name:       "bad remote ip",
			localIP:    net.ParseIP("127.0.0.1"),
			localPort:  1,
			remoteIP:   net.IP{1, 2, 3},
			remotePort: 1,
		},
		{
			name:       "negative port",
			localIP:    net.ParseIP("127.0.0.1"),
			localPort:  -1,
			remoteIP:   net.ParseIP("127.0.0.1"),
			remotePort: 1,
		},
		{
			name:       "large port",
			localIP:    net.ParseIP("127.0.0.1"),
			localPort:  1,
			remoteIP:   net.ParseIP("127.0.0.1"),
			remotePort: 65536,
		},
	}

	for _, tt := range badCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := flowFromIPAddrs(
				"tcp",
				tt.localIP,
				tt.localPort,
				tt.remoteIP,
				tt.remotePort,
			)
			if !errors.Is(err, ErrInvIP) {
				t.Fatalf("flowFromIPAddrs() error = %v, want ErrInvIP", err)
			}
		})
	}
}

func TestNormalizeFlowIP(t *testing.T) {
	if got, ok := normalizeFlowIP(nil); ok || got != nil {
		t.Fatalf("normalizeFlowIP(nil) = %v, %v; want nil, false", got, ok)
	}

	ip4Input := net.ParseIP("127.0.0.1")
	ip4, ok := normalizeFlowIP(ip4Input)
	if !ok || !ip4.Equal(net.IPv4(127, 0, 0, 1)) || len(ip4) != net.IPv4len {
		t.Fatalf("normalizeFlowIP(ipv4) = %v, %v", ip4, ok)
	}
	ip4[0] = 1
	if ip4Input.To4()[0] != 127 {
		t.Fatal("normalizeFlowIP(ipv4) returned storage aliased with input")
	}

	ip6Input := net.ParseIP("2001:db8::1")
	ip6, ok := normalizeFlowIP(ip6Input)
	if !ok || !ip6.Equal(ip6Input) || len(ip6) != net.IPv6len {
		t.Fatalf("normalizeFlowIP(ipv6) = %v, %v", ip6, ok)
	}
	ip6[0] = 1
	if ip6Input.To16()[0] == 1 {
		t.Fatal("normalizeFlowIP(ipv6) returned storage aliased with input")
	}

	if got, ok := normalizeFlowIP(net.IP{1, 2, 3}); ok || got != nil {
		t.Fatalf("normalizeFlowIP(invalid) = %v, %v; want nil, false", got, ok)
	}
}

func TestAddrLooksUnix(t *testing.T) {
	if addrLooksUnix(nil) {
		t.Fatal("addrLooksUnix(nil) = true, want false")
	}
	if !addrLooksUnix(&net.UnixAddr{Name: "x", Net: "unixgram"}) {
		t.Fatal("addrLooksUnix(*net.UnixAddr) = false, want true")
	}
	if !addrLooksUnix(testAddr{network: "unixpacket"}) {
		t.Fatal("addrLooksUnix(unixpacket) = false, want true")
	}
	if addrLooksUnix(testAddr{network: "tcp"}) {
		t.Fatal("addrLooksUnix(tcp) = true, want false")
	}
}

func TestGetSockOwnerValidation(t *testing.T) {
	_, err := GetSockOwner(FlowTuple{Proto: "icmp"})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("GetSockOwner(icmp) error = %v, want ErrProtocol", err)
	}
}

func TestIncomingConnPeerFlow(t *testing.T) {
	_, err := IncomingConnPeerFlow(nil)
	if !errors.Is(err, ErrConnNil) {
		t.Fatalf("IncomingConnPeerFlow(nil) error = %v, want ErrConnNil", err)
	}

	_, err = IncomingConnPeerFlow(testConn{})
	if !errors.Is(err, ErrAddrNil) {
		t.Fatalf(
			"IncomingConnPeerFlow(nil addrs) error = %v, want ErrAddrNil",
			err,
		)
	}

	_, err = IncomingConnPeerFlow(testConn{
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
	})
	if !errors.Is(err, ErrAddrTypeUnexpected) {
		t.Fatalf(
			"IncomingConnPeerFlow(mixed) error = %v, want ErrAddrTypeUnexpected",
			err,
		)
	}

	flow, err := IncomingConnPeerFlow(testConn{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
	})
	if err != nil {
		t.Fatalf("IncomingConnPeerFlow(udp) error = %v", err)
	}
	if flow.Proto != "udp" || flow.LocalPort != 1234 || flow.RemotePort != 53 {
		t.Fatalf(
			"IncomingConnPeerFlow(udp) = %#v, want reversed UDP flow",
			flow,
		)
	}
}

type testAddr struct {
	network string
}

func (a testAddr) Network() string { return a.network }
func (a testAddr) String() string  { return a.network + ":addr" }

type testConn struct {
	local  net.Addr
	remote net.Addr
}

func (c testConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c testConn) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}
func (c testConn) Close() error                     { return nil }
func (c testConn) LocalAddr() net.Addr              { return c.local }
func (c testConn) RemoteAddr() net.Addr             { return c.remote }
func (c testConn) SetDeadline(time.Time) error      { return nil }
func (c testConn) SetReadDeadline(time.Time) error  { return nil }
func (c testConn) SetWriteDeadline(time.Time) error { return nil }
