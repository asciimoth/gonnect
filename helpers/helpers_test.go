package helpers_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/asciimoth/gonnect/helpers"
)

func TestJointIPPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   net.IP
		port int
		want string
	}{
		{
			name: "IPv4",
			ip:   net.ParseIP("192.168.1.1"),
			port: 8080,
			want: "192.168.1.1:8080",
		},
		{
			name: "IPv6",
			ip:   net.ParseIP("::1"),
			port: 443,
			want: "[::1]:443",
		},
		{
			name: "IPv4 zero port",
			ip:   net.ParseIP("10.0.0.1"),
			port: 0,
			want: "10.0.0.1:0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := helpers.JointIPPort(tt.ip, tt.port)
			if got != tt.want {
				t.Errorf(
					"JointIPPort(%v, %d) = %q, want %q",
					tt.ip,
					tt.port,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestIsTCPNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		network string
		want    bool
	}{
		{"tcp", true},
		{"tcp4", true},
		{"tcp6", true},
		{"udp", false},
		{"udp4", false},
		{"udp6", false},
		{"ip", false},
		{"ip4", false},
		{"ip6", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			t.Parallel()

			if got := helpers.IsTCPNetwork(tt.network); got != tt.want {
				t.Errorf(
					"IsTCPNetwork(%q) = %v, want %v",
					tt.network,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestIsUDPNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		network string
		want    bool
	}{
		{"udp", true},
		{"udp4", true},
		{"udp6", true},
		{"tcp", false},
		{"tcp4", false},
		{"tcp6", false},
		{"ip", false},
		{"ip4", false},
		{"ip6", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			t.Parallel()

			if got := helpers.IsUDPNetwork(tt.network); got != tt.want {
				t.Errorf(
					"IsUDPNetwork(%q) = %v, want %v",
					tt.network,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestIsIPNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		network string
		want    bool
	}{
		{"ip", true},
		{"ip4", true},
		{"ip6", true},
		{"tcp", false},
		{"tcp4", false},
		{"tcp6", false},
		{"udp", false},
		{"udp4", false},
		{"udp6", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			t.Parallel()

			if got := helpers.IsIPNetwork(tt.network); got != tt.want {
				t.Errorf(
					"IsIPNetwork(%q) = %v, want %v",
					tt.network,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestFamilyFromNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		network string
		want    string
	}{
		{"tcp", "ip"},
		{"tcp4", "ip4"},
		{"tcp6", "ip6"},
		{"udp", "ip"},
		{"udp4", "ip4"},
		{"udp6", "ip6"},
		{"ip", "ip"},
		{"ip4", "ip4"},
		{"ip6", "ip6"},
		{"ip4:123", "ip4"},
		{"ip6:456", "ip6"},
		{"", "ip"},
		{"invalid", "ip"},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			t.Parallel()

			if got := helpers.FamilyFromNetwork(tt.network); got != tt.want {
				t.Errorf(
					"FamilyFromNetwork(%q) = %q, want %q",
					tt.network,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestNormalNet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		network string
		want    string
	}{
		{"tcp4", "tcp"},
		{"tcp6", "tcp"},
		{"udp4", "udp"},
		{"udp6", "udp"},
		{"ip4", "ip"},
		{"ip6", "ip"},
		{"tcp", "tcp"},
		{"udp", "udp"},
		{"ip", "ip"},
		{"", ""},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			t.Parallel()

			if got := helpers.NormalNet(tt.network); got != tt.want {
				t.Errorf(
					"NormalNet(%q) = %q, want %q",
					tt.network,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		network  string
		hostport string
		defport  uint16
		wantHost string
		wantPort uint16
	}{
		{
			name:     "IPv4 with port",
			network:  "tcp",
			hostport: "192.168.1.1:8080",
			defport:  80,
			wantHost: "192.168.1.1",
			wantPort: 8080,
		},
		{
			name:     "IPv6 with port",
			network:  "tcp",
			hostport: "[::1]:443",
			defport:  80,
			wantHost: "::1",
			wantPort: 443,
		},
		{
			name:     "no port",
			network:  "tcp",
			hostport: "example.com",
			defport:  80,
			wantHost: "example.com",
			wantPort: 80,
		},
		{
			name:     "invalid port uses default",
			network:  "tcp",
			hostport: "example.com:invalid",
			defport:  9000,
			wantHost: "example.com",
			wantPort: 9000,
		},
		{
			name:     "localhost with port",
			network:  "tcp",
			hostport: "localhost:3000",
			defport:  80,
			wantHost: "localhost",
			wantPort: 3000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, port := helpers.SplitHostPort(
				tt.network,
				tt.hostport,
				tt.defport,
			)
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestPickIP(t *testing.T) {
	t.Parallel()

	ipv4 := net.ParseIP("192.168.1.1")
	ipv6 := net.ParseIP("::1")

	tests := []struct {
		name     string
		ips      []net.IP
		prefer   int
		wantNil  bool
		wantIPv4 bool
		wantIPv6 bool
	}{
		{
			name:    "empty list",
			ips:     []net.IP{},
			prefer:  4,
			wantNil: true,
		},
		{
			name:    "nil list",
			ips:     nil,
			prefer:  4,
			wantNil: true,
		},
		{
			name:     "prefer IPv4 available",
			ips:      []net.IP{ipv4, ipv6},
			prefer:   4,
			wantIPv4: true,
		},
		{
			name:     "prefer IPv6 available",
			ips:      []net.IP{ipv4, ipv6},
			prefer:   6,
			wantIPv6: true,
		},
		{
			name:     "prefer IPv4 not available",
			ips:      []net.IP{ipv6},
			prefer:   4,
			wantIPv6: true,
		},
		{
			name:     "prefer IPv6 not available",
			ips:      []net.IP{ipv4},
			prefer:   6,
			wantIPv4: true,
		},
		{
			name:     "no preference single IPv4",
			ips:      []net.IP{ipv4},
			prefer:   0,
			wantIPv4: true,
		},
		{
			name:     "no preference single IPv6",
			ips:      []net.IP{ipv6},
			prefer:   0,
			wantIPv6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := helpers.PickIP(tt.ips, tt.prefer)
			if tt.wantNil {
				if got != nil {
					t.Errorf(
						"PickIP(%v, %d) = %v, want nil",
						tt.ips,
						tt.prefer,
						got,
					)
				}
				return
			}
			if tt.wantIPv4 && got.To4() == nil {
				t.Errorf(
					"PickIP(%v, %d) = %v, want IPv4",
					tt.ips,
					tt.prefer,
					got,
				)
			}
			if tt.wantIPv6 && got.To4() == nil && len(got) == net.IPv6len {
				// OK - got is IPv6
			} else if tt.wantIPv6 && (got == nil || got.To4() != nil) {
				t.Errorf(
					"PickIP(%v, %d) = %v, want IPv6",
					tt.ips,
					tt.prefer,
					got,
				)
			}
		})
	}
}

func TestReadNullTerminatedString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		bufSize int
		want    string
		wantErr bool
	}{
		{
			name:    "simple null terminated",
			input:   []byte("hello\x00"),
			bufSize: 10,
			want:    "hello",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   []byte("\x00"),
			bufSize: 10,
			want:    "",
			wantErr: false,
		},
		{
			name:    "no null terminator",
			input:   []byte("hello"),
			bufSize: 10,
			want:    "",
			wantErr: true,
		},
		{
			name:    "string too long",
			input:   []byte("hello world\x00"),
			bufSize: 5,
			want:    "",
			wantErr: true,
		},
		{
			name:    "multiple nulls",
			input:   []byte("test\x00\x00"),
			bufSize: 10,
			want:    "test",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := make([]byte, tt.bufSize)
			reader := bytes.NewReader(tt.input)
			got, err := helpers.ReadNullTerminatedString(reader, buf)

			if got != tt.want {
				t.Errorf("got string = %q, want %q", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestClosedNetworkErrToNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "nil error",
			err:  nil,
			want: nil,
		},
		{
			name: "closed network connection",
			err:  errors.New("use of closed network connection"),
			want: nil,
		},
		{
			name: "EOF",
			err:  io.EOF,
			want: nil,
		},
		{
			name: "unexpected EOF",
			err:  io.ErrUnexpectedEOF,
			want: nil,
		},
		{
			name: "closed pipe",
			err:  io.ErrClosedPipe,
			want: nil,
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: errors.New("some other error"),
		},
		{
			name: "wrapped closed connection",
			err:  errors.New("wrapper: " + "use of closed network connection"),
			want: errors.New("wrapper: " + "use of closed network connection"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := helpers.ClosedNetworkErrToNil(tt.err)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("ClosedNetworkErrToNil() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Error() != tt.want.Error() {
				t.Errorf(
					"got.Error() = %q, want %q",
					got.Error(),
					tt.want.Error(),
				)
			}
		})
	}
}

func TestAddrsSameHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    net.Addr
		b    net.Addr
		want bool
	}{
		{
			name: "same TCP addr",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090},
			want: true,
		},
		{
			name: "different TCP addr",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			want: false,
		},
		{
			name: "same UDP addr",
			a:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000},
			b:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 6000},
			want: true,
		},
		{
			name: "different UDP addr",
			a:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000},
			b:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5000},
			want: false,
		},
		{
			name: "nil addr a",
			a:    nil,
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			want: false,
		},
		{
			name: "nil addr b",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    nil,
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "same pointer",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			want: true,
		},
		{
			name: "string addrs same",
			a:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket"},
			b:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket"},
			want: true,
		},
		{
			name: "string addrs different",
			a:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket1"},
			b:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket2"},
			want: false,
		},
		{
			name: "string addrs with port same host",
			a:    &helpers.NetAddr{Net: "tcp", Addr: "127.0.0.1:8080"},
			b:    &helpers.NetAddr{Net: "tcp", Addr: "127.0.0.1:9090"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := helpers.AddrsSameHost(tt.a, tt.b); got != tt.want {
				t.Errorf("AddrsSameHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddrsEq(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    net.Addr
		b    net.Addr
		want bool
	}{
		{
			name: "same TCP addr",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			want: true,
		},
		{
			name: "different port",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090},
			want: false,
		},
		{
			name: "different IP",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			want: false,
		},
		{
			name: "same UDP addr",
			a:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000},
			b:    &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000},
			want: true,
		},
		{
			name: "nil addr a",
			a:    nil,
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			want: false,
		},
		{
			name: "nil addr b",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    nil,
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "same pointer",
			a:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			b:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			want: true,
		},
		{
			name: "string addrs same",
			a:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket"},
			b:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket"},
			want: true,
		},
		{
			name: "string addrs different",
			a:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket1"},
			b:    &helpers.NetAddr{Net: "unix", Addr: "/tmp/socket2"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := helpers.AddrsEq(tt.a, tt.b); got != tt.want {
				t.Errorf("AddrsEq() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIpEqual(t *testing.T) {
	t.Parallel()

	ipv4 := net.ParseIP("192.168.1.1")
	ipv4Same := net.ParseIP("192.168.1.1")
	ipv4Diff := net.ParseIP("10.0.0.1")
	ipv6 := net.ParseIP("::1")

	tests := []struct {
		name string
		a    net.IP
		b    net.IP
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "a nil",
			a:    nil,
			b:    ipv4,
			want: false,
		},
		{
			name: "b nil",
			a:    ipv4,
			b:    nil,
			want: false,
		},
		{
			name: "same IPv4",
			a:    ipv4,
			b:    ipv4Same,
			want: true,
		},
		{
			name: "different IPv4",
			a:    ipv4,
			b:    ipv4Diff,
			want: false,
		},
		{
			name: "same IPv6",
			a:    ipv6,
			b:    net.ParseIP("::1"),
			want: true,
		},
		{
			name: "different families",
			a:    ipv4,
			b:    ipv6,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := helpers.IpEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("IpEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckURLBoolKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values map[string][]string
		key    string
		wantF  bool
		wantS  bool
	}{
		{
			name:   "key not present",
			values: map[string][]string{"other": {"value"}},
			key:    "missing",
			wantF:  false,
			wantS:  false,
		},
		{
			name:   "key with true value",
			values: map[string][]string{"flag": {"true"}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
		{
			name:   "key with yes value",
			values: map[string][]string{"flag": {"yes"}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
		{
			name:   "key with ok value",
			values: map[string][]string{"flag": {"ok"}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
		{
			name:   "key with 1 value",
			values: map[string][]string{"flag": {"1"}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
		{
			name:   "key with empty value",
			values: map[string][]string{"flag": {""}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
		{
			name:   "key with false value",
			values: map[string][]string{"flag": {"false"}},
			key:    "flag",
			wantF:  false,
			wantS:  true,
		},
		{
			name:   "key with 0 value",
			values: map[string][]string{"flag": {"0"}},
			key:    "flag",
			wantF:  false,
			wantS:  true,
		},
		{
			name:   "key with empty slice",
			values: map[string][]string{"flag": {}},
			key:    "flag",
			wantF:  true,
			wantS:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, s := helpers.CheckURLBoolKey(tt.values, tt.key)
			if f != tt.wantF {
				t.Errorf("f = %v, want %v", f, tt.wantF)
			}
			if s != tt.wantS {
				t.Errorf("s = %v, want %v", s, tt.wantS)
			}
		})
	}
}

func TestIsLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want bool
	}{
		{"localhost", true},
		{"localhost:80", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"::1", true},
		{"[::1]:8080", true},
		{"127.1.2.3", true},
		{"127.255.255.255:9000", true},
		{"192.168.1.1", false},
		{"10.0.0.1:80", false},
		{"example.com", false},
		{"example.com:443", false},
		{"", false},
		{"invalid", false},
		{"fe80::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()

			if got := helpers.IsLocal(tt.addr); got != tt.want {
				t.Errorf("IsLocal(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestReadUntilClose(t *testing.T) {
	t.Parallel()

	// Test with a reader that returns error immediately
	closed := false
	rc := &mockReadCloser{
		readFunc: func([]byte) (int, error) {
			return 0, io.EOF
		},
		closeFunc: func() error {
			closed = true
			return nil
		},
	}

	helpers.ReadUntilClose(rc)

	if !closed {
		t.Error("ReadUntilClose did not close the reader")
	}
}

type mockReadCloser struct {
	readFunc  func([]byte) (int, error)
	closeFunc func() error
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.readFunc != nil {
		return m.readFunc(p)
	}
	return 0, io.EOF
}

func (m *mockReadCloser) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}
