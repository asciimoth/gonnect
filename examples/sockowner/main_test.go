package main

import (
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sockowner"
)

func TestWriteHTTPJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	writeHTTPJSON(rec, Report{Transport: "test"})

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Body.String(); !strings.HasSuffix(got, "\n") {
		t.Fatalf("body = %q, want trailing newline", got)
	}
	if got := rec.Body.String(); !strings.Contains(got, `"transport": "test"`) {
		t.Fatalf("body = %q, want transport field", got)
	}
}

func TestPrettyJSON(t *testing.T) {
	t.Run("valid value", func(t *testing.T) {
		got := string(prettyJSON(map[string]string{"a": "b"}))
		if !strings.Contains(got, `"a": "b"`) {
			t.Fatalf("prettyJSON() = %q, want field", got)
		}
	})

	t.Run("marshal error", func(t *testing.T) {
		got := string(prettyJSON(map[string]any{"bad": func() {}}))
		if !strings.Contains(got, `"error"`) ||
			!strings.Contains(got, "unsupported type") {
			t.Fatalf("prettyJSON() = %q, want encoded error", got)
		}
	})
}

func TestAddrString(t *testing.T) {
	if got := addrString(nil); got != "" {
		t.Fatalf("addrString(nil) = %q, want empty", got)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	if got := addrString(addr); got != "127.0.0.1:8080" {
		t.Fatalf("addrString() = %q, want address string", got)
	}
}

func TestPrintableTCPAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "bad address", addr: "bad", want: "bad"},
		{name: "empty host", addr: ":8080", want: "127.0.0.1:8080"},
		{name: "ipv4 wildcard", addr: "0.0.0.0:8080", want: "127.0.0.1:8080"},
		{name: "ipv6 wildcard", addr: "[::]:8080", want: "127.0.0.1:8080"},
		{
			name: "ipv6 host",
			addr: "[2001:db8::1]:443",
			want: "[2001:db8::1]:443",
		},
		{name: "hostname", addr: "example.com:443", want: "example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printableTCPAddr(tt.addr); got != tt.want {
				t.Fatalf(
					"printableTCPAddr(%q) = %q, want %q",
					tt.addr,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestNormalizeServerIP(t *testing.T) {
	tests := []struct {
		name     string
		serverIP net.IP
		peerIP   net.IP
		want     net.IP
	}{
		{
			name:     "specified server",
			serverIP: net.ParseIP("192.0.2.1"),
			peerIP:   net.ParseIP("127.0.0.1"),
			want:     net.ParseIP("192.0.2.1"),
		},
		{
			name:     "ipv4 loopback fallback",
			serverIP: net.IPv4zero,
			peerIP:   net.ParseIP("127.0.0.1"),
			want:     net.ParseIP("127.0.0.1"),
		},
		{
			name:     "ipv6 loopback fallback",
			serverIP: net.IPv6zero,
			peerIP:   net.ParseIP("::1"),
			want:     net.ParseIP("::1"),
		},
		{
			name:     "wildcard non-loopback",
			serverIP: net.IPv4zero,
			peerIP:   net.ParseIP("198.51.100.4"),
			want:     net.IPv4zero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeServerIP(
				tt.serverIP,
				tt.peerIP,
			); !got.Equal(
				tt.want,
			) {
				t.Fatalf("normalizeServerIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUDPPeerOwnerRejectsNilAddrs(t *testing.T) {
	_, err := udpPeerOwner(nil, &net.UDPAddr{})
	if !errors.Is(err, sockowner.ErrNoOwner) {
		t.Fatalf("udpPeerOwner(nil, peer) error = %v, want ErrNoOwner", err)
	}

	_, err = udpPeerOwner(&net.UDPAddr{}, nil)
	if !errors.Is(err, sockowner.ErrNoOwner) {
		t.Fatalf("udpPeerOwner(server, nil) error = %v, want ErrNoOwner", err)
	}
}

func TestLogReportAndMustNil(t *testing.T) {
	logReport("test report", Report{Transport: "test"})
	must(nil)
}

func TestUsageWritesProgramName(t *testing.T) {
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}
	os.Args = []string{"sockowner-demo"}
	os.Stderr = w

	usage()
	_ = w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	got := string(buf[:n])
	if !strings.Contains(got, "sockowner-demo http") ||
		!strings.Contains(got, "udp-client") {
		t.Fatalf("usage output = %q, want command names", got)
	}
}
