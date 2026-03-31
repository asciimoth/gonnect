package gonnect_test

import (
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestLoopbackFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		network string
		address string
		want    bool
	}{
		{
			name:    "localhost no port",
			network: "tcp",
			address: "localhost",
			want:    true,
		},
		{
			name:    "localhost with port",
			network: "tcp",
			address: "localhost:8080",
			want:    true,
		},
		{
			name:    "IPv4 loopback",
			network: "tcp",
			address: "127.0.0.1:8080",
			want:    true,
		},
		{
			name:    "IPv4 loopback no port",
			network: "tcp",
			address: "127.0.0.1",
			want:    true,
		},
		{
			name:    "IPv6 loopback",
			network: "tcp",
			address: "[::1]:8080",
			want:    true,
		},
		{
			name:    "IPv6 loopback no port",
			network: "tcp",
			address: "::1",
			want:    true,
		},
		{
			name:    "IPv4 non-loopback",
			network: "tcp",
			address: "192.168.1.1:8080",
			want:    false,
		},
		{
			name:    "IPv6 non-loopback",
			network: "tcp",
			address: "[fe80::1]:8080",
			want:    false,
		},
		{
			name:    "hostname non-loopback",
			network: "tcp",
			address: "example.com:443",
			want:    false,
		},
		{
			name:    "invalid address",
			network: "tcp",
			address: "not-a-valid-address",
			want:    false,
		},
		{
			name:    "empty address",
			network: "tcp",
			address: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := gonnect.LoopbackFilter(tt.network, tt.address); got != tt.want {
				t.Errorf("LoopbackFilter(%q, %q) = %v, want %v", tt.network, tt.address, got, tt.want)
			}
		})
	}
}

func TestBuildFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		tests   []struct {
			network string
			address string
			want    bool
		}
	}{
		{
			name:    "empty pattern",
			pattern: "",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "127.0.0.1:8080", false},
				{"tcp", "localhost:80", false},
				{"tcp", "example.com:443", false},
			},
		},
		{
			name:    "localhost and IP",
			pattern: "localhost,127.0.0.1",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "localhost:8080", true},
				{"tcp", "localhost", true},
				{"tcp", "127.0.0.1:8080", true},
				{"tcp", "127.0.0.1", true},
				{"tcp", "127.0.0.2:8080", false},
				{"tcp", "example.com:443", false},
			},
		},
		{
			name:    "wildcard pattern",
			pattern: "*.example.com",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "www.example.com:80", true},
				{"tcp", "api.example.com:443", true},
				{"tcp", "sub.sub.example.com:8080", true},
				{"tcp", "example.com:80", false},
				{"tcp", "notexample.com:80", false},
				{"tcp", "www.example.org:80", false},
			},
		},
		{
			name:    "CIDR subnet",
			pattern: "192.168.0.0/16",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "192.168.0.1:8080", true},
				{"tcp", "192.168.255.255:8080", true},
				{"tcp", "192.168.100.50:443", true},
				{"tcp", "192.169.0.1:8080", false},
				{"tcp", "192.17.0.1:8080", false},
				{"tcp", "10.0.0.1:8080", false},
			},
		},
		{
			name:    "host:port specific",
			pattern: "internal.corp:8080",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "internal.corp:8080", true},
				{"tcp", "internal.corp:80", false},
				{"tcp", "internal.corp:9090", false},
				{"tcp", "other.corp:8080", false},
			},
		},
		{
			name:    "IPv6 bracketed",
			pattern: "[::1]:8080",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "[::1]:8080", true},
				{"tcp", "[::1]:80", false},
				{"tcp", "::1", false},
			},
		},
		{
			name:    "trailing dot handling",
			pattern: "localhost.,example.com.",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "localhost:80", true},
				{"tcp", "localhost.:80", true},
				{"tcp", "example.com:443", true},
				{"tcp", "example.com.:443", true},
			},
		},
		{
			name:    "case insensitive",
			pattern: "LOCALHOST,Example.COM",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "localhost:80", true},
				{"tcp", "LOCALHOST:80", true},
				{"tcp", "example.com:443", true},
				{"tcp", "EXAMPLE.COM:443", true},
				{"tcp", "Example.Com:443", true},
			},
		},
		{
			name:    "multiple CIDRs",
			pattern: "10.0.0.0/8,172.16.0.0/12",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "10.0.0.1:80", true},
				{"tcp", "10.255.255.255:80", true},
				{"tcp", "172.16.0.1:80", true},
				{"tcp", "172.31.255.255:80", true},
				{"tcp", "172.32.0.1:80", false},
				{"tcp", "192.168.1.1:80", false},
			},
		},
		{
			name:    "IP with port",
			pattern: "192.168.1.1:8080",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "192.168.1.1:8080", true},
				{"tcp", "192.168.1.1:80", false},
				{"tcp", "192.168.1.2:8080", false},
			},
		},
		{
			name:    "IPv6 CIDR",
			pattern: "fe80::/10",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "[fe80::1]:80", true},
				{"tcp", "[fe80::ffff]:80", true},
				{"tcp", "[febf::1]:80", true},
				{"tcp", "[fec0::1]:80", false},
			},
		},
		{
			name:    "wildcard with port",
			pattern: "*.corp.com:443",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "internal.corp.com:443", true},
				{"tcp", "api.corp.com:443", true},
				{"tcp", "internal.corp.com:80", false},
				{"tcp", "corp.com:443", false},
			},
		},
		{
			name:    "question mark wildcard",
			pattern: "host?.example.com",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "host1.example.com:80", true},
				{"tcp", "hostA.example.com:80", true},
				{"tcp", "host.example.com:80", false},
				{"tcp", "host12.example.com:80", false},
			},
		},
		{
			name:    "character class wildcard",
			pattern: "host[123].example.com",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "host1.example.com:80", true},
				{"tcp", "host2.example.com:80", true},
				{"tcp", "host3.example.com:80", true},
				{"tcp", "host4.example.com:80", false},
			},
		},
		{
			name:    "mixed entries",
			pattern: "localhost,192.168.0.0/16,*.internal.com,10.0.0.1:8080",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "localhost:80", true},
				{"tcp", "192.168.1.1:80", true},
				{"tcp", "api.internal.com:443", true},
				{"tcp", "10.0.0.1:8080", true},
				{"tcp", "10.0.0.1:80", false},
				{"tcp", "external.com:80", false},
			},
		},
		{
			name:    "spaces in pattern",
			pattern: "  localhost  ,  127.0.0.1  ",
			tests: []struct {
				network string
				address string
				want    bool
			}{
				{"tcp", "localhost:80", true},
				{"tcp", "127.0.0.1:8080", true},
				{"tcp", "192.168.1.1:80", false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filter := gonnect.BuildFilter(tt.pattern)

			for _, test := range tt.tests {
				t.Run(test.address, func(t *testing.T) {
					t.Parallel()

					if got := filter(test.network, test.address); got != test.want {
						t.Errorf("filter(%q, %q) = %v, want %v (pattern: %q)",
							test.network, test.address, got, test.want, tt.pattern)
					}
				})
			}
		})
	}
}

func TestBuildFilter_IPMatching(t *testing.T) {
	t.Parallel()

	// Test that numeric IPs don't match host patterns
	t.Run("IP does not match host pattern", func(t *testing.T) {
		t.Parallel()

		filter := gonnect.BuildFilter("example.com")

		if got := filter("tcp", "93.184.216.34:80"); got != false {
			t.Errorf("filter(tcp, 93.184.216.34:80) = %v, want false", got)
		}
	})

	// Test that hostname matching works when address is IP
	t.Run("hostname pattern does not match IP", func(t *testing.T) {
		t.Parallel()

		filter := gonnect.BuildFilter("192.168.1.1")

		if got := filter("tcp", "192.168.1.1:8080"); got != true {
			t.Errorf("filter(tcp, 192.168.1.1:8080) = %v, want true", got)
		}

		if got := filter("tcp", "192.168.1.1"); got != true {
			t.Errorf("filter(tcp, 192.168.1.1) = %v, want true", got)
		}
	})
}

func TestBuildFilter_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		address string
		want    bool
	}{
		{
			name:    "empty address",
			pattern: "localhost",
			address: "",
			want:    false,
		},
		{
			name:    "empty pattern empty address",
			pattern: "",
			address: "",
			want:    false,
		},
		{
			name:    "only commas",
			pattern: ",,,",
			address: "localhost:80",
			want:    false,
		},
		{
			name:    "malformed CIDR treated as host pattern",
			pattern: "192.168.0.0/33",
			address: "192.168.0.0/33:80",
			want:    true, // malformed CIDR falls through to host pattern matching
		},
		{
			name:    "IPv4 mapped IPv6",
			pattern: "::ffff:127.0.0.1",
			address: "[::ffff:127.0.0.1]:80",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filter := gonnect.BuildFilter(tt.pattern)

			if got := filter("tcp", tt.address); got != tt.want {
				t.Errorf("filter(tcp, %q) = %v, want %v (pattern: %q)", tt.address, got, tt.want, tt.pattern)
			}
		})
	}
}
