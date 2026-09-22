package dns

import (
	"testing"
	"time"
)

func TestClientRequestTimeoutOptions(t *testing.T) {
	defaultClient := NewClient(nil, nil, nil)
	if got := defaultClient.timeout; got != defaultClientRequestTimeout {
		t.Fatalf(
			"NewClient() timeout = %v, want %v",
			got,
			defaultClientRequestTimeout,
		)
	}
	if err := defaultClient.Close(); err != nil {
		t.Fatalf("NewClient().Close() error = %v", err)
	}

	const customTimeout = 250 * time.Millisecond
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name: "zero uses default",
			want: defaultClientRequestTimeout,
		},
		{
			name:    "negative uses default",
			timeout: -time.Second,
			want:    defaultClientRequestTimeout,
		},
		{
			name:    "custom timeout",
			timeout: customTimeout,
			want:    customTimeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClientWithOptions(
				nil,
				nil,
				nil,
				ClientOptions{RequestTimeout: test.timeout},
			)
			if got := client.timeout; got != test.want {
				t.Errorf("client timeout = %v, want %v", got, test.want)
			}
			if err := client.Close(); err != nil {
				t.Fatalf("Client.Close() error = %v", err)
			}
		})
	}
}

func TestSplitServerHostPortMoreCases(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:    "empty",
			wantErr: true,
		},
		{
			name:     "host port",
			addr:     "example.test:5353",
			wantHost: "example.test",
			wantPort: "5353",
		},
		{
			name:     "ipv4 default port",
			addr:     "192.0.2.53",
			wantHost: "192.0.2.53",
			wantPort: "53",
		},
		{
			name:     "bracketed ipv6 default port",
			addr:     "[2001:db8::53]",
			wantHost: "2001:db8::53",
			wantPort: "53",
		},
		{
			name:    "bad ipv6 without brackets",
			addr:    "2001:db8::zz",
			wantErr: true,
		},
		{
			name:     "host default port",
			addr:     "dns.example.test",
			wantHost: "dns.example.test",
			wantPort: "53",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := splitServerHostPort(test.addr)
			if test.wantErr {
				if err == nil {
					t.Fatalf("splitServerHostPort(%q) error = nil", test.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitServerHostPort(%q) error = %v", test.addr, err)
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf(
					"splitServerHostPort(%q) = %q, %q; want %q, %q",
					test.addr,
					host,
					port,
					test.wantHost,
					test.wantPort,
				)
			}
		})
	}
}
