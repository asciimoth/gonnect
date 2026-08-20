package dns

import "testing"

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
