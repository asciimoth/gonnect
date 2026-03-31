package gonnect

import (
	"context"
	"errors"
	"net"
	"strings"
)

// DnsServer specifies a custom DNS server to use for resolution.
type DnsServer struct {
	// Net is the network type to use (e.g., "udp", "tcp").
	// If empty, defaults to "udp".
	Net string
	// Addr is the address of the DNS server (e.g., "8.8.8.8:53" or "1.1.1.1").
	// By default port is 53 so it can be omitted.
	Addr string
}

// net returns the network type, defaulting to "udp" if not specified.
func (s *DnsServer) net() string {
	if s.Net == "" {
		return "udp"
	}
	return s.Net
}

func (s *DnsServer) addr() string {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return net.JoinHostPort(s.Addr, "53")
	}
	if strings.ToLower(port) == "dns" {
		return net.JoinHostPort(host, "53")
	}
	return s.Addr
}

// ResolverCfg configures a DNS resolver.
type ResolverCfg struct {
	// DontPreferGo disables the use of Go's pure Go DNS resolver.
	// When false (default), PreferGo is enabled in the built resolver.
	DontPreferGo bool
	// StrictErrors controls whether errors from the DNS server are fatal.
	// When true, errors stop resolution immediately.
	StrictErrors bool
	// Dial is an optional custom dial function for establishing connections.
	// If nil, uses net.Dialer.DialContext.
	Dial Dial
	// Server is an optional custom DNS server to use for resolution.
	// If nil, uses the system default DNS servers.
	Server *DnsServer
}

// dial establishes a connection using the custom Dial function if provided,
// otherwise falls back to net.Dialer.DialContext.
func (cfg ResolverCfg) dial(
	ctx context.Context, network, address string,
) (net.Conn, error) {
	if cfg.Dial == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	} else {
		return cfg.Dial(ctx, network, address)
	}
}

// Build creates and returns a configured net.Resolver instance.
// If Server is set, all DNS queries are routed through that server.
// If Dial is set, it is used for establishing connections instead of the default dialer.
func (cfg ResolverCfg) Build() net.Resolver {
	return net.Resolver{
		PreferGo:     !cfg.DontPreferGo,
		StrictErrors: cfg.StrictErrors,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if cfg.Server == nil {
				return cfg.dial(ctx, network, address)
			} else {
				return cfg.dial(ctx, cfg.Server.net(), cfg.Server.addr())
			}
		},
	}
}

// wellKnownPorts contains a fallback table of common service names to port numbers.
var wellKnownPorts = map[string]map[string]int{
	"tcp": {
		"http":     80,
		"https":    443,
		"tls":      443,
		"ssl":      443,
		"ssh":      22,
		"ftp":      21,
		"smtp":     25,
		"dns":      53,
		"pop3":     110,
		"pop":      110,
		"imap":     143,
		"telnet":   23,
		"mysql":    3306,
		"postgres": 5432,
		"redis":    6379,
		"mongodb":  27017,
	},
	"udp": {
		"dns":  53,
		"dhcp": 67,
		"ntp":  123,
	},
}

// LookupPortOffline resolve port name to port (e.g. http to 80) using only
// local data.
func LookupPortOffline(network, service string) (port int, err error) {
	// Dirty hack
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("BLOCKED")
		},
	}
	port, err = r.LookupPort(context.Background(), network, service)
	if err != nil {
		// Fallback to hardcoded well-known ports
		service = strings.ToLower(service)
		network = strings.ToLower(network)
		if ports, ok := wellKnownPorts[network]; ok {
			if p, ok := ports[service]; ok {
				return p, nil
			}
		}
		err = &net.DNSError{
			Err:        "unknown port",
			Name:       network + "/" + service,
			IsNotFound: true,
		}
	}
	return
}
