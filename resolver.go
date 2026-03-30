package gonnect

import (
	"context"
	"net"
)

// DnsServer specifies a custom DNS server to use for resolution.
type DnsServer struct {
	// Net is the network type to use (e.g., "udp", "tcp").
	// If empty, defaults to "udp".
	Net string
	// Addr is the address of the DNS server (e.g., "8.8.8.8:53").
	Addr string
}

// net returns the network type, defaulting to "udp" if not specified.
func (s *DnsServer) net() string {
	if s.Net == "" {
		return "udp"
	}
	return s.Net
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
				return cfg.dial(ctx, cfg.Server.net(), cfg.Server.Addr)
			}
		},
	}
}
