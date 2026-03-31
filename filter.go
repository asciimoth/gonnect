package gonnect

import (
	"net"
	"path"
	"strings"
)

// Filter functions are used whenever different handling should be applied to
// connections/requests depending on their network and address.
// For example, a proxy can use a filter to decide whether a connection should be
// passed directly (true) or proxied (false), or to block/allow, etc.
//
// Network may be "" if unknown.
type Filter = func(network, address string) bool

// FalseFilter is a Filter that always returns false.
func FalseFilter(_, _ string) bool {
	return false
}

// TrueFilter is a Filter that always returns true.
func TrueFilter(_, _ string) bool {
	return true
}

// LoopbackFilter returns true for localhost and loopback addresses.
func LoopbackFilter(_, address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// BuildFilter creates a Filter from a comma-separated string similar to the
// NO_PROXY environment variable format.
//
// Each entry can be:
//   - host:port - matches this host and port combination
//   - host - matches this host on any port
//   - ip - matches this exact IP address
//   - ip/subnet - matches any IP in this CIDR subnet
//   - Wildcards (*, ?) are supported in host patterns using shell glob matching
//
// Examples:
//   - "localhost,127.0.0.1" - true for localhost and IPv4 loopback
//   - "*.example.com" - true for all subdomains of example.com
//   - "192.168.0.0/16" - true for entire 192.168.x.x subnet
//   - "internal.corp:8080" - true for specific host:port
//
// The filter is case-insensitive and handles both bracketed IPv6 addresses
// (e.g., [::1]:8080) and trailing dots in hostnames.
func BuildFilter(str string) Filter {
	type hostEntry struct {
		pattern string // wildcard pattern, lowercased, no trailing dot
		hasPort bool
		port    string
	}
	type ipEntry struct {
		ip      net.IP
		hasPort bool
		port    string
	}
	var hosts []hostEntry
	var ips []ipEntry
	var cidrs []*net.IPNet

	// parse entries
	for raw := range strings.SplitSeq(str, ",") {
		e := strings.TrimSpace(raw)

		// Try CIDR
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				cidrs = append(cidrs, ipnet)
				continue
			}
			// fallthrough if not valid CIDR
		}

		// Try plain IP (v4 or v6) without port
		if ip := net.ParseIP(e); ip != nil {
			ips = append(ips, ipEntry{ip: ip, hasPort: false})
			continue
		}

		// Try split host:port (handles bracketed IPv6)
		if host, port, err := net.SplitHostPort(e); err == nil {
			// host part might be IP or pattern/hostname
			host = trimDot(strings.ToLower(host))
			if ip := net.ParseIP(host); ip != nil {
				ips = append(ips, ipEntry{ip: ip, hasPort: true, port: port})
			} else {
				hosts = append(
					hosts,
					hostEntry{pattern: host, hasPort: true, port: port},
				)
			}
			continue
		}

		// Finally treat as host pattern (may include wildcards)
		if e != "" {
			patt := trimDot(strings.ToLower(e))
			hosts = append(hosts, hostEntry{pattern: patt, hasPort: false})
		}
	}

	// filter function
	return func(network, address string) bool {
		// normalize host and port from address input
		var host string
		var port string

		// Try to split host:port using net.SplitHostPort (will handle [::1]:80)
		if h, p, err := net.SplitHostPort(address); err == nil {
			host, port = h, p
		} else {
			host = address
			port = ""
		}

		// normalize host for comparisons
		normHost := trimDot(strings.ToLower(host))

		// Try parse host as IP
		if ip := net.ParseIP(strings.Trim(normHost, "[]")); ip != nil {
			// match exact IP entries
			for _, e := range ips {
				if e.ip.Equal(ip) {
					if !e.hasPort || e.port == port {
						return true
					}
				}
			}
			// match CIDR entries
			for _, n := range cidrs {
				if n.Contains(ip) {
					return true
				}
			}
			// no host-pattern match for numeric IPs
			return false
		}

		// host is a hostname - match host patterns (with wildcard support)
		for _, h := range hosts {
			// path.Match uses shell-style globs: '*' '?' '[]'
			if ok, _ := path.Match(h.pattern, normHost); ok {
				if !h.hasPort || h.port == port {
					return true
				}
			}
		}
		return false
	}
}

func trimDot(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".") {
		s = strings.TrimRight(s, ".")
	}
	return s
}
