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

// InvertFilter is a Filter that returns iverted result of filter.
func InvertFilter(filter Filter) Filter {
	return func(network, address string) bool {
		return !filter(network, address)
	}
}

// OrFilter is a Filter that returns true if any of filters do it.
func OrFilter(filters ...Filter) Filter {
	return func(network, address string) bool {
		for _, filter := range filters {
			if filter(network, address) {
				return true
			}
		}
		return false
	}
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

// CustomFilter is a Filter that matches addresses based on a set of patterns.
// Patterns are similar to the NO_PROXY environment variable format.
type CustomFilter struct {
	Hosts []HostFilterEntry
	IPs   []IpFilterEntry
	CIDRs []*net.IPNet
}

type HostFilterEntry struct {
	Pattern  string // wildcard pattern, lowercased, no trailing dot
	WithPort bool
	Port     string
}

type IpFilterEntry struct {
	IP       net.IP
	WithPort bool
	Port     string
}

// FilterFromString creates a CustomFilter from a comma-separated string.
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
func FilterFromString(str string) CustomFilter {
	var hosts []HostFilterEntry
	var ips []IpFilterEntry
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
			ips = append(ips, IpFilterEntry{IP: ip, WithPort: false})
			continue
		}

		// Try split host:port (handles bracketed IPv6)
		if host, port, err := net.SplitHostPort(e); err == nil {
			// host part might be IP or pattern/hostname
			host = trimDot(strings.ToLower(host))
			if ip := net.ParseIP(host); ip != nil {
				ips = append(ips, IpFilterEntry{IP: ip, WithPort: true, Port: port})
			} else {
				hosts = append(
					hosts,
					HostFilterEntry{Pattern: host, WithPort: true, Port: port},
				)
			}
			continue
		}

		// Finally treat as host pattern (may include wildcards)
		if e != "" {
			patt := trimDot(strings.ToLower(e))
			hosts = append(hosts, HostFilterEntry{Pattern: patt, WithPort: false})
		}
	}

	return CustomFilter{Hosts: hosts, IPs: ips, CIDRs: cidrs}
}

// Filter implements the Filter function for CustomFilter.
func (f CustomFilter) Filter(network, address string) bool {
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
		for _, e := range f.IPs {
			if e.IP.Equal(ip) {
				if !e.WithPort || e.Port == port {
					return true
				}
			}
		}
		// match CIDR entries
		for _, n := range f.CIDRs {
			if n.Contains(ip) {
				return true
			}
		}
		// no host-pattern match for numeric IPs
		return false
	}

	// host is a hostname - match host patterns (with wildcard support)
	for _, h := range f.Hosts {
		// path.Match uses shell-style globs: '*' '?' '[]'
		if ok, _ := path.Match(h.Pattern, normHost); ok {
			if !h.WithPort || h.Port == port {
				return true
			}
		}
	}
	return false
}

func trimDot(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".") {
		s = strings.TrimRight(s, ".")
	}
	return s
}
