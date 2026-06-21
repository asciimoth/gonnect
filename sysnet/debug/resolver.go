package sysnetdebug

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect"
)

var _ gonnect.Resolver = (*mapResolver)(nil)

type mapResolver struct {
	hosts map[string]string
}

func newMapResolver(hosts map[string]string) *mapResolver {
	resolver := &mapResolver{hosts: make(map[string]string, len(hosts))}
	for host, addr := range hosts {
		resolver.hosts[normalizeHost(host)] = addr
	}
	return resolver
}

func (r *mapResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr, err := r.lookupAddr(host)
	if err != nil {
		return nil, err
	}
	if !networkMatchesAddr(network, addr) {
		return nil, notFoundError(host)
	}
	return []net.IP{addr.AsSlice()}, nil
}

func (r *mapResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr, err := r.lookupAddr(host)
	if err != nil {
		return nil, err
	}
	return []net.IPAddr{{IP: addr.AsSlice()}}, nil
}

func (r *mapResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr, err := r.lookupAddr(host)
	if err != nil {
		return nil, err
	}
	if !networkMatchesAddr(network, addr) {
		return nil, notFoundError(host)
	}
	return []netip.Addr{addr}, nil
}

func (r *mapResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr, err := r.lookupAddr(host)
	if err != nil {
		return nil, err
	}
	return []string{addr.String()}, nil
}

func (r *mapResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr = strings.TrimSuffix(addr, ".")
	for host, value := range r.hosts {
		if strings.TrimSuffix(value, ".") == addr {
			return []string{dnsName(host)}, nil
		}
	}
	return nil, notFoundError(addr)
}

func (r *mapResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := r.lookupAddr(host); err != nil {
		return "", err
	}
	return dnsName(host), nil
}

func (r *mapResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(service)
	if err == nil && port > 0 && port <= 65535 {
		return port, nil
	}
	return 0, notFoundError(service)
}

func (r *mapResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, notFoundError(name)
}

func (r *mapResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, notFoundError(name)
}

func (r *mapResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	return "", nil, notFoundError(name)
}

func (r *mapResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, notFoundError(name)
}

func (r *mapResolver) lookupAddr(host string) (netip.Addr, error) {
	value, ok := r.hosts[normalizeHost(host)]
	if !ok {
		return netip.Addr{}, notFoundError(host)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func dnsName(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return "."
	}
	return host + "."
}

func networkMatchesAddr(network string, addr netip.Addr) bool {
	switch {
	case strings.HasSuffix(network, "4"):
		return addr.Is4()
	case strings.HasSuffix(network, "6"):
		return addr.Is6()
	default:
		return true
	}
}

func notFoundError(name string) error {
	return &net.DNSError{
		Name:       name,
		Err:        "no such host",
		IsNotFound: true,
	}
}
