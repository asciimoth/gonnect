// Package meshnames implements mesh-oriented name resolution helpers for gonnect.
//
// The package provides a gonnect.Resolver implementation that understands
// naming schemes where the authoritative DNS server can be derived directly
// from the queried name, including:
//
//   - .meshname labels defined by the Meshname protocol
//   - .meship direct label-to-IPv6 lookups
//   - .pk.ygg direct host-to-address labels derived from Yggdrasil public keys
//   - .ygg labels in the straight, base32, and dashed YggNS formats
//
// Resolution is performed through a gonnect.Network, so DNS traffic follows
// the caller-provided network abstraction instead of the host OS network stack.
// Names outside the supported mesh schemes are only resolved when the caller
// explicitly provides a fallback resolver.
package meshnames

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/miekg/dns"
)

const (
	defaultDNSPort = 53
	defaultTimeout = 5 * time.Second
)

var _ gonnect.Resolver = &Resolver{}

var yggNet = netip.MustParsePrefix("0200::/7")

// Resolver implements gonnect.Resolver for mesh-specific naming schemes such
// as .meshname, .meship, .pk.ygg, and .ygg.
//
// For supported mesh names, Resolver derives the authoritative node address
// from the queried name and sends DNS requests to that node through Network.
// For unsupported names, it falls back to Fallback or, if Fallback is nil,
// returns canonical rejection errors compatible with gonnect.RejectNetwork.
type Resolver struct {
	// Network carries all DNS traffic used for authoritative mesh lookups.
	Network gonnect.Network

	// Fallback handles names outside the mesh-specific schemes understood by
	// Resolver. When nil, unsupported names return canonical rejection errors
	// instead of being resolved by a default system resolver.
	Fallback gonnect.Resolver

	// Port is the destination DNS port used when contacting authoritative mesh
	// nodes. Zero or a negative value means the standard DNS port 53.
	Port int

	// Timeout bounds a single DNS exchange with an authoritative mesh node.
	// Zero or a negative value means the default timeout.
	Timeout time.Duration
}

// NewResolver constructs a Resolver that performs mesh-aware lookups through
// the provided gonnect.Network.
//
// The returned resolver uses port 53 and a default request timeout unless the
// caller overrides those fields.
func NewResolver(network gonnect.Network) *Resolver {
	return &Resolver{
		Network: network,
		Port:    defaultDNSPort,
		Timeout: defaultTimeout,
	}
}

// LookupIP resolves address according to the requested IP family.
//
// For .meship and .pk.ygg names, the IPv6 address is decoded directly from the
// label. For .meshname and .ygg names, the authoritative node is derived from
// the name and queried over DNS through Network.
func (r *Resolver) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	if ip, ok, err := r.lookupDirectIP(address); ok {
		if err != nil {
			return nil, err
		}
		return filterNetIPs([]net.IP{ip}, network), nil
	}

	if !r.isSpecialName(address) {
		return r.fallback().LookupIP(ctx, network, address)
	}

	var out []net.IP
	for _, qtype := range qtypesForNetwork(network) {
		resp, err := r.exchangeName(ctx, address, qtype)
		if err != nil {
			return nil, err
		}
		out = append(out, extractIPs(resp.Answer, qtype)...)
	}

	out = filterNetIPs(dedupeIPs(out), network)
	if len(out) == 0 {
		return nil, noSuchHost(address)
	}
	return out, nil
}

// LookupIPAddr resolves host and returns the results as net.IPAddr values.
func (r *Resolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

// LookupNetIP resolves host and returns the results as netip.Addr values.
func (r *Resolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	ips, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, noSuchHost(host)
	}
	return out, nil
}

// LookupHost resolves host and returns the matching IP addresses as strings.
func (r *Resolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	if !r.isSpecialName(host) {
		return r.fallback().LookupHost(ctx, host)
	}
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

// LookupAddr performs a reverse lookup by querying the DNS server running on
// the provided IP address through Network.
func (r *Resolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return r.fallback().LookupAddr(ctx, addr)
	}

	arpa, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, err
	}

	resp, err := r.exchangeToServer(ctx, ip, arpa, dns.TypePTR)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			out = append(out, ptr.Ptr)
		}
	}
	if len(out) == 0 {
		return nil, noSuchHost(addr)
	}
	return out, nil
}

// LookupCNAME resolves the canonical name for host.
func (r *Resolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	if !r.isSpecialName(host) {
		return r.fallback().LookupCNAME(ctx, host)
	}
	resp, err := r.exchangeName(ctx, host, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}
	return "", noSuchHost(host)
}

// LookupPort resolves service names using gonnect's offline port table.
func (r *Resolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return gonnect.LookupPortOffline(network, service)
}

// LookupNS resolves NS records for name.
func (r *Resolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	if !r.isSpecialName(name) {
		return r.fallback().LookupNS(ctx, name)
	}
	resp, err := r.exchangeName(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []*net.NS
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, &net.NS{Host: ns.Ns})
		}
	}
	if len(out) == 0 {
		return nil, noSuchHost(name)
	}
	return out, nil
}

// LookupMX resolves MX records for name.
func (r *Resolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	if !r.isSpecialName(name) {
		return r.fallback().LookupMX(ctx, name)
	}
	resp, err := r.exchangeName(ctx, name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	var out []*net.MX
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, &net.MX{Host: mx.Mx, Pref: mx.Preference})
		}
	}
	if len(out) == 0 {
		return nil, noSuchHost(name)
	}
	return out, nil
}

// LookupSRV resolves SRV records for service, proto, and name.
func (r *Resolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	if !r.isSpecialName(name) {
		return r.fallback().LookupSRV(ctx, service, proto, name)
	}

	qname := name
	if service != "" && proto != "" {
		qname = "_" + service + "._" + proto + "." + name
	}

	resp, err := r.exchangeName(ctx, qname, dns.TypeSRV)
	if err != nil {
		return "", nil, err
	}

	var cname string
	var out []*net.SRV
	for _, rr := range resp.Answer {
		switch rr := rr.(type) {
		case *dns.SRV:
			out = append(out, &net.SRV{
				Target:   rr.Target,
				Port:     rr.Port,
				Priority: rr.Priority,
				Weight:   rr.Weight,
			})
		case *dns.CNAME:
			cname = rr.Target
		}
	}
	if len(out) == 0 {
		return "", nil, noSuchHost(name)
	}
	return cname, out, nil
}

// LookupTXT resolves TXT records for name.
func (r *Resolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	if !r.isSpecialName(name) {
		return r.fallback().LookupTXT(ctx, name)
	}
	resp, err := r.exchangeName(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, txt.Txt...)
		}
	}
	if len(out) == 0 {
		return nil, noSuchHost(name)
	}
	return out, nil
}

func (r *Resolver) exchangeName(
	ctx context.Context,
	name string,
	qtype uint16,
) (*dns.Msg, error) {
	serverIP, err := authorityIP(name)
	if err != nil {
		return nil, err
	}
	return r.exchangeToServer(ctx, serverIP, name, qtype)
}

func (r *Resolver) exchangeToServer(
	ctx context.Context,
	serverIP net.IP,
	name string,
	qtype uint16,
) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)

	conn, err := r.Network.Dial(
		ctx,
		"tcp",
		net.JoinHostPort(serverIP.String(), strconv.Itoa(r.port())),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint

	client := &dns.Client{Net: "tcp", Timeout: r.timeout()}
	resp, _, err := client.ExchangeWithConnContext(
		ctx,
		msg,
		&dns.Conn{Conn: conn},
	)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, noSuchHost(name)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, &net.DNSError{
			Err:  dns.RcodeToString[resp.Rcode],
			Name: name,
		}
	}
	return resp, nil
}

func (r *Resolver) fallback() gonnect.Resolver {
	if r.Fallback != nil {
		return r.Fallback
	}
	return &gonnect.RejectNetwork{}
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout <= 0 {
		return defaultTimeout
	}
	return r.Timeout
}

func (r *Resolver) port() int {
	if r.Port <= 0 {
		return defaultDNSPort
	}
	return r.Port
}

func (r *Resolver) isSpecialName(name string) bool {
	_, ok, _ := r.lookupDirectIP(name)
	if ok {
		return true
	}
	_, err := authorityIP(name)
	return err == nil
}

func (r *Resolver) lookupDirectIP(name string) (net.IP, bool, error) {
	labels := splitLabels(name)
	if len(labels) == 2 && labels[1] == "meship" {
		ip, err := decodeMeshnameLabel(labels[0])
		if err != nil {
			return nil, true, err
		}
		return ip, true, nil
	}

	if len(labels) >= 3 && labels[len(labels)-2] == "pk" &&
		labels[len(labels)-1] == "ygg" {
		ip, err := decodeYggPublicKeyLabel(labels[len(labels)-3])
		if err != nil {
			return nil, true, err
		}
		return ip, true, nil
	}

	return nil, false, nil
}

func authorityIP(name string) (net.IP, error) {
	labels := splitLabels(name)
	if len(labels) < 2 {
		return nil, noSuchHost(name)
	}

	label := labels[len(labels)-2]
	switch labels[len(labels)-1] {
	case "meshname":
		return decodeMeshnameLabel(label)
	case "ygg":
		return decodeYggLabel(label)
	default:
		return nil, noSuchHost(name)
	}
}

func decodeYggPublicKeyLabel(label string) (net.IP, error) {
	keyBytes, err := hex.DecodeString(label)
	if err != nil {
		return nil, noSuchHost(label)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, noSuchHost(label)
	}

	return yggAddrForKey(ed25519.PublicKey(keyBytes)), nil
}

func yggAddrForKey(publicKey ed25519.PublicKey) net.IP {
	var inverted [ed25519.PublicKeySize]byte
	copy(inverted[:], publicKey)
	for i := range inverted {
		inverted[i] = ^inverted[i]
	}

	var addr [net.IPv6len]byte
	setByte(&addr, 0, 0x02)

	ones := byte(0)
	bitIndex := 0
	for ; bitIndex < len(inverted)*8; bitIndex++ {
		if bitAt(inverted[:], bitIndex) == 0 {
			bitIndex++
			break
		}
		ones++
	}
	setByte(&addr, 1, ones)

	outBit := 16
	for ; bitIndex < len(inverted)*8 && outBit < net.IPv6len*8; bitIndex++ {
		setBitIf(&addr, outBit, bitAt(inverted[:], bitIndex) != 0)
		outBit++
	}

	return net.IP(addr[:])
}

func bitAt(data []byte, bitIndex int) byte {
	byteIndex := bitIndex / 8
	if bitIndex < 0 || byteIndex >= len(data) {
		return 0
	}
	return (data[byteIndex] >> (7 - (bitIndex % 8))) & 0x01
}

func setBitIf(data *[net.IPv6len]byte, bitIndex int, value bool) {
	byteIndex := bitIndex / 8
	if !value || bitIndex < 0 || byteIndex >= len(data) {
		return
	}
	data[byteIndex] |= 0x80 >> (bitIndex % 8)
}

func setByte(data *[net.IPv6len]byte, index int, value byte) {
	if index < 0 || index >= len(data) {
		return
	}
	data[index] = value
}

func splitLabels(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func decodeMeshnameLabel(label string) (net.IP, error) {
	data, err := base32.StdEncoding.DecodeString(
		strings.ToUpper(label) + "======",
	)
	if err != nil {
		return nil, noSuchHost(label)
	}
	if len(data) != net.IPv6len {
		return nil, noSuchHost(label)
	}
	return net.IP(data), nil
}

func decodeYggLabel(label string) (net.IP, error) {
	switch {
	case len(label) == 32 && strings.HasPrefix(label, "02") || len(label) == 32 && strings.HasPrefix(label, "03"):
		return decodeYggStraight(label)
	case len(label) == 25 && (strings.HasPrefix(label, "2") || strings.HasPrefix(label, "3")):
		return decodeYggBase32(label)
	case strings.Contains(label, "-"):
		return decodeYggDashed(label)
	default:
		return nil, noSuchHost(label)
	}
}

func decodeYggStraight(label string) (net.IP, error) {
	if _, err := hex.DecodeString(label); err != nil {
		return nil, noSuchHost(label)
	}
	var parts []string
	for i := 0; i < len(label); i += 4 {
		parts = append(parts, label[i:i+4])
	}
	return validateYggIP(net.ParseIP(strings.Join(parts, ":")))
}

func decodeYggBase32(label string) (net.IP, error) {
	body, err := base32.StdEncoding.DecodeString(strings.ToUpper(label[1:]))
	if err != nil {
		return nil, noSuchHost(label)
	}
	if len(body) != 15 {
		return nil, noSuchHost(label)
	}
	hexBody := hex.EncodeToString(body)
	return decodeYggStraight("0" + label[:1] + hexBody)
}

func decodeYggDashed(label string) (net.IP, error) {
	return validateYggIP(net.ParseIP(strings.ReplaceAll(label, "-", ":")))
}

func validateYggIP(ip net.IP) (net.IP, error) {
	if ip == nil {
		return nil, errors.New("invalid ygg address")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !yggNet.Contains(addr.Unmap()) {
		return nil, errors.New("address is outside of 0200::/7")
	}
	return ip, nil
}

func qtypesForNetwork(network string) []uint16 {
	switch strings.ToLower(network) {
	case "ip4", "tcp4", "udp4":
		return []uint16{dns.TypeA}
	case "ip6", "tcp6", "udp6":
		return []uint16{dns.TypeAAAA}
	default:
		return []uint16{dns.TypeA, dns.TypeAAAA}
	}
}

func extractIPs(rrs []dns.RR, qtype uint16) []net.IP {
	var out []net.IP
	for _, rr := range rrs {
		switch rr := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				out = append(out, rr.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				out = append(out, rr.AAAA)
			}
		}
	}
	return out
}

func filterNetIPs(ips []net.IP, network string) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		switch strings.ToLower(network) {
		case "ip4", "tcp4", "udp4":
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4)
			}
		case "ip6", "tcp6", "udp6":
			if ip.To4() == nil && ip.To16() != nil {
				out = append(out, ip)
			}
		default:
			out = append(out, ip)
		}
	}
	return out
}

func dedupeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func noSuchHost(name string) error {
	return &net.DNSError{
		Err:        "no such host",
		Name:       name,
		IsNotFound: true,
	}
}
