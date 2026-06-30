package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/gonnect"
)

// ResolverProvider adapts a gonnect.Resolver into a DNS Interface.
//
// It supports standard IN-class A, AAAA, PTR, CNAME, TXT, MX, NS, and SRV
// queries. Unsupported opcodes, classes, or record types are answered with
// RCodeNotImplemented. Resolver lookup failures are mapped to NameError when
// the resolver reports not-found and ServerFailure otherwise. Successful
// resource records use the configured TTL.
type ResolverProvider struct {
	resolver gonnect.Resolver
	ttl      uint32
	p        *provider
}

// NewResolverProvider returns a DNS provider backed by resolver.
func NewResolverProvider(
	resolver gonnect.Resolver,
	ttl time.Duration,
	spawner gonnect.Spawner,
) *ResolverProvider {
	r := &ResolverProvider{resolver: resolver, ttl: uint32(ttl.Seconds())}
	if r.ttl == 0 {
		r.ttl = 60
	}
	r.p = newProvider(r.handle, spawner)
	return r
}

func (r *ResolverProvider) Requests() chan<- Request { return r.p.Requests() }
func (r *ResolverProvider) Close() error             { return r.p.Close() }

func (r *ResolverProvider) handle(root context.Context, req Request) {
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-root.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	resp := responseFor(req.Message)
	if req.Message == nil || req.Message.Opcode != OpcodeQuery ||
		len(req.Message.Questions) == 0 {
		resp.RCode = RCodeFormatError
		sendResponse(req, resp, nil)
		return
	}
	for _, q := range req.Message.Questions {
		if q.Class != 0 && q.Class != ClassIN {
			resp.RCode = RCodeNotImplemented
			sendResponse(req, resp, nil)
			return
		}
		rrs, err := r.lookup(ctx, q)
		if err != nil {
			resp.RCode = errRCode(err)
			sendResponse(req, resp, nil)
			return
		}
		resp.Answers = append(resp.Answers, rrs...)
	}
	sendResponse(req, resp, nil)
}

func (r *ResolverProvider) lookup(
	ctx context.Context,
	q Question,
) ([]Resource, error) {
	name := strings.TrimSuffix(q.Name, ".")
	switch q.Type {
	case TypeA:
		ips, err := r.resolver.LookupIP(ctx, "ip4", name)
		return ipResources(q.Name, TypeA, r.ttl, ips), err
	case TypeAAAA:
		ips, err := r.resolver.LookupIP(ctx, "ip6", name)
		return ipResources(q.Name, TypeAAAA, r.ttl, ips), err
	case TypePTR:
		names, err := r.resolver.LookupAddr(ctx, name)
		return nameResources(q.Name, TypePTR, r.ttl, names), err
	case TypeCNAME:
		cname, err := r.resolver.LookupCNAME(ctx, name)
		if err != nil {
			return nil, err
		}
		return nameResources(q.Name, TypeCNAME, r.ttl, []string{cname}), nil
	case TypeTXT:
		txts, err := r.resolver.LookupTXT(ctx, name)
		return textResources(q.Name, r.ttl, txts), err
	case TypeMX:
		mxs, err := r.resolver.LookupMX(ctx, name)
		return mxResources(q.Name, r.ttl, mxs), err
	case TypeNS:
		nss, err := r.resolver.LookupNS(ctx, name)
		return nsResources(q.Name, r.ttl, nss), err
	case TypeSRV:
		service, proto, host := splitSRV(name)
		_, srvs, err := r.resolver.LookupSRV(ctx, service, proto, host)
		return srvResources(q.Name, r.ttl, srvs), err
	default:
		return nil, notImplementedError{}
	}
}

type notImplementedError struct{}

func (notImplementedError) Error() string { return "not implemented" }

func errRCode(err error) uint8 {
	var notImplemented notImplementedError
	if errors.As(err, &notImplemented) {
		return RCodeNotImplemented
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return RCodeNameError
	}
	return RCodeServerFailure
}

func responseFor(req *Message) *Message {
	resp := &Message{
		Response:           true,
		RCode:              RCodeSuccess,
		RecursionAvailable: true,
	}
	if req != nil {
		resp.ID = req.ID
		resp.Opcode = req.Opcode
		resp.RecursionDesired = req.RecursionDesired
		resp.Questions = append([]Question(nil), req.Questions...)
	}
	return resp
}

// Resolver adapts a DNS Interface into a full gonnect.Resolver.
type Resolver struct {
	DNS Interface
}

func NewResolver(d Interface) *Resolver { return &Resolver{DNS: d} }

func literalIP(network, host string) (net.IP, bool, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, false, nil // nolint
	}
	if strings.HasSuffix(network, "4") && !addr.Is4() {
		return nil, true, dnsErr(host)
	}
	if strings.HasSuffix(network, "6") && !addr.Is6() {
		return nil, true, dnsErr(host)
	}
	return net.IP(append([]byte(nil), addr.AsSlice()...)), true, nil
}

func (r *Resolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	if ip, ok, err := literalIP(network, host); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}

	var out []net.IP
	if !strings.HasSuffix(network, "6") {
		rrs, err := r.lookup(ctx, TypeA, host)
		if err != nil && strings.HasSuffix(network, "4") {
			return nil, err
		}
		out = append(out, ipsFromResources(rrs)...)
	}
	if !strings.HasSuffix(network, "4") {
		rrs, err := r.lookup(ctx, TypeAAAA, host)
		if err != nil && strings.HasSuffix(network, "6") {
			return nil, err
		}
		out = append(out, ipsFromResources(rrs)...)
	}
	if len(out) == 0 {
		return nil, dnsErr(host)
	}
	return out, nil
}

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
			out = append(out, addr)
		}
	}
	return out, nil
}

func (r *Resolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
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

func (r *Resolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	rrs, err := r.lookup(ctx, TypePTR, addr)
	return namesFromResources(rrs), err
}

func (r *Resolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	rrs, err := r.lookup(ctx, TypeCNAME, host)
	names := namesFromResources(rrs)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

func (r *Resolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return gonnect.LookupPortOffline(network, service)
}

func (r *Resolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	rrs, err := r.lookup(ctx, TypeNS, name)
	names := namesFromResources(rrs)
	out := make([]*net.NS, 0, len(names))
	for _, n := range names {
		out = append(out, &net.NS{Host: n})
	}
	return out, err
}

func (r *Resolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	rrs, err := r.lookup(ctx, TypeMX, name)
	out := make([]*net.MX, 0, len(rrs))
	for _, rr := range rrs {
		if len(rr.Data) >= 2 {
			out = append(out, &net.MX{
				Pref: binary.BigEndian.Uint16(rr.Data[:2]),
				Host: string(rr.Data[2:]),
			})
		}
	}
	return out, err
}

func (r *Resolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	q := "_" + service + "._" + proto + "." + name
	rrs, err := r.lookup(ctx, TypeSRV, q)
	out := make([]*net.SRV, 0, len(rrs))
	for _, rr := range rrs {
		if len(rr.Data) >= 6 {
			out = append(out, &net.SRV{
				Priority: binary.BigEndian.Uint16(rr.Data[0:2]),
				Weight:   binary.BigEndian.Uint16(rr.Data[2:4]),
				Port:     binary.BigEndian.Uint16(rr.Data[4:6]),
				Target:   string(rr.Data[6:]),
			})
		}
	}
	return "", out, err
}

func (r *Resolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	rrs, err := r.lookup(ctx, TypeTXT, name)
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, string(rr.Data))
	}
	return out, err
}

func (r *Resolver) lookup(
	ctx context.Context,
	typ uint16,
	name string,
) ([]Resource, error) {
	resp, err := Query(ctx, r.DNS, &Message{
		ID:               NextID(),
		RecursionDesired: true,
		Questions: []Question{{
			Name:  absName(name),
			Type:  typ,
			Class: ClassIN,
		}},
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.RCode != RCodeSuccess {
		return nil, dnsErr(name)
	}
	return resp.Answers, nil
}

func dnsErr(name string) error {
	return &net.DNSError{Name: name, Err: "no such host", IsNotFound: true}
}

func ipResources(name string, typ uint16, ttl uint32, ips []net.IP) []Resource {
	var out []Resource
	for _, ip := range ips {
		var data []byte
		if typ == TypeA {
			data = ip.To4()
		} else {
			data = ip.To16()
		}
		if data == nil {
			continue
		}
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  typ,
				Class: ClassIN,
				TTL:   ttl,
				Data:  append([]byte(nil), data...),
			},
		)
	}
	return out
}

func nameResources(
	name string,
	typ uint16,
	ttl uint32,
	names []string,
) []Resource {
	out := make([]Resource, 0, len(names))
	for _, n := range names {
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  typ,
				Class: ClassIN,
				TTL:   ttl,
				Data:  []byte(absName(n)),
			},
		)
	}
	return out
}

func textResources(name string, ttl uint32, txts []string) []Resource {
	out := make([]Resource, 0, len(txts))
	for _, txt := range txts {
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  TypeTXT,
				Class: ClassIN,
				TTL:   ttl,
				Data:  []byte(txt),
			},
		)
	}
	return out
}

func mxResources(name string, ttl uint32, mxs []*net.MX) []Resource {
	out := make([]Resource, 0, len(mxs))
	for _, mx := range mxs {
		data := make([]byte, 2, 2+len(absName(mx.Host)))
		binary.BigEndian.PutUint16(data, mx.Pref)
		data = append(data, absName(mx.Host)...)
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  TypeMX,
				Class: ClassIN,
				TTL:   ttl,
				Data:  data,
			},
		)
	}
	return out
}

func nsResources(name string, ttl uint32, nss []*net.NS) []Resource {
	out := make([]Resource, 0, len(nss))
	for _, ns := range nss {
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  TypeNS,
				Class: ClassIN,
				TTL:   ttl,
				Data:  []byte(absName(ns.Host)),
			},
		)
	}
	return out
}

func srvResources(name string, ttl uint32, srvs []*net.SRV) []Resource {
	out := make([]Resource, 0, len(srvs))
	for _, srv := range srvs {
		data := make([]byte, 6, 6+len(absName(srv.Target)))
		binary.BigEndian.PutUint16(data[0:2], srv.Priority)
		binary.BigEndian.PutUint16(data[2:4], srv.Weight)
		binary.BigEndian.PutUint16(data[4:6], srv.Port)
		data = append(data, absName(srv.Target)...)
		out = append(
			out,
			Resource{
				Name:  absName(name),
				Type:  TypeSRV,
				Class: ClassIN,
				TTL:   ttl,
				Data:  data,
			},
		)
	}
	return out
}

func ipsFromResources(rrs []Resource) []net.IP {
	var out []net.IP
	for _, rr := range rrs {
		if rr.Type == TypeA && len(rr.Data) == 4 {
			out = append(
				out,
				net.IPv4(rr.Data[0], rr.Data[1], rr.Data[2], rr.Data[3]),
			)
		}
		if rr.Type == TypeAAAA && len(rr.Data) == 16 {
			out = append(out, net.IP(append([]byte(nil), rr.Data...)))
		}
	}
	return out
}

func namesFromResources(rrs []Resource) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, string(rr.Data))
	}
	return out
}

func splitSRV(name string) (string, string, string) {
	parts := strings.SplitN(name, ".", 3)
	if len(parts) < 3 {
		return "", "", name
	}
	return strings.TrimPrefix(
			parts[0],
			"_",
		), strings.TrimPrefix(
			parts[1],
			"_",
		), parts[2]
}

func reverseAddr(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return strconv.Itoa(
			int(ip4[3]),
		) + "." + strconv.Itoa(
			int(ip4[2]),
		) + "." + strconv.Itoa(
			int(ip4[1]),
		) + "." + strconv.Itoa(
			int(ip4[0]),
		) + ".in-addr.arpa."
	}
	return ""
}
