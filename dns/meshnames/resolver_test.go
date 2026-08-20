package meshnames_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns/meshnames"
	"github.com/miekg/dns"
)

func TestResolverLookupHostMeshname(t *testing.T) {
	t.Parallel()

	const (
		authorityIP = "200:6fc8:9220:f400:5cc2:305a:4ac6:967e"
		label       = "aiag7sesed2aaxgcgbnevruwpy"
		host        = "svc." + label + ".meshname"
		answerIP    = "2001:db8::42"
	)

	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		for _, q := range req.Question {
			if q.Name == dns.Fqdn(host) && q.Qtype == dns.TypeAAAA {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: net.ParseIP(answerIP),
				})
			}
		}
		_ = w.WriteMsg(msg)
	})

	r := &meshnames.Resolver{
		Network: &mapNetwork{
			routes: map[string]string{
				net.ParseIP(authorityIP).String(): server.addr,
			},
		},
	}

	addrs, err := r.LookupHost(context.Background(), host)
	if err != nil {
		t.Fatalf("LookupHost() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != answerIP {
		t.Fatalf("LookupHost() = %v, want [%s]", addrs, answerIP)
	}
}

func TestResolverLookupIPMeship(t *testing.T) {
	t.Parallel()

	r := &meshnames.Resolver{Network: &mapNetwork{}}
	ips, err := r.LookupIP(
		context.Background(),
		"ip6",
		"aiag7sesed2aaxgcgbnevruwpy.meship",
	)
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(ips) != 1 ||
		ips[0].String() != "200:6fc8:9220:f400:5cc2:305a:4ac6:967e" {
		t.Fatalf("LookupIP() = %v", ips)
	}
}

func TestResolverSupportsYggFormats(t *testing.T) {
	t.Parallel()

	const authorityIP = "0202:12a9:00e5:4474:d473:82be:16ac:9381"
	labels := []string{
		"020212a900e54474d47382be16ac9381",
		"2aijksahfir2ni44cxylkze4b",
		"202-12a9-e5-4474-d473-82be-16ac-9381",
	}

	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		for _, q := range req.Question {
			if strings.HasPrefix(q.Name, "svc.") &&
				strings.HasSuffix(q.Name, ".ygg.") &&
				q.Qtype == dns.TypeAAAA {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					AAAA: net.ParseIP("2001:db8::99"),
				})
			}
		}
		_ = w.WriteMsg(msg)
	})

	r := &meshnames.Resolver{
		Network: &mapNetwork{
			routes: map[string]string{
				net.ParseIP(authorityIP).String(): server.addr,
			},
		},
	}

	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			ips, err := r.LookupIP(
				context.Background(),
				"ip6",
				"svc."+label+".ygg",
			)
			if err != nil {
				t.Fatalf("LookupIP() error = %v", err)
			}
			if len(ips) != 1 || ips[0].String() != "2001:db8::99" {
				t.Fatalf("LookupIP() = %v", ips)
			}
		})
	}
}

func TestResolverSupportsPkYgg(t *testing.T) {
	t.Parallel()

	const publicKey = "d40d4a7153cf288ea28f1865f6cfe95143a478b5c8c9e7cb002a0633d10a53eb"
	const wantIP = "200:57e5:6b1d:5861:aee2:bae1:cf34:1260"
	r := &meshnames.Resolver{Network: &mapNetwork{}}

	ips, err := r.LookupIP(
		context.Background(),
		"ip6",
		"svc."+publicKey+".pk.ygg",
	)
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(ips) != 1 || ips[0].String() != wantIP {
		t.Fatalf("LookupIP() = %v", ips)
	}
}

func TestResolverPrefersPkYggBeforePlainYgg(t *testing.T) {
	t.Parallel()

	const publicKey = "d40d4a7153cf288ea28f1865f6cfe95143a478b5c8c9e7cb002a0633d10a53eb"
	const wantIP = "200:57e5:6b1d:5861:aee2:bae1:cf34:1260"
	r := &meshnames.Resolver{Network: &mapNetwork{}}

	addrs, err := r.LookupHost(
		context.Background(),
		"host."+publicKey+".pk.ygg",
	)
	if err != nil {
		t.Fatalf("LookupHost() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != wantIP {
		t.Fatalf("LookupHost() = %v", addrs)
	}
}

func TestResolverLookupStructuredRecords(t *testing.T) {
	t.Parallel()

	const (
		authorityIP = "0202:12a9:00e5:4474:d473:82be:16ac:9381"
		label       = "2aijksahfir2ni44cxylkze4b"
		name        = "netwhood." + label + ".ygg"
	)

	reverse, err := dns.ReverseAddr(authorityIP)
	if err != nil {
		t.Fatalf("ReverseAddr() error = %v", err)
	}

	server := startDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		for _, q := range req.Question {
			switch {
			case q.Name == dns.Fqdn(name) && q.Qtype == dns.TypeTXT:
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{"hello", "mesh"},
				})
			case q.Name == dns.Fqdn(name) && q.Qtype == dns.TypeMX:
				msg.Answer = append(msg.Answer, &dns.MX{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Mx:         "mail." + dns.Fqdn(name),
					Preference: 10,
				})
			case q.Name == dns.Fqdn(name) && q.Qtype == dns.TypeNS:
				msg.Answer = append(msg.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Ns: "ns1." + dns.Fqdn(name),
				})
			case q.Name == "_xmpp._tcp."+dns.Fqdn(name) && q.Qtype == dns.TypeSRV:
				msg.Answer = append(msg.Answer, &dns.SRV{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target:   "svc." + dns.Fqdn(name),
					Port:     5222,
					Priority: 5,
					Weight:   10,
				})
			case q.Name == "alias."+dns.Fqdn(name) && q.Qtype == dns.TypeCNAME:
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target: dns.Fqdn(name),
				})
			case q.Name == reverse && q.Qtype == dns.TypePTR:
				msg.Answer = append(msg.Answer, &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Ptr: dns.Fqdn(name),
				})
			}
		}
		_ = w.WriteMsg(msg)
	})

	r := &meshnames.Resolver{
		Network: &mapNetwork{
			routes: map[string]string{
				net.ParseIP(authorityIP).String(): server.addr,
			},
		},
	}

	txt, err := r.LookupTXT(context.Background(), name)
	if err != nil || strings.Join(txt, ",") != "hello,mesh" {
		t.Fatalf("LookupTXT() = %v, %v", txt, err)
	}

	mx, err := r.LookupMX(context.Background(), name)
	if err != nil || len(mx) != 1 || mx[0].Host != "mail."+dns.Fqdn(name) ||
		mx[0].Pref != 10 {
		t.Fatalf("LookupMX() = %v, %v", mx, err)
	}

	ns, err := r.LookupNS(context.Background(), name)
	if err != nil || len(ns) != 1 || ns[0].Host != "ns1."+dns.Fqdn(name) {
		t.Fatalf("LookupNS() = %v, %v", ns, err)
	}

	cname, srv, err := r.LookupSRV(context.Background(), "xmpp", "tcp", name)
	if err != nil || cname != "" || len(srv) != 1 ||
		srv[0].Target != "svc."+dns.Fqdn(name) ||
		srv[0].Port != 5222 {
		t.Fatalf("LookupSRV() = %q %v %v", cname, srv, err)
	}

	gotCNAME, err := r.LookupCNAME(context.Background(), "alias."+name)
	if err != nil || gotCNAME != dns.Fqdn(name) {
		t.Fatalf("LookupCNAME() = %q, %v", gotCNAME, err)
	}

	ptr, err := r.LookupAddr(context.Background(), authorityIP)
	if err != nil || len(ptr) != 1 || ptr[0] != dns.Fqdn(name) {
		t.Fatalf("LookupAddr() = %v, %v", ptr, err)
	}
}

func TestResolverUsesFallbackForNonSpecialNames(t *testing.T) {
	t.Parallel()

	fb := &fakeResolver{}
	r := &meshnames.Resolver{
		Network:  &mapNetwork{},
		Fallback: fb,
	}

	addrs, err := r.LookupHost(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupHost() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "198.51.100.7" {
		t.Fatalf("LookupHost() = %v", addrs)
	}
	if fb.lookupHostCalls != 1 {
		t.Fatalf("fallback LookupHost calls = %d", fb.lookupHostCalls)
	}
}

func TestResolverWithoutFallbackRejectsNonSpecialNames(t *testing.T) {
	t.Parallel()

	r := &meshnames.Resolver{Network: &mapNetwork{}}

	_, err := r.LookupHost(context.Background(), "example.com")
	if err == nil {
		t.Fatal("LookupHost() error = nil, want not found error")
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("LookupHost() error type = %T, want *net.DNSError", err)
	}
	if dnsErr.Name != "example.com" || dnsErr.Server != "rejectdns" ||
		!dnsErr.IsNotFound {
		t.Fatalf(
			"LookupHost() error = %#v, want canonical rejectdns not found error",
			dnsErr,
		)
	}

	want := gonnect.NoSuchHost("example.com", "rejectdns")
	if dnsErr.Err != want.Err || dnsErr.Server != want.Server ||
		dnsErr.IsNotFound != want.IsNotFound {
		t.Fatalf("LookupHost() error = %#v, want %#v", dnsErr, want)
	}
}

type dnsServer struct {
	addr string
	stop func()
}

func startDNSServer(t *testing.T, handler dns.HandlerFunc) dnsServer {
	t.Helper()

	mux := dns.NewServeMux()
	mux.Handle(".", handler)

	listener, err := (&net.ListenConfig{}).Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	server := &dns.Server{Listener: listener, Net: "tcp", Handler: mux}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("dns server shutdown timed out")
		}
	})

	return dnsServer{
		addr: listener.Addr().String(),
		stop: func() { _ = server.Shutdown() },
	}
}

type mapNetwork struct {
	gonnect.RejectNetwork
	routes map[string]string
}

func (n *mapNetwork) IsNative() bool { return false }

func (n *mapNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	target, ok := n.routes[host]
	if !ok {
		return nil, fmt.Errorf("no route for %s", host)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (*mapNetwork) Listen(
	context.Context,
	string,
	string,
) (net.Listener, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) PacketDial(
	context.Context,
	string,
	string,
) (gonnect.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) ListenPacket(
	context.Context,
	string,
	string,
) (gonnect.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) DialTCP(
	context.Context,
	string,
	string,
	string,
) (gonnect.TCPConn, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) ListenTCP(
	context.Context,
	string,
	string,
) (gonnect.TCPListener, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) DialUDP(
	context.Context,
	string,
	string,
	string,
) (gonnect.UDPConn, error) {
	return nil, errors.New("not implemented")
}

func (*mapNetwork) ListenUDP(
	context.Context,
	string,
	string,
) (gonnect.UDPConn, error) {
	return nil, errors.New("not implemented")
}

type fakeResolver struct {
	lookupHostCalls int
}

func (f *fakeResolver) LookupIP(
	context.Context,
	string,
	string,
) ([]net.IP, error) {
	return []net.IP{net.ParseIP("198.51.100.7")}, nil
}

func (f *fakeResolver) LookupIPAddr(
	context.Context,
	string,
) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("198.51.100.7")}}, nil
}

func (f *fakeResolver) LookupNetIP(
	context.Context,
	string,
	string,
) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
}

func (f *fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	f.lookupHostCalls++
	return []string{"198.51.100.7"}, nil
}

func (*fakeResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"example.com."}, nil
}

func (*fakeResolver) LookupCNAME(
	context.Context,
	string,
) (string, error) {
	return "example.com.", nil
}
func (*fakeResolver) LookupPort(context.Context, string, string) (int, error) {
	return 80, nil
}
func (*fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns.example.com."}}, nil
}
func (*fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
}

func (*fakeResolver) LookupSRV(
	context.Context,
	string,
	string,
	string,
) (string, []*net.SRV, error) {
	return "", []*net.SRV{{Target: "srv.example.com.", Port: 80}}, nil
}
func (*fakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"example"}, nil
}
