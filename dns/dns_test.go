// nolint
package dns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestMessageCopyAndNextID(t *testing.T) {
	m := &Message{
		ID: 1,
		Questions: []Question{
			{Name: "localhost.", Type: TypeA, Class: ClassIN},
		},
		Answers: []Resource{
			{
				Name:  "localhost.",
				Type:  TypeA,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte{127, 0, 0, 1},
			},
		},
	}
	cp := m.Copy()
	cp.Answers[0].Data[0] = 1
	if m.Answers[0].Data[0] != 127 {
		t.Fatal("Copy did not deep-copy resource data")
	}
	if NextID() == NextID() {
		t.Fatal("NextID returned duplicate consecutive values")
	}
}

func TestWirePackUnpack(t *testing.T) {
	msg := &Message{
		ID:               42,
		RecursionDesired: true,
		Questions: []Question{
			{Name: "localhost.", Type: TypeA, Class: ClassIN},
		},
		Answers: []Resource{
			{
				Name:  "localhost.",
				Type:  TypeA,
				Class: ClassIN,
				TTL:   5,
				Data:  []byte{127, 0, 0, 1},
			},
			{
				Name:  "localhost.",
				Type:  TypeAAAA,
				Class: ClassIN,
				TTL:   5,
				Data:  net.ParseIP("::1").To16(),
			},
		},
	}
	pkt, err := Pack(msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != msg.ID || len(got.Questions) != 1 || len(got.Answers) != 2 {
		t.Fatalf("unexpected unpack result: %#v", got)
	}
}

func TestWireRecordTypes(t *testing.T) {
	m := &Message{
		ID:       7,
		Response: true,
		Questions: []Question{
			{Name: "example.test.", Type: TypeMX, Class: ClassIN},
		},
		Answers: []Resource{
			{
				Name:  "example.test.",
				Type:  TypeCNAME,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("alias.example.test."),
			},
			{
				Name:  "example.test.",
				Type:  TypeNS,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("ns.example.test."),
			},
			{
				Name:  "1.0.0.127.in-addr.arpa.",
				Type:  TypePTR,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("localhost."),
			},
			{
				Name:  "example.test.",
				Type:  TypeTXT,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("hello"),
			},
			{
				Name:  "example.test.",
				Type:  TypeMX,
				Class: ClassIN,
				TTL:   1,
				Data:  prefName(10, "mail.example.test."),
			},
			{
				Name:  "_svc._tcp.example.test.",
				Type:  TypeSRV,
				Class: ClassIN,
				TTL:   1,
				Data:  srvData(1, 2, 443, "srv.example.test."),
			},
			{
				Name:  "example.test.",
				Type:  TypeSOA,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte{1, 2, 3},
			},
		},
	}
	pkt, err := Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Answers) != len(m.Answers) {
		t.Fatalf("answers = %d", len(got.Answers))
	}
	if string(got.Answers[3].Data) != "hello" {
		t.Fatalf("TXT data = %q", got.Answers[3].Data)
	}
}

func TestDetachedChainCancelsWithoutClosingUpstream(t *testing.T) {
	up := newBlockingDNS()
	d1 := Detach(up, nil)
	d2 := Detach(d1, nil)
	defer up.Close()
	defer d1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := Query(ctx, d2, aQuery("localhost."))
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := d2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("detached close error = %v", err)
	}
	resp, err := Query(context.Background(), up, aQuery("localhost."))
	if err != nil || len(resp.Answers) != 1 {
		t.Fatalf("upstream after detached close: resp=%#v err=%v", resp, err)
	}
}

func TestResolverAdapterChain(t *testing.T) {
	root := NewResolverProvider(gonnect.NewLoopbackNetwok(), time.Second, nil)
	res1 := NewResolver(root)
	prov2 := NewResolverProvider(res1, time.Second, nil)
	res2 := NewResolver(prov2)
	defer root.Close()
	defer prov2.Close()

	hosts, err := res2.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("LookupHost returned %v", hosts)
	}
}

func TestResolverProviderRecordTypesAndErrors(t *testing.T) {
	provider := NewResolverProvider(fakeResolver{}, time.Second, nil)
	defer provider.Close()
	cases := []uint16{
		TypeA,
		TypeAAAA,
		TypePTR,
		TypeCNAME,
		TypeTXT,
		TypeMX,
		TypeNS,
		TypeSRV,
	}
	for _, typ := range cases {
		resp, err := Query(context.Background(), provider, &Message{
			ID: NextID(),
			Questions: []Question{
				{Name: queryName(typ), Type: typ, Class: ClassIN},
			},
		})
		if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
			t.Fatalf("type %d resp=%#v err=%v", typ, resp, err)
		}
	}
	resp, err := Query(context.Background(), provider, &Message{
		ID: NextID(),
		Questions: []Question{
			{Name: "example.test.", Type: TypeSOA, Class: ClassIN},
		},
	})
	if err != nil || resp.RCode != RCodeNotImplemented {
		t.Fatalf("unsupported resp=%#v err=%v", resp, err)
	}
	resp, err = Query(context.Background(), provider, &Message{
		ID: NextID(),
		Questions: []Question{
			{Name: "missing.test.", Type: TypeA, Class: ClassIN},
		},
	})
	if err != nil || resp.RCode != RCodeNameError {
		t.Fatalf("missing resp=%#v err=%v", resp, err)
	}
}

func TestResolverConsumerRecordTypes(t *testing.T) {
	res := NewResolver(newStaticDNS())
	if addrs, err := res.LookupIPAddr(
		context.Background(),
		"example.test",
	); err != nil ||
		len(addrs) != 2 {
		t.Fatalf("LookupIPAddr addrs=%v err=%v", addrs, err)
	}
	if addrs, err := res.LookupNetIP(
		context.Background(),
		"ip4",
		"example.test",
	); err != nil ||
		len(addrs) != 1 {
		t.Fatalf("LookupNetIP addrs=%v err=%v", addrs, err)
	}
	if names, err := res.LookupAddr(
		context.Background(),
		"127.0.0.1",
	); err != nil ||
		len(names) != 1 {
		t.Fatalf("LookupAddr names=%v err=%v", names, err)
	}
	if cname, err := res.LookupCNAME(
		context.Background(),
		"example.test",
	); err != nil ||
		cname == "" {
		t.Fatalf("LookupCNAME cname=%q err=%v", cname, err)
	}
	if port, err := res.LookupPort(
		context.Background(),
		"tcp",
		"https",
	); err != nil ||
		port != 443 {
		t.Fatalf("LookupPort port=%d err=%v", port, err)
	}
	if ns, err := res.LookupNS(
		context.Background(),
		"example.test",
	); err != nil ||
		len(ns) != 1 {
		t.Fatalf("LookupNS ns=%v err=%v", ns, err)
	}
	if mx, err := res.LookupMX(
		context.Background(),
		"example.test",
	); err != nil ||
		len(mx) != 1 {
		t.Fatalf("LookupMX mx=%v err=%v", mx, err)
	}
	if _, srv, err := res.LookupSRV(
		context.Background(),
		"svc",
		"tcp",
		"example.test",
	); err != nil ||
		len(srv) != 1 {
		t.Fatalf("LookupSRV srv=%v err=%v", srv, err)
	}
	if txt, err := res.LookupTXT(
		context.Background(),
		"example.test",
	); err != nil ||
		len(txt) != 1 {
		t.Fatalf("LookupTXT txt=%v err=%v", txt, err)
	}
	if _, err := res.LookupIP(
		context.Background(),
		"ip4",
		"missing.test",
	); err == nil {
		t.Fatal("LookupIP missing succeeded")
	}
}

func TestResolverLookupIPNumericLiteralDoesNotQueryDNS(t *testing.T) {
	dns := newCountingNameErrorDNS()
	defer dns.Close()
	res := NewResolver(dns)

	ips, err := res.LookupIP(context.Background(), "ip", "127.0.0.1")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("LookupIP IPv4 literal = %v, %v", ips, err)
	}

	ips, err = res.LookupIP(context.Background(), "ip6", "::1")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("LookupIP IPv6 literal = %v, %v", ips, err)
	}

	if _, err := res.LookupIP(
		context.Background(),
		"ip6",
		"127.0.0.1",
	); err == nil {
		t.Fatal("LookupIP incompatible literal returned nil error")
	}

	if got := dns.calls.Load(); got != 0 {
		t.Fatalf("DNS calls for numeric literals = %d, want 0", got)
	}
}

func TestCacheAttachDetachReattach(t *testing.T) {
	storage := NewMemoryStorage()
	cache := NewCache(
		NewResolverProvider(gonnect.NewLoopbackNetwok(), time.Second, nil),
		storage,
		nil,
	)
	defer cache.Close()

	resp, err := Query(context.Background(), cache, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("initial query resp=%#v err=%v", resp, err)
	}
	cache.Detach()
	resp, err = Query(context.Background(), cache, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("cached query after detach resp=%#v err=%v", resp, err)
	}
	_, err = Query(context.Background(), cache, aQuery("example.invalid."))
	if !errors.Is(err, ErrNoUpstream) {
		t.Fatalf("miss after detach error = %v", err)
	}
	cache.Attach(
		NewResolverProvider(gonnect.NewLoopbackNetwok(), time.Second, nil),
	)
	resp, err = Query(context.Background(), cache, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("query after reattach resp=%#v err=%v", resp, err)
	}
}

func TestMemoryStorageExpiryDeleteAndNoCache(t *testing.T) {
	s := NewMemoryStorage()
	now := time.Now()
	s.Set("x", &Message{Response: true, RCode: RCodeSuccess}, now)
	if _, ok := s.Get("x", now); ok {
		t.Fatal("stored message without answers")
	}
	msg := &Message{
		Response:  true,
		RCode:     RCodeSuccess,
		Questions: []Question{{Name: "x.", Type: TypeA, Class: ClassIN}},
		Answers:   []Resource{{TTL: 1}},
	}
	s.Set("x", msg, now)
	if _, ok := s.Get("x", now); !ok {
		t.Fatal("cache miss before expiry")
	}
	if _, ok := s.Get("x", now.Add(2*time.Second)); ok {
		t.Fatal("cache hit after expiry")
	}
	s.Set("x", msg, now)
	s.Delete("x")
	if _, ok := s.Get("x", now); ok {
		t.Fatal("cache hit after delete")
	}
}

func TestLoopbackClientServerCacheTree(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	base := NewResolverProvider(ln, time.Second, nil)
	cache := NewCache(base, NewMemoryStorage(), nil)
	defer base.Close()
	defer cache.Close()

	pc, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5353")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(pc, cache, nil)
	defer server.Close()

	client := NewClient(ln.Dial, nil, nil, "udp://127.0.0.1:5353")
	defer client.Close()

	resolverBranch := NewResolverProvider(
		gonnect.NewLoopbackNetwok(),
		time.Second,
		nil,
	)
	tree := NewCache(client, NewMemoryStorage(), nil)
	defer resolverBranch.Close()
	defer tree.Close()

	resp, err := Query(context.Background(), tree, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("client/server query resp=%#v err=%v", resp, err)
	}

	tree.Attach(resolverBranch)
	resp, err = Query(context.Background(), tree, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("tree after attach change resp=%#v err=%v", resp, err)
	}
	tree.Detach()
	resp, err = Query(context.Background(), tree, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("tree cached after detach resp=%#v err=%v", resp, err)
	}
}

func TestClientTCPAndServerDetach(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	upstream := NewResolverProvider(ln, time.Second, nil)
	defer upstream.Close()

	pc, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5354")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(pc, upstream, nil)
	defer server.Close()
	server.Detach()
	client := NewClient(ln.Dial, nil, nil, "udp://127.0.0.1:5354")
	resp, err := Query(context.Background(), client, aQuery("localhost."))
	if err != nil || resp.RCode != RCodeServerFailure {
		t.Fatalf("detached server resp=%#v err=%v", resp, err)
	}
	client.Close()

	lnr, err := ln.Listen(context.Background(), "tcp4", "127.0.0.1:5355")
	if err != nil {
		t.Fatal(err)
	}
	defer lnr.Close()
	go serveOneTCP(t, lnr, upstream)
	tcpClient := NewClient(ln.Dial, nil, nil, "tcp://127.0.0.1:5355")
	defer tcpClient.Close()
	resp, err = Query(context.Background(), tcpClient, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("tcp client resp=%#v err=%v", resp, err)
	}

	bad := NewClient(ln.Dial, nil, nil, "bogus://127.0.0.1:53")
	defer bad.Close()
	if _, err = Query(
		context.Background(),
		bad,
		aQuery("localhost."),
	); err == nil {
		t.Fatal("unknown scheme succeeded")
	}
}

func TestClientDoTUsesBootstrapAndCustomTLSConfig(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	upstream := NewResolverProvider(ln, time.Second, nil)
	defer upstream.Close()

	cert, roots := testTLSCert(t, "dns.test")
	lnr, err := ln.Listen(context.Background(), "tcp4", "127.0.0.1:5361")
	if err != nil {
		t.Fatal(err)
	}
	defer lnr.Close()
	go serveOneTLS(t, lnr, upstream, cert)

	bootstrap := newBootstrapDNS("127.0.0.1")
	defer bootstrap.Close()
	client := NewClient(ln.Dial, bootstrap, nil, "dot://dns.test:5361")
	client.TLSConfig = &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	defer client.Close()

	resp, err := Query(context.Background(), client, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("DoT client resp=%#v err=%v", resp, err)
	}
}

func TestClientRejectsHostnameServerWithoutBootstrap(t *testing.T) {
	var dials atomic.Int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dial should not be called")
	}
	client := NewClient(dial, nil, nil, "udp://dns.test:5353")
	defer client.Close()

	_, err := Query(context.Background(), client, aQuery("localhost."))
	if err == nil {
		t.Fatal("hostname server without bootstrap succeeded")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("error = %T %v, want not-found DNS error", err, err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dial calls = %d, want 0", got)
	}
}

func TestClientRejectsRequestsWithoutDialer(t *testing.T) {
	client := NewClient(nil, nil, nil, "udp://127.0.0.1:5353")
	defer client.Close()

	_, err := Query(context.Background(), client, aQuery("localhost."))
	if !errors.Is(err, ErrNoDialer) {
		t.Fatalf("error = %v, want ErrNoDialer", err)
	}
}

func TestClientTriesBootstrapAddressesBeforeNextServer(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	upstream := NewResolverProvider(ln, time.Second, nil)
	defer upstream.Close()

	lnr, err := ln.Listen(context.Background(), "tcp4", "127.0.0.1:5362")
	if err != nil {
		t.Fatal(err)
	}
	defer lnr.Close()
	go serveOneTCP(t, lnr, upstream)

	bootstrap := newBootstrapDNS("127.0.0.2", "127.0.0.1")
	defer bootstrap.Close()
	client := NewClient(ln.Dial, bootstrap, nil, "tcp://dns.test:5362")
	defer client.Close()

	resp, err := Query(context.Background(), client, aQuery("localhost."))
	if err != nil || len(resp.Answers) == 0 {
		t.Fatalf("tcp client with bootstrap resp=%#v err=%v", resp, err)
	}
}

func aQuery(name string) *Message {
	return &Message{
		ID:               NextID(),
		RecursionDesired: true,
		Questions:        []Question{{Name: name, Type: TypeA, Class: ClassIN}},
	}
}

type blockingDNS struct {
	p *provider
}

func newBlockingDNS() *blockingDNS {
	b := &blockingDNS{}
	b.p = newProvider(func(root context.Context, req Request) {
		select {
		case <-time.After(100 * time.Millisecond):
			resp := responseFor(req.Message)
			resp.Answers = []Resource{
				{
					Name:  "localhost.",
					Type:  TypeA,
					Class: ClassIN,
					TTL:   1,
					Data:  []byte{127, 0, 0, 1},
				},
			}
			sendResponse(req, resp, nil)
		case <-root.Done():
			sendResponse(req, nil, root.Err())
		case <-req.Context.Done():
			sendResponse(req, nil, req.Context.Err())
		}
	}, nil)
	return b
}

func (b *blockingDNS) Requests() chan<- Request { return b.p.Requests() }
func (b *blockingDNS) Close() error             { return b.p.Close() }

type fakeResolver struct{}

func (fakeResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	if strings.HasPrefix(host, "missing") {
		return nil, &net.DNSError{
			Name:       host,
			Err:        "no such host",
			IsNotFound: true,
		}
	}
	if strings.HasSuffix(network, "6") {
		return []net.IP{net.ParseIP("::1")}, nil
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

func (fakeResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

func (fakeResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return nil, nil
}

func (fakeResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return []string{"127.0.0.1"}, nil
}

func (fakeResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return []string{"localhost."}, nil
}

func (fakeResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return "alias.example.test.", nil
}

func (fakeResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return 443, nil
}

func (fakeResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns.example.test."}}, nil
}

func (fakeResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.test.", Pref: 10}}, nil
}

func (fakeResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return "", []*net.SRV{
		{Target: "srv.example.test.", Port: 443, Priority: 1, Weight: 2},
	}, nil
}

func (fakeResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return []string{"hello"}, nil
}

type staticDNS struct {
	p *provider
}

type bootstrapDNS struct {
	p   *provider
	ips []net.IP
}

type countingNameErrorDNS struct {
	p     *provider
	calls atomic.Int32
}

func newBootstrapDNS(addrs ...string) *bootstrapDNS {
	b := &bootstrapDNS{}
	for _, addr := range addrs {
		b.ips = append(b.ips, net.ParseIP(addr))
	}
	b.p = newProvider(func(root context.Context, req Request) {
		resp := responseFor(req.Message)
		q := req.Message.Questions[0]
		for _, ip := range b.ips {
			switch q.Type {
			case TypeA:
				if data := ip.To4(); data != nil {
					resp.Answers = append(resp.Answers, Resource{
						Name:  q.Name,
						Type:  TypeA,
						Class: ClassIN,
						TTL:   1,
						Data:  append([]byte(nil), data...),
					})
				}
			case TypeAAAA:
				if ip.To4() == nil {
					if data := ip.To16(); data != nil {
						resp.Answers = append(resp.Answers, Resource{
							Name:  q.Name,
							Type:  TypeAAAA,
							Class: ClassIN,
							TTL:   1,
							Data:  append([]byte(nil), data...),
						})
					}
				}
			}
		}
		if len(resp.Answers) == 0 {
			resp.RCode = RCodeNameError
		}
		sendResponse(req, resp, nil)
	}, nil)
	return b
}

func (b *bootstrapDNS) Requests() chan<- Request { return b.p.Requests() }
func (b *bootstrapDNS) Close() error             { return b.p.Close() }

func newCountingNameErrorDNS() *countingNameErrorDNS {
	d := &countingNameErrorDNS{}
	d.p = newProvider(func(root context.Context, req Request) {
		d.calls.Add(1)
		resp := responseFor(req.Message)
		resp.RCode = RCodeNameError
		sendResponse(req, resp, nil)
	}, nil)
	return d
}

func (d *countingNameErrorDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *countingNameErrorDNS) Close() error             { return d.p.Close() }

func newStaticDNS() *staticDNS {
	s := &staticDNS{}
	s.p = newProvider(func(root context.Context, req Request) {
		resp := responseFor(req.Message)
		q := req.Message.Questions[0]
		if strings.HasPrefix(q.Name, "missing") {
			resp.RCode = RCodeNameError
			sendResponse(req, resp, nil)
			return
		}
		resp.Answers = staticAnswers(q)
		sendResponse(req, resp, nil)
	}, nil)
	return s
}

func (s *staticDNS) Requests() chan<- Request { return s.p.Requests() }
func (s *staticDNS) Close() error             { return s.p.Close() }

func staticAnswers(q Question) []Resource {
	switch q.Type {
	case TypeA:
		return []Resource{
			{
				Name:  q.Name,
				Type:  TypeA,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte{127, 0, 0, 1},
			},
		}
	case TypeAAAA:
		return []Resource{
			{
				Name:  q.Name,
				Type:  TypeAAAA,
				Class: ClassIN,
				TTL:   1,
				Data:  net.ParseIP("::1").To16(),
			},
		}
	case TypePTR, TypeCNAME, TypeNS:
		return []Resource{
			{
				Name:  q.Name,
				Type:  q.Type,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("name.example.test."),
			},
		}
	case TypeTXT:
		return []Resource{
			{
				Name:  q.Name,
				Type:  q.Type,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte("hello"),
			},
		}
	case TypeMX:
		return []Resource{
			{
				Name:  q.Name,
				Type:  q.Type,
				Class: ClassIN,
				TTL:   1,
				Data:  prefName(10, "mail.example.test."),
			},
		}
	case TypeSRV:
		return []Resource{
			{
				Name:  q.Name,
				Type:  q.Type,
				Class: ClassIN,
				TTL:   1,
				Data:  srvData(1, 2, 443, "srv.example.test."),
			},
		}
	default:
		return nil
	}
}

func queryName(typ uint16) string {
	if typ == TypePTR {
		return "1.0.0.127.in-addr.arpa."
	}
	if typ == TypeSRV {
		return "_svc._tcp.example.test."
	}
	return "example.test."
}

func prefName(pref uint16, name string) []byte {
	out := make([]byte, 2, 2+len(name))
	binary.BigEndian.PutUint16(out, pref)
	return append(out, name...)
}

func srvData(priority, weight, port uint16, target string) []byte {
	out := make([]byte, 6, 6+len(target))
	binary.BigEndian.PutUint16(out[0:2], priority)
	binary.BigEndian.PutUint16(out[2:4], weight)
	binary.BigEndian.PutUint16(out[4:6], port)
	return append(out, target...)
}

func serveOneTCP(t *testing.T, l net.Listener, upstream Interface) {
	t.Helper()
	conn, err := l.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	var lenBuf [2]byte
	if _, err = io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Error(err)
		return
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Error(err)
		return
	}
	msg, err := Unpack(buf)
	if err != nil {
		t.Error(err)
		return
	}
	resp, err := Query(context.Background(), upstream, msg)
	if err != nil {
		t.Error(err)
		return
	}
	pkt, err := Pack(resp)
	if err != nil {
		t.Error(err)
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(pkt)))
	_, err = conn.Write(append(lenBuf[:], pkt...))
	if err != nil {
		t.Error(err)
	}
}

func serveOneTLS(
	t *testing.T,
	l net.Listener,
	upstream Interface,
	cert tls.Certificate,
) {
	t.Helper()
	conn, err := l.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	serveDNSStreamConn(t, tlsConn, upstream)
}

func serveDNSStreamConn(t *testing.T, conn net.Conn, upstream Interface) {
	t.Helper()
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Error(err)
		return
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Error(err)
		return
	}
	msg, err := Unpack(buf)
	if err != nil {
		t.Error(err)
		return
	}
	resp, err := Query(context.Background(), upstream, msg)
	if err != nil {
		t.Error(err)
		return
	}
	pkt, err := Pack(resp)
	if err != nil {
		t.Error(err)
		return
	}
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(pkt)))
	if _, err = conn.Write(append(lenBuf[:], pkt...)); err != nil {
		t.Error(err)
	}
}

func testTLSCert(
	t *testing.T,
	dnsName string,
) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{dnsName},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append test root")
	}
	return cert, roots
}

func TestReverseAddrHelper(t *testing.T) {
	got := reverseAddr(net.ParseIP("127.0.0.1"))
	if got != "1.0.0.127.in-addr.arpa." {
		t.Fatalf("reverseAddr = %q", got)
	}
	if reverseAddr(net.ParseIP("::1")) != "" {
		t.Fatal("reverseAddr IPv6 should be empty")
	}
	if strconv.Itoa(1) != "1" {
		t.Fatal("strconv import guard")
	}
}
