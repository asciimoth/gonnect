// nolint
package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func TestComplexChainClientDialErrorDoesNotPoisonChain(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	upstream := NewResolverProvider(ln, time.Second, nil)
	defer upstream.Close()

	pc, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5358")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(pc, upstream, nil)
	defer server.Close()

	failDial := true
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if failDial {
			return nil, errors.New("synthetic dial failure")
		}
		return ln.Dial(ctx, network, address)
	}
	client := NewClient(dial, nil, nil, "udp://127.0.0.1:5358")
	defer client.Close()
	cache := NewCache(client, NewMemoryStorage(), nil)
	defer cache.Close()
	chain := Detach(cache, nil)
	defer chain.Close()

	if _, err := queryWithTimeout(chain, "localhost."); err == nil {
		t.Fatal("query through failing client succeeded")
	}

	failDial = false
	resp, err := queryWithTimeout(chain, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"chain did not recover after dial failure: resp=%#v err=%v",
			resp,
			err,
		)
	}

	server.Detach()
	resp, err = queryWithTimeout(chain, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"cached chain response after server detach: resp=%#v err=%v",
			resp,
			err,
		)
	}
}

func TestComplexChainClientRetriesNextServerAndSurvivesBadServer(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	upstream := NewResolverProvider(ln, time.Second, nil)
	defer upstream.Close()

	pc, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5359")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(pc, upstream, nil)
	defer server.Close()

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "127.0.0.1:1" {
			return nil, errors.New("synthetic first-server failure")
		}
		return ln.Dial(ctx, network, address)
	}
	client := NewClient(
		dial,
		nil,
		nil,
		"udp://127.0.0.1:1",
		"udp://127.0.0.1:5359",
	)
	defer client.Close()
	cache := NewCache(client, NewMemoryStorage(), nil)
	defer cache.Close()
	chain := Detach(cache, nil)
	defer chain.Close()

	resp, err := queryWithTimeout(chain, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf("client did not retry next server: resp=%#v err=%v", resp, err)
	}
	resp, err = queryWithTimeout(chain, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"chain did not survive earlier retry error: resp=%#v err=%v",
			resp,
			err,
		)
	}
}

func TestServerUpstreamErrorDoesNotPoisonServer(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	bad := newErrorDNS(errors.New("upstream failed"))
	defer bad.Close()

	pc, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5360")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(pc, bad, nil)
	defer server.Close()

	client := NewClient(ln.Dial, nil, nil, "udp://127.0.0.1:5360")
	defer client.Close()
	resp, err := queryWithTimeout(client, "localhost.")
	if err != nil || resp.RCode != RCodeServerFailure {
		t.Fatalf(
			"server did not map upstream error to server failure: resp=%#v err=%v",
			resp,
			err,
		)
	}

	good := NewResolverProvider(ln, time.Second, nil)
	defer good.Close()
	server.Attach(good)
	resp, err = queryWithTimeout(client, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"server did not recover after attaching good upstream: resp=%#v err=%v",
			resp,
			err,
		)
	}
}

func TestCacheDoesNotStoreFailedResponsesAndSurvivesUpstreamErrors(
	t *testing.T,
) {
	bad := newRCodeDNS(RCodeServerFailure)
	cache := NewCache(bad, NewMemoryStorage(), nil)
	defer bad.Close()
	defer cache.Close()

	resp, err := queryWithTimeout(cache, "localhost.")
	if err != nil || resp.RCode != RCodeServerFailure {
		t.Fatalf(
			"bad upstream response not forwarded: resp=%#v err=%v",
			resp,
			err,
		)
	}

	good := NewResolverProvider(gonnect.NewLoopbackNetwok(), time.Second, nil)
	defer good.Close()
	cache.Attach(good)
	resp, err = queryWithTimeout(cache, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"cache did not survive failed upstream response: resp=%#v err=%v",
			resp,
			err,
		)
	}

	cache.Detach()
	resp, err = queryWithTimeout(cache, "localhost.")
	if err != nil || resp.RCode != RCodeSuccess || len(resp.Answers) == 0 {
		t.Fatalf(
			"cache did not store later successful response: resp=%#v err=%v",
			resp,
			err,
		)
	}
}

func TestResolverAdapterSurvivesDNSFailuresInChain(t *testing.T) {
	up := newToggleDNS()
	defer up.Close()
	cache := NewCache(up, NewMemoryStorage(), nil)
	defer cache.Close()
	detached := Detach(cache, nil)
	defer detached.Close()
	resolver := NewResolver(detached)

	up.fail = true
	if _, err := resolver.LookupHost(
		context.Background(),
		"localhost",
	); err == nil {
		t.Fatal("resolver lookup succeeded through failing DNS")
	}
	up.fail = false
	hosts, err := resolver.LookupHost(context.Background(), "localhost")
	if err != nil || len(hosts) == 0 {
		t.Fatalf(
			"resolver adapter did not recover after DNS failure: hosts=%v err=%v",
			hosts,
			err,
		)
	}
}

func queryWithTimeout(d Interface, name string) (*Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return Query(ctx, d, aQuery(name))
}

type errorDNS struct {
	p *provider
}

func newErrorDNS(err error) *errorDNS {
	d := &errorDNS{}
	d.p = newProvider(func(root context.Context, req Request) {
		sendResponse(req, nil, err)
	}, nil)
	return d
}

func (d *errorDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *errorDNS) Close() error             { return d.p.Close() }

type rcodeDNS struct {
	p     *provider
	rcode uint8
}

func newRCodeDNS(rcode uint8) *rcodeDNS {
	d := &rcodeDNS{rcode: rcode}
	d.p = newProvider(func(root context.Context, req Request) {
		resp := responseFor(req.Message)
		resp.RCode = d.rcode
		sendResponse(req, resp, nil)
	}, nil)
	return d
}

func (d *rcodeDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *rcodeDNS) Close() error             { return d.p.Close() }

type toggleDNS struct {
	p    *provider
	fail bool
}

func newToggleDNS() *toggleDNS {
	d := &toggleDNS{}
	d.p = newProvider(func(root context.Context, req Request) {
		resp := responseFor(req.Message)
		if d.fail {
			resp.RCode = RCodeServerFailure
		} else {
			resp.Answers = staticAnswers(req.Message.Questions[0])
		}
		sendResponse(req, resp, nil)
	}, nil)
	return d
}

func (d *toggleDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *toggleDNS) Close() error             { return d.p.Close() }
