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

func TestResolverProviderCloseCancelsInFlightAndIsIdempotent(t *testing.T) {
	res := &cancelAwareResolver{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	provider := NewResolverProvider(res, time.Second)

	queryDone := make(chan error, 1)
	go func() {
		resp, err := Query(context.Background(), provider, aQuery("localhost."))
		if err == nil && (resp == nil || resp.RCode != RCodeServerFailure) {
			err = errors.New(
				"expected canceled resolver lookup to become server failure",
			)
		}
		queryDone <- err
	}()
	mustRecv(t, res.started, "resolver lookup start")
	mustCloseQuickly(t, provider, "resolver provider")
	mustRecv(t, res.canceled, "resolver lookup cancellation")
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	mustCloseQuickly(t, provider, "resolver provider second close")
	assertQueryAfterCloseReturns(t, provider)
}

func TestDetachedCloseCancelsInFlightAndKeepsUpstreamAlive(t *testing.T) {
	up := newControlledDNS()
	d := Detach(up)
	defer up.Close()

	queryDone := make(chan error, 1)
	go func() {
		_, err := Query(context.Background(), d, aQuery("localhost."))
		queryDone <- err
	}()
	mustRecv(t, up.started, "upstream request start")
	mustCloseQuickly(t, d, "detached")
	if err := <-queryDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("query error = %v, want context canceled", err)
	}
	if !up.sawCancel() {
		t.Fatal("upstream did not observe request cancellation")
	}

	resp, err := Query(context.Background(), up, aQuery("localhost."))
	if err != nil || len(resp.Answers) != 1 {
		t.Fatalf("upstream after detached close: resp=%#v err=%v", resp, err)
	}
}

func TestCacheCloseCancelsInFlightAndKeepsUpstreamAlive(t *testing.T) {
	up := newControlledDNS()
	cache := NewCache(up, NewMemoryStorage())
	defer up.Close()

	queryDone := make(chan error, 1)
	go func() {
		_, err := Query(context.Background(), cache, aQuery("uncached.test."))
		queryDone <- err
	}()
	mustRecv(t, up.started, "cache upstream request start")
	mustCloseQuickly(t, cache, "cache")
	if err := <-queryDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("query error = %v, want context canceled", err)
	}
	if !up.sawCancel() {
		t.Fatal("upstream did not observe cache cancellation")
	}

	resp, err := Query(context.Background(), up, aQuery("localhost."))
	if err != nil || len(resp.Answers) != 1 {
		t.Fatalf("upstream after cache close: resp=%#v err=%v", resp, err)
	}
	assertQueryAfterCloseReturns(t, cache)
}

func TestClientCloseCancelsInFlightUDPRead(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	sink, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:5356")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	client := NewClient(ln.Dial, "udp://127.0.0.1:5356")
	client.timeout = time.Hour
	queryDone := make(chan error, 1)
	go func() {
		_, err := Query(context.Background(), client, aQuery("localhost."))
		queryDone <- err
	}()
	waitForUDPDatagram(t, sink)
	mustCloseQuickly(t, client, "client")
	if err := <-queryDone; err == nil {
		t.Fatal("in-flight client query succeeded after close")
	}
	assertQueryAfterCloseReturns(t, client)
}

func TestServerCloseCancelsForwardedRequestAndClosesPacketConn(t *testing.T) {
	ln := gonnect.NewLoopbackNetwok()
	up := newControlledDNS()
	defer up.Close()

	serverConn, err := ln.ListenPacket(
		context.Background(),
		"udp4",
		"127.0.0.1:5357",
	)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(serverConn, up)

	clientConn, err := ln.Dial(context.Background(), "udp4", "127.0.0.1:5357")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	pkt, err := Pack(aQuery("localhost."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clientConn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	mustRecv(t, up.started, "server upstream request start")
	mustCloseQuickly(t, server, "server")
	if !up.sawCancel() {
		t.Fatal("upstream did not observe server cancellation")
	}
	if _, _, err = serverConn.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("server packet conn still readable after close")
	}
}

func mustCloseQuickly(t *testing.T, d Interface, name string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- d.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s close error = %v", name, err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s close did not return", name)
	}
}

func mustRecv(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func assertQueryAfterCloseReturns(t *testing.T, d Interface) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	if _, err := Query(
		ctx,
		d,
		aQuery("localhost."),
	); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("query after close error = %v, want deadline exceeded", err)
	}
}

func waitForUDPDatagram(t *testing.T, conn net.PacketConn) {
	t.Helper()
	if err := conn.SetReadDeadline(
		time.Now().Add(500 * time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	_, _, err := conn.ReadFrom(make([]byte, 512))
	if err != nil {
		t.Fatalf("timed out waiting for UDP datagram: %v", err)
	}
}

type cancelAwareResolver struct {
	fakeResolver
	started  chan struct{}
	canceled chan struct{}
}

func (r *cancelAwareResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	return nil, ctx.Err()
}

type controlledDNS struct {
	p        *provider
	started  chan struct{}
	canceled chan struct{}
}

func newControlledDNS() *controlledDNS {
	d := &controlledDNS{
		started:  make(chan struct{}, 8),
		canceled: make(chan struct{}, 8),
	}
	d.p = newProvider(func(root context.Context, req Request) {
		d.started <- struct{}{}
		ctx := req.Context
		if ctx == nil {
			ctx = context.Background()
		}
		select {
		case <-ctx.Done():
			d.canceled <- struct{}{}
			sendResponse(req, nil, ctx.Err())
		case <-root.Done():
			d.canceled <- struct{}{}
			sendResponse(req, nil, root.Err())
		case <-time.After(50 * time.Millisecond):
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
		}
	})
	return d
}

func (d *controlledDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *controlledDNS) Close() error             { return d.p.Close() }

func (d *controlledDNS) sawCancel() bool {
	select {
	case <-d.canceled:
		return true
	case <-time.After(500 * time.Millisecond):
		return false
	}
}
