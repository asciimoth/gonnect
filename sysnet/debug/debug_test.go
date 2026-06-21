// nolint
package sysnetdebug

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
)

func TestBuildTunPeerRenameAndClose(t *testing.T) {
	system := &System{}
	tunDev, err := system.BuildTun(sysnet.TunOpts{
		MTU:      1400,
		TunAddrs: []string{"10.0.0.2/32"},
	})
	if err != nil {
		t.Fatalf("BuildTun error = %v", err)
	}

	entry, ok := system.GetTunPeer("tun")
	if !ok {
		t.Fatal("GetTunPeer(tun) not found")
	}
	if entry.Tun != tunDev || entry.Peer == nil {
		t.Fatalf(
			"GetTunPeer returned unexpected handles: tun=%v peer=%v",
			entry.Tun,
			entry.Peer,
		)
	}

	names, err := system.SetTunName(tunDev, "renamed0")
	if err != nil {
		t.Fatalf("SetTunName error = %v", err)
	}
	if len(names) != 1 || names[0] != "renamed0" {
		t.Fatalf("SetTunName names = %v, want [renamed0]", names)
	}
	name, err := tunDev.Name()
	if err != nil {
		t.Fatalf("Tun.Name error = %v", err)
	}
	if name != "renamed0" {
		t.Fatalf("Tun.Name = %q, want renamed0", name)
	}
	if _, ok := system.GetTunPeer("tun"); ok {
		t.Fatal("old tun name still present")
	}

	if err := tunDev.Close(); err != nil {
		t.Fatalf("Tun.Close error = %v", err)
	}
	if _, ok := system.GetTunPeer("renamed0"); ok {
		t.Fatal("closed tun still present")
	}
	if err := system.SetTunMTU(
		tunDev,
		1200,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunMTU(closed) = %v, want ErrUnknownTun", err)
	}
}

func TestDefaultTunRebuildClearsDNSAndCloseRemovesEntry(t *testing.T) {
	system := &System{}
	first, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{MTU: 1300})
	if err != nil {
		t.Fatalf("BuildDefaultTun error = %v", err)
	}
	entry, ok := system.GetDefaultTunPeer()
	if !ok || entry.Peer == nil || !entry.Default {
		t.Fatalf(
			"GetDefaultTunPeer = (%+v, %v), want default entry with peer",
			entry,
			ok,
		)
	}

	provider := newFakeDNS()
	first.SetDns(provider)
	second, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		MTU:       1200,
		TunRoutes: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatalf("rebuild BuildDefaultTun error = %v", err)
	}
	if second != first {
		t.Fatal("BuildDefaultTun rebuild returned a different tun")
	}
	if got, err := second.MTU(); err != nil || got != 1200 {
		t.Fatalf("rebuilt MTU = %d, %v; want 1200, nil", got, err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	reply := make(chan dns.Response, 1)
	system.Requests() <- dns.Request{Context: ctx, Reply: reply}
	select {
	case <-reply:
		t.Fatal("DNS request was routed after rebuild cleared resolver")
	case <-ctx.Done():
	}
	if provider.requestsSeen() != 0 {
		t.Fatalf("provider saw %d requests, want 0", provider.requestsSeen())
	}

	second.SetDns(provider)
	reply = make(chan dns.Response, 1)
	system.Requests() <- dns.Request{Context: context.Background(), Reply: reply}
	select {
	case response := <-reply:
		if response.Err != nil {
			t.Fatalf("routed DNS response error = %v", response.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for routed DNS response")
	}
	if provider.requestsSeen() != 1 {
		t.Fatalf("provider saw %d requests, want 1", provider.requestsSeen())
	}

	if err := second.Close(); err != nil {
		t.Fatalf("DefaultTun.Close error = %v", err)
	}
	if _, ok := system.GetDefaultTunPeer(); ok {
		t.Fatal("closed default tun still present")
	}
}

type fakeDNS struct {
	requests chan dns.Request
	seen     chan struct{}
}

func newFakeDNS() *fakeDNS {
	f := &fakeDNS{
		requests: make(chan dns.Request),
		seen:     make(chan struct{}, 8),
	}
	go func() {
		for req := range f.requests {
			f.seen <- struct{}{}
			if req.Reply != nil {
				req.Reply <- dns.Response{}
			}
		}
	}()
	return f
}

func (f *fakeDNS) Requests() chan<- dns.Request { return f.requests }

func (f *fakeDNS) Close() error {
	close(f.requests)
	return nil
}

func (f *fakeDNS) requestsSeen() int {
	return len(f.seen)
}
