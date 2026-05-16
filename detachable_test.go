package gonnect_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/loopback"
	"github.com/asciimoth/gonnect/native"
	gt "github.com/asciimoth/gonnect/testing"
)

func TestDetachedNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return gonnect.DetachNetwork(native.Config{}.Build())
	})
}

func TestDetachedNetwork_Stoppable(t *testing.T) {
	gt.RunStoppableNetworkTests(t, func() gt.UpDownNetwork {
		return gonnect.DetachNetwork(native.Config{}.Build())
	}, "127.0.0.1:0")
}

func TestDetachedNetworkTcpPingPong(t *testing.T) {
	base := native.Config{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestDetachedNetworkHTTP(t *testing.T) {
	base := native.Config{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestDetachedNetworkUdpPingPong(t *testing.T) {
	base := native.Config{}.Build()
	pair := gt.NetAddrPair{
		Network: gonnect.DetachNetwork(base),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestDetachedNetworkDownDoesNotStopWrappedNetwork(t *testing.T) {
	base := native.Config{}.Build()
	wrapper := gonnect.DetachNetwork(base)

	if err := wrapper.Down(); err != nil {
		t.Fatalf("wrapper Down() error = %v", err)
	}

	ln, err := base.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wrapped Network stopped by wrapper Down(): %v", err)
	}
	_ = ln.Close()
}

func TestDetachedNetworkWrappersAreIndependent(t *testing.T) {
	base := native.Config{}.Build()
	a := gonnect.DetachNetwork(base)
	b := gonnect.DetachNetwork(base)

	if err := a.Down(); err != nil {
		t.Fatalf("first wrapper Down() error = %v", err)
	}

	ln, err := b.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("second wrapper affected by first wrapper Down(): %v", err)
	}
	_ = ln.Close()
}

type blockingDialNetwork struct {
	gonnect.Network
	entered chan struct{}
}

func (n *blockingDialNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.entered <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDetachedNetworkDownCancelsParallelBlockedDials(t *testing.T) {
	wrapped := &blockingDialNetwork{
		Network: native.Config{}.Build(),
		entered: make(chan struct{}, 2),
	}
	wrapper := gonnect.DetachNetwork(wrapped)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := wrapper.Dial(context.Background(), "tcp", "blocked")
			errs <- err
		}()
	}

	for range 2 {
		select {
		case <-wrapped.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("blocked dials did not run in parallel")
		}
	}

	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not cancel blocked dials")
	}

	for range 2 {
		if err := <-errs; err == nil {
			t.Fatal("Dial returned nil error after Down()")
		}
	}
}

type delayedLoopbackNetwork struct {
	gonnect.Network
	delay   time.Duration
	entered chan string
}

func (n *delayedLoopbackNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.entered <- "Dial"
	time.Sleep(n.delay)
	return n.Network.Dial(ctx, network, address)
}

func (n *delayedLoopbackNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	n.entered <- "Listen"
	time.Sleep(n.delay)
	return n.Network.Listen(ctx, network, address)
}

func TestDetachedNetworkCloseCancelsContextIgnoringDialAndListen(
	t *testing.T,
) {
	wrapped := &delayedLoopbackNetwork{
		Network: loopback.NewLoopbackNetwok(),
		delay:   time.Second,
		entered: make(chan string, 2),
	}
	wrapper := gonnect.DetachNetwork(wrapped)

	dialErr := make(chan error, 1)
	go func() {
		_, err := wrapper.Dial(context.Background(), "tcp", "127.0.0.1:9")
		dialErr <- err
	}()

	listenErr := make(chan error, 1)
	go func() {
		ln, err := wrapper.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err == nil {
			_ = ln.Close()
		}
		listenErr <- err
	}()

	for range 2 {
		select {
		case <-wrapped.entered:
		case <-time.After(200 * time.Millisecond):
			t.Fatal("delayed operation did not start")
		}
	}

	start := time.Now()
	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for _, ch := range []chan error{dialErr, listenErr} {
		select {
		case err := <-ch:
			if err == nil {
				t.Fatal("operation returned nil error after Close()")
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("Close() did not release delayed operation immediately")
		}
	}
	if elapsed := time.Since(start); elapsed >= wrapped.delay {
		t.Fatalf("operations waited for wrapped delay: %v", elapsed)
	}
}
