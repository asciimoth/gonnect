package gonnect

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func newCloseRaceListener(t *testing.T) *loopbackTCPListener {
	t.Helper()
	reg := &loopbackTCPRegistry{Network: "tcp4", Host: "127.0.0.1"}
	listener, err := newLoopbackTCPListener(reg, nil)
	if err != nil {
		t.Fatalf("newLoopbackTCPListener() error = %v", err)
	}
	return listener
}

func newCloseRaceConn(
	listener *loopbackTCPListener,
) (net.Conn, *loopbackTCPConn) {
	client, server := newLoopbackTCPPipePair(
		&NetAddr{Net: "tcp4", Addr: "pipe:client"},
		listener.Laddr,
	)
	return client, &loopbackTCPConn{Conn: server, Laddr: listener.Laddr}
}

func TestLoopbackTCPListenerRejectsConnectionAfterClose(t *testing.T) {
	listener := newCloseRaceListener(t)
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for i := range 1000 {
		client, server := newCloseRaceConn(listener)
		err := listener.NewConn(server)
		_ = client.Close()
		_ = server.Close()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf(
				"NewConn() iteration %d error = %v, want net.ErrClosed",
				i,
				err,
			)
		}
	}
}

func TestLoopbackTCPListenerStaleLookupCannotReachReplacement(t *testing.T) {
	reg := &loopbackTCPRegistry{Network: "tcp4", Host: "127.0.0.1"}
	port := uint16(18080)
	oldListener, err := newLoopbackTCPListener(reg, &port)
	if err != nil {
		t.Fatalf("old newLoopbackTCPListener() error = %v", err)
	}
	stale := reg.Lookup(oldListener.Laddr)
	if stale != oldListener {
		t.Fatal("Lookup() did not return the old listener")
	}
	if err := oldListener.Close(); err != nil {
		t.Fatalf("old listener Close() error = %v", err)
	}

	replacement, err := newLoopbackTCPListener(reg, &port)
	if err != nil {
		t.Fatalf("replacement newLoopbackTCPListener() error = %v", err)
	}
	defer func() {
		_ = replacement.Close()
	}()
	client, server := newCloseRaceConn(oldListener)
	defer func() {
		_ = client.Close()
	}()
	defer func() {
		_ = server.Close()
	}()
	if err := stale.NewConn(server); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stale NewConn() error = %v, want net.ErrClosed", err)
	}
	if got := len(oldListener.acceptQ); got != 0 {
		t.Fatalf("old accept queue length = %d, want 0", got)
	}
	if got := len(replacement.acceptQ); got != 0 {
		t.Fatalf("replacement accept queue length = %d, want 0", got)
	}
}

func TestLoopbackTCPListenerCloseDrainsQueuedConnections(t *testing.T) {
	listener := newCloseRaceListener(t)
	clients := make([]net.Conn, 0, cap(listener.acceptQ))
	for range cap(listener.acceptQ) {
		client, server := newCloseRaceConn(listener)
		if err := listener.NewConn(server); err != nil {
			t.Fatalf("NewConn() error = %v", err)
		}
		clients = append(clients, client)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := len(listener.acceptQ); got != 0 {
		t.Fatalf("accept queue length = %d, want 0", got)
	}
	for i, client := range clients {
		if err := client.SetReadDeadline(
			time.Now().Add(time.Second),
		); err != nil {
			t.Fatalf("client %d SetReadDeadline() error = %v", i, err)
		}
		_, err := client.Read(make([]byte, 1))
		_ = client.Close()
		if err == nil {
			t.Fatalf("client %d Read() error = nil, want closed peer", i)
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf(
				"client %d Read() timed out; server peer was not closed",
				i,
			)
		}
	}
}

func TestLoopbackTCPListenerAcceptRejectsQueuedConnectionAfterClose(
	t *testing.T,
) {
	listener := newCloseRaceListener(t)
	client, server := newCloseRaceConn(listener)
	defer func() {
		_ = client.Close()
	}()
	if err := listener.NewConn(server); err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	conn, err := listener.AcceptTCP()
	if conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptTCP() = %v, %v; want nil, net.ErrClosed", conn, err)
	}
}

func TestLoopbackTCPListenerCloseWakesBlockedAccept(t *testing.T) {
	listener := newCloseRaceListener(t)
	result := make(chan error, 1)
	go func() {
		_, err := listener.AcceptTCP()
		result <- err
	}()

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("AcceptTCP() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AcceptTCP() did not return after Close()")
	}
}

func TestLoopbackTCPListenerCloseWakesBlockedNewConn(t *testing.T) {
	listener := newCloseRaceListener(t)
	clients := make([]net.Conn, 0, cap(listener.acceptQ)+1)
	for range cap(listener.acceptQ) {
		client, server := newCloseRaceConn(listener)
		if err := listener.NewConn(server); err != nil {
			t.Fatalf("NewConn() error = %v", err)
		}
		clients = append(clients, client)
	}
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()

	extraClient, extraServer := newCloseRaceConn(listener)
	clients = append(clients, extraClient)
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- listener.NewConn(extraServer)
	}()
	<-started
	select {
	case err := <-result:
		t.Fatalf("NewConn() returned before queue space or close: %v", err)
	case <-time.After(10 * time.Millisecond):
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("NewConn() error = %v, want net.ErrClosed", err)
		}
		_ = extraServer.Close()
	case <-time.After(time.Second):
		t.Fatal("NewConn() did not return after Close()")
	}
}

func TestLoopbackTCPListenerConcurrentCloseAndNewConn(t *testing.T) {
	const rounds = 100
	workers := min(16, runtime.GOMAXPROCS(0)*2)

	for round := range rounds {
		listener := newCloseRaceListener(t)
		start := make(chan struct{})
		clients := make(chan net.Conn, workers)
		var wg sync.WaitGroup
		for range workers {
			client, server := newCloseRaceConn(listener)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := listener.NewConn(server); err != nil {
					_ = server.Close()
				}
				clients <- client
			}()
		}
		close(start)
		if err := listener.Close(); err != nil {
			t.Fatalf("round %d Close() error = %v", round, err)
		}
		wg.Wait()
		close(clients)

		if got := len(listener.acceptQ); got != 0 {
			t.Fatalf("round %d accept queue length = %d, want 0", round, got)
		}
		for client := range clients {
			if err := client.SetReadDeadline(
				time.Now().Add(time.Second),
			); err != nil {
				t.Fatalf("round %d SetReadDeadline() error = %v", round, err)
			}
			_, err := client.Read(make([]byte, 1))
			_ = client.Close()
			if err == nil {
				t.Fatalf("round %d Read() error = nil, want closed peer", round)
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatalf("round %d client has an orphaned server peer", round)
			}
		}
	}
}
