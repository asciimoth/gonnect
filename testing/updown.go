package testing

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type UpDownNetwork interface {
	gonnect.Network
	gonnect.Resolver
	gonnect.UpDown
}

// RunStoppableNetworkTests verify that all Dial/Listen/Lookup operation fails
// for down networks.
func RunStoppableNetworkTests(t *testing.T, makeNet func() UpDownNetwork, safeAddr string) {
	t.Helper()
	ctx := context.Background()

	t.Run("Stop_Idempotent", func(t *testing.T) {
		nn := makeNet()
		// stop twice; must not panic and successive stops should be fine.
		nn.Down()
		nn.Down()
	})

	t.Run("MethodsReturnErrAfterStop", func(t *testing.T) {
		nn := makeNet()
		nn.Down()

		try := func(name string, fn func() error) {
			t.Run(name, func(t *testing.T) {
				if fn() == nil {
					t.Fatalf("expected network error after Down()")
				}
			})
		}

		// These calls should immediately return ErrNetworkStopped (per contract).
		try("Dial", func() error {
			_, err := nn.Dial(ctx, "tcp", "127.0.0.1:1")
			return err
		})
		try("Listen", func() error {
			_, err := nn.Listen(ctx, "tcp", "127.0.0.1:0")
			return err
		})
		try("ListenPacket", func() error {
			_, err := nn.ListenPacket(ctx, "udp", "127.0.0.1:0")
			return err
		})
		try("DialTCP", func() error {
			_, err := nn.DialTCP(ctx, "tcp", "", "127.0.0.1:1")
			return err
		})
		try("ListenTCP", func() error {
			_, err := nn.ListenTCP(ctx, "tcp", "127.0.0.1:0")
			return err
		})
		try("DialUDP", func() error {
			_, err := nn.DialUDP(ctx, "udp", "", "127.0.0.1:1")
			return err
		})
		try("ListenUDP", func() error {
			_, err := nn.ListenUDP(ctx, "udp", "127.0.0.1:0")
			return err
		})
		try("LookupMX", func() error {
			_, err := nn.LookupMX(ctx, "example.invalid")
			return err
		})
		try("LookupTXT", func() error {
			_, err := nn.LookupTXT(ctx, "example.invalid")
			return err
		})
		try("LookupSRV", func() error {
			_, _, err := nn.LookupSRV(ctx, "svc", "tcp", "example.invalid")
			return err
		})
	})

	t.Run("Stop_closes_listeners_and_connections_tcp", func(t *testing.T) {
		nn := makeNet()

		ln, err := nn.Listen(ctx, "tcp", safeAddr)
		if err != nil {
			t.Fatalf("failed to start tcp listener: %#v", err)
		}
		defer ln.Close() // safe no-op if already closed by Stop

		// obtain address string to connect
		addr := ln.Addr().String()

		// accept goroutine that returns accepted conn
		acceptCh := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			acceptCh <- c
		}()

		// Dial using the network under test
		client, err := nn.Dial(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial tcp: %#v", err)
		}

		// Ensure accept finished and we have the server side conn
		var server net.Conn
		select {
		case server = <-acceptCh:
			// ok
		case err := <-acceptErr:
			// accept errored unexpectedly => fail
			client.Close()
			t.Fatalf("accept failed unexpectedly: %v", err)
			return
		case <-time.After(10 * time.Second):
			client.Close()
			t.Fatal("timeout waiting for Accept()")
			return
		}

		// Now we have client and server open. Call Stop and confirm both get closed.
		nn.Down()

		// reading/writing should fail quickly
		_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 1)
		_, clientReadErr := client.Read(buf)

		_ = server.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, serverWriteErr := server.Write([]byte{0x1})

		// Accept was already done; listener Close should have been called by Stop. Double-close is safe.
		_ = ln.Close()
		_ = client.Close()
		_ = server.Close()

		if clientReadErr == nil || serverWriteErr == nil {
			t.Fatalf("expected read/write to fail after Stop(); got nil errors (clientReadErr=%v, serverWriteErr=%v)", clientReadErr, serverWriteErr)
		}
	})

	t.Run("Stop_unblocks_Accept_when_blocked", func(t *testing.T) {
		nn := makeNet()

		ln, err := nn.Listen(ctx, "tcp", safeAddr)
		if err != nil {
			t.Fatalf("failed to start tcp listener: %#v", err)
		}
		defer ln.Close()

		errCh := make(chan error, 1)
		go func() {
			_, err := ln.Accept()
			errCh <- err
		}()

		// Wait briefly to let Accept start and block.
		time.Sleep(time.Second)

		// Calling Stop should close the listener and make Accept return quickly with an error.
		nn.Down()

		select {
		case err := <-errCh:
			if err == nil {
				t.Fatalf("expected Accept() to return an error after Stop(), got nil")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for Accept() to return after Stop()")
		}
	})

	t.Run("Stop_unblocks_ReadFrom_when_blocked_packetconn", func(t *testing.T) {
		nn := makeNet()

		pc, err := nn.ListenPacket(ctx, "udp", safeAddr)
		if err != nil {
			t.Fatalf("failed to start udp listener: %#v", err)
		}
		defer pc.Close()

		// start goroutine which blocks in ReadFrom
		errCh := make(chan error, 1)
		go func() {
			buf := make([]byte, 16)
			_, _, err := pc.ReadFrom(buf)
			errCh <- err
		}()

		// give the goroutine a little time to enter ReadFrom
		time.Sleep(time.Second)

		// Stop should close the packet conn and unblock ReadFrom with an error
		nn.Down()

		select {
		case err := <-errCh:
			if err == nil {
				t.Fatalf("expected ReadFrom() to return an error after Stop(), got nil")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for ReadFrom() to return after Stop()")
		}
	})

	t.Run("Stop_closes_existing_tcp_connections_accept_and_dial_pairs", func(t *testing.T) {
		nn := makeNet()

		ln, err := nn.Listen(ctx, "tcp", safeAddr)
		if err != nil {
			t.Fatalf("failed to start tcp listener: %#v", err)
		}
		defer ln.Close()

		addr := ln.Addr().String()

		// accept the connection and return the server conn over a channel
		accCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			accCh <- c
		}()

		cli, err := nn.Dial(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial tcp: %#v", err)
		}

		var srv net.Conn
		select {
		case srv = <-accCh:
			// ok
		case e := <-errCh:
			cli.Close()
			t.Fatalf("accept failed: %v", e)
			return
		case <-time.After(10 * time.Second):
			cli.Close()
			t.Fatal("timeout waiting for Accept()")
			return
		}

		// now stop; existing conns must be closed
		nn.Down()

		// both sides should see EOF or error quickly
		_ = cli.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, rErr := cli.Read(make([]byte, 1))

		_ = srv.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, sErr := srv.Read(make([]byte, 1))

		_ = cli.Close()
		_ = srv.Close()

		if rErr == nil || sErr == nil {
			t.Fatalf("expected existing connections to be closed after Stop(); both Read() returned nil errors")
		}
	})
}
