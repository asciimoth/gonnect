package tun_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

func TestDetachedTunDownUnblocksPendingRead(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := wrapper.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not unblock Read()")
	}

	done := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{1}}, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrapped Tun was closed by wrapper Down(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped Tun did not remain usable after wrapper Down()")
	}
}

func TestDetachedTunDownUnblocksPendingWrite(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	errCh := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([][]byte{{7}}, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Write() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Down() did not unblock Write()")
	}

	buf := make([]byte, 1500)
	sizes := make([]int, 1)
	_, err := b.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("wrapped Tun was closed by wrapper Down(): %v", err)
	}
}

func TestDetachedTunCloseDoesNotCloseWrappedTun(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	wrapper := tun.Detach(a)

	if err := wrapper.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := wrapper.Write(
		[][]byte{{1}},
		0,
	); !errors.Is(
		err,
		os.ErrClosed,
	) {
		t.Fatalf("Write() after Close() error = %v, want closed error", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{1}}, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrapped Tun was closed by wrapper Close(): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wrapped Tun did not remain usable after wrapper Close()")
	}
}

func TestNestedDetachedTunParentDownUnblocksChildRead(t *testing.T) {
	a, _ := tun.Pipe(1, 1500, 0, 0)
	parent := tun.Detach(a)
	child := tun.Detach(parent)
	grandchild := tun.Detach(child)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, err := grandchild.Read([][]byte{buf}, sizes, 0)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := parent.Down(); err != nil {
		t.Fatalf("parent Down() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("nested Read() error = %v, want closed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent Down() did not unblock nested Read()")
	}
}

func TestNestedDetachedTunChildDownDoesNotStopParent(t *testing.T) {
	a, b := tun.Pipe(1, 1500, 0, 0)
	parent := tun.Detach(a)
	child := tun.Detach(parent)

	if err := child.Down(); err != nil {
		t.Fatalf("child Down() error = %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := b.Write([][]byte{{9}}, 0)
		writeDone <- err
	}()

	buf := make([]byte, 1500)
	sizes := make([]int, 1)
	n, err := parent.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("parent Read() after child Down() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("parent Read() n = %d, want 1", n)
	}
	if len(sizes) == 0 {
		t.Fatal("parent Read() sizes is empty")
	}
	size := sizes[0]
	if size != 1 {
		t.Fatalf("parent Read() size = %d, want 1", size)
	}
	if buf[0] != 9 {
		t.Fatalf(
			"parent Read() byte = %d, want 9",
			buf[0],
		)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("peer Write() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer Write() did not complete")
	}
}
