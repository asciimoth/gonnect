package sniffer

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

type internalTCPConn struct {
	local, remote net.Addr
	closeCalls    int
}

func (c *internalTCPConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *internalTCPConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *internalTCPConn) Close() error {
	c.closeCalls++
	return nil
}

func (c *internalTCPConn) LocalAddr() net.Addr { return c.local }

func (c *internalTCPConn) RemoteAddr() net.Addr { return c.remote }

func (c *internalTCPConn) SetDeadline(time.Time) error { return nil }

func (c *internalTCPConn) SetReadDeadline(time.Time) error { return nil }

func (c *internalTCPConn) SetWriteDeadline(time.Time) error { return nil }

func (c *internalTCPConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(io.Discard, r)
}

func (c *internalTCPConn) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte("tcp"))
	return int64(n), err
}

func (c *internalTCPConn) SetKeepAlive(bool) error { return nil }

func (c *internalTCPConn) SetKeepAliveConfig(net.KeepAliveConfig) error {
	return nil
}

func (c *internalTCPConn) SetKeepAlivePeriod(time.Duration) error {
	return nil
}

func (c *internalTCPConn) SetLinger(int) error { return nil }

func (c *internalTCPConn) SetNoDelay(bool) error { return nil }

func (c *internalTCPConn) CloseRead() error { return nil }

func (c *internalTCPConn) CloseWrite() error { return nil }

type internalMulticastPacketConn struct {
	closeCalls int
}

func (c *internalMulticastPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (c *internalMulticastPacketConn) ReadFromControl(
	p []byte,
) (int, gonnect.ControlMessage, net.Addr, error) {
	return 0, gonnect.ControlMessage{}, nil, io.EOF
}

func (c *internalMulticastPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	return len(p), nil
}

func (c *internalMulticastPacketConn) WriteToControl(
	p []byte,
	cm gonnect.ControlMessage,
	dst net.Addr,
) (int, error) {
	return len(p), nil
}

func (c *internalMulticastPacketConn) Close() error {
	c.closeCalls++
	return nil
}

func (c *internalMulticastPacketConn) LocalAddr() net.Addr {
	return &gonnect.NetAddr{Net: "udp", Addr: "local"}
}

func (c *internalMulticastPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *internalMulticastPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *internalMulticastPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *internalMulticastPacketConn) JoinGroup(
	gonnect.NetworkInterface,
	net.Addr,
) error {
	return nil
}

func (c *internalMulticastPacketConn) LeaveGroup(
	gonnect.NetworkInterface,
	net.Addr,
) error {
	return nil
}

func (c *internalMulticastPacketConn) SetControlMessage(
	gonnect.ControlFlags,
	bool,
) error {
	return nil
}

func TestSnifferTCPConnAccessorsAndClose(t *testing.T) {
	base := &internalTCPConn{
		local:  &gonnect.NetAddr{Net: "tcp", Addr: "base-local"},
		remote: &gonnect.NetAddr{Net: "tcp", Addr: "base-remote"},
	}
	cancelCalls := 0
	conn := &snifferTCPConn{
		TCPConn:      base,
		cancelBridge: func() { cancelCalls++ },
	}

	if conn.GetWrapped() != base {
		t.Fatal("GetWrapped() returned the wrong connection")
	}
	if conn.LocalAddr().String() != "base-local" {
		t.Fatalf("LocalAddr() = %v, want base-local", conn.LocalAddr())
	}
	if conn.RemoteAddr().String() != "base-remote" {
		t.Fatalf("RemoteAddr() = %v, want base-remote", conn.RemoteAddr())
	}

	conn.setAddrs(
		&gonnect.NetAddr{Net: "tcp", Addr: "override-local"},
		&gonnect.NetAddr{Net: "tcp", Addr: "override-remote"},
	)
	if conn.LocalAddr().String() != "override-local" {
		t.Fatalf("LocalAddr() = %v, want override-local", conn.LocalAddr())
	}
	if conn.RemoteAddr().String() != "override-remote" {
		t.Fatalf("RemoteAddr() = %v, want override-remote", conn.RemoteAddr())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if cancelCalls != 1 || base.closeCalls != 1 {
		t.Fatalf(
			"close calls = cancel %d base %d, want 1 each",
			cancelCalls,
			base.closeCalls,
		)
	}
}

func TestMulticastPacketConnWithCallbackCloseOnce(t *testing.T) {
	base := &internalMulticastPacketConn{}
	callbacks := 0
	conn := &multicastPacketConnWithCallback{
		MulticastPacketConn: base,
		beforeClose:         func() { callbacks++ },
	}

	if conn.GetWrapped() != base {
		t.Fatal("GetWrapped() returned the wrong packet conn")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if callbacks != 1 || base.closeCalls != 1 {
		t.Fatalf(
			"close calls = callback %d base %d, want 1 each",
			callbacks,
			base.closeCalls,
		)
	}
}

func TestRunSnifferOpContextDoneClosesLateValue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	closedLate := make(chan string, 1)

	errCh := make(chan error, 1)
	go func() {
		_, err := runSnifferOp(
			nil,
			ctx,
			make(chan struct{}),
			func(context.Context) (string, error) {
				close(started)
				<-release
				return "late", nil
			},
			func(value string) {
				closedLate <- value
			},
		)
		errCh <- err
	}()

	<-started
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("runSnifferOp() error = %v, want context.Canceled", err)
	}
	close(release)
	select {
	case got := <-closedLate:
		if got != "late" {
			t.Fatalf("closed late value = %q, want late", got)
		}
	case <-time.After(time.Second):
		t.Fatal("late value was not closed")
	}
}

func TestRunSnifferOpDoneClosesLateValue(t *testing.T) {
	done := make(chan struct{})
	started := make(chan struct{})
	release := make(chan struct{})
	closedLate := make(chan string, 1)

	errCh := make(chan error, 1)
	go func() {
		_, err := runSnifferOp(
			nil,
			context.Background(),
			done,
			func(context.Context) (string, error) {
				close(started)
				<-release
				return "late", nil
			},
			func(value string) {
				closedLate <- value
			},
		)
		errCh <- err
	}()

	<-started
	close(done)
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("runSnifferOp() error = %v, want net.ErrClosed", err)
	}
	close(release)
	select {
	case got := <-closedLate:
		if got != "late" {
			t.Fatalf("closed late value = %q, want late", got)
		}
	case <-time.After(time.Second):
		t.Fatal("late value was not closed")
	}
}
