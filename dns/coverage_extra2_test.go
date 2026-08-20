// nolint
package dns

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestNotImplementedErrorString(t *testing.T) {
	if got := (notImplementedError{}).Error(); got != "not implemented" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestRouterSetRouter(t *testing.T) {
	r := NewRouter(nil)
	defer r.Close()

	called := false
	if err := r.SetRouter(func(*Message) string {
		called = true
		return ""
	}); err != nil {
		t.Fatalf("SetRouter() error = %v", err)
	}
	_, _, err := r.current(&Message{})
	if !errors.Is(err, ErrNoUpstream) {
		t.Fatalf("current() error = %v, want ErrNoUpstream", err)
	}
	if !called {
		t.Fatal("SetRouter route function was not called")
	}
}

func TestCloseAllJoinsErrors(t *testing.T) {
	errA := errors.New("a")
	errB := errors.New("b")

	err := closeAll([]io.Closer{
		errCloser{err: errA},
		errCloser{},
		errCloser{err: errB},
	})
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("closeAll() error = %v, want joined a and b", err)
	}
}

func TestRawTXTSegments(t *testing.T) {
	if got := rawTXTSegments(nil); len(got) != 1 || got[0] != "" {
		t.Fatalf("rawTXTSegments(nil) = %q", got)
	}

	data := strings.Repeat("a", 256)
	got := rawTXTSegments([]byte(data))
	if len(got) != 2 || len(got[0]) != 255 || got[1] != "a" {
		t.Fatalf(
			"rawTXTSegments(256 bytes) lengths = %d/%d",
			len(got),
			len(got[0]),
		)
	}
}

func TestServerRequestsAccessor(t *testing.T) {
	ln := gonnect.NewLoopbackNetwork()
	conn, err := ln.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	server := NewServer(conn, nil, nil)
	defer func() { _ = server.Close() }()

	if server.Requests() == nil {
		t.Fatal("Requests() = nil")
	}
}

func TestPacketLimiterAcquireCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	limiter := newPacketLimiter(1)
	if !limiter.acquire(context.Background()) {
		t.Fatal("first acquire() = false, want true")
	}
	if limiter.acquire(ctx) {
		t.Fatal(
			"second acquire() = true with full limiter and canceled context",
		)
	}
	limiter.release()
	limiter.release()
}

func TestSendResponseDropsWhenReplyChannelFull(t *testing.T) {
	reply := make(chan Response, 1)
	reply <- Response{Err: errors.New("existing")}

	sendResponse(Request{Reply: reply}, &Message{ID: 42}, nil)

	got := <-reply
	if got.Message != nil || got.Err == nil || got.Err.Error() != "existing" {
		t.Fatalf("reply channel was overwritten: %#v", got)
	}
}

type errCloser struct {
	err error
}

func (c errCloser) Close() error { return c.err }
