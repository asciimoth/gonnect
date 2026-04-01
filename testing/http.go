package testing

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

// genRandomString returns a random alpha-numeric string of length n.
func genRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// seed once (best-effort; tests typically run in single process)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range n {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// RunSimpleHTTPTest runs a very small HTTP client-server test over net.Conn.
// - ln: the net.Listener (server side)
// - dial: function to create a client net.Conn connected to ln.Addr()
func RunSimpleHTTPTest(t *testing.T, ln net.Listener, dial gonnect.Dial) {
	t.Helper()

	serverErrCh := make(chan error, 1)

	body := genRandomString(256)
	// resp := fmt.Sprintf(
	// 	"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n%s",
	// 	len(body),
	// 	body,
	// )

	// HTTP handler: generate body, publish it, write response
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, body) // ignore write error here; Serve will report
	})

	server := &http.Server{
		Handler: handler,
	}

	// Serve in background
	go func() {
		// Serve returns ErrServerClosed when closed normally; convert that to nil.
		err := server.Serve(ln)
		if err == http.ErrServerClosed {
			serverErrCh <- nil
			return
		}
		serverErrCh <- err
	}()

	defer server.Close()

	// Create http.Client with custom Transport that uses provided dial.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
		// disable keep-alives to keep server lifecycle simple (one request)
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// Build URL using the listener address.
	url := "http://" + ln.Addr().String() + "/"

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("http client GET error: %v", err)
	}
	defer resp.Body.Close()

	// Expect 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Read response body
	gotBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = server.Close()
		t.Fatalf("read response body: %v", err)
	}
	gotBody := string(gotBodyBytes)

	// Compare
	if gotBody != body {
		_ = server.Close()
		t.Fatalf("body mismatch: expected %d bytes, got %d bytes\nexpected: %q\nreceived: %q",
			len(body), len(gotBody), body, gotBody)
	}

	// close server gracefully
	_ = server.Close()
	// wait for server goroutine to finish
	select {
	case serr := <-serverErrCh:
		if serr != nil {
			t.Fatalf("server error: %v", serr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server to stop")
	}
}

func RunSimpleHTTPForNetworks(t *testing.T, a, b NetAddrPair) {
	t.Helper()

	ctx := context.Background()
	lnA, err := a.Network.Listen(ctx, "tcp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()

	lnB, err := b.Network.Listen(ctx, "tcp", b.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lnA.Close()

	RunSimpleHTTPTest(t, lnA, b.Network.Dial)
	RunSimpleHTTPTest(t, lnB, a.Network.Dial)
}
