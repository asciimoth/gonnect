package sniffer_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestHTTPClassifierMatchesArbitraryRequestLine(t *testing.T) {
	classifier := sniffer.HTTP()
	if got := sniffer.Metadata(classifier); got != nil {
		t.Fatalf("initial Metadata() = %#v, want nil", got)
	}
	if got := classifier.Feed(nil); got != sniffer.NeedMore {
		t.Fatalf("initial state = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("WEIRD-")); got != sniffer.NeedMore {
		t.Fatalf("partial method state = %v, want NeedMore", got)
	}
	if got := classifier.Feed(
		[]byte("METHOD /path?q=1 HTTP/9.custom\r\nHeader: value\r\n"),
	); got != sniffer.Match {
		t.Fatalf("request state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("state after Match = %v, want Match", got)
	}
	info, ok := sniffer.Metadata(classifier).(sniffer.HTTPInfo)
	if !ok || info.Method != "WEIRD-METHOD" ||
		info.URL != "/path?q=1" ||
		info.Version != "HTTP/9.custom" {
		t.Fatalf(
			"Metadata() = %#v, want parsed HTTP info",
			sniffer.Metadata(classifier),
		)
	}
}

func TestHTTPClassifierConfig(t *testing.T) {
	requestLine := []byte("POST /submit?x=1 HTTP/1.1\r\n")
	tests := []struct {
		name   string
		config sniffer.HTTPConfig
		want   sniffer.State
	}{
		{
			name: "exact fields",
			config: sniffer.HTTPConfig{
				Method:  "POST",
				URL:     "/submit?x=1",
				Version: "HTTP/1.1",
			},
			want: sniffer.Match,
		},
		{
			name: "method mismatch",
			config: sniffer.HTTPConfig{
				Method:  "GET",
				URL:     "/submit?x=1",
				Version: "HTTP/1.1",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "URL mismatch",
			config: sniffer.HTTPConfig{
				Method:  "POST",
				URL:     "/other",
				Version: "HTTP/1.1",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "version mismatch",
			config: sniffer.HTTPConfig{
				Method:  "POST",
				URL:     "/submit?x=1",
				Version: "HTTP/2.0",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "wildcards",
			config: sniffer.HTTPConfig{
				URL: "/submit?x=1",
			},
			want: sniffer.Match,
		},
		{
			name: "multiple methods",
			config: sniffer.HTTPConfig{
				Methods: []string{http.MethodGet, http.MethodPost},
				URL:     "/submit?x=1",
				Version: "HTTP/1.1",
			},
			want: sniffer.Match,
		},
		{
			name: "multiple versions",
			config: sniffer.HTTPConfig{
				Method:   http.MethodPost,
				URL:      "/submit?x=1",
				Versions: []string{"HTTP/1.0", "HTTP/1.1"},
			},
			want: sniffer.Match,
		},
		{
			name: "multiple URLs",
			config: sniffer.HTTPConfig{
				Method: http.MethodPost,
				URLs:   []string{"/other", "/submit?x=1"},
			},
			want: sniffer.Match,
		},
		{
			name: "multiple method mismatch",
			config: sniffer.HTTPConfig{
				Methods: []string{http.MethodGet, http.MethodPut},
				URL:     "/submit?x=1",
			},
			want: sniffer.Mismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifier := sniffer.HTTPWithConfig(test.config)
			if got := classifier.Feed(requestLine); got != test.want {
				t.Fatalf("state = %v, want %v", got, test.want)
			}
		})
	}
}

func TestHTTPClassifierURLPatterns(t *testing.T) {
	tests := []struct {
		name   string
		config sniffer.HTTPConfig
		line   string
		want   sniffer.State
	}{
		{
			name: "API prefix matches nested URL",
			config: sniffer.HTTPConfig{
				Methods:     []string{http.MethodGet, http.MethodPost},
				URLPatterns: []string{"/api/*"},
			},
			line: "GET /api/v1/users?id=7 HTTP/9.custom\r\n",
			want: sniffer.Match,
		},
		{
			name: "method must still match",
			config: sniffer.HTTPConfig{
				Methods:     []string{http.MethodGet, http.MethodPost},
				URLPatterns: []string{"/api/*"},
			},
			line: "DELETE /api/v1/users HTTP/1.1\r\n",
			want: sniffer.Mismatch,
		},
		{
			name: "URL must still match",
			config: sniffer.HTTPConfig{
				Methods:     []string{http.MethodGet, http.MethodPost},
				URLPatterns: []string{"/api/*"},
			},
			line: "GET /health HTTP/1.1\r\n",
			want: sniffer.Mismatch,
		},
		{
			name: "escaped pattern metacharacter",
			config: sniffer.HTTPConfig{
				URLPatterns: []string{`/api/search\?q=*`},
			},
			line: "GET /api/search?q=name HTTP/1.1\r\n",
			want: sniffer.Match,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifier := sniffer.HTTPWithConfig(test.config)
			if got := classifier.Feed([]byte(test.line)); got != test.want {
				t.Fatalf("state = %v, want %v", got, test.want)
			}
		})
	}
}

func TestHTTPClassifierHostname(t *testing.T) {
	tests := []struct {
		name      string
		config    sniffer.HTTPConfig
		fragments []string
		want      sniffer.State
	}{
		{
			name: "Host header exact match",
			config: sniffer.HTTPConfig{
				Method:   http.MethodGet,
				URL:      "/api/users",
				Hostname: "api.example.test",
			},
			fragments: []string{
				"GET /api/users HTTP/1.1\r\nUser-Agent: test\r\n",
				"Host: API.EXAMPLE.TEST:8080\r\n",
			},
			want: sniffer.Match,
		},
		{
			name: "absolute request-target host match",
			config: sniffer.HTTPConfig{
				URLPatterns: []string{"http://*/api/*"},
				Hostnames:   []string{"api.example.test"},
			},
			fragments: []string{
				"GET http://api.example.test/api/users HTTP/1.1\r\n",
				"Host: other.example.test\r\n",
			},
			want: sniffer.Match,
		},
		{
			name: "Host pattern match",
			config: sniffer.HTTPConfig{
				URLPatterns:      []string{"/api/*"},
				HostnamePatterns: []string{"*.example.test"},
			},
			fragments: []string{
				"GET /api/users HTTP/1.1\r\n",
				"Host: v1.api.example.test\r\n",
			},
			want: sniffer.Match,
		},
		{
			name: "Host mismatch",
			config: sniffer.HTTPConfig{
				Hostname: "api.example.test",
			},
			fragments: []string{
				"GET /api/users HTTP/1.1\r\n",
				"Host: www.example.test\r\n",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "missing Host",
			config: sniffer.HTTPConfig{
				Hostname: "api.example.test",
			},
			fragments: []string{
				"GET /api/users HTTP/1.1\r\n",
				"User-Agent: test\r\n\r\n",
			},
			want: sniffer.Mismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifier := sniffer.HTTPWithConfig(test.config)
			state := classifier.Feed(nil)
			for _, fragment := range test.fragments {
				if state != sniffer.NeedMore {
					break
				}
				state = classifier.Feed([]byte(fragment))
			}
			if state != test.want {
				t.Fatalf("state = %v, want %v", state, test.want)
			}
		})
	}
}

func TestHTTPClassifierHeaderLimit(t *testing.T) {
	classifier := sniffer.HTTPWithConfig(sniffer.HTTPConfig{
		MaxHeaderBytes: 10,
		Hostname:       "api.example.test",
	})
	if got := classifier.Feed(
		[]byte("GET / HTTP/1.1\r\nX-Test: value\r\n"),
	); got != sniffer.Mismatch {
		t.Fatalf("state = %v, want Mismatch", got)
	}
}

func TestHTTPClassifierRejectsInvalidRequestLines(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "response", line: "HTTP/1.1 200 OK\r\n"},
		{name: "empty method", line: " / HTTP/1.1\r\n"},
		{name: "empty target", line: "GET  HTTP/1.1\r\n"},
		{name: "empty version suffix", line: "GET / HTTP/\r\n"},
		{name: "extra field", line: "GET / HTTP/1.1 extra\r\n"},
		{name: "space in target", line: "GET /bad path HTTP/1.1\r\n"},
		{name: "control byte", line: "GET /\x00 HTTP/1.1\r\n"},
		{name: "bare carriage return", line: "GET / HTTP/1.1\rx\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.HTTP().
				Feed([]byte(test.line)); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}
}

func TestHTTPClassifierLineEndingAndLimit(t *testing.T) {
	requestLine := "GET / HTTP/1.1\r\n"

	classifier := sniffer.HTTPWithConfig(sniffer.HTTPConfig{
		MaxRequestLineBytes: len(requestLine),
	})
	if got := classifier.Feed(
		[]byte(requestLine[:len(requestLine)-1]),
	); got != sniffer.NeedMore {
		t.Fatalf("state before LF = %v, want NeedMore", got)
	}
	if got := classifier.Feed(
		[]byte(requestLine[len(requestLine)-1:]),
	); got != sniffer.Match {
		t.Fatalf("state at LF = %v, want Match", got)
	}

	classifier = sniffer.HTTPWithConfig(sniffer.HTTPConfig{
		MaxRequestLineBytes: len(requestLine) - 1,
	})
	if got := classifier.Feed([]byte(requestLine)); got != sniffer.Mismatch {
		t.Fatalf("over-limit state = %v, want Mismatch", got)
	}
}

func TestHTTPFactory(t *testing.T) {
	factory := sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
		MaxRequestLineBytes: 64,
		Method:              "GET",
	})
	if got := factory.MinSniffBufferSize(); got != 64 {
		t.Fatalf("MinSniffBufferSize = %d, want 64", got)
	}

	first := factory.NewClassifier()
	second := factory.NewClassifier()
	if got := first.Feed([]byte("G")); got != sniffer.NeedMore {
		t.Fatalf("first partial state = %v, want NeedMore", got)
	}
	if got := second.Feed([]byte("GET /two HTTP/1.1\n")); got != sniffer.Match {
		t.Fatalf("second state = %v, want Match", got)
	}
	if got := first.Feed([]byte("ET /one HTTP/1.1\n")); got != sniffer.Match {
		t.Fatalf("first final state = %v, want Match", got)
	}

	hostnameFactory := sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
		MaxRequestLineBytes: 64,
		MaxHeaderBytes:      128,
		Hostname:            "api.example.test",
	})
	if got := hostnameFactory.MinSniffBufferSize(); got != 192 {
		t.Fatalf("hostname MinSniffBufferSize = %d, want 192", got)
	}
}

func TestHTTPNegativeLimitPanics(t *testing.T) {
	tests := []struct {
		name   string
		config sniffer.HTTPConfig
	}{
		{
			name:   "request line",
			config: sniffer.HTTPConfig{MaxRequestLineBytes: -1},
		},
		{
			name:   "header",
			config: sniffer.HTTPConfig{MaxHeaderBytes: -1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("HTTPWithConfig did not panic")
				}
			}()
			_ = sniffer.HTTPWithConfig(test.config)
		})
	}
}

type sniffResult struct {
	index int
	err   error
}

type sniffingListener struct {
	net.Listener
	factories  []sniffer.Factory
	bufferSize int
	results    chan sniffResult
}

func (l *sniffingListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	conn := putback.New(raw, nil)
	if err := conn.SetReadDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		_ = conn.Close()
		return nil, err
	}

	index, sniffErr := sniffer.SniffFactories(
		make([]byte, l.bufferSize),
		conn,
		l.factories...,
	)
	if clearErr := conn.SetReadDeadline(time.Time{}); sniffErr == nil {
		sniffErr = clearErr
	}

	l.results <- sniffResult{index: index, err: sniffErr}
	if sniffErr != nil {
		_ = conn.Close()
		return nil, sniffErr
	}
	return conn, nil
}

func TestHTTPFactoryWithRealClientServerThroughSniffer(t *testing.T) {
	var listenConfig net.ListenConfig
	rawListener, err := listenConfig.Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	factories := []sniffer.Factory{
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			Methods:          []string{http.MethodGet, http.MethodPost},
			URLPatterns:      []string{"/classified*"},
			Version:          "HTTP/1.1",
			HostnamePatterns: []string{"api.*.test"},
		}),
	}
	listener := &sniffingListener{
		Listener:   rawListener,
		factories:  factories,
		bufferSize: sniffer.MinFactorySniffBufferSize(factories...),
		results:    make(chan sniffResult, 1),
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "wrong method", http.StatusBadRequest)
				return
			}
			if r.RequestURI != "/classified?route=sniffer" {
				http.Error(w, "wrong request URI", http.StatusBadRequest)
				return
			}
			if r.Proto != "HTTP/1.1" {
				http.Error(w, "wrong protocol", http.StatusBadRequest)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, "received:%s", body)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("Server.Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Server.Serve did not return")
		}
	})

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(
			ctx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(
				ctx,
				rawListener.Addr().Network(),
				rawListener.Addr().String(),
			)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://api.example.test/classified?route=sniffer",
		strings.NewReader("payload"),
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, body = %q, want 200 OK", resp.Status, body)
	}
	if string(body) != "received:payload" {
		t.Fatalf("body = %q, want received:payload", body)
	}

	select {
	case result := <-listener.results:
		if result.err != nil {
			t.Fatalf("sniff error: %v", result.err)
		}
		if result.index != 0 {
			t.Fatalf("sniff index = %d, want 0", result.index)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sniffer did not inspect the accepted connection")
	}
}
