package sniffer_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestTLSClassifierConfig(t *testing.T) {
	hello := testTLSClientHello(
		t,
		tls.VersionTLS13,
		"api.example.test",
		[]string{"h2", "http/1.1"},
	)

	tests := []struct {
		name   string
		config sniffer.TLSConfig
		want   sniffer.State
	}{
		{
			name:   "wildcard",
			config: sniffer.TLSConfig{},
			want:   sniffer.Match,
		},
		{
			name: "exact fields",
			config: sniffer.TLSConfig{
				Version:      tls.VersionTLS13,
				SNIAvailable: sniffer.TLSFlagRequired,
				SNIEncrypted: sniffer.TLSFlagForbidden,
				Hostname:     "API.EXAMPLE.TEST",
				ALPN:         "h2",
			},
			want: sniffer.Match,
		},
		{
			name: "version mismatch",
			config: sniffer.TLSConfig{
				Version: tls.VersionTLS12,
			},
			want: sniffer.Mismatch,
		},
		{
			name: "hostname pattern",
			config: sniffer.TLSConfig{
				HostnamePatterns: []string{"*.example.test"},
			},
			want: sniffer.Match,
		},
		{
			name: "hostname mismatch",
			config: sniffer.TLSConfig{
				Hostname: "www.example.test",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "ALPNs",
			config: sniffer.TLSConfig{
				ALPNs: []string{"spdy/3", "http/1.1"},
			},
			want: sniffer.Match,
		},
		{
			name: "ALPN mismatch",
			config: sniffer.TLSConfig{
				ALPN: "acme-tls/1",
			},
			want: sniffer.Mismatch,
		},
		{
			name: "visible SNI forbidden",
			config: sniffer.TLSConfig{
				SNIAvailable: sniffer.TLSFlagForbidden,
			},
			want: sniffer.Mismatch,
		},
		{
			name: "encrypted SNI required",
			config: sniffer.TLSConfig{
				SNIEncrypted: sniffer.TLSFlagRequired,
			},
			want: sniffer.Mismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classifier := sniffer.TLSWithConfig(test.config)
			if got := classifier.Feed(hello); got != test.want {
				t.Fatalf("state = %v, want %v", got, test.want)
			}
		})
	}
}

func TestTLSClassifierEncryptedClientHelloFlag(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, "public.example.test"),
		tlsTestALPN(t, "h2"),
		tlsTestExtension{typ: 0xfe0d},
	)

	classifier := sniffer.TLSWithConfig(sniffer.TLSConfig{
		Version:      tls.VersionTLS13,
		SNIAvailable: sniffer.TLSFlagRequired,
		SNIEncrypted: sniffer.TLSFlagRequired,
		Hostname:     "public.example.test",
		ALPN:         "h2",
	})
	if got := classifier.Feed(hello); got != sniffer.Match {
		t.Fatalf("state = %v, want Match", got)
	}

	classifier = sniffer.TLSWithConfig(sniffer.TLSConfig{
		SNIEncrypted: sniffer.TLSFlagForbidden,
	})
	if got := classifier.Feed(hello); got != sniffer.Mismatch {
		t.Fatalf("forbidden ECH state = %v, want Mismatch", got)
	}
}

func TestSniffTLSClientHelloInfoAndReplay(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13, tls.VersionTLS12),
		tlsTestServerName(t, "API.Example.Test"),
		tlsTestALPN(t, "h2", "http/1.1"),
		tlsTestExtension{typ: 0xfe0d},
	)
	conn := putback.New(newChunkConn(string(hello), "payload"), nil)

	info, ok, err := sniffer.SniffTLSClientHello(
		make([]byte, len(hello)),
		conn,
	)
	if err != nil {
		t.Fatalf("SniffTLSClientHello() error = %v", err)
	}
	if !ok {
		t.Fatal("SniffTLSClientHello() ok = false, want true")
	}
	if !slices.Equal(
		info.Versions,
		[]uint16{tls.VersionTLS13, tls.VersionTLS12},
	) {
		t.Fatalf(
			"Versions = %v, want [%d %d]",
			info.Versions,
			tls.VersionTLS13,
			tls.VersionTLS12,
		)
	}
	if info.SNIHostname != "api.example.test" {
		t.Fatalf(
			"SNIHostname = %q, want api.example.test",
			info.SNIHostname,
		)
	}
	if !info.SNIEncrypted {
		t.Fatal("SNIEncrypted = false, want true")
	}
	if !slices.Equal(info.ALPNProtocols, []string{"h2", "http/1.1"}) {
		t.Fatalf(
			"ALPNProtocols = %v, want [h2 http/1.1]",
			info.ALPNProtocols,
		)
	}

	if got := readAll(t, conn); got != string(hello)+"payload" {
		t.Fatalf("replayed stream = %q, want original stream", got)
	}
}

func TestSniffTLSClientHelloNoMatchAndReplay(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
	)
	conn := putback.New(newChunkConn(string(hello)), nil)

	_, ok, err := sniffer.SniffTLSClientHello(
		make([]byte, len(hello)-1),
		conn,
	)
	if err != nil {
		t.Fatalf("SniffTLSClientHello() error = %v", err)
	}
	if ok {
		t.Fatal("SniffTLSClientHello() ok = true, want false")
	}

	if got := readAll(t, conn); got != string(hello) {
		t.Fatalf("replayed stream = %q, want original ClientHello", got)
	}
}

func TestSniffTLSClientHelloUsesBufferLengthAsLimit(t *testing.T) {
	const host = "large.example.test"
	hello := largeTLSTestClientHello(t, host)
	if len(hello) <= sniffer.DefaultTLSClientHelloMaxBytes {
		t.Fatalf(
			"large ClientHello length = %d, want > %d",
			len(hello),
			sniffer.DefaultTLSClientHelloMaxBytes,
		)
	}

	conn := putback.New(newChunkConn(string(hello), "payload"), nil)
	info, ok, err := sniffer.SniffTLSClientHello(
		make([]byte, len(hello)),
		conn,
	)
	if err != nil {
		t.Fatalf("SniffTLSClientHello() error = %v", err)
	}
	if !ok {
		t.Fatal("SniffTLSClientHello() ok = false, want true")
	}
	if info.SNIHostname != host {
		t.Fatalf("SNIHostname = %q, want %s", info.SNIHostname, host)
	}

	if got := readAll(t, conn); got != string(hello)+"payload" {
		t.Fatalf("replayed stream = %q, want original stream", got)
	}
}

func TestTLSClassifierWithoutExtensions(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12)

	classifier := sniffer.TLSWithConfig(sniffer.TLSConfig{
		Version:      tls.VersionTLS12,
		SNIAvailable: sniffer.TLSFlagForbidden,
		SNIEncrypted: sniffer.TLSFlagForbidden,
	})
	if got := classifier.Feed(hello); got != sniffer.Match {
		t.Fatalf("state = %v, want Match", got)
	}

	classifier = sniffer.TLSWithConfig(sniffer.TLSConfig{
		Hostname: "api.example.test",
	})
	if got := classifier.Feed(hello); got != sniffer.Mismatch {
		t.Fatalf("hostname state = %v, want Mismatch", got)
	}
}

func TestTLSClassifierFragmentationAndFactory(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
	)
	factory := sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
		MaxClientHelloBytes: len(hello),
		Version:             tls.VersionTLS12,
		Hostname:            "api.example.test",
	})
	if got := factory.MinSniffBufferSize(); got != len(hello) {
		t.Fatalf("MinSniffBufferSize = %d, want %d", got, len(hello))
	}

	first := factory.NewClassifier()
	second := factory.NewClassifier()
	if got := first.Feed(hello[:7]); got != sniffer.NeedMore {
		t.Fatalf("first partial state = %v, want NeedMore", got)
	}
	if got := second.Feed(hello); got != sniffer.Match {
		t.Fatalf("second state = %v, want Match", got)
	}
	if got := first.Feed(hello[7:]); got != sniffer.Match {
		t.Fatalf("first final state = %v, want Match", got)
	}
	if got := first.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("state after Match = %v, want Match", got)
	}
}

func TestTLSClassifierMatchesEveryTCPFeedSplit(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
		tlsTestALPN(t, "http/1.1"),
	)

	for split := range len(hello) + 1 {
		t.Run(fmt.Sprintf("split-%d", split), func(t *testing.T) {
			classifier := testTLSConfiguredClassifier()
			state := classifier.Feed(hello[:split])
			if split < len(hello) {
				if state != sniffer.NeedMore {
					t.Fatalf(
						"first state = %v, want NeedMore",
						state,
					)
				}
				state = classifier.Feed(hello[split:])
			}
			if state != sniffer.Match {
				t.Fatalf("final state = %v, want Match", state)
			}
		})
	}
}

func TestTLSClassifierMatchesOneByteFeeds(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
		tlsTestALPN(t, "http/1.1"),
	)

	classifier := testTLSConfiguredClassifier()
	state := classifier.Feed(nil)
	if state != sniffer.NeedMore {
		t.Fatalf("initial state = %v, want NeedMore", state)
	}
	for offset, b := range hello {
		state = classifier.Feed([]byte{b})
		if offset < len(hello)-1 {
			if state != sniffer.NeedMore {
				t.Fatalf(
					"state at offset %d = %v, want NeedMore",
					offset,
					state,
				)
			}
			continue
		}
		if state != sniffer.Match {
			t.Fatalf("final state = %v, want Match", state)
		}
	}
}

func TestTLSSniffMatchesFragmentedClientHelloAndReplays(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
		tlsTestALPN(t, "http/1.1"),
	)
	chunks := make([]string, len(hello)+1)
	for i, b := range hello {
		chunks[i] = string([]byte{b})
	}
	chunks[len(hello)] = "payload"

	conn := putback.New(newChunkConn(chunks...), nil)
	index, err := sniffer.Sniff(
		make([]byte, len(hello)),
		conn,
		testTLSConfiguredClassifier(),
	)
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if index != 0 {
		t.Fatalf("index = %d, want 0", index)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll after Sniff: %v", err)
	}
	if want := append(
		append([]byte(nil), hello...),
		[]byte("payload")...); !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf("replayed stream changed")
	}
}

func TestTLSClassifierMatchesEveryClientHelloRecordSplit(t *testing.T) {
	hello := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestServerName(t, "api.example.test"),
		tlsTestALPN(t, "http/1.1"),
	)
	recordLength := int(binary.BigEndian.Uint16(hello[3:5]))

	for recordSplit := 1; recordSplit < recordLength; recordSplit++ {
		t.Run(fmt.Sprintf("record-split-%d", recordSplit), func(t *testing.T) {
			fragmented := splitTLSClientHelloRecord(t, hello, recordSplit)
			for feedSplit := range len(fragmented) + 1 {
				classifier := testTLSConfiguredClassifier()
				state := classifier.Feed(fragmented[feedSplit:feedSplit])
				if state != sniffer.NeedMore {
					t.Fatalf(
						"empty Feed at split %d = %v, want NeedMore",
						feedSplit,
						state,
					)
				}
				state = classifier.Feed(fragmented[:feedSplit])
				if feedSplit < len(fragmented) {
					if state != sniffer.NeedMore {
						t.Fatalf(
							"first state at split %d = %v, want NeedMore",
							feedSplit,
							state,
						)
					}
					state = classifier.Feed(fragmented[feedSplit:])
				}
				if state != sniffer.Match {
					t.Fatalf(
						"final state at split %d = %v, want Match",
						feedSplit,
						state,
					)
				}
			}
		})
	}
}

func testTLSConfiguredClassifier() sniffer.Classifier {
	return sniffer.TLSWithConfig(sniffer.TLSConfig{
		Version:  tls.VersionTLS12,
		Hostname: "api.example.test",
		ALPN:     "http/1.1",
	})
}

func TestTLSClassifierRejectsMalformedInput(t *testing.T) {
	valid := tlsTestClientHello(t, tls.VersionTLS12)
	malformedSNI := tlsTestClientHello(t, tls.VersionTLS12,
		tlsTestExtension{typ: 0, data: []byte{0, 0}},
	)
	truncated := append([]byte(nil), valid[:len(valid)-1]...)

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "not TLS", input: []byte("GET / HTTP/1.1\r\n")},
		{name: "zero record length", input: []byte{22, 3, 3, 0, 0}},
		{
			name:  "non ClientHello handshake",
			input: []byte{22, 3, 3, 0, 4, 2, 0, 0, 0},
		},
		{name: "malformed SNI", input: malformedSNI},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.TLS().Feed(test.input); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	classifier := sniffer.TLSWithConfig(sniffer.TLSConfig{
		MaxClientHelloBytes: len(truncated),
	})
	if got := classifier.Feed(truncated); got != sniffer.Mismatch {
		t.Fatalf("truncated over-limit state = %v, want Mismatch", got)
	}
}

func TestTLSNegativeConfigPanics(t *testing.T) {
	tests := []struct {
		name   string
		config sniffer.TLSConfig
	}{
		{
			name: "negative limit",
			config: sniffer.TLSConfig{
				MaxClientHelloBytes: -1,
			},
		},
		{
			name: "bad SNI available flag",
			config: sniffer.TLSConfig{
				SNIAvailable: sniffer.TLSFlag(99),
			},
		},
		{
			name: "bad SNI encrypted flag",
			config: sniffer.TLSConfig{
				SNIEncrypted: sniffer.TLSFlag(99),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("TLSWithConfig did not panic")
				}
			}()
			_ = sniffer.TLSWithConfig(test.config)
		})
	}
}

func TestTLSFactoryWithRealClientServerThroughSniffer(t *testing.T) {
	cert, roots := testSnifferTLSCert(t, "api.example.test")

	var listenConfig net.ListenConfig
	rawListener, err := listenConfig.Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() {
		_ = rawListener.Close()
	})

	factories := []sniffer.Factory{
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			Version:          tls.VersionTLS13,
			SNIAvailable:     sniffer.TLSFlagRequired,
			SNIEncrypted:     sniffer.TLSFlagForbidden,
			HostnamePatterns: []string{"*.example.test"},
			ALPNs:            []string{"h2", "http/1.1"},
		}),
	}
	listener := &sniffingListener{
		Listener:   rawListener,
		factories:  factories,
		bufferSize: sniffer.MinFactorySniffBufferSize(factories...),
		results:    make(chan sniffResult, 1),
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		})
		defer func() { _ = tlsConn.Close() }()
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			serverErr <- err
			return
		}
		state := tlsConn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			serverErr <- fmt.Errorf("TLS version = %x", state.Version)
			return
		}
		if state.ServerName != "api.example.test" {
			serverErr <- fmt.Errorf("SNI = %q", state.ServerName)
			return
		}
		if state.NegotiatedProtocol != "h2" {
			serverErr <- fmt.Errorf("ALPN = %q", state.NegotiatedProtocol)
			return
		}
		var request [4]byte
		if _, err := io.ReadFull(tlsConn, request[:]); err != nil {
			serverErr <- err
			return
		}
		if string(request[:]) != "ping" {
			serverErr <- fmt.Errorf("request = %q", request)
			return
		}
		_, err = tlsConn.Write([]byte("pong"))
		serverErr <- err
	}()

	clientConfig := &tls.Config{
		RootCAs:    roots,
		ServerName: "api.example.test",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	conn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    clientConfig,
	}).DialContext(
		context.Background(),
		rawListener.Addr().Network(),
		rawListener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatalf("client ReadFull: %v", err)
	}
	if string(response[:]) != "pong" {
		t.Fatalf("response = %q, want pong", response)
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

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS server did not finish")
	}
}

func TestSnifferRoutesSSHHTTPAndTLSThroughOneMiddleware(t *testing.T) {
	const sharedHost = "shared.example.test"

	cert, roots := testSnifferTLSCert(t, sharedHost)
	sshAddr, stopSSH := startSnifferTestSSHServer(t)
	t.Cleanup(stopSSH)
	httpAddr, stopHTTP := startSnifferTestHTTPServer(t, sharedHost)
	t.Cleanup(stopHTTP)
	tlsAddr, stopTLS := startSnifferTestTLSServer(t, cert)
	t.Cleanup(stopTLS)

	factories := []sniffer.Factory{
		sniffer.SSHFactory(),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			Method:   http.MethodPost,
			URL:      "/route",
			Hostname: sharedHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			Version:      tls.VersionTLS13,
			SNIAvailable: sniffer.TLSFlagRequired,
			SNIEncrypted: sniffer.TLSFlagForbidden,
			Hostname:     sharedHost,
			ALPN:         "gonnect-test",
		}),
	}
	frontAddr, stopProxy, routeResults := startSnifferTestProxy(
		t,
		factories,
		[]string{sshAddr, httpAddr, tlsAddr},
	)
	t.Cleanup(stopProxy)

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	runClient := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- fn()
		}()
	}

	runClient(func() error {
		return runSnifferTestSSHClient(frontAddr)
	})
	runClient(func() error {
		return runSnifferTestHTTPClient(frontAddr, sharedHost)
	})
	runClient(func() error {
		return runSnifferTestTLSClient(frontAddr, sharedHost, roots)
	})

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got := map[int]int{}
	for range 3 {
		select {
		case result := <-routeResults:
			if result.err != nil {
				t.Fatalf("sniff error: %v", result.err)
			}
			got[result.index]++
		case <-time.After(2 * time.Second):
			t.Fatal("missing route result")
		}
	}
	want := map[int]int{0: 1, 1: 1, 2: 1}
	if !mapsEqual(got, want) {
		t.Fatalf("route counts = %v, want %v", got, want)
	}
}

func TestSnifferRoutesManyConfiguredClassifiersThroughOneMiddleware(
	t *testing.T,
) {
	const sharedHost = "shared.example.test"

	cert, roots := testSnifferTLSCert(t, sharedHost)
	sshAddr, stopSSH := startSnifferTaggedSSHServer(t, "ssh-primary")
	t.Cleanup(stopSSH)
	httpAPIAddr, stopHTTPAPI := startSnifferTaggedHTTPServer(
		t,
		sharedHost,
		http.MethodPost,
		"/api/v1",
		"http-api",
	)
	t.Cleanup(stopHTTPAPI)
	httpHealthAddr, stopHTTPHealth := startSnifferTaggedHTTPServer(
		t,
		sharedHost,
		http.MethodGet,
		"/health",
		"http-health",
	)
	t.Cleanup(stopHTTPHealth)
	tlsH2Addr, stopTLSH2 := startSnifferTaggedTLSServer(
		t,
		cert,
		[]string{"h2", "http/1.1"},
		"tls-h2",
	)
	t.Cleanup(stopTLSH2)
	tlsHTTP1Addr, stopTLSHTTP1 := startSnifferTaggedTLSServer(
		t,
		cert,
		[]string{"http/1.1"},
		"tls-http1",
	)
	t.Cleanup(stopTLSHTTP1)
	httpPublicAddr, stopHTTPPublic := startSnifferTaggedHTTPServer(
		t,
		sharedHost,
		http.MethodGet,
		"/public/info",
		"http-public",
	)
	t.Cleanup(stopHTTPPublic)
	tlsWildcardAddr, stopTLSWildcard := startSnifferTaggedTLSServer(
		t,
		cert,
		[]string{"gonnect-fallback"},
		"tls-wildcard",
	)
	t.Cleanup(stopTLSWildcard)

	factories := []sniffer.Factory{
		sniffer.SSHFactory(),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			Method:   http.MethodPost,
			URL:      "/api/v1",
			Hostname: sharedHost,
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			Method:   http.MethodGet,
			URL:      "/health",
			Hostname: sharedHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			Version:      tls.VersionTLS13,
			SNIAvailable: sniffer.TLSFlagRequired,
			SNIEncrypted: sniffer.TLSFlagForbidden,
			Hostname:     sharedHost,
			ALPN:         "h2",
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			Version:      tls.VersionTLS13,
			SNIAvailable: sniffer.TLSFlagRequired,
			SNIEncrypted: sniffer.TLSFlagForbidden,
			Hostname:     sharedHost,
			ALPN:         "http/1.1",
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			Method:           http.MethodGet,
			URLPatterns:      []string{"/public/*"},
			HostnamePatterns: []string{"*.example.test"},
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			Version:          tls.VersionTLS13,
			SNIAvailable:     sniffer.TLSFlagRequired,
			SNIEncrypted:     sniffer.TLSFlagForbidden,
			HostnamePatterns: []string{"*.example.test"},
		}),
	}
	routes := []string{
		sshAddr,
		httpAPIAddr,
		httpHealthAddr,
		tlsH2Addr,
		tlsHTTP1Addr,
		httpPublicAddr,
		tlsWildcardAddr,
	}
	frontAddr, stopProxy, routeResults := startSnifferTestProxy(
		t,
		factories,
		routes,
	)
	t.Cleanup(stopProxy)

	clients := []struct {
		name string
		run  func() error
	}{
		{
			name: "SSH",
			run: func() error {
				return runSnifferTaggedSSHClient(
					frontAddr,
					"ssh-primary",
				)
			},
		},
		{
			name: "HTTP API",
			run: func() error {
				return runSnifferTaggedHTTPClient(
					frontAddr,
					sharedHost,
					http.MethodPost,
					"/api/v1",
					"http-api",
				)
			},
		},
		{
			name: "HTTP health",
			run: func() error {
				return runSnifferTaggedHTTPClient(
					frontAddr,
					sharedHost,
					http.MethodGet,
					"/health",
					"http-health",
				)
			},
		},
		{
			name: "TLS h2",
			run: func() error {
				return runSnifferTaggedTLSClient(
					frontAddr,
					sharedHost,
					roots,
					[]string{"h2"},
					"tls-h2",
				)
			},
		},
		{
			name: "TLS HTTP/1.1",
			run: func() error {
				return runSnifferTaggedTLSClient(
					frontAddr,
					sharedHost,
					roots,
					[]string{"http/1.1"},
					"tls-http1",
				)
			},
		},
		{
			name: "HTTP public wildcard",
			run: func() error {
				return runSnifferTaggedHTTPClient(
					frontAddr,
					sharedHost,
					http.MethodGet,
					"/public/info",
					"http-public",
				)
			},
		},
		{
			name: "TLS wildcard",
			run: func() error {
				return runSnifferTaggedTLSClient(
					frontAddr,
					sharedHost,
					roots,
					[]string{"gonnect-fallback"},
					"tls-wildcard",
				)
			},
		},
	}

	runSnifferTestClients(t, clients)

	got := map[int]int{}
	for range clients {
		select {
		case result := <-routeResults:
			if result.err != nil {
				t.Fatalf("sniff error: %v", result.err)
			}
			got[result.index]++
		case <-time.After(2 * time.Second):
			t.Fatal("missing route result")
		}
	}
	want := map[int]int{
		0: 1,
		1: 1,
		2: 1,
		3: 1,
		4: 1,
		5: 1,
		6: 1,
	}
	if !mapsEqual(got, want) {
		t.Fatalf("route counts = %v, want %v", got, want)
	}
}

func testTLSClientHello(
	t *testing.T,
	version uint16,
	serverName string,
	nextProtos []string,
) []byte {
	t.Helper()

	server, client := net.Pipe()
	defer func() { _ = server.Close() }()

	errc := make(chan error, 1)
	go func() {
		defer func() { _ = client.Close() }()
		tlsConn := tls.Client(
			client,
			&tls.Config{ // #nosec G402 -- Captures a test ClientHello for the requested TLS version.
				ServerName: serverName,
				MinVersion: version,
				MaxVersion: version,
				NextProtos: nextProtos,
			},
		)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		errc <- tlsConn.HandshakeContext(ctx)
	}()

	if err := server.SetReadDeadline(
		time.Now().Add(2 * time.Second),
	); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, sniffer.DefaultTLSClientHelloMaxBytes)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	_ = server.Close()
	<-errc

	return append([]byte(nil), buf[:n]...)
}

type tlsTestExtension struct {
	typ  uint16
	data []byte
}

func tlsTestUint16Length(t *testing.T, name string, length int) uint16 {
	t.Helper()
	if length > math.MaxUint16 {
		t.Fatalf("%s length = %d, want <= %d", name, length, math.MaxUint16)
	}
	return uint16(length) //nolint:gosec // length is checked above.
}

func tlsTestUint8Length(t *testing.T, name string, length int) byte {
	t.Helper()
	if length > math.MaxUint8 {
		t.Fatalf("%s length = %d, want <= %d", name, length, math.MaxUint8)
	}
	return byte(length) //nolint:gosec // length is checked above.
}

func tlsTestClientHello(
	t *testing.T,
	legacyVersion uint16,
	extensions ...tlsTestExtension,
) []byte {
	t.Helper()

	body := make([]byte, 0, 256)
	body = binary.BigEndian.AppendUint16(body, legacyVersion)
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body, 0) // legacy_session_id
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, tls.TLS_AES_128_GCM_SHA256)
	body = append(body, 1, 0) // legacy_compression_methods

	if len(extensions) != 0 {
		extensionBlock := make([]byte, 0, 128)
		for _, extension := range extensions {
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				extension.typ,
			)
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				tlsTestUint16Length(t, "extension data", len(extension.data)),
			)
			extensionBlock = append(extensionBlock, extension.data...)
		}
		body = binary.BigEndian.AppendUint16(
			body,
			tlsTestUint16Length(t, "extension block", len(extensionBlock)),
		)
		body = append(body, extensionBlock...)
	}

	handshake := make([]byte, 4, 4+len(body))
	handshake[0] = 1
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	handshake = append(handshake, body...)

	record := []byte{22, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(
		record[3:],
		tlsTestUint16Length(t, "TLS handshake", len(handshake)),
	)
	return append(record, handshake...)
}

func splitTLSClientHelloRecord(
	t *testing.T,
	hello []byte,
	split int,
) []byte {
	t.Helper()

	if len(hello) < 5 || hello[0] != 22 {
		t.Fatal("test input is not a TLS handshake record")
	}
	recordLength := int(binary.BigEndian.Uint16(hello[3:5]))
	if len(hello) != 5+recordLength {
		t.Fatal("test input must contain one complete TLS record")
	}
	if split <= 0 || split >= recordLength {
		t.Fatal("invalid TLS record split")
	}

	first := append([]byte(nil), hello[:5+split]...)
	binary.BigEndian.PutUint16(
		first[3:5],
		tlsTestUint16Length(t, "first TLS record", split),
	)

	second := make([]byte, 5, len(hello)-split)
	second[0] = 22
	second[1] = hello[1]
	second[2] = hello[2]
	binary.BigEndian.PutUint16(
		second[3:5],
		tlsTestUint16Length(t, "second TLS record", recordLength-split),
	)
	second = append(second, hello[5+split:]...)

	return append(first, second...)
}

func largeTLSTestClientHello(t *testing.T, host string) []byte {
	t.Helper()

	sni := tlsTestServerName(t, host)
	const maxExtensionBlockLen = 65535 - 47
	paddingLen := maxExtensionBlockLen - (4 + len(sni.data)) - 4
	if paddingLen <= 0 {
		t.Fatal("test SNI extension is too large")
	}
	hello := tlsTestClientHello(
		t,
		tls.VersionTLS12,
		sni,
		tlsTestExtension{
			typ:  21,
			data: bytes.Repeat([]byte{0}, paddingLen),
		},
	)
	return splitTLSClientHelloRecords(t, hello, 16*1024)
}

func splitTLSClientHelloRecords(
	t *testing.T,
	hello []byte,
	maxFragment int,
) []byte {
	t.Helper()

	if len(hello) < 5 || hello[0] != 22 {
		t.Fatal("test input is not a TLS handshake record")
	}
	if maxFragment <= 0 || maxFragment > 16*1024 {
		t.Fatal("invalid TLS record fragment size")
	}
	recordLength := int(binary.BigEndian.Uint16(hello[3:5]))
	if len(hello) != 5+recordLength {
		t.Fatal("test input must contain one complete TLS record")
	}

	payload := hello[5:]
	out := make([]byte, 0, len(hello)+(len(payload)/maxFragment)*5)
	for len(payload) != 0 {
		fragmentLen := maxFragment
		if fragmentLen > len(payload) {
			fragmentLen = len(payload)
		}
		out = append(out, hello[0], hello[1], hello[2], 0, 0)
		binary.BigEndian.PutUint16(
			out[len(out)-2:],
			tlsTestUint16Length(t, "TLS record fragment", fragmentLen),
		)
		out = append(out, payload[:fragmentLen]...)
		payload = payload[fragmentLen:]
	}
	return out
}

func tlsTestServerName(t *testing.T, hostname string) tlsTestExtension {
	t.Helper()

	hostBytes := []byte(hostname)
	name := []byte{0}
	name = binary.BigEndian.AppendUint16(
		name,
		tlsTestUint16Length(t, "SNI host", len(hostBytes)),
	)
	name = append(name, hostBytes...)

	data := binary.BigEndian.AppendUint16(
		nil,
		tlsTestUint16Length(t, "SNI list", len(name)),
	)
	data = append(data, name...)
	return tlsTestExtension{typ: 0, data: data}
}

func tlsTestALPN(t *testing.T, protocols ...string) tlsTestExtension {
	t.Helper()

	list := make([]byte, 0, 32)
	for _, protocol := range protocols {
		list = append(
			list,
			tlsTestUint8Length(t, "ALPN protocol", len(protocol)),
		)
		list = append(list, protocol...)
	}
	data := binary.BigEndian.AppendUint16(
		nil,
		tlsTestUint16Length(t, "ALPN list", len(list)),
	)
	data = append(data, list...)
	return tlsTestExtension{typ: 16, data: data}
}

func tlsTestSupportedVersions(
	t *testing.T,
	versions ...uint16,
) tlsTestExtension {
	t.Helper()

	data := []byte{byte(len(versions) * 2)}
	for _, version := range versions {
		data = binary.BigEndian.AppendUint16(data, version)
	}
	return tlsTestExtension{typ: 43, data: data}
}

func testSnifferTLSCert(
	t *testing.T,
	dnsName string,
) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{dnsName},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append root certificate")
	}
	return cert, roots
}

func startSnifferTestSSHServer(t *testing.T) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if !strings.HasPrefix(line, "SSH-2.0-") {
			done <- fmt.Errorf("SSH line = %q", line)
			return
		}
		var payload [4]byte
		if _, err := io.ReadFull(reader, payload[:]); err != nil {
			done <- err
			return
		}
		_, err = conn.Write([]byte("ssh:" + string(payload[:])))
		done <- err
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("SSH server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("SSH server did not stop")
		}
	}
}

func startSnifferTestHTTPServer(
	t *testing.T,
	host string,
) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				http.Error(w, "wrong host", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost || r.URL.Path != "/route" {
				http.Error(w, "wrong request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("http:ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	return listener.Addr().String(), func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP server did not stop")
		}
	}
}

func startSnifferTestTLSServer(
	t *testing.T,
	cert tls.Certificate,
) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"gonnect-test"},
		})
		defer func() { _ = tlsConn.Close() }()
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		var payload [4]byte
		if _, err := io.ReadFull(tlsConn, payload[:]); err != nil {
			done <- err
			return
		}
		_, err = tlsConn.Write([]byte("tls:" + string(payload[:])))
		done <- err
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("TLS server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("TLS server did not stop")
		}
	}
}

func startSnifferTaggedSSHServer(
	t *testing.T,
	response string,
) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if !strings.HasPrefix(line, "SSH-2.0-") {
			done <- fmt.Errorf("SSH line = %q", line)
			return
		}
		if err := readSnifferPing(reader); err != nil {
			done <- err
			return
		}
		_, err = conn.Write([]byte(response))
		done <- err
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("SSH server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("SSH server did not stop")
		}
	}
}

func startSnifferTaggedHTTPServer(
	t *testing.T,
	host string,
	method string,
	path string,
	response string,
) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				http.Error(w, "wrong host", http.StatusBadRequest)
				return
			}
			if r.Method != method || r.URL.Path != path {
				http.Error(w, "wrong request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(response))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	return listener.Addr().String(), func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP server did not stop")
		}
	}
}

func startSnifferTaggedTLSServer(
	t *testing.T,
	cert tls.Certificate,
	nextProtos []string,
	response string,
) (string, func()) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   append([]string(nil), nextProtos...),
		})
		defer func() { _ = tlsConn.Close() }()
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		if len(nextProtos) != 0 {
			if got := tlsConn.ConnectionState().NegotiatedProtocol; got != nextProtos[0] {
				done <- fmt.Errorf("ALPN = %q, want %q", got, nextProtos[0])
				return
			}
		}
		if err := readSnifferPing(tlsConn); err != nil {
			done <- err
			return
		}
		_, err = tlsConn.Write([]byte(response))
		done <- err
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("TLS server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("TLS server did not stop")
		}
	}
}

func startSnifferTestProxy(
	t *testing.T,
	factories []sniffer.Factory,
	routes []string,
) (string, func(), <-chan sniffResult) {
	t.Helper()

	listener := listenSnifferTestTCP(t)
	resultsCapacity := len(routes)
	if resultsCapacity == 0 {
		resultsCapacity = 1
	}
	results := make(chan sniffResult, resultsCapacity)
	done := make(chan struct{})
	var wg sync.WaitGroup

	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleSnifferTestProxyConn(t, raw, factories, routes, results)
			}()
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
		wg.Wait()
	}, results
}

func handleSnifferTestProxyConn(
	t *testing.T,
	raw net.Conn,
	factories []sniffer.Factory,
	routes []string,
	results chan<- sniffResult,
) {
	t.Helper()

	conn := putback.New(raw, nil)
	if err := conn.SetReadDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		results <- sniffResult{index: sniffer.NoMatch, err: err}
		_ = conn.Close()
		return
	}
	index, err := sniffer.SniffFactories(
		make([]byte, sniffer.MinFactorySniffBufferSize(factories...)),
		conn,
		factories...,
	)
	if clearErr := conn.SetReadDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	results <- sniffResult{index: index, err: err}
	if err != nil || index < 0 || index >= len(routes) {
		_ = conn.Close()
		return
	}

	upstream, err := dialSnifferTestTCP(routes[index])
	if err != nil {
		_ = conn.Close()
		return
	}
	proxySnifferTestConns(conn, upstream)
}

func proxySnifferTestConns(client net.Conn, upstream net.Conn) {
	_ = gonnect.PipeConn(client, upstream, nil)
}

func runSnifferTestClients(
	t *testing.T,
	clients []struct {
		name string
		run  func() error
	},
) {
	t.Helper()

	var wg sync.WaitGroup
	errs := make(chan error, len(clients))
	for _, client := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.run(); err != nil {
				errs <- fmt.Errorf("%s: %w", client.name, err)
				return
			}
			errs <- nil
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func readSnifferPing(reader io.Reader) error {
	var payload [4]byte
	if _, err := io.ReadFull(reader, payload[:]); err != nil {
		return err
	}
	if string(payload[:]) != "ping" {
		return fmt.Errorf("payload = %q, want ping", payload)
	}
	return nil
}

func dialSnifferTestTCP(address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
		context.Background(),
		"tcp",
		address,
	)
}

func runSnifferTaggedSSHClient(address string, want string) error {
	conn, err := dialSnifferTestTCP(address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("SSH-2.0-client\r\nping")); err != nil {
		return err
	}
	return readSnifferResponse(conn, want)
}

func runSnifferTaggedHTTPClient(
	address string,
	host string,
	method string,
	path string,
	want string,
) error {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(
			ctx context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()

	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = strings.NewReader("ping")
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		method,
		"http://"+host+path,
		body,
	)
	if err != nil {
		return err
	}

	response, err := (&http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}).Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	got, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"HTTP status = %s, body = %q",
			response.Status,
			got,
		)
	}
	if string(got) != want {
		return fmt.Errorf("HTTP body = %q, want %q", got, want)
	}
	return nil
}

func runSnifferTaggedTLSClient(
	address string,
	host string,
	roots *x509.CertPool,
	nextProtos []string,
	want string,
) error {
	conn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			RootCAs:    roots,
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: append([]string(nil), nextProtos...),
		},
	}).DialContext(context.Background(), "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return fmt.Errorf("TLS dial returned %T", conn)
	}

	if len(nextProtos) != 0 {
		if got := tlsConn.ConnectionState().NegotiatedProtocol; got != nextProtos[0] {
			return fmt.Errorf("ALPN = %q, want %q", got, nextProtos[0])
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	return readSnifferResponse(conn, want)
}

func readSnifferResponse(reader io.Reader, want string) error {
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(reader, buf); err != nil {
		return err
	}
	if string(buf) != want {
		return fmt.Errorf("response = %q, want %q", buf, want)
	}
	return nil
}

func runSnifferTestSSHClient(address string) error {
	conn, err := dialSnifferTestTCP(address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("SSH-2.0-client\r\nping")); err != nil {
		return err
	}
	var response [8]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if string(response[:]) != "ssh:ping" {
		return fmt.Errorf("SSH response = %q", response)
	}
	return nil
}

func runSnifferTestHTTPClient(address string, host string) error {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(
			ctx context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://"+host+"/route",
		strings.NewReader("ping"),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status = %s, body = %q", resp.Status, body)
	}
	if string(body) != "http:ok" {
		return fmt.Errorf("HTTP body = %q", body)
	}
	return nil
}

func runSnifferTestTLSClient(
	address string,
	host string,
	roots *x509.CertPool,
) error {
	conn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			RootCAs:    roots,
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"gonnect-test"},
		},
	}).DialContext(context.Background(), "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	var response [8]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if string(response[:]) != "tls:ping" {
		return fmt.Errorf("TLS response = %q", response)
	}
	return nil
}

func listenSnifferTestTCP(t *testing.T) net.Listener {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func mapsEqual(a map[int]int, b map[int]int) bool {
	if len(a) != len(b) {
		return false
	}
	for key, aValue := range a {
		if b[key] != aValue {
			return false
		}
	}
	return true
}
