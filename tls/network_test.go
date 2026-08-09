package tls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gonnecttls "github.com/asciimoth/gonnect/tls"
)

var errCapture = errors.New("capture")

func TestHTTPSClientServerThroughMiddleware(t *testing.T) {
	ctx := context.Background()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	mitmCA, mitmCACert := testCA(t, "mitm.test")
	originCA, originCACert := testCA(t, "origin.test")
	originCert := testLeafCert(t, originCACert, originCA.PrivateKey, host)

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	port := mustPort(t, listener.Addr().String())

	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(
				w,
				"host=%s\nsni=%s\nproto=%s\n",
				r.Host,
				r.TLS.ServerName,
				r.Proto,
			)
		}),
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(stdtls.NewListener(
			listener,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{originCert},
				NextProtos:   []string{"http/1.1"},
				MinVersion:   stdtls.VersionTLS12,
			},
		))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("timeout waiting for HTTP server shutdown")
		}
	})

	mitm, err := gonnecttls.NewNetwork(
		wrapped,
		mitmCA,
		&stdtls.Config{ // #nosec G402 -- Test client config.
			RootCAs:    certPool(originCACert),
			NextProtos: []string{"http/1.1"},
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				return mitm.Dial(ctx, network, address)
			},
			TLSClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
				RootCAs:    certPool(mitmCACert),
				ServerName: host,
				NextProtos: []string{"http/1.1"},
				MinVersion: stdtls.VersionTLS12,
			},
			ForceAttemptHTTP2: false,
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://"+net.JoinHostPort(host, port)+"/resource",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through middleware error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	text := string(body)
	if !strings.Contains(text, "host="+net.JoinHostPort(host, port)) {
		t.Fatalf("body %q does not contain expected Host", text)
	}
	if !strings.Contains(text, "sni="+host) {
		t.Fatalf("body %q does not contain expected upstream SNI", text)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("response has no downstream TLS state")
	}
	if got := resp.TLS.PeerCertificates[0].DNSNames; len(got) != 1 ||
		got[0] != host {
		t.Fatalf("downstream certificate DNSNames = %v, want [%s]", got, host)
	}
	if got := resp.TLS.NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("downstream ALPN = %q, want http/1.1", got)
	}
}

func TestRecreatedUpstreamTLSPreservesClientHelloMetadata(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		clientProtos []string
		originProtos []string
		wantProto    string
	}{
		{
			name:         "with ALPN",
			host:         "API.Example.Test",
			clientProtos: []string{"h2", "http/1.1"},
			originProtos: []string{"h2"},
			wantProto:    "h2",
		},
		{
			name:         "without ALPN",
			host:         "NoALPN.Example.Test",
			originProtos: []string{"mitm-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()

			wrapped := gonnect.NewLoopbackNetwork()
			wrapped.AllowAnyHost = true
			t.Cleanup(func() { _ = wrapped.Close() })

			mitmCA, mitmCACert := testCA(t, "mitm.test")
			originCA, originCACert := testCA(t, "origin.test")
			originCert := testLeafCert(
				t,
				originCACert,
				originCA.PrivateKey,
				strings.ToLower(tt.host),
			)

			listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen() error = %v", err)
			}
			defer func() { _ = listener.Close() }()
			port := mustPort(t, listener.Addr().String())

			type upstreamHello struct {
				serverName      string
				supportedProtos []string
				dst             string
				src             string
			}
			helloCh := make(chan upstreamHello, 1)
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer func() { _ = conn.Close() }()

				tlsConn := stdtls.Server(
					conn,
					&stdtls.Config{ // #nosec G402 -- Test TLS server.
						GetConfigForClient: func(
							hello *stdtls.ClientHelloInfo,
						) (*stdtls.Config, error) {
							metadata := upstreamHello{
								serverName: hello.ServerName,
								supportedProtos: append(
									[]string(nil),
									hello.SupportedProtos...),
							}
							if hello.Conn != nil {
								metadata.dst = hello.Conn.LocalAddr().String()
								metadata.src = hello.Conn.RemoteAddr().String()
							}
							helloCh <- metadata
							return &stdtls.Config{ // #nosec G402 -- Test TLS server.
								Certificates: []stdtls.Certificate{originCert},
								NextProtos:   tt.originProtos,
								MinVersion:   stdtls.VersionTLS12,
							}, nil
						},
						MinVersion: stdtls.VersionTLS12,
					},
				)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					serverDone <- err
					return
				}
				if got := tlsConn.ConnectionState().NegotiatedProtocol; got != tt.wantProto {
					serverDone <- fmt.Errorf(
						"upstream ALPN = %q, want %q",
						got,
						tt.wantProto,
					)
					return
				}
				_, err = tlsConn.Write([]byte("ok"))
				serverDone <- err
			}()

			mitm, err := gonnecttls.NewNetwork(
				wrapped,
				mitmCA,
				&stdtls.Config{ // #nosec G402 -- Test client config.
					RootCAs:    certPool(originCACert),
					NextProtos: []string{"mitm-only"},
					MinVersion: stdtls.VersionTLS12,
				},
			)
			if err != nil {
				t.Fatalf("NewNetwork() error = %v", err)
			}

			raw, err := mitm.DialTCP(
				ctx,
				"tcp",
				"",
				net.JoinHostPort(tt.host, port),
			)
			if err != nil {
				t.Fatalf("DialTCP() error = %v", err)
			}
			defer func() { _ = raw.Close() }()

			client := stdtls.Client(
				raw,
				&stdtls.Config{ // #nosec G402 -- Test client config.
					RootCAs:    certPool(mitmCACert),
					ServerName: tt.host,
					NextProtos: tt.clientProtos,
					MinVersion: stdtls.VersionTLS12,
				},
			)
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatalf("client HandshakeContext() error = %v", err)
			}
			if got := client.ConnectionState().NegotiatedProtocol; got != tt.wantProto {
				t.Fatalf("client ALPN = %q, want %q", got, tt.wantProto)
			}

			hello := receiveValue(t, helloCh)
			if got := hello.serverName; got != tt.host {
				t.Fatalf("upstream SNI = %q, want %q", got, tt.host)
			}
			if !sameStrings(hello.supportedProtos, tt.clientProtos) {
				t.Fatalf(
					"upstream ALPN offer = %v, want %v",
					hello.supportedProtos,
					tt.clientProtos,
				)
			}
			if got, want := hello.dst, listener.Addr().String(); got != want {
				t.Fatalf("upstream dst = %q, want %q", got, want)
			}
			if hello.src == "" {
				t.Fatal("upstream src is empty")
			}

			buf := make([]byte, len("ok"))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatalf("client ReadFull() error = %v", err)
			}
			if string(buf) != "ok" {
				t.Fatalf("client read %q, want ok", buf)
			}
			waitForServer(t, serverDone)
		})
	}
}

func TestUpstreamCloseNotifyReachesClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	mitmCA, mitmCACert := testCA(t, "mitm.test")
	originCA, originCACert := testCA(t, "origin.test")
	originCert := testLeafCert(t, originCACert, originCA.PrivateKey, host)

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	port := mustPort(t, listener.Addr().String())

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}

		tlsConn := stdtls.Server(
			conn,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{originCert},
				MinVersion:   stdtls.VersionTLS12,
			},
		)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tlsConn.Close()
			serverDone <- err
			return
		}
		serverDone <- tlsConn.Close()
	}()

	mitm, err := gonnecttls.NewNetwork(
		wrapped,
		mitmCA,
		&stdtls.Config{ // #nosec G402 -- Test client config.
			RootCAs:    certPool(originCACert),
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}

	raw, err := mitm.DialTCP(
		ctx,
		"tcp",
		"",
		net.JoinHostPort(host, port),
	)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()

	client := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test client config.
			RootCAs:    certPool(mitmCACert),
			ServerName: host,
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client HandshakeContext() error = %v", err)
	}

	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client Read() error = %v, want EOF", err)
	}
	waitForServer(t, serverDone)
}

func TestHTTPSRejectsUntrustedOrigin(t *testing.T) {
	ctx := context.Background()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	mitmCA, mitmCACert := testCA(t, "mitm.test")
	originCA, originCACert := testCA(t, "origin.test")
	originCert := testLeafCert(t, originCACert, originCA.PrivateKey, host)

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	port := mustPort(t, listener.Addr().String())

	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("unexpected success"))
			},
		),
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(stdtls.NewListener(
			listener,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{originCert},
				MinVersion:   stdtls.VersionTLS12,
			},
		))
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
			t.Error("timeout waiting for HTTP server shutdown")
		}
	})

	mitm, err := gonnecttls.NewNetwork(
		wrapped,
		mitmCA,
		&stdtls.Config{ // #nosec G402 -- Empty roots must reject the origin.
			RootCAs:    x509.NewCertPool(),
			ServerName: "wrong.example.test",
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				return mitm.Dial(ctx, network, address)
			},
			TLSClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
				RootCAs:    certPool(mitmCACert),
				ServerName: host,
				MinVersion: stdtls.VersionTLS12,
			},
			ForceAttemptHTTP2: false,
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://"+net.JoinHostPort(host, port)+"/",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("GET unexpectedly succeeded with untrusted upstream origin")
	}
}

func TestPlainTCPPassesThrough(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, len("ping\n"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "ping\n" {
			serverDone <- fmt.Errorf("server read %q", buf)
			return
		}
		_, err = conn.Write([]byte("pong\n"))
		serverDone <- err
	}()

	mitm := mustNetwork(t, wrapped)
	conn, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, len("pong\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != "pong\n" {
		t.Fatalf("client read %q, want pong", buf)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestInterceptionFilterInclusiveSNIAndALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	mitmCA, mitmCACert := testCA(t, "mitm.test")
	originCA, originCACert := testCA(t, "origin.test")
	clientRoots := certPoolOf(mitmCACert, originCACert)
	originRoots := certPool(originCACert)

	mitm, err := gonnecttls.NewNetworkWithConfig(
		wrapped,
		gonnecttls.Config{
			CA: mitmCA,
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
				RootCAs:    originRoots,
				MinVersion: stdtls.VersionTLS12,
			},
			InterceptionFilter: gonnecttls.InterceptionFilter{
				Mode: gonnecttls.InterceptionFilterInclusive,
				Rules: []gonnecttls.InterceptionRule{
					{
						SNIHosts: []string{"*.example.test"},
						ALPNs:    []string{"h?", "http/*"},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewNetworkWithConfig() error = %v", err)
	}

	tests := []struct {
		name       string
		host       string
		protos     []string
		wantIssuer string
		wantProto  string
	}{
		{
			name:       "matching SNI and ALPN is intercepted",
			host:       "api.example.test",
			protos:     []string{"h2"},
			wantIssuer: "mitm.test",
			wantProto:  "h2",
		},
		{
			name:       "ALPN slash glob is intercepted",
			host:       "api.example.test",
			protos:     []string{"http/1.1"},
			wantIssuer: "mitm.test",
			wantProto:  "http/1.1",
		},
		{
			name:       "ALPN mismatch passes through",
			host:       "api.example.test",
			wantIssuer: "origin.test",
		},
		{
			name:       "SNI mismatch passes through",
			host:       "api.other.test",
			protos:     []string{"h2"},
			wantIssuer: "origin.test",
			wantProto:  "h2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverAddr, serverDone := startOneShotTLSServer(
				t,
				ctx,
				wrapped,
				originCACert,
				originCA.PrivateKey,
				tt.host,
				[]string{"h2", "http/1.1"},
			)
			raddr := net.JoinHostPort(tt.host, mustPort(t, serverAddr))

			result := dialTLSAndRead(
				t,
				ctx,
				mitm,
				"",
				raddr,
				tt.host,
				clientRoots,
				tt.protos,
			)
			if result.issuer != tt.wantIssuer {
				t.Fatalf(
					"peer issuer = %q, want %q",
					result.issuer,
					tt.wantIssuer,
				)
			}
			if result.proto != tt.wantProto {
				t.Fatalf(
					"client ALPN = %q, want %q",
					result.proto,
					tt.wantProto,
				)
			}

			server := waitForTLSServer(t, serverDone)
			if server.sni != tt.host {
				t.Fatalf("upstream SNI = %q, want %q", server.sni, tt.host)
			}
			if server.proto != tt.wantProto {
				t.Fatalf(
					"upstream ALPN = %q, want %q",
					server.proto,
					tt.wantProto,
				)
			}
		})
	}
}

func TestInterceptionFilterExclusiveConnDstPatterns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tests := []struct {
		name          string
		host          string
		rulesForPort  func(string, string) []gonnecttls.InterceptionRule
		wantIssuer    string
		wantServerSNI string
	}{
		{
			name: "requested hostname wildcard passes through",
			host: "api.direct.test",
			rulesForPort: func(port, _ string) []gonnecttls.InterceptionRule {
				return []gonnecttls.InterceptionRule{
					{
						ConnDsts: []string{
							net.JoinHostPort("*.direct.test", port),
						},
					},
				}
			},
			wantIssuer:    "origin.test",
			wantServerSNI: "api.direct.test",
		},
		{
			name: "actual IP address passes through",
			host: "api.actual.test",
			rulesForPort: func(_, actual string) []gonnecttls.InterceptionRule {
				return []gonnecttls.InterceptionRule{
					{ConnDsts: []string{actual}},
				}
			},
			wantIssuer:    "origin.test",
			wantServerSNI: "api.actual.test",
		},
		{
			name: "nonmatching destination is intercepted",
			host: "api.intercept.test",
			rulesForPort: func(port, _ string) []gonnecttls.InterceptionRule {
				return []gonnecttls.InterceptionRule{
					{
						ConnDsts: []string{
							net.JoinHostPort("*.direct.test", port),
						},
					},
				}
			},
			wantIssuer:    "mitm.test",
			wantServerSNI: "api.intercept.test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := gonnect.NewLoopbackNetwork()
			wrapped.AllowAnyHost = true
			t.Cleanup(func() { _ = wrapped.Close() })

			mitmCA, mitmCACert := testCA(t, "mitm.test")
			originCA, originCACert := testCA(t, "origin.test")
			serverAddr, serverDone := startOneShotTLSServer(
				t,
				ctx,
				wrapped,
				originCACert,
				originCA.PrivateKey,
				tt.host,
				nil,
			)
			port := mustPort(t, serverAddr)

			mitm, err := gonnecttls.NewNetworkWithConfig(
				wrapped,
				gonnecttls.Config{
					CA: mitmCA,
					ClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
						RootCAs:    certPool(originCACert),
						MinVersion: stdtls.VersionTLS12,
					},
					InterceptionFilter: gonnecttls.InterceptionFilter{
						Mode:  gonnecttls.InterceptionFilterExclusive,
						Rules: tt.rulesForPort(port, serverAddr),
					},
				},
			)
			if err != nil {
				t.Fatalf("NewNetworkWithConfig() error = %v", err)
			}

			result := dialTLSAndRead(
				t,
				ctx,
				mitm,
				"",
				net.JoinHostPort(tt.host, port),
				tt.host,
				certPoolOf(mitmCACert, originCACert),
				nil,
			)
			if result.issuer != tt.wantIssuer {
				t.Fatalf(
					"peer issuer = %q, want %q",
					result.issuer,
					tt.wantIssuer,
				)
			}

			server := waitForTLSServer(t, serverDone)
			if server.sni != tt.wantServerSNI {
				t.Fatalf(
					"upstream SNI = %q, want %q",
					server.sni,
					tt.wantServerSNI,
				)
			}
		})
	}
}

func TestInterceptionFilterConnSrcPattern(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	mitmCA, mitmCACert := testCA(t, "mitm.test")
	originCA, originCACert := testCA(t, "origin.test")
	host := "source.example.test"

	mitm, err := gonnecttls.NewNetworkWithConfig(
		wrapped,
		gonnecttls.Config{
			CA: mitmCA,
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
				RootCAs:    certPool(originCACert),
				MinVersion: stdtls.VersionTLS12,
			},
			InterceptionFilter: gonnecttls.InterceptionFilter{
				Mode: gonnecttls.InterceptionFilterInclusive,
				Rules: []gonnecttls.InterceptionRule{
					{ConnSrcs: []string{"127.0.0.1:0"}},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewNetworkWithConfig() error = %v", err)
	}

	tests := []struct {
		name       string
		laddr      string
		wantIssuer string
	}{
		{
			name:       "requested source matches",
			laddr:      "127.0.0.1:0",
			wantIssuer: "mitm.test",
		},
		{
			name:       "no requested source does not match port-zero rule",
			wantIssuer: "origin.test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverAddr, serverDone := startOneShotTLSServer(
				t,
				ctx,
				wrapped,
				originCACert,
				originCA.PrivateKey,
				host,
				nil,
			)

			result := dialTLSAndRead(
				t,
				ctx,
				mitm,
				tt.laddr,
				net.JoinHostPort(host, mustPort(t, serverAddr)),
				host,
				certPoolOf(mitmCACert, originCACert),
				nil,
			)
			if result.issuer != tt.wantIssuer {
				t.Fatalf(
					"peer issuer = %q, want %q",
					result.issuer,
					tt.wantIssuer,
				)
			}
			_ = waitForTLSServer(t, serverDone)
		})
	}
}

func TestInterceptionFilterExclusiveEncryptedSNIFlagPassesThrough(
	t *testing.T,
) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, accepted := listenAndAcceptOne(t, wrapped)
	defer func() { _ = listener.Close() }()

	ca, _ := testCA(t, "mitm.test")
	mitm, err := gonnecttls.NewNetworkWithConfig(
		wrapped,
		gonnecttls.Config{
			CA: ca,
			InterceptionFilter: gonnecttls.InterceptionFilter{
				Mode: gonnecttls.InterceptionFilterExclusive,
				Rules: []gonnecttls.InterceptionRule{
					{SNIEncrypted: gonnecttls.InterceptionFlagRequired},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewNetworkWithConfig() error = %v", err)
	}

	conn, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	hello := testClientHello(
		t,
		testSupportedVersions(t, stdtls.VersionTLS13),
		testServerName(t, "public.example.test"),
		testExtension{typ: 0xfe0d},
	)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	upstream := receiveValue(t, accepted)
	requireUpstreamBytes(t, upstream, hello)
}

func TestInterceptionFilterInclusiveSNIHostSkipsTLSWithoutSNI(
	t *testing.T,
) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, accepted := listenAndAcceptOne(t, wrapped)
	defer func() { _ = listener.Close() }()

	ca, _ := testCA(t, "mitm.test")
	mitm, err := gonnecttls.NewNetworkWithConfig(
		wrapped,
		gonnecttls.Config{
			CA: ca,
			InterceptionFilter: gonnecttls.InterceptionFilter{
				Mode: gonnecttls.InterceptionFilterInclusive,
				Rules: []gonnecttls.InterceptionRule{
					{SNIHosts: []string{"*.example.test"}},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewNetworkWithConfig() error = %v", err)
	}

	conn, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	hello := testClientHello(t, testSupportedVersions(t, stdtls.VersionTLS12))
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	upstream := receiveValue(t, accepted)
	requireUpstreamBytes(t, upstream, hello)
}

func TestReadDeadlineDoesNotClosePassthrough(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, len("ping\n"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "ping\n" {
			serverDone <- fmt.Errorf("server read %q", buf)
			return
		}
		_, err = conn.Write([]byte("pong\n"))
		serverDone <- err
	}()

	mitm := mustNetwork(t, wrapped)
	conn, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(
		time.Now().Add(20 * time.Millisecond),
	); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !isTimeoutError(err) {
		t.Fatalf("Read() error = %v, want timeout", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline() error = %v", err)
	}

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write() after timeout error = %v", err)
	}
	buf := make([]byte, len("pong\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() after timeout error = %v", err)
	}
	if string(buf) != "pong\n" {
		t.Fatalf("client read %q, want pong", buf)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestTLSWithoutSNIIsRejected(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, accepted := listenAndAcceptOne(t, wrapped)
	defer func() { _ = listener.Close() }()

	mitm := mustNetwork(t, wrapped)
	raw, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()

	client := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test client omits SNI on purpose.
			InsecureSkipVerify: true, // #nosec G402 -- This test verifies rejection before certificate validation.
			MinVersion:         stdtls.VersionTLS12,
		},
	)
	if err := client.HandshakeContext(ctx); err == nil {
		t.Fatal("TLS handshake unexpectedly succeeded without SNI")
	}

	requireNoUpstreamBytes(t, <-accepted)
}

func TestEncryptedClientHelloIsRejected(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener, accepted := listenAndAcceptOne(t, wrapped)
	defer func() { _ = listener.Close() }()

	mitm := mustNetwork(t, wrapped)
	conn, err := mitm.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	hello := testClientHello(
		t,
		testSupportedVersions(t, stdtls.VersionTLS13),
		testServerName(t, "public.example.test"),
		testExtension{typ: 0xfe0d},
	)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() succeeded after ECH ClientHello")
	}

	requireNoUpstreamBytes(t, <-accepted)
}

func TestNetworkDelegatesNonTCPAndNonDialCalls(t *testing.T) {
	ctx := context.Background()
	wrapped := newCaptureNetwork()
	mitm := mustNetwork(t, wrapped)

	cases := []struct {
		name string
		run  func() error
		want []string
	}{
		{
			name: "Dial udp",
			run: func() error {
				_, err := mitm.Dial(ctx, "udp", "127.0.0.1:53")
				return err
			},
			want: []string{"udp", "127.0.0.1:53"},
		},
		{
			name: "DialTCP unknown",
			run: func() error {
				_, err := mitm.DialTCP(
					ctx,
					"tcp5",
					"127.0.0.1:1",
					"127.0.0.1:2",
				)
				return err
			},
			want: []string{"tcp5", "127.0.0.1:1", "127.0.0.1:2"},
		},
		{
			name: "PacketDial",
			run: func() error {
				_, err := mitm.PacketDial(ctx, "udp", "127.0.0.1:53")
				return err
			},
			want: []string{"udp", "127.0.0.1:53"},
		},
		{
			name: "DialUDP",
			run: func() error {
				_, err := mitm.DialUDP(
					ctx,
					"udp",
					"127.0.0.1:1",
					"127.0.0.1:53",
				)
				return err
			},
			want: []string{"udp", "127.0.0.1:1", "127.0.0.1:53"},
		},
		{
			name: "Listen",
			run: func() error {
				_, err := mitm.Listen(ctx, "tcp", "127.0.0.1:0")
				return err
			},
			want: []string{"tcp", "127.0.0.1:0"},
		},
		{
			name: "LookupHost",
			run: func() error {
				_, err := mitm.LookupHost(ctx, "example.test")
				return err
			},
			want: []string{"example.test"},
		},
		{
			name: "Interfaces",
			run: func() error {
				_, err := mitm.Interfaces()
				return err
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, errCapture) {
				t.Fatalf("error = %v, want capture", err)
			}
			if got := wrapped.args(tt.name); !sameStrings(got, tt.want) {
				t.Fatalf("args = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkLifecycleNoOpsWhenWrappedUnsupported(t *testing.T) {
	mitm := mustNetwork(t, &gonnect.RejectNetwork{})

	if mitm.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	if err := mitm.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := mitm.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if err := mitm.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if up, err := mitm.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true nil", up, err)
	}

	unsubscribeCloser, err := mitm.SubscribeCloser(&countCloser{})
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	unsubscribeCloser()
	unsubscribeCloser()

	unsubscribeUpDown, err := mitm.SubscribeUpDown(&countUpDown{})
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	unsubscribeUpDown()
	unsubscribeUpDown()
}

func TestNetworkLifecyclePassesThrough(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwork()
	mitm := mustNetwork(t, wrapped)
	closer := &countCloser{}
	updown := &countUpDown{}

	unsubscribeCloser, err := mitm.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeCloser()

	unsubscribeUpDown, err := mitm.SubscribeUpDown(updown)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribeUpDown()

	if err := mitm.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if updown.downs.Load() != 1 {
		t.Fatalf("Down calls = %d, want 1", updown.downs.Load())
	}
	if up, err := mitm.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}

	if err := mitm.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if updown.ups.Load() != 1 {
		t.Fatalf("Up calls = %d, want 1", updown.ups.Load())
	}

	if err := mitm.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("closer closes = %d, want 1", closer.closes())
	}
	if up, err := mitm.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Close = %v, %v, want false nil", up, err)
	}
}

func TestNewNetworkValidation(t *testing.T) {
	ca, _ := testCA(t, "mitm.test")
	leaf := testSelfSignedLeaf(t, "leaf.test")

	tests := []struct {
		name    string
		network gonnect.Network
		config  gonnecttls.Config
	}{
		{
			name:   "nil network",
			config: gonnecttls.Config{CA: ca},
		},
		{
			name:    "missing CA chain",
			network: &gonnect.RejectNetwork{},
		},
		{
			name:    "non CA certificate",
			network: &gonnect.RejectNetwork{},
			config:  gonnecttls.Config{CA: leaf},
		},
		{
			name:    "negative sniff buffer",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA:              ca,
				SniffBufferSize: -1,
			},
		},
		{
			name:    "negative leaf ttl",
			network: &gonnect.RejectNetwork{},
			config:  gonnecttls.Config{CA: ca, LeafTTL: -time.Second},
		},
		{
			name:    "filter rules without mode",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA: ca,
				InterceptionFilter: gonnecttls.InterceptionFilter{
					Rules: []gonnecttls.InterceptionRule{
						{SNIHosts: []string{"*.example.test"}},
					},
				},
			},
		},
		{
			name:    "invalid filter mode",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA: ca,
				InterceptionFilter: gonnecttls.InterceptionFilter{
					Mode: gonnecttls.InterceptionFilterMode(99),
				},
			},
		},
		{
			name:    "invalid filter SNI available flag",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA: ca,
				InterceptionFilter: gonnecttls.InterceptionFilter{
					Mode: gonnecttls.InterceptionFilterInclusive,
					Rules: []gonnecttls.InterceptionRule{
						{
							SNIAvailable: gonnecttls.InterceptionFlag(99),
						},
					},
				},
			},
		},
		{
			name:    "invalid filter encrypted SNI flag",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA: ca,
				InterceptionFilter: gonnecttls.InterceptionFilter{
					Mode: gonnecttls.InterceptionFilterInclusive,
					Rules: []gonnecttls.InterceptionRule{
						{
							SNIEncrypted: gonnecttls.InterceptionFlag(99),
						},
					},
				},
			},
		},
		{
			name:    "invalid filter wildcard",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.Config{
				CA: ca,
				InterceptionFilter: gonnecttls.InterceptionFilter{
					Mode: gonnecttls.InterceptionFilterInclusive,
					Rules: []gonnecttls.InterceptionRule{
						{SNIHosts: []string{"["}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := gonnecttls.NewNetworkWithConfig(
				tt.network,
				tt.config,
			); err == nil {
				t.Fatal("NewNetworkWithConfig() succeeded")
			}
		})
	}
}

func TestNetworkWrapsNetwork(t *testing.T) {
	wrapped := &gonnect.RejectNetwork{}
	mitm := mustNetwork(t, wrapped)

	if mitm.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() did not return wrapped Network")
	}
	if mitm.GetNetwork() != wrapped {
		t.Fatal("GetNetwork() did not return wrapped Network")
	}
	if mitm.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
}

type tlsDialResult struct {
	issuer string
	proto  string
}

func dialTLSAndRead(
	t *testing.T,
	ctx context.Context,
	network *gonnecttls.Network,
	laddr string,
	raddr string,
	serverName string,
	roots *x509.CertPool,
	nextProtos []string,
) tlsDialResult {
	t.Helper()

	raw, err := network.DialTCP(ctx, "tcp", laddr, raddr)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()

	client := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test client config.
			RootCAs:    roots,
			ServerName: serverName,
			NextProtos: nextProtos,
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client HandshakeContext() error = %v", err)
	}

	buf := make([]byte, len("ok"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("client read %q, want ok", buf)
	}

	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("client has no peer certificates")
	}
	return tlsDialResult{
		issuer: state.PeerCertificates[0].Issuer.CommonName,
		proto:  state.NegotiatedProtocol,
	}
}

type tlsServerResult struct {
	sni   string
	proto string
	err   error
}

func startOneShotTLSServer(
	t *testing.T,
	ctx context.Context,
	network gonnect.Network,
	ca *x509.Certificate,
	caKey any,
	host string,
	nextProtos []string,
) (string, <-chan tlsServerResult) {
	t.Helper()

	cert := testLeafCert(t, ca, caKey, host)
	listener, err := network.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan tlsServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- tlsServerResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := stdtls.Server(
			conn,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   nextProtos,
				MinVersion:   stdtls.VersionTLS12,
			},
		)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			done <- tlsServerResult{err: err}
			return
		}
		state := tlsConn.ConnectionState()
		_, err = tlsConn.Write([]byte("ok"))
		done <- tlsServerResult{
			sni:   state.ServerName,
			proto: state.NegotiatedProtocol,
			err:   err,
		}
	}()

	return listener.Addr().String(), done
}

func waitForTLSServer(
	t *testing.T,
	done <-chan tlsServerResult,
) tlsServerResult {
	t.Helper()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("TLS server error = %v", result.err)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TLS server")
	}
	var zero tlsServerResult
	return zero
}

func mustNetwork(
	t *testing.T,
	wrapped gonnect.Network,
) *gonnecttls.Network {
	t.Helper()
	ca, _ := testCA(t, "mitm.test")
	mitm, err := gonnecttls.NewNetwork(wrapped, ca, nil)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	return mitm
}

func listenAndAcceptOne(
	t *testing.T,
	network gonnect.Network,
) (net.Listener, <-chan net.Conn) {
	t.Helper()
	listener, err := network.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return listener, accepted
}

func requireNoUpstreamBytes(t *testing.T, conn net.Conn) {
	t.Helper()
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("upstream Read() = %d, %v; want no bytes and an error", n, err)
	}
}

func requireUpstreamBytes(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("upstream ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("upstream bytes = %x, want %x", got, want)
	}
}

func receiveValue[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for value")
	}
	var zero T
	return zero
}

func waitForServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func testCA(
	t *testing.T,
	commonName string,
) (stdtls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}, cert
}

func testLeafCert(
	t *testing.T,
	ca *x509.Certificate,
	caKey any,
	host string,
) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca,
		&key.PublicKey,
		caKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func testSelfSignedLeaf(t *testing.T, host string) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func certPoolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func mustPort(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", address, err)
	}
	return port
}

type testExtension struct {
	typ  uint16
	data []byte
}

func testClientHello(t *testing.T, extensions ...testExtension) []byte {
	t.Helper()

	body := make([]byte, 0, 256)
	body = binary.BigEndian.AppendUint16(body, stdtls.VersionTLS12)
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, stdtls.TLS_AES_128_GCM_SHA256)
	body = append(body, 1, 0)

	if len(extensions) != 0 {
		extensionBlock := make([]byte, 0, 128)
		for _, extension := range extensions {
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				extension.typ,
			)
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				uint16Length(t, "extension", len(extension.data)),
			)
			extensionBlock = append(extensionBlock, extension.data...)
		}
		body = binary.BigEndian.AppendUint16(
			body,
			uint16Length(t, "extensions", len(extensionBlock)),
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
		uint16Length(t, "record", len(handshake)),
	)
	return append(record, handshake...)
}

func testServerName(t *testing.T, hostname string) testExtension {
	t.Helper()
	hostBytes := []byte(hostname)
	name := []byte{0}
	name = binary.BigEndian.AppendUint16(
		name,
		uint16Length(t, "SNI host", len(hostBytes)),
	)
	name = append(name, hostBytes...)

	data := binary.BigEndian.AppendUint16(
		nil,
		uint16Length(t, "SNI list", len(name)),
	)
	data = append(data, name...)
	return testExtension{typ: 0, data: data}
}

func testSupportedVersions(t *testing.T, versions ...uint16) testExtension {
	t.Helper()
	data := []byte{byte(len(versions) * 2)}
	for _, version := range versions {
		data = binary.BigEndian.AppendUint16(data, version)
	}
	return testExtension{typ: 43, data: data}
}

func uint16Length(t *testing.T, name string, length int) uint16 {
	t.Helper()
	if length > math.MaxUint16 {
		t.Fatalf("%s length = %d, want <= %d", name, length, math.MaxUint16)
	}
	return uint16(length) //nolint:gosec // length is checked above.
}

type captureNetwork struct {
	gonnect.Network
	mu    sync.Mutex
	calls map[string][]string
}

func newCaptureNetwork() *captureNetwork {
	return &captureNetwork{
		Network: &gonnect.RejectNetwork{},
		calls:   make(map[string][]string),
	}
}

func (n *captureNetwork) record(name string, args ...string) {
	n.mu.Lock()
	n.calls[name] = append([]string(nil), args...)
	n.mu.Unlock()
}

func (n *captureNetwork) args(name string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls[name]...)
}

func (n *captureNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	n.record("Dial udp", network, address)
	return nil, errCapture
}

func (n *captureNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	n.record("DialTCP unknown", network, laddr, raddr)
	return nil, errCapture
}

func (n *captureNetwork) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	n.record("PacketDial", network, address)
	return nil, errCapture
}

func (n *captureNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	n.record("DialUDP", network, laddr, raddr)
	return nil, errCapture
}

func (n *captureNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	n.record("Listen", network, address)
	return nil, errCapture
}

func (n *captureNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	n.record("LookupHost", host)
	return nil, errCapture
}

func (n *captureNetwork) Interfaces() ([]gonnect.NetworkInterface, error) {
	n.record("Interfaces")
	return nil, errCapture
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isTimeoutError(err error) bool {
	type timeoutError interface {
		Timeout() bool
	}

	var timeout timeoutError
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}

	var opErr *net.OpError
	return errors.As(err, &opErr) &&
		opErr.Err != nil &&
		opErr.Err.Error() == "i/o timeout"
}

type countCloser struct {
	count atomic.Int32
}

func (c *countCloser) Close() error {
	c.count.Add(1)
	return nil
}

func (c *countCloser) closes() int32 {
	return c.count.Load()
}

type countUpDown struct {
	ups   atomic.Int32
	downs atomic.Int32
}

func (u *countUpDown) Up() error {
	u.ups.Add(1)
	return nil
}

func (u *countUpDown) Down() error {
	u.downs.Add(1)
	return nil
}

func (u *countUpDown) IsUp() (bool, error) {
	return u.ups.Load() > u.downs.Load(), nil
}
