package tls_test

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gonnecttls "github.com/asciimoth/gonnect/tls"
)

func TestTerminatorHTTPSClientToPlainHTTPServer(t *testing.T) {
	ctx := context.Background()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	terminatorCA, terminatorCACert := testCA(t, "terminator.test")
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
				"host=%s\ntls=%t\nproto=%s\n",
				r.Host,
				r.TLS != nil,
				r.Proto,
			)
		}),
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
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

	terminator, err := gonnecttls.NewTerminatorWithConfig(
		wrapped,
		gonnecttls.TerminatorConfig{
			CA:         terminatorCA,
			NextProtos: []string{"http/1.1"},
		},
	)
	if err != nil {
		t.Fatalf("NewTerminatorWithConfig() error = %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				return terminator.Dial(ctx, network, address)
			},
			TLSClientConfig: &stdtls.Config{ // #nosec G402 -- Test client config.
				RootCAs:    certPool(terminatorCACert),
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
		t.Fatalf("GET through terminator error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	text := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, text)
	}
	if !stringsContainsAll(text,
		"host="+net.JoinHostPort(host, port),
		"tls=false",
		"proto=HTTP/1.1",
	) {
		t.Fatalf("body = %q", text)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("response has no downstream TLS state")
	}
	if got := resp.TLS.PeerCertificates[0].Issuer.CommonName; got != "terminator.test" {
		t.Fatalf("downstream issuer = %q, want terminator.test", got)
	}
	if got := resp.TLS.NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("downstream ALPN = %q, want http/1.1", got)
	}
}

func TestTerminatorDestinationRemapUsesOriginalSNIAndALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tests := []struct {
		name       string
		protos     []string
		wantServer string
	}{
		{
			name:       "all fields match remap",
			protos:     []string{"http/1.1"},
			wantServer: "mapped",
		},
		{
			name:       "ALPN mismatch keeps original destination",
			protos:     []string{"h2"},
			wantServer: "original",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := gonnect.NewLoopbackNetwork()
			wrapped.AllowAnyHost = true
			t.Cleanup(func() { _ = wrapped.Close() })

			ca, caCert := testCA(t, "terminator.test")
			originalListener := listenTCP(t, wrapped)
			mappedListener := listenTCP(t, wrapped)

			originalAddr := net.JoinHostPort(
				"original.example.test",
				mustPort(t, originalListener.Addr().String()),
			)
			mappedAddr := mappedListener.Addr().String()

			var expectedDone <-chan plainServerResult
			var unexpected gonnect.TCPListener
			switch tt.wantServer {
			case "mapped":
				expectedDone = servePlainOnce(
					t,
					mappedListener,
					"mapped",
				)
				unexpected = originalListener
			case "original":
				expectedDone = servePlainOnce(
					t,
					originalListener,
					"original",
				)
				unexpected = mappedListener
			default:
				t.Fatalf("invalid wantServer %q", tt.wantServer)
			}

			terminator, err := gonnecttls.NewTerminatorWithConfig(
				wrapped,
				gonnecttls.TerminatorConfig{
					CA:         ca,
					NextProtos: []string{"http/1.1", "h2"},
					DestinationRemaps: []gonnecttls.TerminatorDestinationRemap{
						{
							OriginalDsts: []string{originalAddr},
							SNIHosts:     []string{"api.example.test"},
							ALPNs:        []string{"http/1.1"},
							Dst:          mappedAddr,
						},
					},
				},
			)
			if err != nil {
				t.Fatalf("NewTerminatorWithConfig() error = %v", err)
			}

			reply := dialTerminatedTLSAndExchange(
				t,
				ctx,
				terminator,
				originalAddr,
				"api.example.test",
				certPool(caCert),
				tt.protos,
				"ping",
			)
			if reply != tt.wantServer {
				t.Fatalf("reply = %q, want %q", reply, tt.wantServer)
			}

			result := waitForPlainServer(t, expectedDone)
			if result.read != "ping" {
				t.Fatalf("server read = %q, want ping", result.read)
			}
			requireNoAccept(t, unexpected)
		})
	}
}

func TestTerminatorUseSNIHostnameForDefaultDestination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	recording := &recordingNetwork{Network: wrapped}
	ca, caCert := testCA(t, "terminator.test")

	listener := listenTCP(t, wrapped)
	done := servePlainOnce(t, listener, "ok")
	port := mustPort(t, listener.Addr().String())

	terminator, err := gonnecttls.NewTerminatorWithConfig(
		recording,
		gonnecttls.TerminatorConfig{
			CA:             ca,
			UseSNIHostname: true,
		},
	)
	if err != nil {
		t.Fatalf("NewTerminatorWithConfig() error = %v", err)
	}

	reply := dialTerminatedTLSAndExchange(
		t,
		ctx,
		terminator,
		net.JoinHostPort("127.0.0.1", port),
		"api.example.test",
		certPool(caCert),
		nil,
		"ping",
	)
	if reply != "ok" {
		t.Fatalf("reply = %q, want ok", reply)
	}
	_ = waitForPlainServer(t, done)

	if got, want := recording.lastTCPRaddr(), net.JoinHostPort(
		"api.example.test",
		port,
	); got != want {
		t.Fatalf("upstream raddr = %q, want %q", got, want)
	}
}

func TestTerminatorBridgeIgnoresDialContextAfterReturn(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "terminator.test")
	listener := listenTCP(t, wrapped)
	done := servePlainOnce(t, listener, "ok")

	terminator, err := gonnecttls.NewTerminator(wrapped, ca)
	if err != nil {
		t.Fatalf("NewTerminator() error = %v", err)
	}

	dialCtx, cancelDial := context.WithCancel(context.Background())
	raw, err := terminator.DialTCP(
		dialCtx,
		"tcp",
		"",
		listener.Addr().String(),
	)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()
	cancelDial()

	handshakeCtx, cancelHandshake := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelHandshake()
	client := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test client config.
			RootCAs:    certPool(caCert),
			ServerName: "api.example.test",
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err := client.HandshakeContext(handshakeCtx); err != nil {
		t.Fatalf("HandshakeContext() error = %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, len("ok"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("reply = %q, want ok", reply)
	}
	_ = waitForPlainServer(t, done)
}

func TestTerminatorRejectsPlainTCPWithoutUpstreamDial(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener := listenTCP(t, wrapped)
	terminator := mustTerminator(t, wrapped)

	conn, err := terminator.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() succeeded after plaintext bytes")
	}
	requireNoAccept(t, listener)
}

func TestTerminatorRejectsInvalidSNIWithoutUpstreamDial(t *testing.T) {
	ctx := context.Background()
	wrapped := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = wrapped.Close() })

	listener := listenTCP(t, wrapped)
	terminator := mustTerminator(t, wrapped)

	conn, err := terminator.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	hello := testClientHello(
		t,
		testSupportedVersions(t, stdtls.VersionTLS12),
		testServerName(t, "api.example.test."),
	)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() succeeded after ClientHello with invalid SNI")
	}
	requireNoAccept(t, listener)
}

func TestTerminatorRejectsUninterceptableTLSWithoutUpstreamDial(
	t *testing.T,
) {
	tests := []struct {
		name string
		run  func(*testing.T, context.Context, *gonnecttls.Terminator, string)
	}{
		{
			name: "without SNI",
			run: func(
				t *testing.T,
				ctx context.Context,
				terminator *gonnecttls.Terminator,
				raddr string,
			) {
				t.Helper()
				conn, err := terminator.DialTCP(ctx, "tcp", "", raddr)
				if err != nil {
					t.Fatalf("DialTCP() error = %v", err)
				}
				defer func() { _ = conn.Close() }()

				hello := testClientHello(
					t,
					testSupportedVersions(t, stdtls.VersionTLS12),
				)
				if _, err := conn.Write(hello); err != nil {
					t.Fatalf("Write() error = %v", err)
				}
				if err := conn.SetReadDeadline(
					time.Now().Add(time.Second),
				); err != nil {
					t.Fatalf("SetReadDeadline() error = %v", err)
				}
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("Read() succeeded after ClientHello without SNI")
				}
			},
		},
		{
			name: "with ECH signal",
			run: func(
				t *testing.T,
				ctx context.Context,
				terminator *gonnecttls.Terminator,
				raddr string,
			) {
				t.Helper()
				conn, err := terminator.DialTCP(ctx, "tcp", "", raddr)
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
				if err := conn.SetReadDeadline(
					time.Now().Add(time.Second),
				); err != nil {
					t.Fatalf("SetReadDeadline() error = %v", err)
				}
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("Read() succeeded after ECH ClientHello")
				}
			},
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
			t.Cleanup(func() { _ = wrapped.Close() })

			listener := listenTCP(t, wrapped)
			terminator := mustTerminator(t, wrapped)

			tt.run(t, ctx, terminator, listener.Addr().String())
			requireNoAccept(t, listener)
		})
	}
}

func TestTerminatorRejectsNonTCPAndNonDialCalls(t *testing.T) {
	ctx := context.Background()
	wrapped := newCaptureNetwork()
	terminator := mustTerminator(t, wrapped)

	cases := []struct {
		name string
		run  func() error
	}{
		{
			name: "Dial udp",
			run: func() error {
				_, err := terminator.Dial(ctx, "udp", "127.0.0.1:53")
				return err
			},
		},
		{
			name: "DialTCP unknown",
			run: func() error {
				_, err := terminator.DialTCP(
					ctx,
					"tcp5",
					"127.0.0.1:1",
					"127.0.0.1:2",
				)
				return err
			},
		},
		{
			name: "PacketDial",
			run: func() error {
				_, err := terminator.PacketDial(ctx, "udp", "127.0.0.1:53")
				return err
			},
		},
		{
			name: "DialUDP",
			run: func() error {
				_, err := terminator.DialUDP(
					ctx,
					"udp",
					"127.0.0.1:1",
					"127.0.0.1:53",
				)
				return err
			},
		},
		{
			name: "Listen",
			run: func() error {
				_, err := terminator.Listen(ctx, "tcp", "127.0.0.1:0")
				return err
			},
		},
		{
			name: "LookupHost",
			run: func() error {
				_, err := terminator.LookupHost(ctx, "example.test")
				return err
			},
		},
		{
			name: "Interfaces",
			run: func() error {
				_, err := terminator.Interfaces()
				return err
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if !errors.Is(err, gonnecttls.ErrTerminatorUnsupported) {
				t.Fatalf(
					"error = %v, want ErrTerminatorUnsupported",
					err,
				)
			}
			if got := wrapped.args(tt.name); len(got) != 0 {
				t.Fatalf("underlying call args = %v, want none", got)
			}
		})
	}
}

func TestTerminatorLifecyclePassesThrough(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwork()
	terminator := mustTerminator(t, wrapped)
	closer := &countCloser{}
	updown := &countUpDown{}

	unsubscribeCloser, err := terminator.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeCloser()

	unsubscribeUpDown, err := terminator.SubscribeUpDown(updown)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribeUpDown()

	if err := terminator.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if updown.downs.Load() != 1 {
		t.Fatalf("Down calls = %d, want 1", updown.downs.Load())
	}
	if up, err := terminator.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}

	if err := terminator.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if updown.ups.Load() != 1 {
		t.Fatalf("Up calls = %d, want 1", updown.ups.Load())
	}

	if err := terminator.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("closer closes = %d, want 1", closer.closes())
	}
}

func TestNewTerminatorValidation(t *testing.T) {
	ca, _ := testCA(t, "terminator.test")
	leaf := testSelfSignedLeaf(t, "leaf.test")

	tests := []struct {
		name    string
		network gonnect.Network
		config  gonnecttls.TerminatorConfig
	}{
		{
			name:   "nil network",
			config: gonnecttls.TerminatorConfig{CA: ca},
		},
		{
			name:    "missing CA chain",
			network: &gonnect.RejectNetwork{},
		},
		{
			name:    "non CA certificate",
			network: &gonnect.RejectNetwork{},
			config:  gonnecttls.TerminatorConfig{CA: leaf},
		},
		{
			name:    "negative sniff buffer",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA:              ca,
				SniffBufferSize: -1,
			},
		},
		{
			name:    "negative leaf ttl",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA:      ca,
				LeafTTL: -time.Second,
			},
		},
		{
			name:    "empty remap destination",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA: ca,
				DestinationRemaps: []gonnecttls.TerminatorDestinationRemap{
					{SNIHosts: []string{"*.example.test"}},
				},
			},
		},
		{
			name:    "invalid remap destination",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA: ca,
				DestinationRemaps: []gonnecttls.TerminatorDestinationRemap{
					{Dst: "missing-port"},
				},
			},
		},
		{
			name:    "invalid SNI pattern",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA: ca,
				DestinationRemaps: []gonnecttls.TerminatorDestinationRemap{
					{SNIHosts: []string{"["}, Dst: "127.0.0.1:443"},
				},
			},
		},
		{
			name:    "invalid ALPN pattern",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.TerminatorConfig{
				CA: ca,
				DestinationRemaps: []gonnecttls.TerminatorDestinationRemap{
					{ALPNs: []string{"["}, Dst: "127.0.0.1:443"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := gonnecttls.NewTerminatorWithConfig(
				tt.network,
				tt.config,
			); err == nil {
				t.Fatal("NewTerminatorWithConfig() succeeded")
			}
		})
	}
}

func TestTerminatorWrapsNetwork(t *testing.T) {
	wrapped := &gonnect.RejectNetwork{}
	terminator := mustTerminator(t, wrapped)

	if terminator.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() did not return wrapped Network")
	}
	if terminator.GetNetwork() != wrapped {
		t.Fatal("GetNetwork() did not return wrapped Network")
	}
	if terminator.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
}

type plainServerResult struct {
	read string
	err  error
}

func listenTCP(
	t *testing.T,
	network gonnect.Network,
) gonnect.TCPListener {
	t.Helper()
	listener, err := network.ListenTCP(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func servePlainOnce(
	t *testing.T,
	listener gonnect.TCPListener,
	reply string,
) <-chan plainServerResult {
	t.Helper()

	done := make(chan plainServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- plainServerResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- plainServerResult{err: err}
			return
		}
		_, err = conn.Write([]byte(reply))
		done <- plainServerResult{read: string(buf), err: err}
	}()

	return done
}

func waitForPlainServer(
	t *testing.T,
	done <-chan plainServerResult,
) plainServerResult {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("plain server error = %v", result.err)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for plain server")
	}
	var zero plainServerResult
	return zero
}

func dialTerminatedTLSAndExchange(
	t *testing.T,
	ctx context.Context,
	terminator *gonnecttls.Terminator,
	raddr string,
	serverName string,
	roots *x509.CertPool,
	nextProtos []string,
	message string,
) string {
	t.Helper()

	raw, err := terminator.DialTCP(ctx, "tcp", "", raddr)
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
		t.Fatalf("HandshakeContext() error = %v", err)
	}
	if _, err := client.Write([]byte(message)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	reply := make([]byte, len("original"))
	n, err := client.Read(reply)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v", err)
	}
	return string(reply[:n])
}

func requireNoAccept(t *testing.T, listener gonnect.TCPListener) {
	t.Helper()
	if err := listener.SetDeadline(
		time.Now().Add(150 * time.Millisecond),
	); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	conn, err := listener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener accepted an upstream connection")
	}
	if !isTimeoutError(err) {
		t.Fatalf("Accept() error = %v, want timeout", err)
	}
}

func mustTerminator(
	t *testing.T,
	wrapped gonnect.Network,
) *gonnecttls.Terminator {
	t.Helper()
	ca, _ := testCA(t, "terminator.test")
	terminator, err := gonnecttls.NewTerminator(wrapped, ca)
	if err != nil {
		t.Fatalf("NewTerminator() error = %v", err)
	}
	return terminator
}

func stringsContainsAll(s string, substrings ...string) bool {
	for _, substring := range substrings {
		if !strings.Contains(s, substring) {
			return false
		}
	}
	return true
}

type recordingNetwork struct {
	gonnect.Network
	mu        sync.Mutex
	tcpRaddrs []string
}

func (n *recordingNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	n.mu.Lock()
	n.tcpRaddrs = append(n.tcpRaddrs, raddr)
	n.mu.Unlock()
	return n.Network.DialTCP(ctx, network, laddr, raddr)
}

func (n *recordingNetwork) lastTCPRaddr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.tcpRaddrs) == 0 {
		return ""
	}
	return n.tcpRaddrs[len(n.tcpRaddrs)-1]
}
