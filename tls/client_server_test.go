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
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gonnecttls "github.com/asciimoth/gonnect/tls"
)

func TestClientServerNetworkHTTPClientToDirectHTTPSServer(t *testing.T) {
	ctx := context.Background()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "origin.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, host)

	listener, err := wrapped.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	port := mustPort(t, listener.Addr().String())

	helloCh := make(chan clientServerTLSHello, 1)
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tlsServerName := ""
			if r.TLS != nil {
				tlsServerName = r.TLS.ServerName
			}
			_, _ = fmt.Fprintf(
				w,
				"host=%s\ntls=%t\nsni=%s\nproto=%s\n",
				r.Host,
				r.TLS != nil,
				tlsServerName,
				r.Proto,
			)
		}),
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(stdtls.NewListener(
			listener,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   []string{"http/1.1"},
				MinVersion:   stdtls.VersionTLS12,
				GetCertificate: func(
					hello *stdtls.ClientHelloInfo,
				) (*stdtls.Certificate, error) {
					helloCh <- clientServerTLSHello{
						serverName: hello.ServerName,
						protos: append(
							[]string(nil),
							hello.SupportedProtos...,
						),
					}
					return &cert, nil
				},
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

	network, err := gonnecttls.NewClientServerNetwork(
		wrapped,
		&stdtls.Config{ // #nosec G402 -- Test TLS client.
			RootCAs:    certPool(caCert),
			NextProtos: []string{"http/1.1"},
			MinVersion: stdtls.VersionTLS12,
		},
		&stdtls.Config{ // #nosec G402 -- Required but unused in this test.
			Certificates: []stdtls.Certificate{cert},
			MinVersion:   stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetwork() error = %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				networkName, address string,
			) (net.Conn, error) {
				return network.Dial(ctx, networkName, address)
			},
			ForceAttemptHTTP2: false,
		},
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://"+net.JoinHostPort(host, port)+"/resource",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through ClientServerNetwork error = %v", err)
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
	if !stringsContainsAll(
		text,
		"host="+net.JoinHostPort(host, port),
		"tls=true",
		"sni="+host,
		"proto=HTTP/1.1",
	) {
		t.Fatalf("body = %q", text)
	}

	hello := receiveValue(t, helloCh)
	if hello.serverName != host {
		t.Fatalf("client SNI = %q, want %q", hello.serverName, host)
	}
	if !sameStrings(hello.protos, []string{"http/1.1"}) {
		t.Fatalf("client ALPN offer = %v, want [http/1.1]", hello.protos)
	}
}

func TestClientServerNetworkHTTPSClientToHTTPServerBehindMiddleware(
	t *testing.T,
) {
	ctx := context.Background()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "server.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, host)

	network, err := gonnecttls.NewClientServerNetwork(
		wrapped,
		&stdtls.Config{ // #nosec G402 -- Required but unused in this test.
			RootCAs:    certPool(caCert),
			MinVersion: stdtls.VersionTLS12,
		},
		&stdtls.Config{ // #nosec G402 -- Test TLS server.
			Certificates: []stdtls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetwork() error = %v", err)
	}

	listener, err := network.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	port := mustPort(t, listener.Addr().String())

	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tlsServerName := ""
			if r.TLS != nil {
				tlsServerName = r.TLS.ServerName
			}
			_, _ = fmt.Fprintf(
				w,
				"host=%s\ntls=%t\nsni=%s\nproto=%s\n",
				r.Host,
				r.TLS != nil,
				tlsServerName,
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

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				networkName, address string,
			) (net.Conn, error) {
				return wrapped.Dial(ctx, networkName, address)
			},
			TLSClientConfig: &stdtls.Config{ // #nosec G402 -- Test TLS client.
				RootCAs:    certPool(caCert),
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
		t.Fatalf("direct HTTPS GET error = %v", err)
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
	if !stringsContainsAll(
		text,
		"host="+net.JoinHostPort(host, port),
		"tls=true",
		"sni="+host,
		"proto=HTTP/1.1",
	) {
		t.Fatalf("body = %q", text)
	}
	if resp.TLS == nil {
		t.Fatal("direct HTTPS client response has no TLS state")
	}
}

func TestClientServerNetworkClientMappingOverridesSNIAndALPNWithoutRemap(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	requestedHost := "api.example.test"
	mappedHost := "mapped.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })
	recording := &recordingNetwork{Network: wrapped}

	ca, caCert := testCA(t, "origin.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, mappedHost)
	serverAddr, serverDone := startClientServerDirectTLSServer(
		t,
		ctx,
		wrapped,
		cert,
		[]string{"base/1", "mapped/1"},
	)
	requestedAddr := net.JoinHostPort(requestedHost, mustPort(t, serverAddr))

	network, err := gonnecttls.NewClientServerNetworkWithConfig(
		recording,
		gonnecttls.ClientServerConfig{
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Test TLS client.
				RootCAs:    certPool(caCert),
				NextProtos: []string{"base/1"},
				MinVersion: stdtls.VersionTLS12,
			},
			ServerConfig: &stdtls.Config{ // #nosec G402 -- Required but unused.
				Certificates: []stdtls.Certificate{cert},
				MinVersion:   stdtls.VersionTLS12,
			},
			Mappings: []gonnecttls.ClientServerMapping{
				{
					Networks: []string{"tcp"},
					ConnDsts: []string{requestedHost},
					Client: gonnecttls.ClientServerTLSOptions{
						ServerName: mappedHost,
						NextProtos: []string{"mapped/1"},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetworkWithConfig() error = %v", err)
	}

	conn, err := network.DialTCP(ctx, "tcp", "", requestedAddr)
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, len("ok"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("reply = %q, want ok", reply)
	}

	result := waitForClientServerTLSResult(t, serverDone)
	if got := recording.lastTCPRaddr(); got != requestedAddr {
		t.Fatalf("underlying raddr = %q, want %q", got, requestedAddr)
	}
	if result.serverName != mappedHost {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, mappedHost)
	}
	if !sameStrings(result.protos, []string{"mapped/1"}) {
		t.Fatalf("server saw ALPN offer = %v, want [mapped/1]", result.protos)
	}
	if result.negotiatedProto != "mapped/1" {
		t.Fatalf(
			"negotiated ALPN = %q, want mapped/1",
			result.negotiatedProto,
		)
	}
	if result.read != "ping" {
		t.Fatalf("server read = %q, want ping", result.read)
	}
}

func TestClientServerNetworkClientMappingCanReplaceTLSConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "origin.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, host)
	serverAddr, serverDone := startClientServerDirectTLSServer(
		t,
		ctx,
		wrapped,
		cert,
		[]string{"mapped/1"},
	)

	network, err := gonnecttls.NewClientServerNetworkWithConfig(
		wrapped,
		gonnecttls.ClientServerConfig{
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Empty roots must be replaced by mapping.
				RootCAs:    x509.NewCertPool(),
				NextProtos: []string{"base/1"},
				MinVersion: stdtls.VersionTLS12,
			},
			ServerConfig: &stdtls.Config{ // #nosec G402 -- Required but unused.
				Certificates: []stdtls.Certificate{cert},
				MinVersion:   stdtls.VersionTLS12,
			},
			Mappings: []gonnecttls.ClientServerMapping{
				{
					ConnDsts: []string{host},
					Client: gonnecttls.ClientServerTLSOptions{
						Config: &stdtls.Config{ // #nosec G402 -- Test mapped TLS client config.
							RootCAs:    certPool(caCert),
							NextProtos: []string{"mapped/1"},
							MinVersion: stdtls.VersionTLS12,
						},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetworkWithConfig() error = %v", err)
	}

	conn, err := network.Dial(
		ctx,
		"tcp",
		net.JoinHostPort(host, mustPort(t, serverAddr)),
	)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, len("ok"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	result := waitForClientServerTLSResult(t, serverDone)
	if result.serverName != host {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, host)
	}
	if !sameStrings(result.protos, []string{"mapped/1"}) {
		t.Fatalf("server saw ALPN offer = %v, want [mapped/1]", result.protos)
	}
}

func TestClientServerNetworkServerMappingUsesListenDestinationALPN(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "server.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, host)

	network, err := gonnecttls.NewClientServerNetworkWithConfig(
		wrapped,
		gonnecttls.ClientServerConfig{
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Required but unused.
				RootCAs:    certPool(caCert),
				MinVersion: stdtls.VersionTLS12,
			},
			ServerConfig: &stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   []string{"base/1"},
				MinVersion:   stdtls.VersionTLS12,
				GetConfigForClient: func(
					*stdtls.ClientHelloInfo,
				) (*stdtls.Config, error) {
					return &stdtls.Config{ // #nosec G402 -- Test dynamic TLS server config.
						Certificates: []stdtls.Certificate{cert},
						NextProtos:   []string{"base/1"},
						MinVersion:   stdtls.VersionTLS12,
					}, nil
				},
			},
			Mappings: []gonnecttls.ClientServerMapping{
				{
					Networks: []string{"tcp"},
					ConnDsts: []string{"127.0.0.1:0"},
					Server: gonnecttls.ClientServerTLSOptions{
						NextProtos: []string{"mapped/1"},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetworkWithConfig() error = %v", err)
	}

	listener, err := network.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	port := mustPort(t, listener.Addr().String())

	serverDone := make(chan clientServerTLSResult, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			serverDone <- clientServerTLSResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- clientServerTLSResult{err: err}
			return
		}
		if _, err := conn.Write([]byte("ok")); err != nil {
			serverDone <- clientServerTLSResult{err: err}
			return
		}

		stateConn, ok := conn.(interface {
			ConnectionState() stdtls.ConnectionState
		})
		if !ok {
			serverDone <- clientServerTLSResult{
				err: fmt.Errorf(
					"accepted connection %T has no TLS connection state",
					conn,
				),
			}
			return
		}
		state := stateConn.ConnectionState()
		serverDone <- clientServerTLSResult{
			negotiatedProto: state.NegotiatedProtocol,
			read:            string(buf),
		}
	}()

	raw, err := wrapped.Dial(
		ctx,
		"tcp",
		net.JoinHostPort(host, port),
	)
	if err != nil {
		t.Fatalf("wrapped Dial() error = %v", err)
	}
	defer func() { _ = raw.Close() }()
	client := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test TLS client.
			RootCAs:    certPool(caCert),
			ServerName: host,
			NextProtos: []string{"mapped/1", "base/1"},
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client HandshakeContext() error = %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	reply := make([]byte, len("ok"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("client reply = %q, want ok", reply)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "mapped/1" {
		t.Fatalf("client ALPN = %q, want mapped/1", got)
	}

	result := waitForClientServerTLSResult(t, serverDone)
	if result.negotiatedProto != "mapped/1" {
		t.Fatalf("server ALPN = %q, want mapped/1", result.negotiatedProto)
	}
	if result.read != "ping" {
		t.Fatalf("server read = %q, want ping", result.read)
	}
}

func TestClientServerNetworkMappingEmptyALPNDisablesClientOffer(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "api.example.test"

	wrapped := gonnect.NewLoopbackNetwork()
	wrapped.AllowAnyHost = true
	t.Cleanup(func() { _ = wrapped.Close() })

	ca, caCert := testCA(t, "origin.test")
	cert := testLeafCert(t, caCert, ca.PrivateKey, host)
	serverAddr, serverDone := startClientServerDirectTLSServer(
		t,
		ctx,
		wrapped,
		cert,
		[]string{"base/1"},
	)

	network, err := gonnecttls.NewClientServerNetworkWithConfig(
		wrapped,
		gonnecttls.ClientServerConfig{
			ClientConfig: &stdtls.Config{ // #nosec G402 -- Test TLS client.
				RootCAs:    certPool(caCert),
				NextProtos: []string{"base/1"},
				MinVersion: stdtls.VersionTLS12,
			},
			ServerConfig: &stdtls.Config{ // #nosec G402 -- Required but unused.
				Certificates: []stdtls.Certificate{cert},
				MinVersion:   stdtls.VersionTLS12,
			},
			Mappings: []gonnecttls.ClientServerMapping{
				{
					ConnDsts: []string{host},
					Client: gonnecttls.ClientServerTLSOptions{
						NextProtos: []string{},
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetworkWithConfig() error = %v", err)
	}

	conn, err := network.Dial(
		ctx,
		"tcp",
		net.JoinHostPort(host, mustPort(t, serverAddr)),
	)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, len("ok"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	result := waitForClientServerTLSResult(t, serverDone)
	if len(result.protos) != 0 {
		t.Fatalf("server saw ALPN offer = %v, want none", result.protos)
	}
	if result.negotiatedProto != "" {
		t.Fatalf("negotiated ALPN = %q, want empty", result.negotiatedProto)
	}
}

func TestClientServerNetworkDelegatesNonTCPAndOtherCalls(t *testing.T) {
	ctx := context.Background()
	wrapped := newCaptureNetwork()
	network := mustClientServerNetwork(t, wrapped)

	cases := []struct {
		name string
		run  func() error
		want []string
	}{
		{
			name: "Dial udp",
			run: func() error {
				_, err := network.Dial(ctx, "udp", "127.0.0.1:53")
				return err
			},
			want: []string{"udp", "127.0.0.1:53"},
		},
		{
			name: "DialTCP unknown",
			run: func() error {
				_, err := network.DialTCP(
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
				_, err := network.PacketDial(ctx, "udp", "127.0.0.1:53")
				return err
			},
			want: []string{"udp", "127.0.0.1:53"},
		},
		{
			name: "DialUDP",
			run: func() error {
				_, err := network.DialUDP(
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
				_, err := network.Listen(ctx, "udp", "127.0.0.1:53")
				return err
			},
			want: []string{"udp", "127.0.0.1:53"},
		},
		{
			name: "LookupHost",
			run: func() error {
				_, err := network.LookupHost(ctx, "example.test")
				return err
			},
			want: []string{"example.test"},
		},
		{
			name: "Interfaces",
			run: func() error {
				_, err := network.Interfaces()
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

func TestClientServerNetworkLifecyclePassesThrough(t *testing.T) {
	wrapped := gonnect.NewLoopbackNetwork()
	network := mustClientServerNetwork(t, wrapped)
	closer := &countCloser{}
	updown := &countUpDown{}

	unsubscribeCloser, err := network.SubscribeCloser(closer)
	if err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}
	defer unsubscribeCloser()

	unsubscribeUpDown, err := network.SubscribeUpDown(updown)
	if err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}
	defer unsubscribeUpDown()

	if network.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	if network.GetWrapped() != wrapped {
		t.Fatal("GetWrapped() did not return wrapped Network")
	}
	if network.GetNetwork() != wrapped {
		t.Fatal("GetNetwork() did not return wrapped Network")
	}

	if err := network.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if updown.downs.Load() != 1 {
		t.Fatalf("Down calls = %d, want 1", updown.downs.Load())
	}
	if up, err := network.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}

	if err := network.Up(); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if updown.ups.Load() != 1 {
		t.Fatalf("Up calls = %d, want 1", updown.ups.Load())
	}

	if err := network.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("closer closes = %d, want 1", closer.closes())
	}
}

func TestNewClientServerNetworkValidation(t *testing.T) {
	cert := testSelfSignedLeaf(t, "server.test")
	clientConfig := &stdtls.Config{ // #nosec G402 -- Validation-only config.
		InsecureSkipVerify: true, // #nosec G402 -- Validation-only config.
		MinVersion:         stdtls.VersionTLS12,
	}
	serverConfig := &stdtls.Config{ // #nosec G402 -- Validation-only config.
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS12,
	}

	tests := []struct {
		name    string
		network gonnect.Network
		config  gonnecttls.ClientServerConfig
	}{
		{
			name: "nil network",
			config: gonnecttls.ClientServerConfig{
				ClientConfig: clientConfig,
				ServerConfig: serverConfig,
			},
		},
		{
			name:    "nil client config",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.ClientServerConfig{
				ServerConfig: serverConfig,
			},
		},
		{
			name:    "nil server config",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.ClientServerConfig{
				ClientConfig: clientConfig,
			},
		},
		{
			name:    "invalid network pattern",
			network: &gonnect.RejectNetwork{},
			config: gonnecttls.ClientServerConfig{
				ClientConfig: clientConfig,
				ServerConfig: serverConfig,
				Mappings: []gonnecttls.ClientServerMapping{
					{Networks: []string{"["}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := gonnecttls.NewClientServerNetworkWithConfig(
				tt.network,
				tt.config,
			); err == nil {
				t.Fatal("NewClientServerNetworkWithConfig() succeeded")
			}
		})
	}
}

type clientServerTLSHello struct {
	serverName string
	protos     []string
}

type clientServerTLSResult struct {
	serverName      string
	protos          []string
	negotiatedProto string
	read            string
	err             error
}

func startClientServerDirectTLSServer(
	t *testing.T,
	ctx context.Context,
	network gonnect.Network,
	cert stdtls.Certificate,
	nextProtos []string,
) (string, <-chan clientServerTLSResult) {
	t.Helper()

	listener, err := network.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan clientServerTLSResult, 1)
	go func() {
		defer func() { _ = listener.Close() }()

		conn, err := listener.Accept()
		if err != nil {
			done <- clientServerTLSResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		var result clientServerTLSResult
		tlsConn := stdtls.Server(
			conn,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   append([]string(nil), nextProtos...),
				MinVersion:   stdtls.VersionTLS12,
				GetCertificate: func(
					hello *stdtls.ClientHelloInfo,
				) (*stdtls.Certificate, error) {
					result.serverName = hello.ServerName
					result.protos = append(
						[]string(nil),
						hello.SupportedProtos...,
					)
					return &cert, nil
				},
			},
		)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			result.err = err
			done <- result
			return
		}

		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			result.err = err
			done <- result
			return
		}
		if _, err := tlsConn.Write([]byte("ok")); err != nil {
			result.err = err
			done <- result
			return
		}

		result.negotiatedProto = tlsConn.ConnectionState().NegotiatedProtocol
		result.read = string(buf)
		done <- result
	}()

	return listener.Addr().String(), done
}

func waitForClientServerTLSResult(
	t *testing.T,
	done <-chan clientServerTLSResult,
) clientServerTLSResult {
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
	var zero clientServerTLSResult
	return zero
}

func mustClientServerNetwork(
	t *testing.T,
	wrapped gonnect.Network,
) *gonnecttls.ClientServerNetwork {
	t.Helper()
	cert := testSelfSignedLeaf(t, "server.test")
	network, err := gonnecttls.NewClientServerNetwork(
		wrapped,
		&stdtls.Config{ // #nosec G402 -- Test TLS client.
			InsecureSkipVerify: true, // #nosec G402 -- Test TLS client.
			MinVersion:         stdtls.VersionTLS12,
		},
		&stdtls.Config{ // #nosec G402 -- Test TLS server.
			Certificates: []stdtls.Certificate{cert},
			MinVersion:   stdtls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("NewClientServerNetwork() error = %v", err)
	}
	return network
}
