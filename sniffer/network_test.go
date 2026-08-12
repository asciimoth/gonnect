package sniffer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sniffer"
)

type metadataPrefixFactory struct {
	prefix []byte
	value  any
}

func (f metadataPrefixFactory) NewClassifier() sniffer.Classifier {
	return &metadataPrefixClassifier{
		classifier: sniffer.Prefix(f.prefix),
		value:      f.value,
	}
}

func (f metadataPrefixFactory) MinSniffBufferSize() int {
	return len(f.prefix)
}

type metadataPrefixClassifier struct {
	classifier sniffer.Classifier
	value      any
}

func (c *metadataPrefixClassifier) Feed(p []byte) sniffer.State {
	return c.classifier.Feed(p)
}

func (c *metadataPrefixClassifier) MinSniffBufferSize() int {
	return c.classifier.MinSniffBufferSize()
}

func (c *metadataPrefixClassifier) Metadata() any {
	return c.value
}

func TestHTTPClassifierMetadata(t *testing.T) {
	classifier := sniffer.HTTPWithConfig(sniffer.HTTPConfig{
		Hostname: "api.example.test",
	})
	request := "GET /v1 HTTP/1.1\r\nHost: API.Example.Test:8443\r\n\r\n"
	if got := classifier.Feed([]byte(request)); got != sniffer.Match {
		t.Fatalf("Feed() = %v, want Match", got)
	}

	info, ok := sniffer.Metadata(classifier).(sniffer.HTTPInfo)
	if !ok {
		t.Fatalf("metadata type = %T, want sniffer.HTTPInfo", info)
	}
	if info.Method != http.MethodGet ||
		info.URL != "/v1" ||
		info.Version != "HTTP/1.1" ||
		info.Hostname != "api.example.test" {
		t.Fatalf("HTTP metadata = %+v", info)
	}
}

func TestSnifferInterceptUsesClassifierMetadataAndRestoresBytes(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	listener, err := backend.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	readCh := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			readCh <- "accept: " + err.Error()
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, len("MAGIC payload"))
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			readCh <- "read: " + err.Error()
			return
		}
		readCh <- string(buf)
	}()

	type routeMetadata struct {
		Protocol string
	}
	seen := make(chan sniffer.SniffResult, 1)
	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs: []gonnect.Network{backend},
		Classifiers: []sniffer.Factory{metadataPrefixFactory{
			prefix: []byte("MAGIC"),
			value:  routeMetadata{Protocol: "test"},
		}},
		Control: func(call *sniffer.Call) sniffer.Action {
			if call.Operation == sniffer.OpDialTCP {
				return sniffer.Action{Slot: sniffer.RejectSlot, Intercept: true}
			}
			return sniffer.Action{Slot: sniffer.DefaultSlot}
		},
		SniffControl: func(call *sniffer.SniffedCall) sniffer.Action {
			seen <- call.Result
			if metadata, ok := call.Result.Metadata.(routeMetadata); ok &&
				metadata.Protocol == "test" {
				call.Dst = listener.Addr().String()
				return sniffer.Action{Slot: sniffer.DefaultSlot}
			}
			return sniffer.Action{Slot: sniffer.RejectSlot}
		},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}
	defer func() { _ = middleware.Close() }()

	conn, err := middleware.DialTCP(ctx, "tcp", "", "original.test:443")
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("MAGIC payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	select {
	case result := <-seen:
		if result.Index != 0 || result.Err != nil {
			t.Fatalf("sniff result = %+v", result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	select {
	case got := <-readCh:
		if got != "MAGIC payload" {
			t.Fatalf("server read = %q, want full restored stream", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSnifferRejectsUnsupportedInterception(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs: []gonnect.Network{backend},
		Control: func(call *sniffer.Call) sniffer.Action {
			return sniffer.Action{
				Slot:      sniffer.DefaultSlot,
				Intercept: true,
			}
		},
		SniffControl: func(call *sniffer.SniffedCall) sniffer.Action {
			t.Fatal("SniffControl was called for unsupported interception")
			return sniffer.Action{Slot: sniffer.DefaultSlot}
		},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}
	defer func() { _ = middleware.Close() }()

	if _, err := middleware.Dial(ctx, "udp", "127.0.0.1:1"); err == nil {
		t.Fatal("Dial(udp) with Intercept succeeded")
	}
	if _, err := middleware.DialUDP(
		ctx,
		"udp",
		"",
		"127.0.0.1:1",
	); err == nil {
		t.Fatal("DialUDP() with Intercept succeeded")
	}
	if _, err := middleware.ListenTCP(ctx, "tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("ListenTCP() with Intercept succeeded")
	}
	if _, err := middleware.LookupHost(ctx, "localhost"); err == nil {
		t.Fatal("LookupHost() with Intercept succeeded")
	}
}

func TestSnifferCloseClosesActiveConnectionsButNotOutputs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	listener, err := backend.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan gonnect.TCPConn, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			accepted <- conn
		}
	}()

	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs: []gonnect.Network{backend},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}

	conn, err := middleware.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	select {
	case serverConn := <-accepted:
		defer func() { _ = serverConn.Close() }()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := middleware.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("Write() after Sniffer.Close() succeeded")
	}
	if _, err := middleware.DialTCP(
		ctx,
		"tcp",
		"",
		listener.Addr().String(),
	); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialTCP() after Close() error = %v, want net.ErrClosed", err)
	}
	if extra, err := backend.ListenTCP(ctx, "tcp", "127.0.0.1:0"); err != nil {
		t.Fatalf("output ListenTCP() after Sniffer.Close() error = %v", err)
	} else {
		_ = extra.Close()
	}
}

func TestExternallyClosedOutputDoesNotAffectOtherSlots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	closedBackend := gonnect.NewLoopbackNetwork()
	openBackend := gonnect.NewLoopbackNetwork()
	openBackend.AllowAnyHost = true
	t.Cleanup(func() { _ = openBackend.Close() })
	_ = closedBackend.Close()

	listener, err := openBackend.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	done := servePlainOnce(t, listener, "ok")

	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs: []gonnect.Network{closedBackend, openBackend},
		Control: func(call *sniffer.Call) sniffer.Action {
			switch call.Dst {
			case "closed.test:443":
				return sniffer.Action{Slot: 1}
			default:
				call.Dst = listener.Addr().String()
				return sniffer.Action{Slot: 2}
			}
		},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}
	defer func() { _ = middleware.Close() }()

	if _, err := middleware.DialTCP(
		ctx,
		"tcp",
		"",
		"closed.test:443",
	); err == nil {
		t.Fatal("DialTCP() to closed output succeeded")
	}
	conn, err := middleware.DialTCP(ctx, "tcp", "", "open.test:443")
	if err != nil {
		t.Fatalf("DialTCP() to open output error = %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if got := string(buf); got != "ok" {
		t.Fatalf("reply = %q, want ok", got)
	}
	_ = conn.Close()

	if got := <-done; got != "ping" {
		t.Fatalf("server read = %q, want ping", got)
	}
}

func TestSnifferRoutesRawTLSByClientHelloMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := "tls.example.test"
	backend1 := gonnect.NewLoopbackNetwork()
	backend2 := gonnect.NewLoopbackNetwork()
	backend2.AllowAnyHost = true
	t.Cleanup(func() { _ = backend1.Close() })
	t.Cleanup(func() { _ = backend2.Close() })

	ca, caCert := testCA(t, "raw tls test ca")
	leaf := testLeafCert(t, caCert, ca.PrivateKey, host)
	listener, err := backend2.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := serveTLSOnce(t, ctx, listener, leaf)

	seen := make(chan sniffer.TLSClientHelloInfo, 1)
	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs:     []gonnect.Network{backend1, backend2},
		Classifiers: []sniffer.Factory{sniffer.TLSFactory()},
		Control: func(call *sniffer.Call) sniffer.Action {
			if call.Operation == sniffer.OpDialTCP {
				return sniffer.Action{Slot: 1, Intercept: true}
			}
			return sniffer.Action{Slot: 1}
		},
		SniffControl: func(call *sniffer.SniffedCall) sniffer.Action {
			info, ok := call.Result.Metadata.(sniffer.TLSClientHelloInfo)
			if !ok || call.Result.Index != 0 || info.SNIHostname != host {
				return sniffer.Action{Slot: sniffer.RejectSlot}
			}
			seen <- info
			call.Dst = listener.Addr().String()
			return sniffer.Action{Slot: 2}
		},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}
	defer func() { _ = middleware.Close() }()

	raw, err := middleware.DialTCP(ctx, "tcp", "", "unmapped.test:443")
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()
	tlsConn := stdtls.Client(
		raw,
		&stdtls.Config{ // #nosec G402 -- Test TLS client.
			RootCAs:    certPool(caCert),
			ServerName: host,
			NextProtos: []string{"test/1"},
			MinVersion: stdtls.VersionTLS12,
		},
	)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("HandshakeContext() error = %v", err)
	}
	if _, err := tlsConn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(tlsConn, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want pong", reply)
	}

	select {
	case info := <-seen:
		if !slices.Contains(info.ALPNProtocols, "test/1") {
			t.Fatalf("ALPN protocols = %v, want test/1", info.ALPNProtocols)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("TLS server error = %v", err)
	}
}

func TestSnifferRoutesHTTPSByClientHelloMetadata(t *testing.T) {
	ctx := context.Background()
	host := "api.example.test"

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	ca, caCert := testCA(t, "https test ca")
	leaf := testLeafCert(t, caCert, ca.PrivateKey, host)
	listener, err := backend.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
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
				Certificates: []stdtls.Certificate{leaf},
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

	seen := make(chan sniffer.TLSClientHelloInfo, 1)
	middleware, err := sniffer.NewSniffer(sniffer.SnifferConfig{
		Outputs:     []gonnect.Network{backend},
		Classifiers: []sniffer.Factory{sniffer.TLSFactory()},
		Control: func(call *sniffer.Call) sniffer.Action {
			if call.Operation == sniffer.OpDial {
				return sniffer.Action{Slot: sniffer.RejectSlot, Intercept: true}
			}
			return sniffer.Action{Slot: sniffer.DefaultSlot}
		},
		SniffControl: func(call *sniffer.SniffedCall) sniffer.Action {
			info, ok := call.Result.Metadata.(sniffer.TLSClientHelloInfo)
			if !ok ||
				info.SNIHostname != host ||
				!slices.Contains(info.ALPNProtocols, "http/1.1") {
				return sniffer.Action{Slot: sniffer.RejectSlot}
			}
			seen <- info
			call.Dst = listener.Addr().String()
			return sniffer.Action{Slot: sniffer.DefaultSlot}
		},
	})
	if err != nil {
		t.Fatalf("NewSniffer() error = %v", err)
	}
	defer func() { _ = middleware.Close() }()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				return middleware.Dial(ctx, network, address)
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
		"https://"+net.JoinHostPort(host, "443")+"/resource",
		nil,
	)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through Sniffer error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	text := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, text)
	}
	if !strings.Contains(text, "host="+net.JoinHostPort(host, "443")) ||
		!strings.Contains(text, "sni="+host) ||
		!strings.Contains(text, "proto=HTTP/1.1") {
		t.Fatalf("body = %q", text)
	}

	select {
	case info := <-seen:
		if info.SNIHostname != host {
			t.Fatalf("SNI = %q, want %q", info.SNIHostname, host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for sniff metadata")
	}
}

func servePlainOnce(
	t *testing.T,
	listener gonnect.TCPListener,
	reply string,
) <-chan string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- "accept: " + err.Error()
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- "read: " + err.Error()
			return
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			done <- "write: " + err.Error()
			return
		}
		done <- string(buf)
	}()
	return done
}

func serveTLSOnce(
	t *testing.T,
	ctx context.Context,
	listener gonnect.TCPListener,
	cert stdtls.Certificate,
) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn := stdtls.Server(
			conn,
			&stdtls.Config{ // #nosec G402 -- Test TLS server.
				Certificates: []stdtls.Certificate{cert},
				NextProtos:   []string{"test/1"},
				MinVersion:   stdtls.VersionTLS12,
			},
		)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "ping" {
			done <- fmt.Errorf("server read %q, want ping", buf)
			return
		}
		_, err = tlsConn.Write([]byte("pong"))
		done <- err
	}()
	return done
}

func testCA(
	t *testing.T,
	commonName string,
) (stdtls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
		t.Fatalf("CreateCertificate(CA) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA) error = %v", err)
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
	hosts ...string,
) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		DNSNames:              hosts,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
		t.Fatalf("CreateCertificate(leaf) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf) error = %v", err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
