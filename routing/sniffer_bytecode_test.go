//nolint:testpackage
package routing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestNewSnifferBytecodeRulesSplitsControlAndSniffControl(t *testing.T) {
	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{
			{Name: "blocked_http", Factory: sniffer.HTTPFactory()},
			{Name: "tls_h2", Factory: sniffer.TLSFactory()},
		},
		`
DIAL
TCP
AND
INTERCEPT

SNIFF blocked_http
DROP

ADDR_S example.test
SLOT 4

SNIFF_NONE
SLOT 3
`,
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}

	wantControl := append(
		[]byte{OP_DIAL, OP_TCP, OP_AND, OP_INTERCEPT},
		param16(OP_ADDR_S, 0)...,
	)
	wantControl = append(wantControl, OP_SLOT, 4)
	if !reflect.DeepEqual(rules.Control, wantControl) {
		t.Fatalf("Control bytecode = %#v, want %#v", rules.Control, wantControl)
	}

	wantSniff := append(param16(OP_SNIFF, 0), OP_DROP)
	wantSniff = append(wantSniff, param16(OP_ADDR_S, 0)...)
	wantSniff = append(wantSniff, OP_SLOT, 4, OP_SNIFF_NONE, OP_SLOT, 3)
	if !reflect.DeepEqual(rules.SniffControl, wantSniff) {
		t.Fatalf(
			"SniffControl bytecode = %#v, want %#v",
			rules.SniffControl,
			wantSniff,
		)
	}
	if got, want := rules.Strings, []string{
		"example.test",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("Strings = %#v, want %#v", got, want)
	}
}

func TestBytecodeSnifferControlsEvaluateControlAndSniff(t *testing.T) {
	controls := newTestSnifferControls(t, `
DIAL
TCP
AND
PORT 443
AND
INTERCEPT

LISTEN
SLOT 2

SNIFF blocked_http
DROP

SNIFF tls_h2
SLOT 3

SNIFF_NONE
SLOT 4

TRUE
SLOT 1
`)

	action := controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "example.test:443",
	})
	if action.Slot != sniffer.RejectSlot || !action.Intercept {
		t.Fatalf(
			"Control(DialTCP :443) = %#v, want intercept reject-slot",
			action,
		)
	}

	action = controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "example.test:80",
	})
	if action != (sniffer.Action{Slot: 1}) {
		t.Fatalf("Control(DialTCP :80) = %#v, want slot 1", action)
	}

	action = controls.Control(&sniffer.Call{
		Operation: sniffer.OpListenTCP,
		Network:   "tcp",
		Src:       "127.0.0.1:0",
	})
	if action != (sniffer.Action{Slot: 2}) {
		t.Fatalf("Control(ListenTCP) = %#v, want slot 2", action)
	}

	sniffAction := controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: 0},
	})
	if sniffAction != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("SniffControl(blocked_http) = %#v, want reject", sniffAction)
	}

	sniffAction = controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: 1},
	})
	if sniffAction != (sniffer.Action{Slot: 3}) {
		t.Fatalf("SniffControl(tls_h2) = %#v, want slot 3", sniffAction)
	}

	sniffAction = controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: sniffer.NoMatch},
	})
	if sniffAction != (sniffer.Action{Slot: 4}) {
		t.Fatalf("SniffControl(NoMatch) = %#v, want slot 4", sniffAction)
	}

	sniffAction = controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: 1, Err: errors.New("read failed")},
	})
	if sniffAction != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("SniffControl(error) = %#v, want forced reject", sniffAction)
	}
}

func TestBytecodeSnifferRejectsNilCallsAndEmptyPrograms(t *testing.T) {
	controls, err := NewBytecodeSnifferControls(SnifferBytecodeRules{})
	if err != nil {
		t.Fatalf("NewBytecodeSnifferControls() error = %v", err)
	}

	if got := controls.Control(
		nil,
	); got != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("Control(nil) = %#v, want reject", got)
	}
	if got := controls.SniffControl(
		nil,
	); got != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("SniffControl(nil) = %#v, want reject", got)
	}
	if got := controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "example.test:443",
	}); got != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("Control(empty) = %#v, want reject", got)
	}
	if got := controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: sniffer.NoMatch},
	}); got != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("SniffControl(empty) = %#v, want reject", got)
	}
}

func TestBytecodeSnifferSharedSegmentsRunBeforeAndAfterSniff(t *testing.T) {
	controls := newTestSnifferControls(t, `
ADDR_S blocked.test
DROP

DIAL
TCP
AND
INTERCEPT

SNIFF_NONE
SLOT 2
`)

	action := controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "blocked.test:443",
	})
	if action != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("Control(blocked) = %#v, want reject before intercept", action)
	}

	action = controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "allowed.test:443",
	})
	if action.Slot != sniffer.RejectSlot || !action.Intercept {
		t.Fatalf("Control(allowed) = %#v, want intercept", action)
	}

	action = controls.SniffControl(&sniffer.SniffedCall{
		Call: sniffer.Call{
			Operation: sniffer.OpDialTCP,
			Network:   "tcp",
			Dst:       "blocked.test:443",
		},
		Result: sniffer.SniffResult{Index: sniffer.NoMatch},
	})
	if action != (sniffer.Action{Slot: sniffer.RejectSlot}) {
		t.Fatalf("SniffControl(blocked) = %#v, want reject", action)
	}

	action = controls.SniffControl(&sniffer.SniffedCall{
		Call: sniffer.Call{
			Operation: sniffer.OpDialTCP,
			Network:   "tcp",
			Dst:       "allowed.test:443",
		},
		Result: sniffer.SniffResult{Index: sniffer.NoMatch},
	})
	if action != (sniffer.Action{Slot: 2}) {
		t.Fatalf("SniffControl(allowed no-match) = %#v, want slot 2", action)
	}
}

func TestBytecodeSnifferSupportsArbitraryClassifierFactory(t *testing.T) {
	factory := sniffer.FactoryWithMinSniffBufferSize(
		4,
		sniffer.FactoryFunc(func() sniffer.Classifier {
			return sniffer.Prefix([]byte("PING"))
		}),
	)
	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{{Name: "ping", Factory: factory}},
		"SNIFF ping\nSLOT 5\n",
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	controls, err := NewBytecodeSnifferControls(rules)
	if err != nil {
		t.Fatalf("NewBytecodeSnifferControls() error = %v", err)
	}
	if got := controls.Classifiers()[0].MinSniffBufferSize(); got != 4 {
		t.Fatalf("classifier min sniff size = %d, want 4", got)
	}
	action := controls.SniffControl(&sniffer.SniffedCall{
		Result: sniffer.SniffResult{Index: 0},
	})
	if action != (sniffer.Action{Slot: 5}) {
		t.Fatalf("SniffControl(custom classifier) = %#v, want slot 5", action)
	}
}

func TestBytecodeSnifferNormalizesNamesAndCopiesClassifiers(t *testing.T) {
	first := &testSniffFactory{prefix: "A"}
	second := &testSniffFactory{prefix: "B"}
	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{{Name: " ping ", Factory: first}},
		"SNIFF ping\nSLOT 5\n",
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	if got := rules.Classifiers[0].Name; got != "ping" {
		t.Fatalf("normalized classifier name = %q, want ping", got)
	}

	controls, err := NewBytecodeSnifferControls(rules)
	if err != nil {
		t.Fatalf("NewBytecodeSnifferControls() error = %v", err)
	}
	classifiers := controls.Classifiers()
	if got := classifiers[0]; got != first {
		t.Fatalf("Classifiers()[0] = %p, want %p", got, first)
	}
	classifiers[0] = second
	if got := controls.Classifiers()[0]; got != first {
		t.Fatalf(
			"Classifiers() after caller mutation = %p, want %p",
			got,
			first,
		)
	}
}

func TestBytecodeSnifferValidation(t *testing.T) {
	validClassifiers := []NamedSniffClassifier{
		{Name: "http", Factory: sniffer.HTTPFactory()},
	}
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{
			name: "unknown classifier",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					validClassifiers,
					"SNIFF missing\nDROP\n",
				)
				return err
			},
			want: `unknown sniff classifier "missing"`,
		},
		{
			name: "duplicate classifier",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					[]NamedSniffClassifier{
						{Name: "http", Factory: sniffer.HTTPFactory()},
						{Name: "http", Factory: sniffer.TLSFactory()},
					},
					"",
				)
				return err
			},
			want: `duplicate sniff classifier "http"`,
		},
		{
			name: "nil factory",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					[]NamedSniffClassifier{{Name: "http"}},
					"",
				)
				return err
			},
			want: `sniff classifier "http" has nil factory`,
		},
		{
			name: "classifier name whitespace",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					[]NamedSniffClassifier{
						{Name: "bad name", Factory: sniffer.HTTPFactory()},
					},
					"",
				)
				return err
			},
			want: `contains whitespace`,
		},
		{
			name: "empty classifier name",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					[]NamedSniffClassifier{
						{Name: " ", Factory: sniffer.HTTPFactory()},
					},
					"",
				)
				return err
			},
			want: "empty sniff classifier name",
		},
		{
			name: "sniff intercept segment",
			run: func() error {
				_, err := NewSnifferBytecodeRules(
					validClassifiers,
					"SNIFF http\nINTERCEPT\n",
				)
				return err
			},
			want: "cannot combine SNIFF and INTERCEPT",
		},
		{
			name: "sniff in control bytecode",
			run: func() error {
				_, err := NewBytecodeSnifferControls(SnifferBytecodeRules{
					Classifiers: validClassifiers,
					Control:     append(param16(OP_SNIFF, 0), OP_DROP),
				})
				return err
			},
			want: "not valid for Sniffer control",
		},
		{
			name: "sniff none in control bytecode",
			run: func() error {
				_, err := NewBytecodeSnifferControls(SnifferBytecodeRules{
					Classifiers: validClassifiers,
					Control:     []byte{OP_SNIFF_NONE, OP_DROP},
				})
				return err
			},
			want: "not valid for Sniffer control",
		},
		{
			name: "intercept in sniff bytecode",
			run: func() error {
				_, err := NewBytecodeSnifferControls(SnifferBytecodeRules{
					Classifiers:  validClassifiers,
					SniffControl: []byte{OP_TRUE, OP_INTERCEPT},
				})
				return err
			},
			want: "not valid for Sniffer sniff control",
		},
		{
			name: "rule invalid",
			run: func() error {
				_, err := NewBytecodeSnifferControls(SnifferBytecodeRules{
					Control: param16(OP_RULE, 0),
				})
				return err
			},
			want: "not valid for Sniffer",
		},
		{
			name: "sniff classifier index",
			run: func() error {
				_, err := NewBytecodeSnifferControls(SnifferBytecodeRules{
					SniffControl: append(param16(OP_SNIFF, 0), OP_DROP),
				})
				return err
			},
			want: "sniff classifier index 0 out of range 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("operation succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestBytecodeSnifferMentionedSlotsAndCopies(t *testing.T) {
	factory := sniffer.HTTPFactory()
	rules := SnifferBytecodeRules{
		Classifiers: []NamedSniffClassifier{{Name: "http", Factory: factory}},
		Strings:     []string{"example.test"},
		Control:     append(param16(OP_ADDR_S, 0), OP_SLOT, 7),
		SniffControl: append(
			param16(OP_SNIFF, 0),
			OP_SLOT,
			9,
			OP_TRUE,
			OP_SLOT,
			0,
		),
	}
	controls, err := NewBytecodeSnifferControls(rules)
	if err != nil {
		t.Fatalf("NewBytecodeSnifferControls() error = %v", err)
	}
	rules.Strings[0] = "changed.test"
	rules.Control = []byte{OP_TRUE, OP_SLOT, 1}

	action := controls.Control(&sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp",
		Dst:       "example.test:443",
	})
	if action != (sniffer.Action{Slot: 7}) {
		t.Fatalf("Control after source mutation = %#v, want slot 7", action)
	}
	got := controls.MentionedSlots()
	want := []int{7, 9}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MentionedSlots() = %v, want %v", got, want)
	}
	got[0] = 99
	if got := controls.MentionedSlots(); !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"MentionedSlots() after caller mutation = %v, want %v",
			got,
			want,
		)
	}
}

func TestBytecodeSnifferUnsupportedInterceptRejectsOperation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := gonnect.NewLoopbackNetwork()
	t.Cleanup(func() { _ = backend.Close() })
	rules, err := NewSnifferBytecodeRules(nil, `
DIAL
INTERCEPT

TRUE
SLOT 1
`)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	middleware, err := NewBytecodeSniffer(
		sniffer.SnifferConfig{Outputs: []gonnect.Network{backend}},
		rules,
	)
	if err != nil {
		t.Fatalf("NewBytecodeSniffer() error = %v", err)
	}
	t.Cleanup(func() { _ = middleware.Close() })

	if _, err := middleware.DialUDP(
		ctx,
		"udp",
		"",
		"127.0.0.1:53",
	); err == nil {
		t.Fatal("DialUDP() succeeded, want unsupported intercept rejection")
	}
}

func TestBytecodeSnifferE2EHTTPURLClassifier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	listener, err := backend.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok:" + r.URL.Path))
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP server error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("timeout waiting for HTTP server")
		}
	})

	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{
			{
				Name: "blocked_http",
				Factory: sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
					URL: "/blocked",
				}),
			},
			{Name: "http", Factory: sniffer.HTTPFactory()},
		},
		`
DIAL
TCP
AND
INTERCEPT

SNIFF blocked_http
DROP

SNIFF http
SLOT 1

TRUE
DROP
`,
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	middleware, err := NewBytecodeSniffer(
		sniffer.SnifferConfig{Outputs: []gonnect.Network{backend}},
		rules,
	)
	if err != nil {
		t.Fatalf("NewBytecodeSniffer() error = %v", err)
	}
	t.Cleanup(func() { _ = middleware.Close() })

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return middleware.Dial(ctx, network, address)
			},
		},
	}

	resp, err := httpClientGet(
		ctx,
		client,
		"http://"+listener.Addr().String()+"/allowed",
	)
	if err != nil {
		t.Fatalf("GET /allowed error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("ReadAll(/allowed) error = %v", err)
	}
	if string(body) != "ok:/allowed" {
		t.Fatalf("GET /allowed body = %q, want ok:/allowed", body)
	}

	resp, err = httpClientGet(
		ctx,
		client,
		"http://"+listener.Addr().String()+"/blocked",
	)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("GET /blocked succeeded, want rejection")
	}
}

func httpClientGet(
	ctx context.Context,
	client *http.Client,
	url string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func TestBytecodeSnifferE2ETLSALPNClassifier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const host = "tls.example.test"

	backend := gonnect.NewLoopbackNetwork()
	backend.AllowAnyHost = true
	t.Cleanup(func() { _ = backend.Close() })

	cert, pool := testSnifferTLSCertificate(t, host)
	listener, err := backend.ListenTCP(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	done := serveSnifferTLSOnce(t, ctx, listener, cert)
	t.Cleanup(func() { _ = listener.Close() })

	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{
			{
				Name: "tls_h2",
				Factory: sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
					ALPN: "h2",
				}),
			},
		},
		`
DIAL
TCP
AND
INTERCEPT

SNIFF tls_h2
SLOT 1

TRUE
DROP
`,
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	middleware, err := NewBytecodeSniffer(
		sniffer.SnifferConfig{Outputs: []gonnect.Network{backend}},
		rules,
	)
	if err != nil {
		t.Fatalf("NewBytecodeSniffer() error = %v", err)
	}
	t.Cleanup(func() { _ = middleware.Close() })

	raw, err := middleware.DialTCP(ctx, "tcp", "", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	defer func() { _ = raw.Close() }()
	client := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("HandshakeContext() error = %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, len("pong"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("TLS reply = %q, want pong", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("TLS server error = %v", err)
	}
}

func newTestSnifferControls(t *testing.T, src string) SnifferControls {
	t.Helper()
	rules, err := NewSnifferBytecodeRules(
		[]NamedSniffClassifier{
			{Name: "blocked_http", Factory: sniffer.HTTPFactory()},
			{Name: "tls_h2", Factory: sniffer.TLSFactory()},
		},
		src,
	)
	if err != nil {
		t.Fatalf("NewSnifferBytecodeRules() error = %v", err)
	}
	controls, err := NewBytecodeSnifferControls(rules)
	if err != nil {
		t.Fatalf("NewBytecodeSnifferControls() error = %v", err)
	}
	return controls
}

type testSniffFactory struct {
	prefix string
}

func (f *testSniffFactory) MinSniffBufferSize() int {
	return len(f.prefix)
}

func (f *testSniffFactory) NewClassifier() sniffer.Classifier {
	return sniffer.Prefix([]byte(f.prefix))
}

func serveSnifferTLSOnce(
	t *testing.T,
	ctx context.Context,
	listener gonnect.TCPListener,
	cert tls.Certificate,
) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()

		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
			MinVersion:   tls.VersionTLS12,
		})
		defer func() { _ = server.Close() }()
		if err := server.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(server, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != "ping" {
			done <- errors.New("unexpected TLS payload: " + string(buf))
			return
		}
		_, err = server.Write([]byte("pong"))
		done <- err
	}()
	return done
}

func testSnifferTLSCertificate(
	t *testing.T,
	host string,
) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{host},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM() failed")
	}
	return cert, pool
}
