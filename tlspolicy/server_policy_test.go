package tlspolicy //nolint:testpackage // Uses shared in-package TLS fixtures.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerPolicyScopesConstraintsAndPins(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.agency.gov.test", "outside.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	intermediate, err := ParseAuthorityDER(pki.intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	govScope, err := NewDNSDomainScope("gov.test", true)
	if err != nil {
		t.Fatal(err)
	}
	correctPin, err := NewSPKIPin(pki.leafDER)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{{
			Authority: pki.rootAuthority,
			Scope:     AnyServerScope(),
		}},
		Constraints: []AuthorityConstraint{{
			Authority: intermediate,
			Match:     MatchSPKI,
			Scope:     govScope,
		}},
		Pins: []ScopedPin{{Pin: correctPin, Scope: govScope}},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowedState := verifiedState(
		t,
		pki,
		"service.agency.gov.test",
		x509.ExtKeyUsageServerAuth,
	)
	allowedIdentity, err := ParseServerIdentity("service.agency.gov.test")
	if err != nil {
		t.Fatal(err)
	}
	verification, err := policy.VerifyServer(allowedIdentity, allowedState)
	if err != nil {
		t.Fatalf("allowed server was rejected: %v", err)
	}
	if len(verification.AuthorizedChains) == 0 {
		t.Fatal("allowed verification returned no chains")
	}
	if got, want := len(
		verification.ConnectionState.VerifiedChains,
	), len(
		verification.AuthorizedChains,
	); got != want {
		t.Fatalf(
			"filtered ConnectionState chain count = %d, want %d",
			got,
			want,
		)
	}

	outsideState := verifiedState(
		t,
		pki,
		"outside.example.test",
		x509.ExtKeyUsageServerAuth,
	)
	outsideIdentity, err := ParseServerIdentity("outside.example.test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = policy.VerifyServer(outsideIdentity, outsideState)
	if !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("outside server error = %v, want ErrUnauthorizedChain", err)
	}

	otherPKI := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"other.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	wrongPin, err := NewSPKIPin(otherPKI.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	pinPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
		Pins: []ScopedPin{{Pin: wrongPin, Scope: govScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pinPolicy.VerifyServer(allowedIdentity, allowedState)
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("wrong pin error = %v, want ErrPinMismatch", err)
	}

	rotationPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
		Pins: []ScopedPin{
			{Pin: wrongPin, Scope: govScope},
			{Pin: correctPin, Scope: govScope},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotationPolicy.VerifyServer(
		allowedIdentity,
		allowedState,
	); err != nil {
		t.Fatalf(
			"one of multiple rotation pins matched but verification failed: %v",
			err,
		)
	}
}

func TestServerVerificationFiltersUnauthorizedChains(t *testing.T) {
	t.Parallel()

	allowedPKI := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	otherPKI := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: allowedPKI.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowedState := verifiedState(
		t,
		allowedPKI,
		"service.example.test",
		x509.ExtKeyUsageServerAuth,
	)
	otherState := verifiedState(
		t,
		otherPKI,
		"service.example.test",
		x509.ExtKeyUsageServerAuth,
	)
	allowedState.VerifiedChains = append(
		cloneCertificateChains(otherState.VerifiedChains),
		allowedState.VerifiedChains...,
	)
	identity, err := ParseServerIdentity("service.example.test")
	if err != nil {
		t.Fatal(err)
	}

	verification, err := policy.VerifyServer(identity, allowedState)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(verification.AuthorizedChains); got != 1 {
		t.Fatalf("AuthorizedChains length = %d, want 1", got)
	}
	if got := len(verification.ConnectionState.VerifiedChains); got != 1 {
		t.Fatalf("ConnectionState.VerifiedChains length = %d, want 1", got)
	}
	root := verification.ConnectionState.VerifiedChains[0][len(verification.ConnectionState.VerifiedChains[0])-1]
	if got := Fingerprint(
		sha256.Sum256(root.Raw),
	); got != allowedPKI.rootAuthority.Fingerprint() {
		t.Fatalf(
			"filtered root = %s, want %s",
			got,
			allowedPKI.rootAuthority.Fingerprint(),
		)
	}
}

func TestVerifyServerRepeatsIdentityCheck(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := verifiedState(
		t,
		pki,
		"service.example.test",
		x509.ExtKeyUsageServerAuth,
	)
	wrongIdentity, err := ParseServerIdentity("other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.VerifyServer(
		wrongIdentity,
		state,
	); !errors.Is(
		err,
		ErrServerIdentityMismatch,
	) {
		t.Fatalf("VerifyServer error = %v, want ErrServerIdentityMismatch", err)
	}
}

func TestTLSClientConfigRequiresServerIdentity(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := policy.TLSClientConfig(ClientTLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if config.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}
	if config.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is true")
	}

	state := verifiedState(
		t,
		pki,
		"service.example.test",
		x509.ExtKeyUsageServerAuth,
	)
	state.ServerName = ""
	if err := config.VerifyConnection(
		state,
	); !errors.Is(
		err,
		ErrMissingServerIdentity,
	) {
		t.Fatalf(
			"VerifyConnection error = %v, want ErrMissingServerIdentity",
			err,
		)
	}
}

func TestMissingIntermediateDoesNotFetchAIA(t *testing.T) {
	var requests atomic.Int64
	aiaServer := httptest.NewServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		}),
	)
	defer aiaServer.Close()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		aiaURL:   aiaServer.URL + "/issuer.der",
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := policy.TLSClientConfigForServer(
		"service.example.test",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	address, serverResult := startOneShotTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{pki.tlsCertificate(false)},
		MinVersion:   tls.VersionTLS12,
	})
	connection, err := dialTestTLS(address, clientConfig)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal(
			"handshake unexpectedly succeeded without the intermediate certificate",
		)
	}
	<-serverResult // The server normally receives the client's certificate alert.

	if got := requests.Load(); got != 0 {
		t.Fatalf("AIA endpoint received %d requests; want 0", got)
	}
}

func TestHandshakeDoesNotFetchOCSPOrCRL(t *testing.T) {
	var requests atomic.Int64
	statusServer := httptest.NewServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		}),
	)
	defer statusServer.Close()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ocspURL:  statusServer.URL + "/ocsp",
		crlURL:   statusServer.URL + "/root.crl",
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := policy.TLSClientConfigForServer(
		"service.example.test",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	address, serverResult := startOneShotTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{pki.tlsCertificate(true)},
		MinVersion:   tls.VersionTLS12,
	})
	connection, err := dialTestTLS(address, clientConfig)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	_ = connection.Close()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}

	if got := requests.Load(); got != 0 {
		t.Fatalf("OCSP/CRL endpoint received %d requests; want 0", got)
	}
}

func TestFixedIPTLSClientConfig(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		ipAddrs: []net.IP{net.ParseIP("127.0.0.1")},
		usages:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var verifierCalls atomic.Int64
	clientConfig, err := policy.TLSClientConfigForServer(
		"127.0.0.1",
		ClientTLSOptions{
			Verifiers: []ServerConnectionVerifier{
				ServerConnectionVerifierFunc(
					func(connection ServerVerification) error {
						verifierCalls.Add(1)
						if connection.Identity.Kind() != IdentityIP ||
							connection.Identity.String() != "127.0.0.1" {
							return errors.New(
								"fixed IP identity was not preserved",
							)
						}
						if connection.ConnectionState.ServerName != "" {
							return errors.New(
								"IP literal was unexpectedly sent or exposed as SNI",
							)
						}
						return nil
					},
				),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	address, serverResult := startOneShotTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{pki.tlsCertificate(true)},
		MinVersion:   tls.VersionTLS12,
	})
	connection, err := dialTestTLS(address, clientConfig)
	if err != nil {
		t.Fatalf("fixed-IP handshake failed: %v", err)
	}
	_ = connection.Close()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}
	if got := verifierCalls.Load(); got != 1 {
		t.Fatalf("server verifier calls = %d, want 1", got)
	}
}

func TestServerPolicyVerifierRunsOnResumption(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	policy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		resumed []bool
	)
	clientConfig, err := policy.TLSClientConfigForServer(
		"service.example.test",
		ClientTLSOptions{
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS12,
			SessionCacheSize: 4,
			Verifiers: []ServerConnectionVerifier{
				ServerConnectionVerifierFunc(
					func(connection ServerVerification) error {
						mu.Lock()
						resumed = append(
							resumed,
							connection.ConnectionState.DidResume,
						)
						mu.Unlock()
						return nil
					},
				),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	listener := listenTestTCP(t)
	t.Cleanup(func() { _ = listener.Close() })
	serverConfig := &tls.Config{ // #nosec G402 -- Exercises TLS 1.2 resumption.
		Certificates: []tls.Certificate{pki.tlsCertificate(true)},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	serverResults := make(chan error, 2)
	go func() {
		defer func() { _ = listener.Close() }()
		for range 2 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverResults <- acceptErr
				continue
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			tlsConnection := tls.Server(connection, serverConfig)
			handshakeErr := tlsConnection.HandshakeContext(context.Background())
			_ = tlsConnection.Close()
			serverResults <- handshakeErr
		}
	}()

	for attempt := range 2 {
		connection, dialErr := dialTestTLS(
			listener.Addr().String(),
			clientConfig,
		)
		if dialErr != nil {
			t.Fatalf("TLS attempt %d failed: %v", attempt+1, dialErr)
		}
		_ = connection.Close()
		if serverErr := <-serverResults; serverErr != nil {
			t.Fatalf("server attempt %d failed: %v", attempt+1, serverErr)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if got := len(resumed); got != 2 {
		t.Fatalf("verifier calls = %d, want 2", got)
	}
	if resumed[0] {
		t.Fatal("first connection unexpectedly resumed")
	}
	if !resumed[1] {
		t.Fatal(
			"second connection did not resume; verifier resumption path was not exercised",
		)
	}
}

func startOneShotTLSServer(
	t *testing.T,
	config *tls.Config,
) (string, <-chan error) {
	t.Helper()

	listener := listenTestTCP(t)
	result := make(chan error, 1)
	go func() {
		defer func() { _ = listener.Close() }()
		connection, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer func() { _ = connection.Close() }()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		tlsConnection := tls.Server(connection, config)
		result <- tlsConnection.HandshakeContext(context.Background())
	}()

	t.Cleanup(func() {
		_ = listener.Close()
	})
	return listener.Addr().String(), result
}
