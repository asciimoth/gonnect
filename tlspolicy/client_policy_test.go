package tlspolicy //nolint:testpackage // Uses shared in-package TLS fixtures.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
)

func TestClientPolicyPinsAndExplicitRoots(t *testing.T) {
	t.Parallel()

	clientPKI := newTestPKI(t, testLeafOptions{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	pin, err := NewCertificatePin(clientPKI.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{clientPKI.rootAuthority},
		Pins:         []Pin{pin},
	})
	if err != nil {
		t.Fatal(err)
	}

	state := verifiedState(t, clientPKI, "", x509.ExtKeyUsageClientAuth)
	verification, err := policy.VerifyClient(state)
	if err != nil {
		t.Fatalf("valid client was rejected: %v", err)
	}
	if len(verification.AuthorizedChains) == 0 {
		t.Fatal("valid client returned no authorized chains")
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

	otherPKI := newTestPKI(t, testLeafOptions{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	wrongPin, err := NewCertificatePin(otherPKI.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	wrongPolicy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{clientPKI.rootAuthority},
		Pins:         []Pin{wrongPin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongPolicy.VerifyClient(
		state,
	); !errors.Is(
		err,
		ErrPinMismatch,
	) {
		t.Fatalf("wrong pin error = %v, want ErrPinMismatch", err)
	}
}

func TestClientVerificationFiltersUnauthorizedChains(t *testing.T) {
	t.Parallel()

	allowedPKI := newTestPKI(t, testLeafOptions{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	otherPKI := newTestPKI(t, testLeafOptions{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	policy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{allowedPKI.rootAuthority},
	})
	if err != nil {
		t.Fatal(err)
	}

	allowedState := verifiedState(t, allowedPKI, "", x509.ExtKeyUsageClientAuth)
	otherState := verifiedState(t, otherPKI, "", x509.ExtKeyUsageClientAuth)
	allowedState.VerifiedChains = append(
		cloneCertificateChains(otherState.VerifiedChains),
		allowedState.VerifiedChains...,
	)

	verification, err := policy.VerifyClient(allowedState)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(verification.AuthorizedChains); got != 1 {
		t.Fatalf("AuthorizedChains length = %d, want 1", got)
	}
	if got := len(verification.ConnectionState.VerifiedChains); got != 1 {
		t.Fatalf("ConnectionState.VerifiedChains length = %d, want 1", got)
	}
}

func TestMutualTLSHandshake(t *testing.T) {
	serverPKI := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"server.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientPKI := newTestPKI(t, testLeafOptions{
		usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	clientPin, err := NewSPKIPin(clientPKI.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	clientPolicy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{clientPKI.rootAuthority},
		Pins:         []Pin{clientPin},
	})
	if err != nil {
		t.Fatal(err)
	}

	var clientVerifierCalls atomic.Int64
	serverConfig, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{serverPKI.tlsCertificate(true)},
		ClientAuth:   ClientAuthRequireAndVerify,
		Verifiers: []ClientConnectionVerifier{
			ClientConnectionVerifierFunc(
				func(connection ClientVerification) error {
					clientVerifierCalls.Add(1)
					if len(connection.AuthorizedChains) == 0 {
						return errors.New("missing authorized chain")
					}
					return nil
				},
			),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.ClientCAs == nil {
		t.Fatal("server ClientCAs is nil")
	}

	serverPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{{
			Authority: serverPKI.rootAuthority,
			Scope:     AnyServerScope(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := serverPolicy.TLSClientConfigForServer(
		"server.example.test",
		ClientTLSOptions{
			Certificates: []tls.Certificate{clientPKI.tlsCertificate(true)},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	address, serverResult := startOneShotTLSServer(t, serverConfig)
	connection, err := dialTestTLS(address, clientConfig)
	if err != nil {
		t.Fatalf("mTLS client handshake failed: %v", err)
	}
	_ = connection.Close()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatalf("mTLS server handshake failed: %v", serverErr)
	}
	if got := clientVerifierCalls.Load(); got != 1 {
		t.Fatalf("client verifier calls = %d, want 1", got)
	}
}

func TestServerTLSConfigFailsClosedWithEmptyClientPolicy(t *testing.T) {
	t.Parallel()

	serverPKI := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"server.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	emptyPolicy, err := CompileClientPolicy(ClientPolicySpec{})
	if err != nil {
		t.Fatal(err)
	}
	config, err := emptyPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{serverPKI.tlsCertificate(true)},
		ClientAuth:   ClientAuthRequireAndVerify,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientCAs == nil {
		t.Fatal("empty client policy produced nil ClientCAs")
	}
}

func TestGeneratedRootPoolsAreIndependent(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"server.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	serverPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: AnyServerScope()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfigA, err := serverPolicy.TLSClientConfigForServer(
		"server.example.test",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConfigB, err := serverPolicy.TLSClientConfigForServer(
		"server.example.test",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if clientConfigA.RootCAs == clientConfigB.RootCAs {
		t.Fatal("generated client configurations share a mutable RootCAs pool")
	}

	clientPolicy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{pki.rootAuthority},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverConfigA, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{pki.tlsCertificate(true)},
		ClientAuth:   ClientAuthRequireAndVerify,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverConfigB, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{pki.tlsCertificate(true)},
		ClientAuth:   ClientAuthRequireAndVerify,
	})
	if err != nil {
		t.Fatal(err)
	}
	if serverConfigA.ClientCAs == serverConfigB.ClientCAs {
		t.Fatal(
			"generated server configurations share a mutable ClientCAs pool",
		)
	}
}
