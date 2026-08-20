package tlspolicy //nolint:testpackage // Covers unexported value helpers.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFingerprintParsingErrorsAndColonInput(t *testing.T) {
	var digest Fingerprint
	for i := range digest {
		digest[i] = byte(i)
	}
	text := digest.String()
	colonText := ""
	for i := 0; i < len(text); i += 2 {
		if i != 0 {
			colonText += ":"
		}
		colonText += text[i : i+2]
	}

	parsed, err := ParseFingerprint(" " + colonText + " ")
	if err != nil {
		t.Fatalf("ParseFingerprint(colon text) error = %v", err)
	}
	if parsed != digest {
		t.Fatalf("ParseFingerprint(colon text) = %s, want %s", parsed, digest)
	}

	if _, err := ParseFingerprint("abc"); err == nil {
		t.Fatal("ParseFingerprint(short) error = nil, want error")
	}
	if _, err := ParseFingerprint(text[:63] + "x"); err == nil {
		t.Fatal("ParseFingerprint(non-hex) error = nil, want error")
	}

	var nilFingerprint *Fingerprint
	if err := nilFingerprint.UnmarshalText([]byte(text)); err == nil {
		t.Fatal(
			"Fingerprint.UnmarshalText on nil receiver error = nil, want error",
		)
	}
}

func TestPinErrorsAndMatches(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	if _, err := NewPin(PinInvalid, Fingerprint{}); err == nil {
		t.Fatal("NewPin(PinInvalid) error = nil, want error")
	}
	if _, err := NewPin(PinKind(99), Fingerprint{}); err == nil {
		t.Fatal("NewPin(unknown) error = nil, want error")
	}
	if _, err := NewCertificatePin([]byte("not der")); err == nil {
		t.Fatal("NewCertificatePin(invalid DER) error = nil, want error")
	}
	if _, err := NewSPKIPin([]byte("not der")); err == nil {
		t.Fatal("NewSPKIPin(invalid DER) error = nil, want error")
	}

	certPin, err := NewCertificatePin(pki.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !certPin.Matches(pki.leafCert) {
		t.Fatal("certificate pin did not match leaf")
	}
	if certPin.Matches(nil) {
		t.Fatal("certificate pin matched nil certificate")
	}
	if _, err := (Pin{}).MarshalText(); err == nil {
		t.Fatal("invalid Pin MarshalText error = nil, want error")
	}

	var nilPin *Pin
	if err := nilPin.UnmarshalText([]byte(certPin.String())); err == nil {
		t.Fatal("Pin.UnmarshalText on nil receiver error = nil, want error")
	}
	var pin Pin
	if err := pin.UnmarshalText([]byte("missing-separator")); err == nil {
		t.Fatal("Pin.UnmarshalText without separator error = nil, want error")
	}
	if err := pin.UnmarshalText(
		[]byte("unknown:" + certPin.Digest().String()),
	); err == nil {
		t.Fatal("Pin.UnmarshalText with unknown kind error = nil, want error")
	}
}

func TestAuthorityErrorBranchesAndNilCatalog(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	if _, err := ParseAuthorityDER(nil); err == nil {
		t.Fatal("ParseAuthorityDER(nil) error = nil, want error")
	}
	if _, err := AuthorityFromCertificate(nil); err == nil {
		t.Fatal("AuthorityFromCertificate(nil) error = nil, want error")
	}
	if _, err := (Authority{}).Certificate(); err == nil {
		t.Fatal("zero Authority Certificate() error = nil, want error")
	}
	var nilAuthority *Authority
	if err := nilAuthority.UnmarshalBinary(
		pki.rootAuthority.DER(),
	); err == nil {
		t.Fatal(
			"Authority.UnmarshalBinary on nil receiver error = nil, want error",
		)
	}

	_, err := ParseAuthoritiesPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("ignored"),
	}))
	if err == nil {
		t.Fatal(
			"ParseAuthoritiesPEM(without certificate) error = nil, want error",
		)
	}
	_, err = ParseAuthoritiesPEM(pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
		Bytes:   pki.rootAuthority.DER(),
	}))
	if err == nil {
		t.Fatal("ParseAuthoritiesPEM(with headers) error = nil, want error")
	}

	var catalog *AuthorityCatalog
	if got := catalog.Len(); got != 0 {
		t.Fatalf("nil catalog Len() = %d, want 0", got)
	}
	if records := catalog.Records(); records != nil {
		t.Fatalf("nil catalog Records() = %v, want nil", records)
	}
	if _, ok := catalog.Lookup(pki.rootAuthority.Fingerprint()); ok {
		t.Fatal("nil catalog Lookup() ok = true, want false")
	}
	if _, err := catalog.Select(nil); err == nil {
		t.Fatal("nil catalog Select() error = nil, want error")
	}

	catalog, err = NewAuthorityCatalog([]AuthorityCandidate{{
		DER: pki.rootAuthority.DER(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Select(
		[]Fingerprint{
			pki.rootAuthority.Fingerprint(),
			pki.rootAuthority.Fingerprint(),
		},
	); err == nil {
		t.Fatal("catalog Select(duplicate) error = nil, want error")
	}
	if _, err := catalog.Select([]Fingerprint{{1}}); err == nil {
		t.Fatal("catalog Select(unknown) error = nil, want error")
	}
}

func TestIdentityAndScopeErrorBranches(t *testing.T) {
	if ClientAuthNone.String() != "none" {
		t.Fatal("unexpected ClientAuthNone string")
	}
	if ClientAuthVerifyIfGiven.String() != "verify-if-given" {
		t.Fatal("unexpected ClientAuthVerifyIfGiven string")
	}
	if ClientAuthRequireAndVerify.String() != "require-and-verify" {
		t.Fatal("unexpected ClientAuthRequireAndVerify string")
	}
	if IdentityKind(99).String() != "IdentityKind(99)" {
		t.Fatal("unexpected unknown IdentityKind string")
	}
	if ClientAuthMode(99).String() != "ClientAuthMode(99)" {
		t.Fatal("unexpected unknown ClientAuthMode string")
	}
	if (ServerIdentity{kind: IdentityKind(99)}).String() != "" {
		t.Fatal("unknown ServerIdentity kind rendered non-empty string")
	}
	if _, err := ParseServerIdentity(""); err == nil {
		t.Fatal("ParseServerIdentity(empty) error = nil, want error")
	}
	if _, err := ParseServerIdentity(" example.test"); err == nil {
		t.Fatal("ParseServerIdentity(space) error = nil, want error")
	}
	if _, err := ParseServerIdentity("[fe80::1%lo0]"); err == nil {
		t.Fatal("ParseServerIdentity(zone) error = nil, want error")
	}
	var nilIdentity *ServerIdentity
	if err := nilIdentity.UnmarshalText([]byte("example.test")); err == nil {
		t.Fatal(
			"ServerIdentity.UnmarshalText on nil receiver error = nil, want error",
		)
	}
	if _, err := (Scope{}).Allows(ServerIdentity{}); err == nil {
		t.Fatal("Scope.Allows(invalid identity) error = nil, want error")
	}
	if _, err := NewIPPrefixScope(
		netip.PrefixFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 128),
	); err == nil {
		t.Fatal("NewIPPrefixScope(IPv4-mapped) error = nil, want error")
	}
	if _, err := NewExactServerScope(""); err == nil {
		t.Fatal("NewExactServerScope(empty) error = nil, want error")
	}
}

func TestTLSConfigHelperBranches(t *testing.T) {
	if err := validateTLSVersionRange(
		tls.VersionTLS13,
		tls.VersionTLS12,
	); err == nil {
		t.Fatal("validateTLSVersionRange(inverted) error = nil, want error")
	}

	cert := tls.Certificate{
		Certificate: [][]byte{[]byte("invalid leaf der")},
		Leaf:        &x509.Certificate{Raw: []byte("invalid leaf der")},
	}
	cloned := cloneTLSCertificates([]tls.Certificate{cert})
	if cloned[0].Leaf != nil {
		t.Fatal("cloneTLSCertificates kept invalid parsed leaf")
	}

	var fn func()
	if !interfaceIsNil(fn) {
		t.Fatal("interfaceIsNil(typed nil func) = false, want true")
	}
	if interfaceIsNil(1) {
		t.Fatal("interfaceIsNil(int) = true, want false")
	}
}

func TestTLSConfigOptionValidationBranches(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})
	serverPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{{
			Authority: pki.rootAuthority,
			Scope:     Scope{Any: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientPolicy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{pki.rootAuthority},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{pki.leafDER}}

	if _, err := (*ServerPolicy)(
		nil,
	).TLSClientConfig(ClientTLSOptions{}); err == nil {
		t.Fatal("nil ServerPolicy TLSClientConfig error = nil, want error")
	}
	if _, err := serverPolicy.TLSClientConfig(ClientTLSOptions{
		SessionCacheSize: -1,
	}); err == nil {
		t.Fatal("negative SessionCacheSize error = nil, want error")
	}
	var nilServerVerifier *stubServerVerifier
	if _, err := serverPolicy.TLSClientConfig(ClientTLSOptions{
		Verifiers: []ServerConnectionVerifier{nilServerVerifier},
	}); err == nil {
		t.Fatal("typed nil server verifier error = nil, want error")
	}
	if _, err := serverPolicy.TLSClientConfigForServer(
		"",
		ClientTLSOptions{},
	); err == nil {
		t.Fatal("empty fixed server identity error = nil, want error")
	}

	serverConfig, err := serverPolicy.TLSClientConfig(ClientTLSOptions{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2"},
		SessionCacheSize: 1,
	})
	if err != nil {
		t.Fatalf("TLSClientConfig() error = %v", err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 ||
		serverConfig.ClientSessionCache == nil ||
		len(serverConfig.NextProtos) != 1 ||
		len(serverConfig.CipherSuites) != 1 ||
		len(serverConfig.CurvePreferences) != 1 {
		t.Fatalf("TLSClientConfig() did not copy options: %+v", serverConfig)
	}

	if err := serverConfig.VerifyConnection(
		tls.ConnectionState{},
	); !errors.Is(
		err,
		ErrMissingServerIdentity,
	) {
		t.Fatalf(
			"VerifyConnection without name error = %v, want missing identity",
			err,
		)
	}

	fixedIP, err := serverPolicy.TLSClientConfigForServer(
		"192.0.2.10",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixedIP.VerifyConnection(
		tls.ConnectionState{},
	); !errors.Is(
		err,
		ErrNoVerifiedChains,
	) {
		t.Fatalf("fixed IP VerifyConnection error = %v, want no chains", err)
	}

	fixedDNS, err := serverPolicy.TLSClientConfigForServer(
		"example.test",
		ClientTLSOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixedDNS.VerifyConnection(
		tls.ConnectionState{},
	); !errors.Is(
		err,
		ErrMissingServerIdentity,
	) {
		t.Fatalf("fixed DNS empty SNI error = %v, want missing identity", err)
	}
	if err := fixedDNS.VerifyConnection(tls.ConnectionState{
		ServerName: "other.example.test",
	}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("fixed DNS mismatch error = %v, want differs", err)
	}
	if err := fixedDNS.VerifyConnection(tls.ConnectionState{
		ServerName: "bad name",
	}); err == nil || !strings.Contains(err.Error(), "parse TLS ServerName") {
		t.Fatalf(
			"invalid observed ServerName error = %v, want parse error",
			err,
		)
	}

	if _, err := (*ClientPolicy)(nil).ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{cert},
	}); err == nil {
		t.Fatal("nil ClientPolicy ServerTLSConfig error = nil, want error")
	}
	if _, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{}); err == nil {
		t.Fatal("ServerTLSConfig without cert error = nil, want error")
	}
	if _, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   ClientAuthMode(99),
	}); err == nil {
		t.Fatal("unsupported ClientAuthMode error = nil, want error")
	}
	if _, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   ClientAuthNone,
		Verifiers: []ClientConnectionVerifier{
			ClientConnectionVerifierFunc(func(ClientVerification) error {
				return nil
			}),
		},
	}); err == nil {
		t.Fatal("verifier without mTLS auth error = nil, want error")
	}
	var nilClientVerifier *stubClientVerifier
	if _, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   ClientAuthVerifyIfGiven,
		Verifiers:    []ClientConnectionVerifier{nilClientVerifier},
	}); err == nil {
		t.Fatal("typed nil client verifier error = nil, want error")
	}

	clientConfig, err := clientPolicy.ServerTLSConfig(ServerTLSOptions{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   ClientAuthVerifyIfGiven,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences:       []tls.CurveID{tls.X25519},
		NextProtos:             []string{"h2"},
		SessionTicketsDisabled: true,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Time:                   func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	if clientConfig.ClientAuth != tls.VerifyClientCertIfGiven ||
		clientConfig.VerifyConnection == nil ||
		clientConfig.SessionTicketsDisabled != true ||
		clientConfig.GetCertificate == nil ||
		clientConfig.Time == nil {
		t.Fatalf(
			"ServerTLSConfig() did not set expected options: %+v",
			clientConfig,
		)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{}); err != nil {
		t.Fatalf(
			"VerifyConnection without optional client cert error = %v",
			err,
		)
	}
}

func TestPolicyCompileErrorBranches(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})
	pin, err := NewCertificatePin(pki.leafDER)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{{}},
	}); err == nil {
		t.Fatal("invalid client trust anchor error = nil, want error")
	}
	if _, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{pki.rootAuthority, pki.rootAuthority},
	}); err == nil {
		t.Fatal("duplicate client trust anchor error = nil, want error")
	}
	if _, err := CompileClientPolicy(ClientPolicySpec{
		Pins: []Pin{{}},
	}); err == nil {
		t.Fatal("invalid client pin error = nil, want error")
	}
	if _, err := CompileClientPolicy(ClientPolicySpec{
		Pins: []Pin{pin, pin},
	}); err == nil {
		t.Fatal("duplicate client pin error = nil, want error")
	}

	scoped := ScopedAuthority{
		Authority: pki.rootAuthority,
		Scope:     Scope{Any: true},
	}
	if _, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{{}},
	}); err == nil {
		t.Fatal("invalid server trust anchor error = nil, want error")
	}
	if _, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{scoped, scoped},
	}); err == nil {
		t.Fatal("duplicate server trust anchor error = nil, want error")
	}
	if _, err := CompileServerPolicy(ServerPolicySpec{
		Constraints: []AuthorityConstraint{{Authority: pki.rootAuthority}},
	}); err == nil {
		t.Fatal("zero-scope server constraint error = nil, want error")
	}
	if _, err := CompileServerPolicy(ServerPolicySpec{
		Constraints: []AuthorityConstraint{{
			Authority: pki.rootAuthority,
			Match:     AuthorityMatch(99),
			Scope:     Scope{Any: true},
		}},
	}); err == nil {
		t.Fatal("unknown server constraint match error = nil, want error")
	}
	if _, err := CompileServerPolicy(ServerPolicySpec{
		Pins: []ScopedPin{{}},
	}); err == nil {
		t.Fatal("invalid scoped server pin error = nil, want error")
	}
}

func TestPinMatchesUnknownKindReturnsFalse(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	pin := Pin{
		kind:   PinKind(99),
		digest: Fingerprint(sha256.Sum256(pki.leafDER)),
	}
	if pin.Matches(pki.leafCert) {
		t.Fatal("unknown pin kind matched certificate")
	}
	if !errors.Is(ErrPinMismatch, ErrPinMismatch) {
		t.Fatal("sentinel errors package check failed")
	}
}

type stubServerVerifier struct{}

func (*stubServerVerifier) VerifyServer(ServerVerification) error {
	return nil
}

type stubClientVerifier struct{}

func (*stubClientVerifier) VerifyClient(ClientVerification) error {
	return nil
}
