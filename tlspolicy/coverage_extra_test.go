// nolint
package tlspolicy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func TestEnumStringFallbacks(t *testing.T) {
	tests := map[string]string{
		"identity invalid": IdentityInvalid.String(),
		"identity dns":     IdentityDNS.String(),
		"identity ip":      IdentityIP.String(),
		"identity unknown": IdentityKind(99).String(),
		"pin invalid":      PinInvalid.String(),
		"pin cert":         PinLeafCertificate.String(),
		"pin spki":         PinLeafSPKI.String(),
		"pin unknown":      PinKind(99).String(),
		"authority cert":   MatchCertificate.String(),
		"authority spki":   MatchSPKI.String(),
		"authority other":  AuthorityMatch(99).String(),
		"trust unknown":    TrustHintUnknown.String(),
		"trust anchor":     TrustHintAnchor.String(),
		"trust distrusted": TrustHintDistrusted.String(),
		"trust restricted": TrustHintRestricted.String(),
		"trust other":      TrustHint(99).String(),
	}
	for name, got := range tests {
		if got == "" {
			t.Fatalf("%s returned empty string", name)
		}
	}
}

func TestFingerprintTextRoundTripAndNilReceiver(t *testing.T) {
	var digest Fingerprint
	for i := range digest {
		digest[i] = byte(i)
	}

	text, err := digest.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if len(text) != hex.EncodedLen(len(digest)) {
		t.Fatalf("MarshalText() length = %d", len(text))
	}

	var parsed Fingerprint
	if err := parsed.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	if parsed != digest {
		t.Fatalf("UnmarshalText() = %s, want %s", parsed, digest)
	}

	var nilFingerprint *Fingerprint
	if err := nilFingerprint.UnmarshalText(text); err == nil {
		t.Fatal("nil Fingerprint UnmarshalText() error = nil")
	}
}

func TestServerIdentityAccessorsAndText(t *testing.T) {
	dnsID, err := ParseServerIdentity("Example.COM.")
	if err != nil {
		t.Fatalf("ParseServerIdentity(DNS) error = %v", err)
	}
	if name, ok := dnsID.DNSName(); !ok || name != "example.com" {
		t.Fatalf("DNSName() = %q, %v", name, ok)
	}
	if _, ok := dnsID.IP(); ok {
		t.Fatal("IP() ok = true for DNS identity")
	}

	text, err := dnsID.MarshalText()
	if err != nil || string(text) != "example.com" {
		t.Fatalf("MarshalText() = %q, %v", text, err)
	}

	var parsed ServerIdentity
	if err := parsed.UnmarshalText([]byte("[2001:db8::1]")); err != nil {
		t.Fatalf("UnmarshalText(IP) error = %v", err)
	}
	if addr, ok := parsed.IP(); !ok ||
		addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("IP() = %v, %v", addr, ok)
	}

	if _, err := (ServerIdentity{}).MarshalText(); err == nil {
		t.Fatal("invalid ServerIdentity MarshalText() error = nil")
	}
	var nilID *ServerIdentity
	if err := nilID.UnmarshalText([]byte("example.com")); err == nil {
		t.Fatal("nil ServerIdentity UnmarshalText() error = nil")
	}
}

func TestExactServerScope(t *testing.T) {
	dnsScope, err := NewExactServerScope("Example.COM")
	if err != nil {
		t.Fatalf("NewExactServerScope(DNS) error = %v", err)
	}
	if len(dnsScope.DNS) != 1 || dnsScope.DNS[0].Domain != "example.com" {
		t.Fatalf("DNS scope = %+v", dnsScope)
	}

	ipScope, err := NewExactServerScope("192.0.2.1")
	if err != nil {
		t.Fatalf("NewExactServerScope(IP) error = %v", err)
	}
	if len(ipScope.IPPrefixes) != 1 ||
		ipScope.IPPrefixes[0].String() != "192.0.2.1/32" {
		t.Fatalf("IP scope = %+v", ipScope)
	}
}

func TestPinTextRoundTripAndErrors(t *testing.T) {
	var digest Fingerprint
	digest[0] = 1
	pin, err := NewPin(PinLeafCertificate, digest)
	if err != nil {
		t.Fatalf("NewPin() error = %v", err)
	}
	if got := pin.String(); got != "certificate:"+digest.String() {
		t.Fatalf("String() = %q", got)
	}

	text, err := pin.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	var parsed Pin
	if err := parsed.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	if parsed != pin {
		t.Fatalf("UnmarshalText() = %v, want %v", parsed, pin)
	}

	if _, err := (Pin{}).MarshalText(); err == nil {
		t.Fatal("invalid Pin MarshalText() error = nil")
	}
	var nilPin *Pin
	if err := nilPin.UnmarshalText(text); err == nil {
		t.Fatal("nil Pin UnmarshalText() error = nil")
	}
	if err := parsed.UnmarshalText([]byte("certificate")); err == nil {
		t.Fatal("pin without separator error = nil")
	}
	if err := parsed.UnmarshalText(
		[]byte("unknown:" + digest.String()),
	); err == nil {
		t.Fatal("pin with unknown kind error = nil")
	}
}

func TestAuthorityBinaryAndFromCertificate(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})

	authority, err := AuthorityFromCertificate(pki.rootCert)
	if err != nil {
		t.Fatalf("AuthorityFromCertificate() error = %v", err)
	}
	if !authority.Equal(pki.rootAuthority) {
		t.Fatal("AuthorityFromCertificate() did not match root authority")
	}

	der, err := authority.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if !bytes.Equal(der, pki.rootCert.Raw) {
		t.Fatal("MarshalBinary() returned unexpected DER")
	}

	var parsed Authority
	if err := parsed.UnmarshalBinary(der); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if !parsed.Equal(authority) {
		t.Fatal("UnmarshalBinary() did not round-trip authority")
	}

	if _, err := AuthorityFromCertificate(nil); err == nil {
		t.Fatal("AuthorityFromCertificate(nil) error = nil")
	}
	if _, err := (Authority{}).MarshalBinary(); err == nil {
		t.Fatal("invalid Authority MarshalBinary() error = nil")
	}
	var nilAuthority *Authority
	if err := nilAuthority.UnmarshalBinary(der); err == nil {
		t.Fatal("nil Authority UnmarshalBinary() error = nil")
	}
}

func TestCompiledPolicyCounts(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})
	pin, err := NewCertificatePin(pki.leafDER)
	if err != nil {
		t.Fatalf("NewCertificatePin() error = %v", err)
	}

	clientPolicy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{pki.rootAuthority},
		Pins:         []Pin{pin},
	})
	if err != nil {
		t.Fatalf("CompileClientPolicy() error = %v", err)
	}
	if clientPolicy.TrustAnchorCount() != 1 || clientPolicy.PinCount() != 1 {
		t.Fatalf(
			"client counts = %d/%d",
			clientPolicy.TrustAnchorCount(),
			clientPolicy.PinCount(),
		)
	}
	var nilClient *ClientPolicy
	if nilClient.TrustAnchorCount() != 0 || nilClient.PinCount() != 0 {
		t.Fatal("nil ClientPolicy counts are not zero")
	}

	scope := AnyServerScope()
	serverPolicy, err := CompileServerPolicy(ServerPolicySpec{
		TrustAnchors: []ScopedAuthority{
			{Authority: pki.rootAuthority, Scope: scope},
		},
		Pins: []ScopedPin{{Pin: pin, Scope: scope}},
	})
	if err != nil {
		t.Fatalf("CompileServerPolicy() error = %v", err)
	}
	if serverPolicy.TrustAnchorCount() != 1 || serverPolicy.PinCount() != 1 {
		t.Fatalf(
			"server counts = %d/%d",
			serverPolicy.TrustAnchorCount(),
			serverPolicy.PinCount(),
		)
	}
	var nilServer *ServerPolicy
	if nilServer.TrustAnchorCount() != 0 || nilServer.PinCount() != 0 {
		t.Fatal("nil ServerPolicy counts are not zero")
	}
}

func TestVerifierFuncNilErrors(t *testing.T) {
	var clientVerifier ClientConnectionVerifierFunc
	if err := clientVerifier.VerifyClient(ClientVerification{}); err == nil {
		t.Fatal("nil ClientConnectionVerifierFunc error = nil")
	}

	errWant := errors.New("client rejected")
	clientVerifier = func(ClientVerification) error { return errWant }
	if err := clientVerifier.VerifyClient(
		ClientVerification{},
	); !errors.Is(
		err,
		errWant,
	) {
		t.Fatalf("VerifyClient() error = %v, want %v", err, errWant)
	}
}
