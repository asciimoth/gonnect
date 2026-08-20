package tlspolicy //nolint:testpackage // Covers unexported value helpers.

import (
	"crypto/sha256"
	"crypto/x509"
	"net/netip"
	"strings"
	"testing"
)

func TestCoverageCanonicalDNSNameBranches(t *testing.T) {
	tests := []string{
		".",
		"example..test",
		"-example.test",
		"example-.test",
		strings.Repeat("a", 64) + ".test",
		strings.Repeat("a", 250) + ".test",
		"ex_ample.test",
		"tést.example",
	}

	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			if _, err := canonicalDNSName(value); err == nil {
				t.Fatal("canonicalDNSName() error = nil, want error")
			}
		})
	}
}

func TestCoverageScopeCompileBranches(t *testing.T) {
	duplicateDNS := Scope{
		DNS: []DNSRule{
			{Domain: "Example.TEST", IncludeSubdomains: true},
			{Domain: "example.test.", IncludeSubdomains: true},
		},
	}
	compiled, err := compileScope(duplicateDNS, false)
	if err != nil {
		t.Fatalf("compileScope(duplicate DNS) error = %v", err)
	}
	if len(compiled.dns) != 1 || compiled.dns[0].Domain != "example.test" {
		t.Fatalf("compiled DNS = %#v, want one canonical rule", compiled.dns)
	}

	if _, err := compileScope(Scope{}, false); err == nil {
		t.Fatal("compileScope(empty disallowed) error = nil, want error")
	}

	if _, err := compileScope(Scope{
		IPPrefixes: []netip.Prefix{{}},
	}, true); err == nil {
		t.Fatal("compileScope(invalid prefix) error = nil, want error")
	}

	zoneStrippedPrefix := netip.PrefixFrom(
		netip.MustParseAddr("fe80::1%eth0"),
		128,
	)
	if zoneStrippedPrefix.Addr().Zone() != "" {
		t.Fatal("PrefixFrom preserved zone unexpectedly")
	}
	if _, err := compileScope(Scope{
		IPPrefixes: []netip.Prefix{zoneStrippedPrefix},
	}, true); err != nil {
		t.Fatalf("compileScope(zone-stripped prefix) error = %v", err)
	}
	if _, err := netip.ParsePrefix("fe80::1%eth0/128"); err == nil {
		t.Fatal("netip.ParsePrefix(zone prefix) error = nil, want error")
	}

	duplicatePrefix := Scope{
		IPPrefixes: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/24"),
			netip.MustParsePrefix("192.0.2.128/24"),
		},
	}
	compiled, err = compileScope(duplicatePrefix, false)
	if err != nil {
		t.Fatalf("compileScope(duplicate prefix) error = %v", err)
	}
	if len(compiled.ipPrefixes) != 1 ||
		compiled.ipPrefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf(
			"compiled prefixes = %#v, want 192.0.2.0/24",
			compiled.ipPrefixes,
		)
	}
}

func TestCoverageIdentityAndPinInternalBranches(t *testing.T) {
	if _, err := NewIPPrefixScope(netip.Prefix{}); err == nil {
		t.Fatal("NewIPPrefixScope(invalid) error = nil, want error")
	}

	scope := AnyServerScope()
	if ok := (compiledScope{any: true}).allows(ServerIdentity{}); ok {
		t.Fatal("Any compiled scope allowed invalid identity")
	}
	identity, err := ParseServerIdentity("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := scope.Allows(identity); err != nil || !ok {
		t.Fatalf("AnyServerScope.Allows() = %v, %v, want true, nil", ok, err)
	}

	cert := &x509.Certificate{
		Raw:                     []byte("leaf"),
		RawSubjectPublicKeyInfo: []byte("spki"),
	}
	badCertificatePin := Pin{
		kind:   PinLeafCertificate,
		digest: Fingerprint(sha256.Sum256([]byte("other"))),
	}
	if badCertificatePin.Matches(cert) {
		t.Fatal("certificate pin matched different certificate")
	}
	badSPKIPin := Pin{
		kind:   PinLeafSPKI,
		digest: Fingerprint(sha256.Sum256([]byte("other"))),
	}
	if badSPKIPin.Matches(cert) {
		t.Fatal("SPKI pin matched different public key")
	}
	unknownPin := Pin{kind: PinKind(99)}
	if unknownPin.Matches(cert) {
		t.Fatal("unknown pin kind matched certificate")
	}
}
