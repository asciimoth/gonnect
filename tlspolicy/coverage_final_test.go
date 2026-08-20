package tlspolicy //nolint:testpackage // Covers unexported branch helpers.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"testing"
)

func TestCoverageAuthorityCatalogFetchAndCopies(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})
	source := AuthoritySource{
		Name:  "store",
		Trust: TrustHintAnchor,
		Metadata: map[string]string{
			"path": "root",
		},
	}

	catalog, err := FetchAuthorityCatalog(
		context.Background(),
		AuthorityFetcherFunc(
			func(context.Context) ([]AuthorityCandidate, error) {
				return []AuthorityCandidate{
					{DER: pki.rootAuthority.DER(), Source: source},
					{DER: pki.rootAuthority.DER(), Source: source},
					{
						DER: pki.rootAuthority.DER(),
						Source: AuthoritySource{
							Name:  "store",
							Trust: TrustHintAnchor,
							Metadata: map[string]string{
								"path": "other",
							},
						},
					},
				}, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("FetchAuthorityCatalog() error = %v", err)
	}
	if catalog.Len() != 1 {
		t.Fatalf("catalog Len() = %d, want 1", catalog.Len())
	}

	records := catalog.Records()
	if len(records) != 1 || len(records[0].Sources) != 2 {
		t.Fatalf("catalog records = %#v", records)
	}
	records[0].Sources[0].Metadata["path"] = "changed"
	record, ok := catalog.Lookup(pki.rootAuthority.Fingerprint())
	if !ok {
		t.Fatal("Lookup() ok = false")
	}
	if record.Sources[0].Metadata["path"] == "changed" {
		t.Fatal("Lookup() returned aliased source metadata")
	}

	selected, err := catalog.Select(
		[]Fingerprint{pki.rootAuthority.Fingerprint()},
	)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if len(selected) != 1 || !selected[0].Equal(pki.rootAuthority) {
		t.Fatalf("Select() = %#v", selected)
	}
}

func TestCoverageAuthorityCatalogErrorBranches(t *testing.T) {
	if _, err := FetchAuthorityCatalog(context.Background(), nil); err == nil {
		t.Fatal("FetchAuthorityCatalog(nil fetcher) error = nil")
	}

	wantErr := errors.New("fetch failed")
	_, err := FetchAuthorityCatalog(
		context.Background(),
		AuthorityFetcherFunc(
			func(context.Context) ([]AuthorityCandidate, error) {
				return nil, wantErr
			},
		),
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("FetchAuthorityCatalog() error = %v, want %v", err, wantErr)
	}
	if _, err := FetchAuthorityCatalog(
		context.Background(),
		AuthorityFetcherFunc(
			func(context.Context) ([]AuthorityCandidate, error) {
				return []AuthorityCandidate{{DER: []byte("bad")}}, nil
			},
		),
	); err == nil {
		t.Fatal("FetchAuthorityCatalog(bad DER) error = nil")
	}
	if _, err := (AuthorityFetcherFunc)(nil).FetchAuthorities(
		context.Background(),
	); err == nil {
		t.Fatal("nil AuthorityFetcherFunc error = nil")
	}
}

func TestCoverageAuthorityPEMAndMutableAuthorityErrors(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{})
	pemData := append(
		pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("skip")}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pki.rootAuthority.DER(),
		})...,
	)
	authorities, err := ParseAuthoritiesPEM(pemData)
	if err != nil {
		t.Fatalf("ParseAuthoritiesPEM() error = %v", err)
	}
	if len(authorities) != 1 || !authorities[0].Equal(pki.rootAuthority) {
		t.Fatalf("ParseAuthoritiesPEM() = %#v", authorities)
	}
	if _, err := ParseAuthoritiesPEM([]byte("not pem")); err == nil {
		t.Fatal("ParseAuthoritiesPEM(non-PEM) error = nil")
	}
	if _, err := ParseAuthoritiesPEM(
		[]byte("-----BEGIN BAD-----"),
	); err == nil {
		t.Fatal("ParseAuthoritiesPEM(malformed) error = nil")
	}

	broken := pki.rootAuthority
	broken.der = []byte("bad")
	if _, err := broken.Certificate(); err == nil {
		t.Fatal("broken Authority Certificate() error = nil")
	}
	if broken.Equal(pki.rootAuthority) {
		t.Fatal("broken Authority matched valid authority")
	}
	if !bytes.Equal(pki.rootAuthority.DER(), pki.rootCert.Raw) {
		t.Fatal("Authority DER() changed bytes")
	}
}

func TestCoverageIdentityScopeAndPinBranches(t *testing.T) {
	if err := (Scope{Any: true, DNS: []DNSRule{{Domain: "example.test"}}}).
		Validate(); err == nil {
		t.Fatal("Scope.Any combined with DNS error = nil")
	}
	if _, err := NewDNSDomainScope("Example.TEST.", true); err != nil {
		t.Fatalf("NewDNSDomainScope() error = %v", err)
	}

	scope, err := NewDNSDomainScope("example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	child, err := ParseServerIdentity("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := scope.Allows(child); err != nil || !ok {
		t.Fatalf("subdomain Allows() = %v, %v, want true, nil", ok, err)
	}
	ipScope, err := NewIPPrefixScope(netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	ipID, err := ParseServerIdentity("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ipScope.Allows(ipID); err != nil || !ok {
		t.Fatalf("IP Allows() = %v, %v, want true, nil", ok, err)
	}

	var pin Pin
	if err := pin.UnmarshalText([]byte("certificate:bad")); err == nil {
		t.Fatal("Pin.UnmarshalText(bad digest) error = nil")
	}
	var fingerprint Fingerprint
	if err := fingerprint.UnmarshalText([]byte("bad")); err == nil {
		t.Fatal("Fingerprint.UnmarshalText(bad digest) error = nil")
	}
}

func TestCoverageClientPolicyVerifyBranches(t *testing.T) {
	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	policy, err := CompileClientPolicy(ClientPolicySpec{
		TrustAnchors: []Authority{pki.rootAuthority},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := policy.VerifyClient(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{nil, pki.rootCert}},
	}); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("VerifyClient(nil leaf) error = %v", err)
	}
	if _, err := policy.VerifyClient(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{pki.leafCert, nil}},
	}); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("VerifyClient(nil root) error = %v", err)
	}
}
