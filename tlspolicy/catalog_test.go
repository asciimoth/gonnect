package tlspolicy //nolint:testpackage // Uses shared in-package TLS fixtures.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

type nilAuthorityFetcher struct{}

func (*nilAuthorityFetcher) FetchAuthorities(
	context.Context,
) ([]AuthorityCandidate, error) {
	return nil, errors.New("unexpected call")
}

func TestAuthorityCatalogDeduplicatesAndCopies(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	metadata := map[string]string{"domain": "system"}
	candidates := []AuthorityCandidate{
		{
			DER: pki.rootAuthority.DER(),
			Source: AuthoritySource{
				Name:     "store-a",
				Trust:    TrustHintAnchor,
				Metadata: metadata,
			},
		},
		{
			DER: pki.rootAuthority.DER(),
			Source: AuthoritySource{
				Name:  "store-b",
				Trust: TrustHintRestricted,
			},
		},
		{
			DER: pki.rootAuthority.DER(),
			Source: AuthoritySource{
				Name:     "store-a",
				Trust:    TrustHintAnchor,
				Metadata: map[string]string{"domain": "system"},
			},
		},
	}

	catalog, err := NewAuthorityCatalog(candidates)
	if err != nil {
		t.Fatal(err)
	}
	metadata["domain"] = "mutated"

	if got, want := catalog.Len(), 1; got != want {
		t.Fatalf("Len = %d, want %d", got, want)
	}
	records := catalog.Records()
	if got, want := len(records[0].Sources), 2; got != want {
		t.Fatalf("source count = %d, want %d", got, want)
	}
	if got, want := records[0].Sources[0].Metadata["domain"], "system"; got != want {
		t.Fatalf("metadata = %q, want %q", got, want)
	}

	selected, err := catalog.Select(
		[]Fingerprint{pki.rootAuthority.Fingerprint()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || !selected[0].Equal(pki.rootAuthority) {
		t.Fatal("catalog selection returned the wrong authority")
	}
}

func TestFetchAuthorityCatalogAndPEMParsing(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	fetcher := AuthorityFetcherFunc(
		func(ctx context.Context) ([]AuthorityCandidate, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return []AuthorityCandidate{{
				DER:    pki.rootAuthority.DER(),
				Source: AuthoritySource{Name: "test", Trust: TrustHintAnchor},
			}}, nil
		},
	)
	catalog, err := FetchAuthorityCatalog(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != 1 {
		t.Fatalf("Len = %d, want 1", catalog.Len())
	}

	pemBytes := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: pki.rootAuthority.DER()},
	)
	authorities, err := ParseAuthoritiesPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorities) != 1 || !authorities[0].Equal(pki.rootAuthority) {
		t.Fatal("PEM parser returned the wrong authority")
	}

	if _, err := ParseAuthoritiesPEM(
		append([]byte("garbage\n"), pemBytes...),
	); err == nil {
		t.Fatal("PEM parser accepted leading non-PEM data")
	}
	if _, err := ParseAuthoritiesPEM(
		append(pemBytes, []byte("garbage")...),
	); err == nil {
		t.Fatal("PEM parser accepted trailing non-PEM data")
	}
}

func TestFingerprintTextRoundTrip(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, testLeafOptions{
		dnsNames: []string{"service.example.test"},
		usages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	original := pki.rootAuthority.Fingerprint()
	parsed, err := ParseFingerprint(original.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != original {
		t.Fatalf("parsed fingerprint differs: %s != %s", parsed, original)
	}
}

func TestFetchAuthorityCatalogRejectsTypedNilFetcher(t *testing.T) {
	t.Parallel()

	var fetcher *nilAuthorityFetcher
	if _, err := FetchAuthorityCatalog(
		context.Background(),
		fetcher,
	); err == nil {
		t.Fatal("FetchAuthorityCatalog accepted a typed nil AuthorityFetcher")
	}
}

func TestAuthorityFetcherFuncRejectsNil(t *testing.T) {
	t.Parallel()

	var fetcher AuthorityFetcherFunc
	if _, err := fetcher.FetchAuthorities(context.Background()); err == nil {
		t.Fatal("nil AuthorityFetcherFunc returned nil error")
	}
}

func TestFetchAuthorityCatalogRejectsBadInputsAndFetcherErrors(t *testing.T) {
	t.Parallel()

	var nilContext context.Context
	if _, err := FetchAuthorityCatalog(nilContext, AuthorityFetcherFunc(
		func(context.Context) ([]AuthorityCandidate, error) {
			return nil, nil
		},
	)); err == nil {
		t.Fatal("FetchAuthorityCatalog accepted nil context")
	}

	if _, err := FetchAuthorityCatalog(context.Background(), nil); err == nil {
		t.Fatal("FetchAuthorityCatalog accepted nil fetcher")
	}

	marker := errors.New("fetch failed")
	_, err := FetchAuthorityCatalog(context.Background(), AuthorityFetcherFunc(
		func(context.Context) ([]AuthorityCandidate, error) {
			return nil, marker
		},
	))
	if !errors.Is(err, marker) {
		t.Fatalf("FetchAuthorityCatalog error = %v, want marker", err)
	}
}

func TestNewAuthorityCatalogRejectsMalformedDER(t *testing.T) {
	t.Parallel()

	_, err := NewAuthorityCatalog([]AuthorityCandidate{{
		DER:    []byte("not der"),
		Source: AuthoritySource{Name: "test"},
	}})
	if err == nil {
		t.Fatal("NewAuthorityCatalog accepted malformed DER")
	}
}
