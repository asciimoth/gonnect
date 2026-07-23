package tlspolicy

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"
)

// TrustHint describes how the source store characterized a discovered
// certificate.
//
// A TrustHint is informational. CompileServerPolicy and CompileClientPolicy do
// not consult it. Selecting a discovered certificate as an application trust
// anchor must always be an explicit policy decision.
type TrustHint uint8

const (
	// TrustHintUnknown means the fetcher could not express the source store's
	// trust semantics as one of the other hints.
	TrustHintUnknown TrustHint = iota

	// TrustHintAnchor means the source presented the certificate as a candidate
	// trust anchor. Platform-specific restrictions may still apply and are not
	// represented by this value alone.
	TrustHintAnchor

	// TrustHintDistrusted means the source explicitly distrusted the certificate.
	// User interfaces should not preselect such a certificate as an anchor.
	TrustHintDistrusted

	// TrustHintRestricted means trust depends on usage, policy, hostname,
	// application, key usage, or other source-specific constraints.
	TrustHintRestricted
)

// String returns a stable human-readable name for h.
func (h TrustHint) String() string {
	switch h {
	case TrustHintUnknown:
		return "unknown"
	case TrustHintAnchor:
		return "anchor"
	case TrustHintDistrusted:
		return "distrusted"
	case TrustHintRestricted:
		return "restricted"
	default:
		return fmt.Sprintf("TrustHint(%d)", uint8(h))
	}
}

// AuthoritySource identifies one local source from which an authority
// candidate was discovered.
//
// Name should be stable and suitable for display or audit logs, for example
// "windows:CurrentUser\\Root", "macos:system", or a certificate-bundle path.
// Metadata may contain platform-specific details. FetchAuthorityCatalog copies
// the map, and callers should treat values returned by Records and Lookup as
// snapshots.
type AuthoritySource struct {
	// Name identifies the store, file, domain, or other local source.
	Name string

	// Trust is the source's informational trust classification.
	Trust TrustHint

	// Metadata carries optional platform-specific, non-secret attributes.
	Metadata map[string]string
}

// AuthorityCandidate is one DER certificate and the local source that exposed
// it. AuthorityFetcher implementations may return the same DER certificate
// more than once with different AuthoritySource values; AuthorityCatalog
// deduplicates the certificate and preserves all distinct sources.
type AuthorityCandidate struct {
	// DER is one complete DER-encoded X.509 certificate.
	DER []byte

	// Source describes where DER was discovered.
	Source AuthoritySource
}

// AuthorityFetcher enumerates certificate-authority candidates from a local
// source such as an operating-system certificate store.
//
// Implementations belong in platform-specific code. They should enumerate and
// export local certificate objects only. They should not build certificate
// paths, validate arbitrary remote certificates, follow AIA URLs, contact OCSP
// responders, download CRLs, or otherwise perform network I/O as a side effect
// of discovery.
//
// The configured fetcher decides which user, machine, service, enterprise, or
// other store views are included. Returning a candidate does not grant trust.
type AuthorityFetcher interface {
	// FetchAuthorities returns a snapshot of locally discoverable certificate
	// candidates. It should honor ctx cancellation, copy DER bytes out of any
	// platform-owned buffers, and describe each source precisely enough for user
	// display and audit logging. Returning a candidate does not select it as a
	// trust anchor.
	FetchAuthorities(ctx context.Context) ([]AuthorityCandidate, error)
}

// AuthorityFetcherFunc adapts a function to AuthorityFetcher.
type AuthorityFetcherFunc func(context.Context) ([]AuthorityCandidate, error)

// FetchAuthorities calls f(ctx).
func (f AuthorityFetcherFunc) FetchAuthorities(
	ctx context.Context,
) ([]AuthorityCandidate, error) {
	if f == nil {
		return nil, errors.New("tlspolicy: nil AuthorityFetcherFunc")
	}
	return f(ctx)
}

// AuthorityRecord is a validated, display-ready certificate-authority
// candidate in an AuthorityCatalog.
//
// Authority contains the immutable DER value to use when building a policy.
// CertificateFingerprint identifies the exact certificate, while
// SPKIFingerprint can group cross-signed certificate variants that share a
// public key. Sources contains every distinct discovery source reported for
// the exact DER certificate.
type AuthorityRecord struct {
	// Authority is the immutable certificate value accepted by policy specs.
	Authority Authority

	// CertificateFingerprint is SHA-256 over the complete certificate DER.
	CertificateFingerprint Fingerprint

	// SPKIFingerprint is SHA-256 over DER SubjectPublicKeyInfo.
	SPKIFingerprint Fingerprint

	// Subject is the certificate subject formatted by pkix.Name.String.
	Subject string

	// Issuer is the certificate issuer formatted by pkix.Name.String.
	Issuer string

	// SerialNumber is the certificate serial number in hexadecimal.
	SerialNumber string

	// NotBefore is the beginning of the certificate validity interval.
	NotBefore time.Time

	// NotAfter is the end of the certificate validity interval.
	NotAfter time.Time

	// IsCA reports the parsed BasicConstraints CA value.
	IsCA bool

	// PublicKeyAlgorithm identifies the certificate subject's public-key type.
	PublicKeyAlgorithm x509.PublicKeyAlgorithm

	// SignatureAlgorithm identifies the algorithm that signed the certificate.
	SignatureAlgorithm x509.SignatureAlgorithm

	// Sources lists the local stores or files that reported this certificate.
	Sources []AuthoritySource
}

// AuthorityCatalog is an immutable, fingerprint-deduplicated snapshot of
// authority candidates.
//
// Catalog methods return copies. An AuthorityCatalog is safe for concurrent
// use after construction.
type AuthorityCatalog struct {
	records []AuthorityRecord
	byID    map[Fingerprint]int
}

// FetchAuthorityCatalog invokes fetcher and validates its results with
// NewAuthorityCatalog.
func FetchAuthorityCatalog(
	ctx context.Context,
	fetcher AuthorityFetcher,
) (*AuthorityCatalog, error) {
	if ctx == nil {
		return nil, errors.New(
			"tlspolicy: nil context passed to FetchAuthorityCatalog",
		)
	}
	if interfaceIsNil(fetcher) {
		return nil, errors.New("tlspolicy: nil AuthorityFetcher")
	}

	candidates, err := fetcher.FetchAuthorities(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlspolicy: fetch authority candidates: %w", err)
	}
	return NewAuthorityCatalog(candidates)
}

// NewAuthorityCatalog validates candidates, deduplicates them by exact
// certificate fingerprint, and returns a stable, subject-sorted catalog.
//
// The function copies all DER bytes and source metadata. It rejects malformed
// certificates. Exact duplicate source entries for the same certificate are
// stored once.
func NewAuthorityCatalog(
	candidates []AuthorityCandidate,
) (*AuthorityCatalog, error) {
	records := make([]AuthorityRecord, 0, len(candidates))
	indices := make(map[Fingerprint]int, len(candidates))

	for i, candidate := range candidates {
		authority, err := ParseAuthorityDER(candidate.DER)
		if err != nil {
			return nil, fmt.Errorf(
				"tlspolicy: authority candidate %d: %w",
				i,
				err,
			)
		}

		cert, err := authority.Certificate()
		if err != nil {
			return nil, fmt.Errorf(
				"tlspolicy: authority candidate %d: %w",
				i,
				err,
			)
		}

		id := authority.Fingerprint()
		source := cloneAuthoritySource(candidate.Source)

		if index, ok := indices[id]; ok {
			if !bytes.Equal(records[index].Authority.der, authority.der) {
				return nil, fmt.Errorf(
					"tlspolicy: SHA-256 collision between authority candidates",
				)
			}
			if !containsAuthoritySource(records[index].Sources, source) {
				records[index].Sources = append(records[index].Sources, source)
			}
			continue
		}

		record := AuthorityRecord{
			Authority:              authority,
			CertificateFingerprint: id,
			SPKIFingerprint:        authority.SPKIFingerprint(),
			Subject:                cert.Subject.String(),
			Issuer:                 cert.Issuer.String(),
			SerialNumber:           cert.SerialNumber.Text(16),
			NotBefore:              cert.NotBefore,
			NotAfter:               cert.NotAfter,
			IsCA:                   cert.IsCA,
			PublicKeyAlgorithm:     cert.PublicKeyAlgorithm,
			SignatureAlgorithm:     cert.SignatureAlgorithm,
			Sources:                []AuthoritySource{source},
		}
		indices[id] = len(records)
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Subject != records[j].Subject {
			return records[i].Subject < records[j].Subject
		}
		if records[i].Issuer != records[j].Issuer {
			return records[i].Issuer < records[j].Issuer
		}
		return records[i].CertificateFingerprint.String() < records[j].CertificateFingerprint.String()
	})

	byID := make(map[Fingerprint]int, len(records))
	for i := range records {
		byID[records[i].CertificateFingerprint] = i
	}

	return &AuthorityCatalog{records: records, byID: byID}, nil
}

// Len returns the number of distinct DER certificates in c. A nil catalog has
// length zero.
func (c *AuthorityCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.records)
}

// Records returns all catalog entries in stable subject, issuer, and
// fingerprint order. The returned slice and source metadata are copies.
func (c *AuthorityCatalog) Records() []AuthorityRecord {
	if c == nil {
		return nil
	}

	result := make([]AuthorityRecord, len(c.records))
	for i := range c.records {
		result[i] = cloneAuthorityRecord(c.records[i])
	}
	return result
}

// Lookup returns a copy of the record with the exact certificate fingerprint
// id. The boolean result is false when id is absent or c is nil.
func (c *AuthorityCatalog) Lookup(id Fingerprint) (AuthorityRecord, bool) {
	if c == nil {
		return AuthorityRecord{}, false
	}
	index, ok := c.byID[id]
	if !ok {
		return AuthorityRecord{}, false
	}
	return cloneAuthorityRecord(c.records[index]), true
}

// Select resolves ids to immutable Authority values in the requested order.
// It returns an error for an unknown fingerprint or a duplicate selection.
func (c *AuthorityCatalog) Select(ids []Fingerprint) ([]Authority, error) {
	if c == nil {
		return nil, errors.New("tlspolicy: select from nil AuthorityCatalog")
	}

	selected := make([]Authority, 0, len(ids))
	seen := make(map[Fingerprint]struct{}, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf(
				"tlspolicy: authority %s selected more than once",
				id,
			)
		}
		seen[id] = struct{}{}

		record, ok := c.Lookup(id)
		if !ok {
			return nil, fmt.Errorf(
				"tlspolicy: authority %s is not in the catalog",
				id,
			)
		}
		selected = append(selected, record.Authority)
	}
	return selected, nil
}

func cloneAuthorityRecord(record AuthorityRecord) AuthorityRecord {
	cloned := record
	cloned.Sources = make([]AuthoritySource, len(record.Sources))
	for i := range record.Sources {
		cloned.Sources[i] = cloneAuthoritySource(record.Sources[i])
	}
	return cloned
}

func cloneAuthoritySource(source AuthoritySource) AuthoritySource {
	cloned := source
	if source.Metadata != nil {
		cloned.Metadata = make(map[string]string, len(source.Metadata))
		maps.Copy(cloned.Metadata, source.Metadata)
	}
	return cloned
}

func containsAuthoritySource(
	sources []AuthoritySource,
	wanted AuthoritySource,
) bool {
	for _, source := range sources {
		if source.Name != wanted.Name || source.Trust != wanted.Trust ||
			len(source.Metadata) != len(wanted.Metadata) {
			continue
		}

		equal := true
		for key, value := range source.Metadata {
			wantedValue, exists := wanted.Metadata[key]
			if !exists || wantedValue != value {
				equal = false
				break
			}
		}
		if equal {
			return true
		}
	}
	return false
}
