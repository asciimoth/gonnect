package tlspolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Authority is an immutable, parsed X.509 certificate that can be selected as
// a trust anchor or used to constrain a certificate authority in a chain.
//
// Authority does not assert that the certificate is trusted, self-signed, or a
// CA. Trust is granted only by placing it in a policy's trust-anchor list. The
// zero value is invalid; create values with ParseAuthorityDER,
// ParseAuthoritiesPEM, or AuthorityFromCertificate.
type Authority struct { //nolint:recvcheck // Unmarshal mutates.
	der             []byte
	fingerprint     Fingerprint
	spkiFingerprint Fingerprint
}

// ParseAuthorityDER parses exactly one DER-encoded X.509 certificate and
// returns an immutable Authority value.
func ParseAuthorityDER(der []byte) (Authority, error) {
	if len(der) == 0 {
		return Authority{}, errors.New("tlspolicy: authority DER is empty")
	}

	owned := bytes.Clone(der)
	cert, err := x509.ParseCertificate(owned)
	if err != nil {
		return Authority{}, fmt.Errorf(
			"tlspolicy: parse authority certificate: %w",
			err,
		)
	}

	return Authority{
		der:         owned,
		fingerprint: Fingerprint(sha256.Sum256(cert.Raw)),
		spkiFingerprint: Fingerprint(
			sha256.Sum256(cert.RawSubjectPublicKeyInfo),
		),
	}, nil
}

// AuthorityFromCertificate copies cert.Raw and returns it as an immutable
// Authority value.
//
// The function reparses the DER so that malformed or manually constructed
// x509.Certificate values are rejected.
func AuthorityFromCertificate(cert *x509.Certificate) (Authority, error) {
	if cert == nil {
		return Authority{}, errors.New(
			"tlspolicy: authority certificate is nil",
		)
	}
	return ParseAuthorityDER(cert.Raw)
}

// ParseAuthoritiesPEM parses every CERTIFICATE block in pemData.
//
// Non-certificate PEM blocks are ignored. The function returns an error if a
// CERTIFICATE block is malformed, if non-PEM non-whitespace data remains, or if
// no certificate block is present. Each returned Authority owns its DER bytes.
func ParseAuthoritiesPEM(pemData []byte) ([]Authority, error) {
	remaining := bytes.Clone(pemData)
	var authorities []Authority

	for len(remaining) > 0 {
		remaining = bytes.TrimLeftFunc(remaining, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\r' || r == '\n'
		})
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return nil, errors.New("tlspolicy: non-PEM data in PEM input")
		}

		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("tlspolicy: malformed PEM block")
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(block.Headers) != 0 {
			return nil, errors.New(
				"tlspolicy: CERTIFICATE PEM block contains unsupported headers",
			)
		}

		authority, err := ParseAuthorityDER(block.Bytes)
		if err != nil {
			return nil, err
		}
		authorities = append(authorities, authority)
	}

	if len(authorities) == 0 {
		return nil, errors.New(
			"tlspolicy: PEM input contains no CERTIFICATE block",
		)
	}
	return authorities, nil
}

// Valid reports whether a contains a parsed certificate.
func (a Authority) Valid() bool {
	return len(a.der) != 0
}

// DER returns a copy of the complete DER-encoded certificate.
func (a Authority) DER() []byte {
	return bytes.Clone(a.der)
}

// Certificate returns a newly parsed certificate whose backing byte slices do
// not alias the Authority value.
func (a Authority) Certificate() (*x509.Certificate, error) {
	if !a.Valid() {
		return nil, errors.New("tlspolicy: invalid zero Authority")
	}

	cert, err := x509.ParseCertificate(bytes.Clone(a.der))
	if err != nil {
		// ParseAuthorityDER already validated this data. Preserve an error return
		// because Authority may have arrived through future binary decoding code.
		return nil, fmt.Errorf(
			"tlspolicy: reparse authority certificate: %w",
			err,
		)
	}
	return cert, nil
}

// Fingerprint returns the SHA-256 digest of the complete DER certificate.
func (a Authority) Fingerprint() Fingerprint {
	return a.fingerprint
}

// SPKIFingerprint returns the SHA-256 digest of the certificate's DER-encoded
// SubjectPublicKeyInfo value.
func (a Authority) SPKIFingerprint() Fingerprint {
	return a.spkiFingerprint
}

// Equal reports whether a and other contain the exact same DER certificate.
func (a Authority) Equal(other Authority) bool {
	return a.Valid() && other.Valid() && a.fingerprint == other.fingerprint &&
		bytes.Equal(a.der, other.der)
}

// MarshalBinary implements encoding.BinaryMarshaler by returning a copy of the
// complete DER certificate.
func (a Authority) MarshalBinary() ([]byte, error) {
	if !a.Valid() {
		return nil, errors.New(
			"tlspolicy: cannot marshal invalid zero Authority",
		)
	}
	return a.DER(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (a *Authority) UnmarshalBinary(data []byte) error {
	if a == nil {
		return errors.New(
			"tlspolicy: cannot unmarshal Authority into a nil receiver",
		)
	}

	parsed, err := ParseAuthorityDER(data)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}
