package tlspolicy

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// PinKind selects which part of a leaf certificate a Pin authenticates.
type PinKind uint8

const (
	// PinInvalid is the kind of the zero Pin value.
	PinInvalid PinKind = iota

	// PinLeafCertificate matches SHA-256 over the complete DER leaf certificate.
	// It changes whenever the certificate is renewed or reissued.
	PinLeafCertificate

	// PinLeafSPKI matches SHA-256 over the leaf certificate's DER-encoded
	// SubjectPublicKeyInfo. It can survive certificate renewal when the same key
	// is retained.
	PinLeafSPKI
)

// String returns a stable human-readable name for k.
func (k PinKind) String() string {
	switch k {
	case PinInvalid:
		return "invalid"
	case PinLeafCertificate:
		return "certificate"
	case PinLeafSPKI:
		return "spki"
	default:
		return fmt.Sprintf("PinKind(%d)", uint8(k))
	}
}

// Pin is an immutable SHA-256 leaf-certificate or leaf-SPKI pin.
//
// A Pin is an additional condition after normal certificate-chain and hostname
// verification. It never replaces PKI validation. The zero value is invalid.
type Pin struct { //nolint:recvcheck // Unmarshal mutates.
	kind   PinKind
	digest Fingerprint
}

// NewPin constructs a Pin from kind and digest.
func NewPin(kind PinKind, digest Fingerprint) (Pin, error) {
	switch kind {
	case PinInvalid:
		return Pin{}, fmt.Errorf("tlspolicy: unsupported pin kind %s", kind)
	case PinLeafCertificate, PinLeafSPKI:
		return Pin{kind: kind, digest: digest}, nil
	default:
		return Pin{}, fmt.Errorf("tlspolicy: unsupported pin kind %s", kind)
	}
}

// NewCertificatePin parses certificateDER and returns a pin for the complete
// leaf certificate DER.
func NewCertificatePin(certificateDER []byte) (Pin, error) {
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Pin{}, fmt.Errorf(
			"tlspolicy: parse certificate for certificate pin: %w",
			err,
		)
	}
	return NewPin(PinLeafCertificate, Fingerprint(sha256.Sum256(cert.Raw)))
}

// NewSPKIPin parses certificateDER and returns a pin for the leaf certificate's
// DER SubjectPublicKeyInfo value.
func NewSPKIPin(certificateDER []byte) (Pin, error) {
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Pin{}, fmt.Errorf(
			"tlspolicy: parse certificate for SPKI pin: %w",
			err,
		)
	}
	return NewPin(
		PinLeafSPKI,
		Fingerprint(sha256.Sum256(cert.RawSubjectPublicKeyInfo)),
	)
}

// Kind returns the part of a leaf certificate matched by p.
func (p Pin) Kind() PinKind {
	return p.kind
}

// Digest returns p's SHA-256 digest.
func (p Pin) Digest() Fingerprint {
	return p.digest
}

// Valid reports whether p has a supported kind.
func (p Pin) Valid() bool {
	return p.kind == PinLeafCertificate || p.kind == PinLeafSPKI
}

// Matches reports whether p matches cert. A nil certificate or invalid pin
// returns false.
func (p Pin) Matches(cert *x509.Certificate) bool {
	if cert == nil || !p.Valid() {
		return false
	}

	var actual Fingerprint
	switch p.kind {
	case PinInvalid:
		return false
	case PinLeafCertificate:
		actual = Fingerprint(sha256.Sum256(cert.Raw))
	case PinLeafSPKI:
		actual = Fingerprint(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
	default:
		return false
	}

	return subtle.ConstantTimeCompare(actual[:], p.digest[:]) == 1
}

// String returns p in the form "certificate:<hex>" or "spki:<hex>". An
// invalid pin is rendered as "invalid:<hex>".
func (p Pin) String() string {
	return p.kind.String() + ":" + p.digest.String()
}

// MarshalText implements encoding.TextMarshaler.
func (p Pin) MarshalText() ([]byte, error) {
	if !p.Valid() {
		return nil, errors.New("tlspolicy: cannot marshal invalid Pin")
	}
	return []byte(p.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. It accepts the format
// produced by String.
func (p *Pin) UnmarshalText(text []byte) error {
	if p == nil {
		return errors.New("tlspolicy: cannot unmarshal Pin into a nil receiver")
	}

	kindText, digestText, ok := strings.Cut(
		strings.TrimSpace(string(text)),
		":",
	)
	if !ok {
		return errors.New(
			"tlspolicy: pin text must contain a kind and SHA-256 fingerprint",
		)
	}

	var kind PinKind
	switch strings.ToLower(kindText) {
	case "certificate":
		kind = PinLeafCertificate
	case "spki":
		kind = PinLeafSPKI
	default:
		return fmt.Errorf("tlspolicy: unsupported pin kind %q", kindText)
	}

	digest, err := ParseFingerprint(digestText)
	if err != nil {
		return err
	}
	parsed, err := NewPin(kind, digest)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ScopedPin applies Pin only when Scope contains the remote server identity.
// If several pins apply to one server, they are alternatives: at least one
// matching pin is sufficient. This supports overlap during key rotation.
type ScopedPin struct {
	// Pin is the certificate or SPKI digest to require.
	Pin Pin

	// Scope selects the servers for which Pin is active.
	Scope Scope
}
