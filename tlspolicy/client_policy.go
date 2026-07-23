package tlspolicy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ClientPolicySpec describes how a TLS server authenticates mTLS client
// certificates.
//
// TrustAnchors is the complete client-root set; there is no implicit system
// fallback. If Pins is non-empty, every presented and otherwise valid client
// certificate must match at least one pin. Multiple pins are alternatives,
// allowing overlap during certificate or key rotation.
type ClientPolicySpec struct {
	// TrustAnchors is the explicit set of accepted client-certificate roots.
	TrustAnchors []Authority

	// Pins contains optional global leaf certificate or leaf SPKI pins.
	Pins []Pin
}

// ClientPolicy is an immutable policy used by TLS servers to authenticate mTLS
// clients.
//
// A ClientPolicy is safe for concurrent use. Create one with
// CompileClientPolicy and attach it with ServerTLSConfig.
type ClientPolicy struct {
	roots   *x509.CertPool
	rootIDs map[Fingerprint]struct{}
	pins    []Pin
}

// ClientVerification is the result of applying a ClientPolicy to a normally
// verified mTLS client connection.
//
// AuthorizedChains contains only chains whose terminal certificate was an
// explicit ClientPolicy trust anchor. ConnectionState.VerifiedChains is
// replaced with the same filtered chain set. ConnectionState and certificates
// must be treated as read-only.
type ClientVerification struct {
	// ConnectionState is the TLS state supplied to VerifyConnection.
	ConnectionState tls.ConnectionState

	// AuthorizedChains is the non-empty subset of normally verified client
	// chains accepted by the explicit root set.
	AuthorizedChains [][]*x509.Certificate
}

// ClientConnectionVerifier performs an additional local check after normal
// mTLS verification and client pins have succeeded.
//
// Implementations can enforce application-specific certificate identities or
// extensions. The method may be called concurrently and on resumed sessions.
// Network I/O has the same routing and leakage caveats described for
// ServerConnectionVerifier.
type ClientConnectionVerifier interface {
	// VerifyClient inspects an mTLS client connection already accepted by the
	// compiled client policy. Returning a non-nil error aborts the TLS handshake.
	// The supplied state and certificates are read-only.
	VerifyClient(connection ClientVerification) error
}

// ClientConnectionVerifierFunc adapts a function to ClientConnectionVerifier.
type ClientConnectionVerifierFunc func(ClientVerification) error

// VerifyClient calls f(connection).
func (f ClientConnectionVerifierFunc) VerifyClient(
	connection ClientVerification,
) error {
	if f == nil {
		return errors.New("tlspolicy: nil ClientConnectionVerifierFunc")
	}
	return f(connection)
}

// CompileClientPolicy validates spec and returns an immutable policy.
//
// Every trust anchor is added to an x509.NewCertPool pool. An empty
// TrustAnchors slice is valid and creates a fail-closed policy. Duplicate trust
// anchors and duplicate pins are rejected.
func CompileClientPolicy(spec ClientPolicySpec) (*ClientPolicy, error) {
	policy := &ClientPolicy{
		roots:   x509.NewCertPool(),
		rootIDs: make(map[Fingerprint]struct{}, len(spec.TrustAnchors)),
		pins:    make([]Pin, 0, len(spec.Pins)),
	}

	for i, authority := range spec.TrustAnchors {
		if !authority.Valid() {
			return nil, fmt.Errorf(
				"tlspolicy: client trust anchor %d has an invalid Authority",
				i,
			)
		}
		id := authority.Fingerprint()
		if _, duplicate := policy.rootIDs[id]; duplicate {
			return nil, fmt.Errorf(
				"tlspolicy: client trust anchor %s appears more than once",
				id,
			)
		}

		cert, err := authority.Certificate()
		if err != nil {
			return nil, fmt.Errorf(
				"tlspolicy: client trust anchor %d: %w",
				i,
				err,
			)
		}
		policy.roots.AddCert(cert)
		policy.rootIDs[id] = struct{}{}
	}

	type pinKey struct {
		kind   PinKind
		digest Fingerprint
	}
	seenPins := make(map[pinKey]struct{}, len(spec.Pins))
	for i, pin := range spec.Pins {
		if !pin.Valid() {
			return nil, fmt.Errorf("tlspolicy: client pin %d is invalid", i)
		}
		key := pinKey{kind: pin.Kind(), digest: pin.Digest()}
		if _, duplicate := seenPins[key]; duplicate {
			return nil, fmt.Errorf(
				"tlspolicy: client pin %s appears more than once",
				pin,
			)
		}
		seenPins[key] = struct{}{}
		policy.pins = append(policy.pins, pin)
	}

	return policy, nil
}

// TrustAnchorCount returns the number of exact client trust anchors in p. A nil
// policy has count zero.
func (p *ClientPolicy) TrustAnchorCount() int {
	if p == nil {
		return 0
	}
	return len(p.rootIDs)
}

// PinCount returns the number of client pins in p. A nil policy has count zero.
func (p *ClientPolicy) PinCount() int {
	if p == nil {
		return 0
	}
	return len(p.pins)
}

// VerifyClient applies the explicit-root and pin checks to a normally verified
// mTLS client state.
//
// Normal crypto/tls client-certificate verification must already have
// succeeded and populated state.VerifiedChains. The method does not build
// chains or perform network access.
func (p *ClientPolicy) VerifyClient(
	state tls.ConnectionState,
) (ClientVerification, error) {
	if p == nil {
		return ClientVerification{}, errors.New("tlspolicy: nil ClientPolicy")
	}
	if len(state.VerifiedChains) == 0 {
		return ClientVerification{}, ErrNoVerifiedChains
	}

	authorized := make([][]*x509.Certificate, 0, len(state.VerifiedChains))
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || chain[len(chain)-1] == nil {
			continue
		}
		rootID := Fingerprint(sha256.Sum256(chain[len(chain)-1].Raw))
		if _, selected := p.rootIDs[rootID]; !selected {
			continue
		}
		authorized = append(
			authorized,
			append([]*x509.Certificate(nil), chain...),
		)
	}
	if len(authorized) == 0 {
		return ClientVerification{}, ErrUnauthorizedChain
	}

	if len(p.pins) != 0 {
		leaf := authorized[0][0]
		matched := false
		for _, pin := range p.pins {
			if pin.Matches(leaf) {
				matched = true
			}
		}
		if !matched {
			return ClientVerification{}, ErrPinMismatch
		}
	}

	state.VerifiedChains = cloneCertificateChains(authorized)
	return ClientVerification{
		ConnectionState:  state,
		AuthorizedChains: cloneCertificateChains(authorized),
	}, nil
}
