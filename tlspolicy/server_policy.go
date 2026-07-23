package tlspolicy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// AuthorityMatch selects how an AuthorityConstraint recognizes a certificate
// authority in a verified chain.
type AuthorityMatch uint8

const (
	// MatchCertificate matches the exact DER certificate. This is the default
	// zero value and distinguishes cross-signed certificate variants.
	MatchCertificate AuthorityMatch = iota

	// MatchSPKI matches SHA-256 over SubjectPublicKeyInfo. Use it when every
	// certificate variant sharing a CA key should receive the same restriction.
	// This is broader than exact-certificate matching and should be selected
	// deliberately.
	MatchSPKI
)

// String returns a stable human-readable name for m.
func (m AuthorityMatch) String() string {
	switch m {
	case MatchCertificate:
		return "certificate"
	case MatchSPKI:
		return "spki"
	default:
		return fmt.Sprintf("AuthorityMatch(%d)", uint8(m))
	}
}

// ScopedAuthority is a certificate selected as a trust anchor only for remote
// servers in Scope.
//
// The certificate is placed in an explicit application-owned x509.CertPool.
// Scope is enforced after normal chain and hostname verification. A zero Scope
// is rejected because it would make the anchor unusable.
type ScopedAuthority struct {
	// Authority is the exact certificate to add as a trust anchor.
	Authority Authority

	// Scope selects the DNS names or IP addresses for which the anchor is valid.
	Scope Scope
}

// AuthorityConstraint restricts where a CA certificate may appear in a
// verified server chain.
//
// Constraints are evaluated for every non-leaf certificate, including the
// terminal trust anchor. They do not add Authority to the root pool. A typical
// use is to restrict a government or enterprise intermediate CA even when it
// chains to a more generally trusted root.
type AuthorityConstraint struct {
	// Authority supplies the exact certificate or SPKI to recognize.
	Authority Authority

	// Match chooses exact-certificate or SPKI recognition.
	Match AuthorityMatch

	// Scope selects the servers for which the matched CA is permitted.
	Scope Scope
}

// ServerPolicySpec describes how TLS clients authenticate remote servers.
//
// TrustAnchors is the complete root set; there is never an implicit system-root
// fallback. Constraints can further restrict roots and intermediates. Pins are
// additional leaf requirements after PKI and hostname verification.
type ServerPolicySpec struct {
	// TrustAnchors is the explicit, server-scoped root CA set.
	TrustAnchors []ScopedAuthority

	// Constraints restrict recognized CA certificates wherever they occur above
	// the leaf in an otherwise verified chain.
	Constraints []AuthorityConstraint

	// Pins contains resource-scoped leaf certificate or SPKI pins.
	Pins []ScopedPin
}

// ServerPolicy is an immutable policy used by TLS clients to authenticate
// remote servers.
//
// A ServerPolicy is safe for concurrent use. Create one with
// CompileServerPolicy. Use TLSClientConfig, TLSClientConfigForServer, or
// NewHTTPTransport to attach it to TLS connections.
type ServerPolicy struct {
	roots *x509.CertPool

	anchorScopes     map[Fingerprint]compiledScope
	exactConstraints map[Fingerprint]compiledScope
	spkiConstraints  map[Fingerprint]compiledScope
	pins             []compiledScopedPin
}

type compiledScopedPin struct {
	pin   Pin
	scope compiledScope
}

// ServerVerification is the result of applying a ServerPolicy to a normally
// verified TLS connection.
//
// AuthorizedChains contains only the chains that satisfy all scoped authority
// rules. ConnectionState.VerifiedChains is replaced with the same filtered
// chain set. ConnectionState and the certificates in AuthorizedChains must be
// treated as read-only. The outer and inner chain slices are copies, but the
// x509.Certificate objects are owned by crypto/tls.
type ServerVerification struct {
	// Identity is the canonical remote-server identity used for policy matching.
	Identity ServerIdentity

	// ConnectionState is the TLS state supplied to VerifyConnection.
	ConnectionState tls.ConnectionState

	// AuthorizedChains is the non-empty subset of normally verified chains
	// permitted by the policy.
	AuthorizedChains [][]*x509.Certificate
}

// ServerConnectionVerifier performs an additional local check after normal TLS
// verification, scoped-authority checks, and pins have succeeded.
//
// Implementations may validate a stapled OCSP response, enforce application
// certificate extensions, or consult local policy data. Implementations should
// not perform network I/O unless the application explicitly routes and bounds
// that traffic. The method may be called concurrently and on resumed sessions.
type ServerConnectionVerifier interface {
	// VerifyServer inspects a connection already accepted by the compiled server
	// policy. Returning a non-nil error aborts the TLS handshake. The supplied
	// state and certificates are read-only.
	VerifyServer(connection ServerVerification) error
}

// ServerConnectionVerifierFunc adapts a function to ServerConnectionVerifier.
type ServerConnectionVerifierFunc func(ServerVerification) error

// VerifyServer calls f(connection).
func (f ServerConnectionVerifierFunc) VerifyServer(
	connection ServerVerification,
) error {
	if f == nil {
		return errors.New("tlspolicy: nil ServerConnectionVerifierFunc")
	}
	return f(connection)
}

// CompileServerPolicy validates spec and returns an immutable policy.
//
// Every trust anchor is added to a pool created with x509.NewCertPool. An empty
// TrustAnchors slice is valid and creates a fail-closed policy that trusts no
// server chain. Duplicate exact trust anchors and duplicate constraint keys are
// rejected to make policy mistakes visible.
func CompileServerPolicy(spec ServerPolicySpec) (*ServerPolicy, error) {
	policy := &ServerPolicy{
		roots: x509.NewCertPool(),
		anchorScopes: make(
			map[Fingerprint]compiledScope,
			len(spec.TrustAnchors),
		),
		exactConstraints: make(map[Fingerprint]compiledScope),
		spkiConstraints:  make(map[Fingerprint]compiledScope),
	}

	for i, anchor := range spec.TrustAnchors {
		if !anchor.Authority.Valid() {
			return nil, fmt.Errorf(
				"tlspolicy: trust anchor %d has an invalid Authority",
				i,
			)
		}
		scope, err := compileScope(anchor.Scope, false)
		if err != nil {
			return nil, fmt.Errorf("tlspolicy: trust anchor %d: %w", i, err)
		}

		id := anchor.Authority.Fingerprint()
		if _, duplicate := policy.anchorScopes[id]; duplicate {
			return nil, fmt.Errorf(
				"tlspolicy: trust anchor %s appears more than once",
				id,
			)
		}

		cert, err := anchor.Authority.Certificate()
		if err != nil {
			return nil, fmt.Errorf("tlspolicy: trust anchor %d: %w", i, err)
		}
		policy.roots.AddCert(cert)
		policy.anchorScopes[id] = scope
	}

	for i, constraint := range spec.Constraints {
		if !constraint.Authority.Valid() {
			return nil, fmt.Errorf(
				"tlspolicy: authority constraint %d has an invalid Authority",
				i,
			)
		}
		scope, err := compileScope(constraint.Scope, false)
		if err != nil {
			return nil, fmt.Errorf(
				"tlspolicy: authority constraint %d: %w",
				i,
				err,
			)
		}

		switch constraint.Match {
		case MatchCertificate:
			id := constraint.Authority.Fingerprint()
			if _, duplicate := policy.exactConstraints[id]; duplicate {
				return nil, fmt.Errorf(
					"tlspolicy: exact authority constraint %s appears more than once",
					id,
				)
			}
			policy.exactConstraints[id] = scope
		case MatchSPKI:
			id := constraint.Authority.SPKIFingerprint()
			if _, duplicate := policy.spkiConstraints[id]; duplicate {
				return nil, fmt.Errorf(
					"tlspolicy: SPKI authority constraint %s appears more than once",
					id,
				)
			}
			policy.spkiConstraints[id] = scope
		default:
			return nil, fmt.Errorf(
				"tlspolicy: authority constraint %d uses unsupported match mode %s",
				i,
				constraint.Match,
			)
		}
	}

	policy.pins = make([]compiledScopedPin, 0, len(spec.Pins))
	for i, scopedPin := range spec.Pins {
		if !scopedPin.Pin.Valid() {
			return nil, fmt.Errorf("tlspolicy: scoped pin %d is invalid", i)
		}
		scope, err := compileScope(scopedPin.Scope, false)
		if err != nil {
			return nil, fmt.Errorf("tlspolicy: scoped pin %d: %w", i, err)
		}
		policy.pins = append(
			policy.pins,
			compiledScopedPin{pin: scopedPin.Pin, scope: scope},
		)
	}

	return policy, nil
}

// TrustAnchorCount returns the number of exact trust-anchor certificates in p.
// A nil policy has count zero.
func (p *ServerPolicy) TrustAnchorCount() int {
	if p == nil {
		return 0
	}
	return len(p.anchorScopes)
}

// PinCount returns the number of scoped pins in p. A nil policy has count zero.
func (p *ServerPolicy) PinCount() int {
	if p == nil {
		return 0
	}
	return len(p.pins)
}

// VerifyServer applies scoped-authority and pin checks to state for identity.
//
// Normal crypto/tls verification must already have succeeded and populated
// state.VerifiedChains. The method does not build chains or perform any network
// access. It does repeat leaf hostname or IP verification against identity so a
// direct caller cannot accidentally apply a scoped policy to a chain verified
// for another resource. Policy-generated TLS configurations call this method
// from tls.Config.VerifyConnection.
func (p *ServerPolicy) VerifyServer(
	identity ServerIdentity,
	state tls.ConnectionState,
) (ServerVerification, error) {
	if p == nil {
		return ServerVerification{}, errors.New("tlspolicy: nil ServerPolicy")
	}
	if !identity.Valid() {
		return ServerVerification{}, errors.New(
			"tlspolicy: invalid ServerIdentity",
		)
	}
	if len(state.VerifiedChains) == 0 {
		return ServerVerification{}, ErrNoVerifiedChains
	}

	authorized := make([][]*x509.Certificate, 0, len(state.VerifiedChains))
	for _, chain := range state.VerifiedChains {
		if !p.chainAuthorized(identity, chain) {
			continue
		}
		authorized = append(
			authorized,
			append([]*x509.Certificate(nil), chain...),
		)
	}
	if len(authorized) == 0 {
		return ServerVerification{}, fmt.Errorf(
			"%w for %s",
			ErrUnauthorizedChain,
			identity,
		)
	}

	leaf := authorized[0][0]
	if err := leaf.VerifyHostname(identity.String()); err != nil {
		return ServerVerification{}, fmt.Errorf(
			"%w for %s: %w",
			ErrServerIdentityMismatch,
			identity,
			err,
		)
	}

	pinRequired := false
	pinMatched := false
	for _, scopedPin := range p.pins {
		if !scopedPin.scope.allows(identity) {
			continue
		}
		pinRequired = true
		if scopedPin.pin.Matches(leaf) {
			pinMatched = true
		}
	}
	if pinRequired && !pinMatched {
		return ServerVerification{}, fmt.Errorf(
			"%w for %s",
			ErrPinMismatch,
			identity,
		)
	}

	state.VerifiedChains = cloneCertificateChains(authorized)
	return ServerVerification{
		Identity:         identity,
		ConnectionState:  state,
		AuthorizedChains: cloneCertificateChains(authorized),
	}, nil
}

func (p *ServerPolicy) chainAuthorized(
	identity ServerIdentity,
	chain []*x509.Certificate,
) bool {
	if len(chain) == 0 || chain[0] == nil || chain[len(chain)-1] == nil {
		return false
	}

	root := chain[len(chain)-1]
	rootID := Fingerprint(sha256.Sum256(root.Raw))
	rootScope, selected := p.anchorScopes[rootID]
	if !selected || !rootScope.allows(identity) {
		return false
	}

	// The leaf is intentionally excluded. Authority constraints apply only to
	// intermediates and the terminal trust anchor.
	for _, cert := range chain[1:] {
		if cert == nil {
			return false
		}

		exactID := Fingerprint(sha256.Sum256(cert.Raw))
		if scope, constrained := p.exactConstraints[exactID]; constrained &&
			!scope.allows(identity) {
			return false
		}

		spkiID := Fingerprint(sha256.Sum256(cert.RawSubjectPublicKeyInfo))
		if scope, constrained := p.spkiConstraints[spkiID]; constrained &&
			!scope.allows(identity) {
			return false
		}
	}
	return true
}

func cloneCertificateChains(
	chains [][]*x509.Certificate,
) [][]*x509.Certificate {
	if chains == nil {
		return nil
	}
	cloned := make([][]*x509.Certificate, len(chains))
	for i := range chains {
		cloned[i] = append([]*x509.Certificate(nil), chains[i]...)
	}
	return cloned
}
