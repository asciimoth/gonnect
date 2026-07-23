package tlspolicy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// ClientTLSOptions contains non-trust settings for a TLS client configuration.
//
// RootCAs, ServerName, InsecureSkipVerify, and VerifyConnection are deliberately
// absent because the policy owns them. The returned tls.Config must not be
// modified after first use.
type ClientTLSOptions struct {
	// Certificates contains optional client certificates for mTLS. The slice and
	// certificate byte slices are copied. PrivateKey objects are shared and must
	// be safe for concurrent use as required by crypto/tls.
	Certificates []tls.Certificate

	// GetClientCertificate, when non-nil, selects an mTLS client certificate.
	// Returned chains should contain the leaf followed by all required
	// intermediates. The callback may be called concurrently and must not mutate
	// policy data.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	// MinVersion is the minimum permitted TLS version. Zero means TLS 1.2, which
	// is the package default rather than a request to inherit a future library
	// default.
	MinVersion uint16

	// MaxVersion is the maximum permitted TLS version. Zero lets crypto/tls use
	// its current maximum.
	MaxVersion uint16

	// CipherSuites optionally limits TLS 1.0 through TLS 1.2 cipher suites. TLS
	// 1.3 cipher suites are selected by crypto/tls and are not configurable.
	CipherSuites []uint16

	// CurvePreferences optionally limits key-exchange groups.
	CurvePreferences []tls.CurveID

	// NextProtos lists application protocols for ALPN negotiation.
	NextProtos []string

	// SessionCacheSize enables a new, policy-local LRU TLS client session cache
	// with this capacity. Zero disables client session resumption. Negative
	// values are invalid. The cache is never shared with another generated
	// configuration.
	SessionCacheSize int

	// Time optionally supplies the current time to crypto/tls. It must be safe
	// for concurrent use. Nil uses time.Now.
	Time func() time.Time

	// Verifiers contains additional checks run after normal verification,
	// authority scoping, and pins. They run in order and the first error aborts
	// the handshake.
	Verifiers []ServerConnectionVerifier
}

// TLSClientConfig returns a TLS client configuration for a transport that sets
// tls.Config.ServerName separately for every connection.
//
// This form is appropriate for net/http.Transport and similar multiplexing
// transports that clone the configuration and set ServerName for each
// connection. For direct tls.Client or tls.Dial use, call
// TLSClientConfigForServer instead. Verification fails with
// ErrMissingServerIdentity when no name is available.
//
// The dynamic form supports DNS hostnames, but not IP-literal destinations.
// crypto/tls uses an IP-valued Config.ServerName for SAN verification while
// intentionally omitting it from SNI; ConnectionState.ServerName is therefore
// empty and does not provide this callback with the expected IP. Use
// TLSClientConfigForServer for an IP-literal resource.
func (p *ServerPolicy) TLSClientConfig(
	options ClientTLSOptions,
) (*tls.Config, error) {
	return p.newTLSClientConfig(ServerIdentity{}, false, options)
}

// TLSClientConfigForServer returns a TLS client configuration fixed to
// serverName.
//
// serverName may be an ASCII DNS A-label or an IP address without a port. The
// returned config sets tls.Config.ServerName, so crypto/tls performs normal DNS
// or IP SAN verification before the policy callback runs.
func (p *ServerPolicy) TLSClientConfigForServer(
	serverName string,
	options ClientTLSOptions,
) (*tls.Config, error) {
	identity, err := ParseServerIdentity(serverName)
	if err != nil {
		return nil, err
	}
	return p.newTLSClientConfig(identity, true, options)
}

func (p *ServerPolicy) newTLSClientConfig(
	fixedIdentity ServerIdentity,
	fixed bool,
	options ClientTLSOptions,
) (*tls.Config, error) {
	if p == nil {
		return nil, errors.New("tlspolicy: nil ServerPolicy")
	}
	if err := validateTLSVersionRange(
		options.MinVersion,
		options.MaxVersion,
	); err != nil {
		return nil, err
	}
	if options.SessionCacheSize < 0 {
		return nil, errors.New(
			"tlspolicy: ClientTLSOptions.SessionCacheSize cannot be negative",
		)
	}

	verifiers := append([]ServerConnectionVerifier(nil), options.Verifiers...)
	for i, verifier := range verifiers {
		if interfaceIsNil(verifier) {
			return nil, fmt.Errorf(
				"tlspolicy: ClientTLSOptions.Verifiers[%d] is nil",
				i,
			)
		}
	}

	minVersion := options.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	config := &tls.Config{ // #nosec G402 -- TLS 1.2 is the documented default.
		Certificates:         cloneTLSCertificates(options.Certificates),
		GetClientCertificate: options.GetClientCertificate,
		RootCAs:              p.roots.Clone(),
		NextProtos:           append([]string(nil), options.NextProtos...),
		CipherSuites:         append([]uint16(nil), options.CipherSuites...),
		CurvePreferences: append(
			[]tls.CurveID(nil),
			options.CurvePreferences...),
		MinVersion:         minVersion,
		MaxVersion:         options.MaxVersion,
		Time:               options.Time,
		InsecureSkipVerify: false,
	}
	if fixed {
		config.ServerName = fixedIdentity.String()
	}
	if options.SessionCacheSize > 0 {
		config.ClientSessionCache = tls.NewLRUClientSessionCache(
			options.SessionCacheSize,
		)
	}

	config.VerifyConnection = func(state tls.ConnectionState) error {
		identity, err := identityForConnection(state, fixedIdentity, fixed)
		if err != nil {
			return err
		}

		verification, err := p.VerifyServer(identity, state)
		if err != nil {
			return err
		}
		for i, verifier := range verifiers {
			if err := verifier.VerifyServer(verification); err != nil {
				return fmt.Errorf(
					"tlspolicy: server connection verifier %d: %w",
					i,
					err,
				)
			}
		}
		return nil
	}

	return config, nil
}

func identityForConnection(
	state tls.ConnectionState,
	fixed ServerIdentity,
	hasFixed bool,
) (ServerIdentity, error) {
	if state.ServerName == "" {
		if hasFixed && fixed.Kind() == IdentityIP {
			// IP literals are used for certificate verification but are intentionally
			// omitted from the TLS SNI extension. crypto/tls therefore exposes an
			// empty ConnectionState.ServerName for a fixed IP configuration. The
			// closure-provided identity remains safe because VerifyServer repeats IP
			// SAN verification against it.
			return fixed, nil
		}
		if hasFixed {
			return ServerIdentity{}, fmt.Errorf(
				"%w: fixed identity is %s",
				ErrMissingServerIdentity,
				fixed,
			)
		}
		return ServerIdentity{}, ErrMissingServerIdentity
	}

	observed, err := ParseServerIdentity(state.ServerName)
	if err != nil {
		return ServerIdentity{}, fmt.Errorf(
			"tlspolicy: parse TLS ServerName: %w",
			err,
		)
	}
	if hasFixed && observed != fixed {
		return ServerIdentity{}, fmt.Errorf(
			"tlspolicy: TLS ServerName %s differs from fixed policy identity %s",
			observed,
			fixed,
		)
	}
	return observed, nil
}

// ClientAuthMode selects the mTLS client-certificate requirement installed by
// ClientPolicy.ServerTLSConfig.
type ClientAuthMode uint8

const (
	// ClientAuthNone does not request a client certificate.
	ClientAuthNone ClientAuthMode = iota

	// ClientAuthVerifyIfGiven requests a client certificate and verifies it when
	// the client supplies one, but also permits clients without a certificate.
	ClientAuthVerifyIfGiven

	// ClientAuthRequireAndVerify requires a client certificate and verifies it.
	ClientAuthRequireAndVerify
)

// String returns a stable human-readable name for m.
func (m ClientAuthMode) String() string {
	switch m {
	case ClientAuthNone:
		return "none"
	case ClientAuthVerifyIfGiven:
		return "verify-if-given"
	case ClientAuthRequireAndVerify:
		return "require-and-verify"
	default:
		return fmt.Sprintf("ClientAuthMode(%d)", uint8(m))
	}
}

// ServerTLSOptions contains non-trust settings for a TLS server configuration.
//
// ClientCAs, ClientAuth, and VerifyConnection are owned by ClientPolicy and
// ClientAuthMode. The returned tls.Config must not be modified after first use.
type ServerTLSOptions struct {
	// Certificates contains the server certificate chains. The first certificate
	// in each chain must be the leaf, followed by all required intermediates; the
	// root should normally be omitted. Certificate byte slices are copied.
	Certificates []tls.Certificate

	// GetCertificate optionally selects a server certificate from ClientHello.
	// Returned chains should contain the leaf followed by all required
	// intermediates and normally omit the root.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// ClientAuth selects whether an mTLS client certificate is optional,
	// required, or not requested.
	ClientAuth ClientAuthMode

	// MinVersion is the minimum permitted TLS version. Zero means TLS 1.2.
	MinVersion uint16

	// MaxVersion is the maximum permitted TLS version. Zero lets crypto/tls use
	// its current maximum.
	MaxVersion uint16

	// CipherSuites optionally limits TLS 1.0 through TLS 1.2 cipher suites.
	CipherSuites []uint16

	// CurvePreferences optionally limits key-exchange groups.
	CurvePreferences []tls.CurveID

	// NextProtos lists application protocols for ALPN negotiation.
	NextProtos []string

	// SessionTicketsDisabled disables server-side TLS session tickets and PSK
	// resumption. VerifyConnection runs on resumptions, so disabling tickets is
	// not required for policy enforcement, but may be appropriate operationally.
	SessionTicketsDisabled bool

	// Time optionally supplies the current time to crypto/tls. Nil uses time.Now.
	Time func() time.Time

	// Verifiers contains additional checks for a presented and normally verified
	// client certificate. Verifiers are not called when ClientAuthVerifyIfGiven
	// permits a connection without a certificate.
	Verifiers []ClientConnectionVerifier
}

// ServerTLSConfig combines p with options and returns a TLS server
// configuration.
//
// The configuration always has a non-nil ClientCAs pool. For verification
// modes, an empty ClientPolicy therefore rejects every client chain rather than
// falling back to operating-system roots. At least one server certificate or a
// GetCertificate callback must be configured.
func (p *ClientPolicy) ServerTLSConfig(
	options ServerTLSOptions,
) (*tls.Config, error) {
	if p == nil {
		return nil, errors.New("tlspolicy: nil ClientPolicy")
	}
	if len(options.Certificates) == 0 && options.GetCertificate == nil {
		return nil, errors.New(
			"tlspolicy: ServerTLSOptions requires Certificates or GetCertificate",
		)
	}
	if err := validateTLSVersionRange(
		options.MinVersion,
		options.MaxVersion,
	); err != nil {
		return nil, err
	}

	var clientAuth tls.ClientAuthType
	switch options.ClientAuth {
	case ClientAuthNone:
		clientAuth = tls.NoClientCert
	case ClientAuthVerifyIfGiven:
		clientAuth = tls.VerifyClientCertIfGiven
	case ClientAuthRequireAndVerify:
		clientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fmt.Errorf(
			"tlspolicy: unsupported ClientAuthMode %s",
			options.ClientAuth,
		)
	}

	verifiers := append([]ClientConnectionVerifier(nil), options.Verifiers...)
	if options.ClientAuth == ClientAuthNone && len(verifiers) != 0 {
		return nil, errors.New(
			"tlspolicy: client verifiers require an mTLS ClientAuth mode",
		)
	}
	for i, verifier := range verifiers {
		if interfaceIsNil(verifier) {
			return nil, fmt.Errorf(
				"tlspolicy: ServerTLSOptions.Verifiers[%d] is nil",
				i,
			)
		}
	}

	minVersion := options.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	config := &tls.Config{ // #nosec G402 -- TLS 1.2 is the documented default.
		Certificates:   cloneTLSCertificates(options.Certificates),
		GetCertificate: options.GetCertificate,
		ClientAuth:     clientAuth,
		ClientCAs:      p.roots.Clone(),
		NextProtos:     append([]string(nil), options.NextProtos...),
		CipherSuites:   append([]uint16(nil), options.CipherSuites...),
		CurvePreferences: append(
			[]tls.CurveID(nil),
			options.CurvePreferences...),
		SessionTicketsDisabled: options.SessionTicketsDisabled,
		MinVersion:             minVersion,
		MaxVersion:             options.MaxVersion,
		Time:                   options.Time,
	}

	if options.ClientAuth != ClientAuthNone {
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 &&
				options.ClientAuth == ClientAuthVerifyIfGiven {
				return nil
			}

			verification, err := p.VerifyClient(state)
			if err != nil {
				return err
			}
			for i, verifier := range verifiers {
				if err := verifier.VerifyClient(verification); err != nil {
					return fmt.Errorf(
						"tlspolicy: client connection verifier %d: %w",
						i,
						err,
					)
				}
			}
			return nil
		}
	}

	return config, nil
}

func validateTLSVersionRange(minVersion, maxVersion uint16) error {
	effectiveMin := minVersion
	if effectiveMin == 0 {
		effectiveMin = tls.VersionTLS12
	}
	if maxVersion != 0 && maxVersion < effectiveMin {
		return fmt.Errorf(
			"tlspolicy: maximum TLS version 0x%04x is below minimum 0x%04x",
			maxVersion,
			effectiveMin,
		)
	}
	return nil
}

func cloneTLSCertificates(certificates []tls.Certificate) []tls.Certificate {
	if certificates == nil {
		return nil
	}

	cloned := make([]tls.Certificate, len(certificates))
	for i, certificate := range certificates {
		cloned[i] = certificate
		cloned[i].Certificate = cloneByteSlices(certificate.Certificate)
		cloned[i].SupportedSignatureAlgorithms = append(
			[]tls.SignatureScheme(nil),
			certificate.SupportedSignatureAlgorithms...,
		)
		cloned[i].OCSPStaple = bytes.Clone(certificate.OCSPStaple)
		cloned[i].SignedCertificateTimestamps = cloneByteSlices(
			certificate.SignedCertificateTimestamps,
		)

		if certificate.Leaf != nil && len(certificate.Leaf.Raw) != 0 {
			if leaf, err := x509.ParseCertificate(
				bytes.Clone(certificate.Leaf.Raw),
			); err == nil {
				cloned[i].Leaf = leaf
			} else {
				// crypto/tls can parse Certificate[0] itself. Clearing Leaf is safer
				// than retaining a caller-owned, internally inconsistent object.
				cloned[i].Leaf = nil
			}
		}
	}
	return cloned
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = bytes.Clone(values[i])
	}
	return cloned
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() { //nolint:exhaustive // Only nilable kinds matter here.
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
