package tlspolicy

import "errors"

var (
	// ErrMissingServerIdentity is returned when a shared TLS client
	// configuration reaches verification without a ServerName. This usually
	// means the caller used tls.Client directly without setting Config.ServerName
	// or used a transport that did not populate it.
	ErrMissingServerIdentity = errors.New(
		"tlspolicy: missing remote server identity",
	)

	// ErrNoVerifiedChains is returned when a policy is asked to inspect a
	// connection for which normal crypto/tls certificate verification did not
	// produce any chain. Policy-generated configurations keep normal
	// verification enabled, so this generally indicates manual misuse.
	ErrNoVerifiedChains = errors.New(
		"tlspolicy: normal TLS verification produced no certificate chain",
	)

	// ErrServerIdentityMismatch is returned when the leaf certificate in an
	// otherwise verified chain is not valid for the ServerIdentity supplied to
	// ServerPolicy.VerifyServer. Policy-generated TLS configurations already ask
	// crypto/tls to perform this check; VerifyServer repeats it so direct callers
	// cannot accidentally apply domain-scoped trust to a chain verified for a
	// different name or IP address.
	ErrServerIdentityMismatch = errors.New(
		"tlspolicy: server certificate does not match the policy identity",
	)

	// ErrUnauthorizedChain is returned when normal PKI verification succeeded,
	// but every verified chain violates a scoped trust-anchor or authority rule.
	ErrUnauthorizedChain = errors.New(
		"tlspolicy: no verified certificate chain is authorized by policy",
	)

	// ErrPinMismatch is returned when at least one pin applies to the peer but
	// none of the applicable pins matches the leaf certificate.
	ErrPinMismatch = errors.New("tlspolicy: peer certificate pin mismatch")
)
