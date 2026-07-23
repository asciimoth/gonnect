// Package tlspolicy builds explicit, application-controlled TLS trust policies.
//
// The package is intended for applications that have several TLS clients or
// servers operating in different network contexts, such as a direct route, an
// HTTP CONNECT proxy, a SOCKS tunnel, or an isolated test network. It keeps two
// concerns separate:
//
//   - a network route decides how sockets and DNS requests leave the process;
//   - a compiled policy decides which certificate chains and pins are accepted.
//
// ServerPolicy is used by a TLS client to verify remote servers. It supports an
// explicit set of trust anchors, DNS- and IP-scoped trust anchors, constraints
// on intermediate certificate authorities, and leaf certificate or leaf SPKI
// pins. ClientPolicy is used by a TLS server to verify mTLS clients with an
// explicit set of client trust anchors and optional leaf pins.
//
// Both policy types compile their trust anchors into an ordinary pool created
// by x509.NewCertPool. An empty policy therefore means “trust no certificate”,
// not “fall back to the operating-system trust store”. The package never calls
// x509.SystemCertPool and never installs process-wide fallback roots.
//
// # No implicit certificate-network traffic
//
// The package contains no AIA, OCSP, or CRL downloader. Verification uses the
// certificates supplied by the peer and the explicitly configured pools. A
// peer that omits a required intermediate certificate fails verification.
// Standard crypto/x509 verification does not perform revocation checking.
//
// Additional verifier hooks are available for application-specific checks,
// including validation of a stapled OCSP response. Those hooks execute inside
// the TLS handshake. If a hook performs network I/O, the application is solely
// responsible for binding that I/O to the correct route and for preventing
// recursion, SSRF, direct-network fallback, and unbounded waits. A verifier
// that must preserve the package's no-network property should inspect only the
// supplied ConnectionState and local data.
//
// # Operating-system authority discovery
//
// AuthorityFetcher is deliberately only an interface. Platform-specific code
// may implement it by enumerating local certificate stores and exporting DER
// certificates. x509.CertPool.Subjects is not a certificate-export API and must
// not be used to obtain those DER values. FetchAuthorityCatalog validates and
// deduplicates the candidates for presentation to a user. This package contains
// no Windows, macOS, Linux, or other platform-specific store-enumeration
// implementation.
//
// A DER certificate discovered in an OS store is only a candidate. Importing
// it into an application pool does not reproduce every OS trust decision,
// distrust list, usage restriction, enterprise policy, automatic root-update
// rule, or application-specific exception. User interfaces should preserve
// AuthoritySource information and require an explicit application-policy
// decision before promoting a discovered certificate to a trust anchor.
//
// # Typical client use
//
// A client that talks to a fixed server can build a configuration whose
// ServerName is fixed by policy:
//
//	ca, err := tlspolicy.ParseAuthorityDER(rootDER)
//	if err != nil {
//		return err
//	}
//
//	scope, err := tlspolicy.NewDNSDomainScope("gov.example", true)
//	if err != nil {
//		return err
//	}
//
//	policy, err := tlspolicy.CompileServerPolicy(tlspolicy.ServerPolicySpec{
//		TrustAnchors: []tlspolicy.ScopedAuthority{{
//			Authority: ca,
//			Scope:     scope,
//		}},
//	})
//	if err != nil {
//		return err
//	}
//
//	tlsConfig, err := policy.TLSClientConfigForServer(
//		"service.gov.example",
//		tlspolicy.ClientTLSOptions{},
//	)
//	if err != nil {
//		return err
//	}
//
// For net/http clients that can contact several hosts, use TLSClientConfig.
// The shared configuration form requires a DNS hostname. For an IP-literal
// server, use TLSClientConfigForServer because crypto/tls intentionally omits
// IP literals from SNI and does not expose the expected IP through
// ConnectionState.ServerName.
//
// # Typical server use
//
// CompileClientPolicy builds the trust policy for mTLS client certificates.
// ServerTLSConfig then combines that policy with the server's certificate and
// a ClientAuthMode. Even when the policy contains no roots, ClientCAs remains a
// non-nil empty pool, so verification fails closed instead of using host roots.
//
// # Immutability and sharing
//
// Compiled policies are immutable and safe for concurrent use. The returned
// tls.Config and http.Transport values must be completely configured before
// first use and must not be mutated afterward. In particular, callers must not
// replace RootCAs, ClientCAs, ServerName, VerifyConnection, DialContext, Proxy,
// or the TLS dial hooks installed by this package.
//
// A ClientTLSOptions session cache is created per generated configuration.
// Do not manually share a tls.ClientSessionCache between trust policies. The
// package uses VerifyConnection rather than VerifyPeerCertificate, so scoped
// authority and pin checks also run on resumed TLS sessions.
//
// # DNS names
//
// Policy DNS names must be ASCII DNS A-labels, such as xn--bcher-kva.example,
// not Unicode U-labels. Names are lowercased and a final root dot is removed.
// Wildcards are not accepted in policy rules. Subdomain matching is expressed
// explicitly with DNSRule.IncludeSubdomains and always respects label
// boundaries.
package tlspolicy
