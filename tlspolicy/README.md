# tlspolicy

`tlspolicy` builds explicit, per-context TLS trust policies for Go clients and
servers. It is designed for applications that may have several network routes
and must not silently fall back to the operating-system trust store or perform
certificate-related network lookups outside the selected route.

The module requires Go 1.23 or newer and has no third-party dependencies.

## Guarantees of the core package

- Every server-root and mTLS client-root pool starts with `x509.NewCertPool()`.
- An empty root selection means “trust nobody”; it never means “use system roots”.
- The package never calls `x509.SystemCertPool` or `x509.SetFallbackRoots`.
- The package contains no AIA, OCSP, or CRL downloader.
- Missing intermediates fail verification.
- Pins are additional to normal PKI and hostname verification.
- Scoped authority and pin checks run from `tls.Config.VerifyConnection`, so
  they also run on resumed sessions.

These guarantees do not cover application-provided verifier callbacks or
`AuthorityFetcher` implementations. A callback or fetcher can perform network
I/O if its implementation chooses to do so.

## Discovering OS-store candidates

The package contains no platform-specific store code. Implement
`AuthorityFetcher` in build-tagged files in the application or a separate
module:

```go
type windowsStoreFetcher struct {
    // Platform-specific options belong here.
}

func (f *windowsStoreFetcher) FetchAuthorities(
    ctx context.Context,
) ([]tlspolicy.AuthorityCandidate, error) {
    // Enumerate local store objects and copy each certificate's complete DER.
    // Do not build paths or invoke online retrieval as part of enumeration.
    panic("platform-specific implementation")
}
```

Then create a deduplicated catalog for the policy UI:

```go
catalog, err := tlspolicy.FetchAuthorityCatalog(ctx, fetcher)
if err != nil {
    return err
}

for _, record := range catalog.Records() {
    fmt.Printf("%s  %s  %v\n",
        record.Subject,
        record.CertificateFingerprint,
        record.Sources,
    )
}
```

The fetcher must export complete certificate DER. `x509.CertPool.Subjects` is
not a certificate export API and must not be used for this purpose.

A source's `TrustHint` is display metadata, not an application trust decision.
Importing DER into a Go pool does not copy every platform-specific distrust,
usage restriction, enterprise rule, or automatic root-update behavior.

## Building a scoped remote-server policy

```go
root, err := tlspolicy.ParseAuthorityDER(selectedRootDER)
if err != nil {
    return err
}

govScope, err := tlspolicy.NewDNSDomainScope("gov.example", true)
if err != nil {
    return err
}

policy, err := tlspolicy.CompileServerPolicy(tlspolicy.ServerPolicySpec{
    TrustAnchors: []tlspolicy.ScopedAuthority{
        {
            Authority: root,
            Scope:     govScope,
        },
    },
})
if err != nil {
    return err
}
```

The root above can authenticate only `gov.example` and its subdomains.

Anchor scoping restricts chains that terminate at that exact root. To restrict a
CA regardless of which cross-signed path contains it, add an
`AuthorityConstraint`, commonly with `MatchSPKI`:

```go
constraint := tlspolicy.AuthorityConstraint{
    Authority: governmentCA,
    Match:     tlspolicy.MatchSPKI,
    Scope:     govScope,
}
```

SPKI matching is intentionally broader than exact-certificate matching. Review
all certificates sharing that key before using it.

## Pinning a resource

```go
pin, err := tlspolicy.NewSPKIPin(expectedLeafDER)
if err != nil {
    return err
}

resourceScope, err := tlspolicy.NewExactServerScope("api.example.test")
if err != nil {
    return err
}

policy, err := tlspolicy.CompileServerPolicy(tlspolicy.ServerPolicySpec{
    TrustAnchors: selectedAnchors,
    Pins: []tlspolicy.ScopedPin{
        {Pin: pin, Scope: resourceScope},
    },
})
```

When several pins apply to one server, they are alternatives. Keep an old and a
new pin active during key rotation. A certificate pin changes on every
reissuance; an SPKI pin survives renewal only when the key is retained.

## Fixed-server TLS client

```go
tlsConfig, err := policy.TLSClientConfigForServer(
    "api.example.test",
    tlspolicy.ClientTLSOptions{
        MinVersion:       tls.VersionTLS13,
        SessionCacheSize: 64,
    },
)
if err != nil {
    return err
}

conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
```

Use the fixed-server form with `tls.Dial`, `tls.Client`, or another caller that
does not automatically set `ServerName`.

The fixed-server form also supports IP literals. Go uses an IP-valued
`tls.Config.ServerName` for IP SAN verification but does not send it as SNI, so
the package carries the fixed IP identity into its policy callback explicitly.

## mTLS server

```go
clientRoot, err := tlspolicy.ParseAuthorityDER(clientRootDER)
if err != nil {
    return err
}

clientPolicy, err := tlspolicy.CompileClientPolicy(
    tlspolicy.ClientPolicySpec{
        TrustAnchors: []tlspolicy.Authority{clientRoot},
    },
)
if err != nil {
    return err
}

serverTLS, err := clientPolicy.ServerTLSConfig(
    tlspolicy.ServerTLSOptions{
        Certificates: []tls.Certificate{serverCertificate},
        ClientAuth:   tlspolicy.ClientAuthRequireAndVerify,
    },
)
```

`ClientCAs` remains non-nil even if the selected root list is empty. An empty
mTLS policy therefore rejects every client chain.

## Stapled OCSP and other local checks

The core package deliberately has no OCSP dependency. Add a
`ServerConnectionVerifier` to validate `ConnectionState.OCSPResponse` with a
library and freshness policy selected by the application:

```go
options.Verifiers = []tlspolicy.ServerConnectionVerifier{
    tlspolicy.ServerConnectionVerifierFunc(func(v tlspolicy.ServerVerification) error {
        // Validate v.ConnectionState.OCSPResponse against an issuer from
        // v.AuthorizedChains. Do not contact the network here unless that
        // traffic is explicitly routed and bounded.
        return nil
    }),
}
```

The `ConnectionState.VerifiedChains` delivered to additional verifiers is
filtered to the same authorized chains exposed in `AuthorizedChains`.

## Operational rules

- Treat compiled policies as immutable.
- Do not replace the roots, identity, verification callback, proxy, dialer, or
  TLS dial hooks installed by the package.
- Keep a separate client session cache per policy; the package does this when
  `SessionCacheSize` is positive.
- Servers must send the leaf followed by all required intermediates and should
  omit the root.
- Store selected DER and policy scopes in application configuration. Refreshing
  an OS-store catalog should not silently expand an existing policy.

## Verification

```sh
go test ./...
go test -race ./...
go vet ./...
```
