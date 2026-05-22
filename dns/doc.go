// Package dns provides a channel-based DNS message interface and adapters for
// composing DNS providers, consumers, and middleware.
//
// The central contract is Interface. Implementations expose a request channel;
// every Request carries its own context and reply channel, so callers can cancel
// one request without closing the whole provider. Providers and middleware are
// safe for concurrent consumers unless a concrete type documents otherwise.
//
// The package includes detached middleware, a request router, resolver
// adapters, an in-memory cache middleware, a simple UDP/TCP DNS client, and a
// simple UDP DNS server. These pieces are intentionally small and composable so
// callers can build chains or trees such as resolver adapters feeding shared
// cache middleware that fans out to local or remote DNS transports.
package dns
