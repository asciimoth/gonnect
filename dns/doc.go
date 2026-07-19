// Package dns provides a channel-based DNS message interface and adapters for
// composing DNS providers, consumers, and middleware.
//
// The central contract is Interface. Implementations expose a request channel;
// every Request carries its own context and reply channel, so callers can cancel
// one request without closing the whole provider. Providers and middleware are
// safe for concurrent consumers unless a concrete type documents otherwise.
//
// The package includes detached middleware, a request router, resolver
// adapters, an in-memory cache middleware, a simple UDP/TCP DNS client, a
// simple UDP DNS server, and a raw IP packet adapter for UDP DNS requests.
// These pieces are intentionally small and composable so callers can build
// chains or trees such as resolver adapters feeding shared cache middleware
// that fans out to local or remote DNS transports.
//
// Cache can optionally synthesize reverse PTR cache entries from successful
// A and AAAA responses. Pass false for NewCache's enableReverseLookups
// argument unless this disclosure is acceptable: enabling it can reveal
// forward lookup history to other consumers sharing the same cache, because a
// consumer can probe reverse lookups for selected addresses to infer whether
// another consumer recently resolved associated hostnames.
//
// Cache can also use its CacheStorage in write-only mode. This lets one DNS
// path warm shared storage without serving entries that another path wrote.
package dns
