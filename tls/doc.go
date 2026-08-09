// Package tls provides Network middlewares for outgoing TLS interception.
//
// The middleware is intended for code that accepts a gonnect.Network but does
// not let its caller provide a tls.Config. It detects client-first TLS traffic
// on TCP Dial and DialTCP connections, terminates the client TLS session with a
// leaf certificate signed by a configured CA, and opens a new upstream TLS
// session through the wrapped Network with the configured client tls.Config.
// This lets the owner of the Network enforce root CAs, TLS versions, client
// certificates, and other client TLS settings while preserving the visible SNI
// host and ALPN offer from the original ClientHello.
//
// The client that uses the returned connection must trust the CA supplied to
// this package. The CA private key must be kept private.
//
// Only TLS ClientHello messages with a visible SNI host and no encrypted client
// hello signal can be intercepted. TLS traffic without visible SNI, with ECH,
// malformed TLS, or over the configured sniff limit is rejected. Non-TLS TCP
// traffic that sends client bytes first is passed through unchanged. UDP,
// listen operations, resolver calls, and interface calls are delegated to the
// wrapped Network.
//
// Use Config.InterceptionFilter to limit which TLS connections are intercepted.
// Inclusive filtering intercepts only matching rules. Exclusive filtering
// intercepts all TLS connections except matching rules. Connections filtered
// out by this policy are copied unchanged through the wrapped Network, including
// TLS connections that have no visible SNI or that carry the ECH signal.
//
// Server-first TCP protocols are out of scope. The bridge waits for the first
// client bytes before it can decide whether to intercept TLS or pass bytes
// through. If a caller can dial a server-first protocol through this Network, it
// should use connection deadlines or another timeout policy and close the
// connection when the timeout expires.
//
// Deadlines set on a returned connection apply to reads and writes on that
// returned connection. They are not copied to the hidden upstream socket after
// Dial or DialTCP returns. Close the returned connection to abort hidden
// upstream work.
//
// Terminator is a narrower middleware. It also terminates client TLS with a
// generated certificate, but it does not create a new upstream TLS connection.
// Instead it dials plaintext TCP through the wrapped Network. It rejects
// non-TLS TCP, TLS it cannot intercept, and all operations except TCP Dial and
// DialTCP. Use other gonnect.Network middlewares before or after Terminator for
// filtering, routing, and DNS policy.
package tls
