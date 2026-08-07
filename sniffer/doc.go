// Package sniffer incrementally classifies the client-first prefix of a stream
// while restoring every inspected byte to a putback.Conn before returning.
//
// Classifiers are state machines. Sniff reads into the caller's buffer in normal
// batches, then feeds each active classifier one byte at a time in stream order.
// State is checked after every byte, making classification independent of
// net.Conn Read chunking. Sniff stops when a classifier reports Match, every
// classifier reports Mismatch, the caller-provided buffer is exhausted, or the
// connection returns an error. The complete read prefix is put back on every
// return path, so another sniffer or the selected protocol handler sees the
// original byte sequence.
//
// SniffWithPool and SniffFactoriesWithPool allocate the temporary inspection
// buffer from a bufpool.Pool. Pass the same pool to putback.New when restored
// bytes should also use pooled storage.
//
// Classifiers and factories report MinSniffBufferSize. Use MinSniffBufferSize
// or MinFactorySniffBufferSize to select a buffer large enough for the
// classifiers you pass to Sniff. ClassifierFunc and FactoryFunc report 0 by
// default; use WithMinSniffBufferSize or FactoryWithMinSniffBufferSize when
// they need a non-zero size.
//
// HTTP and HTTPFactory match HTTP request lines. HTTPWithConfig and
// HTTPFactoryWithConfig can also filter by exact or multi-value methods, exact
// or glob URL request-targets, HTTP-version tokens, normalized hostnames, and
// request-line or header byte limits.
//
// TLS and TLSFactory match TLS ClientHello records. TLSWithConfig and
// TLSFactoryWithConfig can also filter by offered TLS versions, visible SNI
// availability, encrypted_client_hello extension presence, visible SNI
// hostnames, ALPN protocol names, and ClientHello byte limits. TLS version
// filters match versions offered by the ClientHello, not the server-selected
// version.
//
// Sniff owns neither timeouts nor policy. Callers should set and clear read
// deadlines on the connection as appropriate. A deadline error is returned as
// the connection's read error. Use gonnect.IsTimeout to identify timeout errors
// when timeout means fallback for the caller. Buffer exhaustion is a normal
// NoMatch result.
//
// Important limitations:
//
//   - Only client-first information can be classified. A server-first protocol,
//     or a client that waits for the server, produces no bytes to inspect. A
//     caller must use metadata, a deadline, or a fallback route for that case.
//   - Some prefixes are fundamentally ambiguous. If one protocol's complete
//     signature is a prefix of another's, an immediate Match may select the
//     shorter classifier. Sniff returns as soon as any classifier matches; it
//     does not wait to learn whether a NeedMore classifier might match later.
//     If several classifiers match after the same byte, the lowest index wins.
//   - TCP read boundaries have no protocol meaning. A classifier must handle
//     every fragmentation and coalescing when used outside Sniff and must not
//     assume that one Feed call corresponds to one packet or protocol field.
//   - Classifiers cannot return errors. Malformed, unsupported, or over-limit
//     input must become Mismatch. The only errors returned by Sniff come from
//     Conn.Read. EOF is returned to the caller; it is not fed to classifiers.
//   - Sniff restores bytes, not external side effects. Classifiers must not read
//     from or write to the connection themselves, and Feed input is read-only.
//   - The caller must give Sniff exclusive ownership of the connection's read
//     side until it returns. Concurrent readers can consume bytes that cannot
//     be attributed or restored safely.
//   - A putback.Conn preserves byte order, but buffered bytes do not call the
//     wrapped connection. Read deadlines and raw socket state are observed only
//     after the put-back buffer drains.
package sniffer
