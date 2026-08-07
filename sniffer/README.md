# sniffer

`sniffer` classifies the client-first prefix of a `net.Conn` without consuming
that prefix from the next handler. It reads from a `putback.Conn`, then puts all
inspected bytes back before it returns.

## Classifiers

A classifier is an incremental state machine:

```go
type Classifier interface {
	MinSniffBufferSize() int
	Feed(next []byte) State
}
```

`MinSniffBufferSize` reports the byte count that lets the classifier make its
bounded decision.

`Feed` receives only newly read bytes. Its result is one of:

- `NeedMore`: the prefix is still possible but incomplete.
- `Match`: the classifier has matched.
- `Mismatch`: no future suffix can make it match.

`Match` and `Mismatch` are terminal. `Feed(nil)` queries the initial or current
state. The slice passed to `Feed` is read-only and can be reused after the call.

Factories create a fresh classifier for each connection:

```go
type Factory interface {
	MinSniffBufferSize() int
	NewClassifier() Classifier
}
```

The factory size is the size needed by the classifiers it creates.

Included building blocks:

- `Prefix` and `PrefixFactory`
- `SSH` and `SSHFactory`, which match `SSH-` at offset zero
- `And`, `Or`, and `Not`
- `AndFactory`, `OrFactory`, and `NotFactory`
- `Limit` and `LimitFactory` for classifier-local byte limits
- `MinSniffBufferSize` and `MinFactorySniffBufferSize` helpers
- `WithMinSniffBufferSize` and `FactoryWithMinSniffBufferSize` wrappers for
  function adapters or other classifiers that need a non-zero size

## Sniffing and routing

```go
func route(raw net.Conn, pool bufpool.Pool) error {
	conn := putback.New(raw, pool)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}

	factories := []sniffer.Factory{
		sniffer.PrefixFactory([]byte("GET ")),
		sniffer.SSHFactory(),
	}
	index, err := sniffer.SniffFactoriesWithPool(
		sniffer.MinFactorySniffBufferSize(factories...),
		pool,
		conn,
		factories...,
	)

	if clearErr := conn.SetReadDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	if err != nil {
		if gonnect.IsTimeout(err) {
			return proxyToOriginalDestination(conn)
		}
		return err
	}

	switch index {
	case 0:
		return handleHTTP(conn)
	case 1:
		return proxySSH(conn)
	case sniffer.NoMatch:
		return proxyToOriginalDestination(conn)
	default:
		panic("unreachable")
	}
}
```

`SniffWithPool` and `SniffFactoriesWithPool` get the scratch buffer from
`bufpool` and return it before they return. Pass the same pool to `putback.New`
if replay copies must also use the pool. Call `Sniff` or `SniffFactories`
directly when the caller already owns the scratch buffer.

When a scratch buffer is passed directly, its contents are ignored on entry and
can be overwritten. The buffer length, not capacity, is the total inspection
limit. A zero-length buffer returns `NoMatch` unless a classifier matches on
`Feed(nil)`.

Every byte read by `Sniff` is copied back before it returns. This is true for
match, no-match, buffer-exhaustion, and read-error paths. You can chain
sniffers on the same wrapper:

```go
index, err := sniffer.SniffWithPool(tlsBudget, pool, conn, tlsClassifier)
if err != nil {
	return err
}
if index == sniffer.NoMatch {
	classifiers := []sniffer.Classifier{
		httpClassifier,
		sniffer.SSH(),
	}
	index, err = sniffer.SniffWithPool(
		sniffer.MinSniffBufferSize(classifiers...),
		pool,
		conn,
		classifiers...,
	)
}
```

## Incomplete prefixes

If a classifier needs four bytes and the peer sends only three, the only correct
state is `NeedMore`. The next byte can complete the signature, or the peer can
be using another protocol.

The caller must set the policy boundary. A common policy treats a classification
timeout as fallback and returns other read errors:

```go
_ = conn.SetReadDeadline(time.Now().Add(classificationBudget))
index, err := sniffer.SniffFactoriesWithPool(
	classificationMaxBytes,
	pool,
	conn,
	factories...,
)
_ = conn.SetReadDeadline(time.Time{})

if err != nil {
	if gonnect.IsTimeout(err) {
		return proxyToOriginalDestination(conn)
	}
	return err
}
```

Use an absolute caller-owned classification deadline. Do not reset it after
every byte, because a slow peer can keep an ambiguous connection alive without
end.

## Match selection

`Sniff` performs normal batched connection reads, but feeds classifiers one byte
at a time and checks their states after every byte. The route does not depend on
how TCP splits the stream across `Read` calls.

`Sniff` returns as soon as any classifier reports `Match`. If several classifiers
match after the same byte, the lowest index wins. It does not wait for a
lower-index classifier that still reports `NeedMore`.

For example, with `Prefix("AB")` followed by `Prefix("A")`, input `A` selects
the second classifier immediately, even when `AB` arrived in one underlying
`Read`. List order only breaks matches observed at the same byte position. It
is not a longest-match parser. Use a combined classifier when overlapping
signatures require another policy.

## Limits

- Server-first or silent-client protocols have no client bytes to classify. Use
  listener metadata, original-destination metadata, a caller-owned deadline, or
  a fallback route.
- Some prefixes are ambiguous. Only more bytes or an external policy boundary
  can decide them.
- `Sniff` has a fixed caller-provided budget. Complex classifiers must also
  enforce their own field or header limits.
- TCP is a byte stream. Classifiers must not attach protocol meaning to `Read`
  boundaries.
- Classifiers must not perform connection I/O, mutate the read-only `Feed`
  slice, or mutate external protocol state.
- EOF is returned by `Sniff`; it is not fed to classifiers.
- `Sniff` requires exclusive read-side ownership until it returns.
- Put-back bytes are returned without calling the wrapped connection. Its read
  deadline is observed after the put-back buffer drains.

SNI, HTTP request lines, PROXY protocol, and similar formats should be bounded
incremental classifiers. Malformed or over-limit input should return
`Mismatch`. Classifier errors are intentionally not part of the API. Only errors
returned by `Conn.Read` are returned from `Sniff`.
