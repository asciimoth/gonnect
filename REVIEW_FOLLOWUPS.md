# Review Follow-ups

This file records code-review findings that were not fixed in the
documentation-only pass. `go test ./...` and `go vet ./...` passed during the
review.

## Security and Policy

- `native.go`: `NativeConfig.Build` overwrites the resolver dialer created from
  `ResolverCfg`. Preserve the configured DNS server and caller dialer while
  still applying filtering.
- `native.go`: `NativeNetwork.Dial` filters the original address before Go
  resolves it. Pre-resolve and filter the final IP endpoint so a hostname cannot
  bypass IP/CIDR deny rules.
- `dns/ip_packet_adapter.go` and `dns/transport.go`: DNS packet paths create
  one worker per packet and can wait on a slow upstream without a per-request
  timeout. Add concurrency limits, backpressure, and configurable deadlines.
- `dns/transport.go`: DNS clients generate an upstream query ID but accept any
  response ID. Reject UDP, TCP, and DoT responses whose ID does not match the
  generated ID.
- `sockowner/sockowner_windows.go`: UDP owner lookup matches only local address
  and port and returns the first row. Detect multiple matching owners and return
  an ambiguity error.
- `sockopt`: routing marks and interface binding can report success when no
  socket option was applied. Propagate `SetsockoptInt` errors and return
  `ErrUnsupported` when the input or network type cannot be handled.

## Correctness

- `dns/router.go`: route mutations can race with a route function call. Snapshot
  a generation or `done` channel and cancel work if it changes before backend
  lookup.
- `tun/forwarder.go`: `SetReadTun` and `SetWriteTun` send config messages while
  holding `f.mu`. Avoid channel sends under the mutex to prevent shutdown
  deadlocks.
- `loopback.go`: IPv6 localhost lookup uses `To4()` on `::1`, which creates an
  invalid `netip.Addr`. Use `netip.MustParseAddr("::1")` or `To16()`.
- `dns/wire.go`: invalid DNS names are encoded as root. Make name conversion
  return an error and propagate it from `Pack`.

## Test Helpers

- `testing/udp.go`: round numbering and missing-reply handling can let the
  helper pass while packets were lost. Align the final-round check with client
  sequence numbers and fail on missing replies.
- `testing/tcp.go`, `testing/http.go`, and `testing/udp.go`: network-pair
  helpers use `b.Addr` when listening on `a.Network`. Use `a.Addr` with
  `a.Network` and `b.Addr` with `b.Network`.
- `testing/http.go`: `RunSimpleHTTPTestForNetworks` defers `lnA.Close` twice.
  Defer `lnB.Close` for the second listener.
