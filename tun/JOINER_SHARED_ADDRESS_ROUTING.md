# `Joiner` shared-address routing contract

## Purpose

This document defines the public behavior of shared-address routing. It is a
baseline for later changes to the routing data structures and packet parser.
An optimization can change the implementation. It must not change this
behavior unless the public contract and its tests change together.

Shared-address routing solves this case:

```text
nested Tun A: 192.0.2.10:41001 -> 198.51.100.20:443
nested Tun B: 192.0.2.10:51820 -> 203.0.113.30:41641
```

Both nested Tuns use `192.0.2.10`. Return traffic must go to the Tun that sent
the related outbound traffic.

## Enable the mode

The existing constructor keeps address-only routing:

```go
joiner := tun.NewJoiner(spawner, pool)
```

Call `NewJoinerWithOptions` to enable shared-address routing:

```go
joiner := tun.NewJoinerWithOptions(spawner, pool, tun.JoinerOptions{
	SharedAddressRouting: true,
	FlowTimeout:          5 * time.Minute,
	MaxFlowEntries:       64 * 1024,
})
```

A zero or negative timeout selects `DefaultJoinerFlowTimeout`. A zero or
negative entry limit selects `DefaultJoinerMaxFlowEntries`.

## Packet directions

This contract uses these direction terms:

- An outbound packet is read by `Joiner` from a nested Tun.
- An inbound packet is written by a caller to `Joiner`.

For a usable outbound flow, `Joiner` records the nested Tun for the reverse
flow. For example:

```text
outbound: TCP 192.0.2.10:41001 -> 198.51.100.20:443, owner A
inbound:  TCP 198.51.100.20:443 -> 192.0.2.10:41001, route to A
```

## Routing precedence

When shared-address routing is enabled, an inbound packet uses the first route
that matches:

1. A fragment route for a non-first fragment.
2. A reverse-flow route.
3. The learned destination-address route.
4. The current default nested Tun.
5. A successful drop if no route exists.

The address and default routes are required fallbacks. They handle malformed
packets, unsupported protocols, incomplete packet quotes, expired flows, and
non-first fragments that arrive before the first fragment.

When shared-address routing is disabled, `Joiner` uses only steps 3 through 5.
This preserves the behavior of `NewJoiner`.

## Flow identity

TCP and UDP flows use all of these values:

- IP version;
- transport protocol;
- local IP address and port;
- remote IP address and port.

IPv4 and IPv6 flows are separate. TCP and UDP flows are also separate. Two
flows to the same remote address and port stay separate when their local ports
differ.

ICMPv4 and ICMPv6 echo flows use the IP version, protocol, source and
destination addresses, echo type, and echo identifier. An echo request records
a route for the related echo reply. An outbound echo reply also records a route
for a later request with the same identity.

## ICMP errors

An inbound ICMP error can select a flow from the original packet quoted in its
payload. The quoted packet must contain a usable TCP or UDP flow key. This
applies to ICMPv4 and ICMPv6 errors.

If the quote is too short or does not contain a supported flow, routing uses
the normal address or default fallback. The outer ICMP source address does not
have to equal the remote address in the quoted flow. Thus, an error from an
intermediate router can still reach the correct nested Tun.

## IP headers and fragments

The flow parser supports IPv4 headers with options. For IPv6, it walks these
extension headers before the transport header:

- Hop-by-Hop Options;
- Routing;
- Destination Options;
- Fragment;
- Authentication Header.

Unknown or incomplete extension chains use fallback routing.

The first inbound IPv4 or IPv6 fragment must contain the transport ports. It
selects the flow owner and records a fragment route. Later fragments use the IP
version, source address, destination address, fragment identity, and applicable
next-header value to select that owner.

If a non-first fragment arrives before the first fragment, it uses address or
default fallback. `Joiner` does not delay fragments or perform IP reassembly.

## Collision policy

Independent stacks can create the same complete flow identity. `Joiner` does
not translate source ports. It therefore cannot distinguish return packets for
such flows.

The first active owner wins. A later outbound packet with the same identity
from another nested Tun does not replace or refresh the first owner's route.
The first owner remains until one of these events occurs:

- the route expires;
- the route is evicted;
- the owner is detached;
- the `Joiner` closes.

Inbound matching traffic refreshes the selected route. Because the inbound
packet is ambiguous, it refreshes the first owner. `FlowCollisions` increases
when `Joiner` detects a different outbound owner for an active identity.

Guaranteed isolation for identical identities requires NAT-style translation.
That translation is not part of this contract.

## Lifetime and capacity

Flow and fragment routes expire after the configured period without matching
traffic. Matching outbound or inbound traffic refreshes a route. Expiration is
lazy: `Joiner` removes expired routes during later routing, learning, or
`RoutingStats` calls. The observable routing result is the same as immediate
expiration.

Flow and fragment routes share one hard entry limit. At the limit, adding a
route removes the least recently used route. The limit does not apply to the
compatibility address table.

Detaching a nested Tun removes all address, flow, and fragment routes owned by
that Tun before `Detach` returns. Replacing the default Tun has the same cleanup
behavior for the old default Tun. Closing the `Joiner` removes all active
routes.

## Batches and concurrency

Each packet in a `Write` batch is routed independently. A batch can contain
packets for different nested Tuns. Shared-address routing does not add stronger
partial-write guarantees than the existing `Joiner.Write` contract.

Packets in nested read batches are learned with the owner of that read. Traffic
from one nested Tun must not replace an unrelated flow owner for another nested
Tun, even when reads happen concurrently.

Flow lookup, refresh, expiration, eviction, attach, detach, and close are safe
to use with concurrent `Read` and `Write` calls.

## Diagnostics contract

`RoutingStats` returns cumulative counters and current active entry counts:

| Field | Meaning |
| --- | --- |
| `ActiveFlows` | Current reverse-flow routes. |
| `ActiveFragments` | Current fragment routes. |
| `FlowRoutes` | Inbound packets sent by a flow route. |
| `FragmentRoutes` | Non-first fragments sent by a fragment route. |
| `AddressFallbacks` | Packets sent by a learned address route after no dynamic route matched. |
| `DefaultFallbacks` | Packets sent to the default Tun after no other route matched. |
| `DroppedFallbacks` | Packets dropped because no route existed. |
| `FlowCollisions` | Active flow identities observed from a different owner. |
| `ExpiredRoutes` | Flow or fragment routes removed after inactivity. |
| `EvictedRoutes` | Flow or fragment routes removed at the entry limit. |

Calling `RoutingStats` can remove expired routes. Counters do not reset during
the lifetime of a `Joiner`. All fields stay zero when shared-address routing is
disabled.

## Stable behavior and implementation details

These properties are part of the behavior contract:

- routing precedence;
- supported flow identities and packet headers;
- first-owner collision policy;
- fallback behavior;
- timeout refresh behavior;
- least-recently-used capacity behavior;
- detach and close cleanup;
- per-packet batch routing;
- diagnostics meanings;
- concurrency safety.

The map types, key encoding, lock layout, cleanup algorithm, and packet-parser
structure are implementation details. Future work can replace them without a
contract change.

The black-box tests in `joiner_contract_test.go` use only exported package
behavior. The lower-level tests in `joiner_flow_test.go` probe packet formats,
limits, malformed input, and implementation edge cases.

## Contract test map

The `TestJoinerSharedAddressBehaviorContract` subtests protect these public
invariants:

| Subtest | Protected behavior |
| --- | --- |
| `legacy constructor keeps address routing` | `NewJoiner` keeps last-owner address routing and does not collect shared-mode statistics. |
| `shared IPv4 and IPv6 flows stay isolated` | IPv4, IPv6, TCP, UDP, local ports, and mixed-owner write batches select the correct Tun. |
| `first collision owner wins until detach` | A collision cannot steal an active flow; detach removes that ownership and permits fallback. |
| `flow refresh and expiry expose address fallback` | A flow is preferred while active, inbound traffic refreshes it, and expiry restores address fallback. |
| `fallback diagnostics distinguish default and drop` | Default delivery and no-route drops have separate counters. |
| `entry limit evicts the least recently used flow` | A route lookup changes LRU order, the true oldest route is evicted, and counters describe the result. |

Run the contract as a focused check:

```text
go test ./tun -run TestJoinerSharedAddressBehaviorContract -race -count=20
```

Run the full repository baseline before a routing optimization:

```text
go test ./... -race -count=1
golangci-lint run ./...
```
