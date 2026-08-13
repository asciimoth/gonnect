# SplitRouter Optimization Notes

This document records the current SplitRouter bytecode optimization work and the
next likely places to continue. The goal is to keep future performance work
measurable and avoid rediscovering the same tradeoffs.

## Current Benchmark Coverage

Benchmarks live in `routing/bytecode_benchmark_test.go` and can be run from the
module root with:

```sh
go test -run '^$' -bench 'BenchmarkBytecodeSplitRouterRoute' -benchmem ./routing
```

Current benchmark cases:

- `BenchmarkBytecodeSplitRouterRouteStatic`: bytecode-only IPv4/TCP/address/port routing.
- `BenchmarkBytecodeSplitRouterRouteComplex`: complex mixed bytecode rule with strings, regexps, subnets, ports, and OP_RULE.
- `BenchmarkBytecodeSplitRouterRouteRuleRepeated`: same native flow repeatedly hitting OP_RULE.
- `BenchmarkBytecodeSplitRouterRouteRuleVaryingFlow`: cold OP_RULE path with varying source addresses/ports and cache disabled.
- `BenchmarkBytecodeSplitRouterRouteRuleGuardedFalse`: OP_RULE guarded by cheap false predicates with caches disabled.
- `BenchmarkBytecodeSplitRouterRouteResultCacheSmallBatch`: three packets from the same native flow in one `Lock`/`Unlock` batch, with OP_RULE cache disabled and route-result cache enabled.

The first five benchmarks disable the whole-route result cache so they continue
to measure the evaluator and OP_RULE cache paths directly.

Latest local results on the development machine, averaged across five runs
(`12th Gen Intel(R) Core(TM) i7-12800H`, 2026-06-26):

| Benchmark | Before | After |
| --- | ---: | ---: |
| Static | 238.3 ns/op, 56 B/op, 2 allocs | 119.6 ns/op, 0 B/op, 0 allocs |
| Complex | 962.3 ns/op, 160 B/op, 9 allocs | 479.3 ns/op, 24 B/op, 2 allocs |
| RULE repeated | 348.3 ns/op, 112 B/op, 5 allocs | 181.8 ns/op, 0 B/op, 0 allocs |
| RULE cold | 358.0 ns/op, 112 B/op, 5 allocs | 213.7 ns/op, 8 B/op, 2 allocs |
| RULE guarded false | n/a | 100.8 ns/op, 0 B/op, 0 allocs |
| Route result cache, batch of 3 | n/a | 442.8 ns/op per batch, 0 B/op, 0 allocs |

Treat these numbers as a local baseline, not absolute performance targets across
machines.

## Optimizations Already Done

### Predecoded Split Bytecode

`NewBytecodeSplitRouter` now compiles `Route []byte` into `[]splitInstr`.
Packet routing no longer decodes opcode parameters with
`readBytecodeParamUnchecked` on every packet.

The compiler also computes maximum boolean stack depth. `Route` uses a stack
allocated `[64]bool` for normal rulesets and only allocates if a program needs a
deeper stack.

### Allocation-Free Hot Stack Path

The old evaluator used `make([]bool, 0, 8)` and append/pop helpers per packet.
The new evaluator uses an explicit stack pointer over fixed storage. This is a
large part of the bytecode-only benchmark improvement.

### Per-Packet OP_RULE Deduping Without Map Allocation

The previous evaluator allocated `map[uint16]bool` per packet so repeated
OP_RULE checks in one bytecode program called the matcher only once.

The new evaluator uses two `uint64` masks for rule indexes `0..63`:

- one mask records which rules were checked,
- one mask stores true results.

Rule indexes above 63 still use a lazily allocated map, which keeps the common
case allocation-free while preserving correctness for large rulesets.

### Cross-Packet OP_RULE Cache

OP_RULE results are now cached across packets by:

- rule index,
- IP protocol,
- source address,
- destination address,
- source port,
- destination port.

This avoids repeated expensive `sysnet.Matcher.Match` calls for packets from
the same flow. The cache stores both true and false matcher results. Matcher
errors are treated as false but are not cached.

Configuration fields on `SplitBytecodeRules`:

- `RuleCacheTTL`: zero uses the default TTL, negative disables the cross-packet cache.
- `RuleCacheMaxEntries`: zero uses the default size, negative disables the cache.

Current defaults:

- TTL: `1s`
- max entries: `4096`

Expiration is measured from after a matcher returns, which matters when matcher
calls are slow. `Close` clears the cache. When the cache grows past its limit it
first removes expired entries, then reduces the map toward half capacity.

### Cross-Packet Route Result Cache

Whole bytecode route results are now cached across packets by:

- native/non-native backend state,
- IP protocol,
- source address,
- destination address,
- source port,
- destination port,
- whether the packet had readable ports,
- whether the packet is eligible for `FlowTupleFromOutgoingIPPacket`.

This targets data-heavy flows where batches are small but many consecutive
packets take the same rule path and slot. A cache hit still parses the packet
header, then skips the bytecode evaluator, string/regexp checks, OP_RULE local
deduping, and matcher/cache lookups.

The cache is router-wide, not tied to `Lock`/`Unlock`: it can reuse decisions
within one small batch and across later batches until TTL expiry or eviction.

Configuration fields on `SplitBytecodeRules`:

- `RouteCacheTTL`: negative disables the whole-route cache.
- `RouteCacheMaxEntries`: negative disables the whole-route cache.

When both route cache fields are zero, the route cache inherits the OP_RULE
cache settings. This intentionally preserves the expectation that setting
`RuleCacheTTL` or `RuleCacheMaxEntries` negative disables cross-packet caching
unless route caching is explicitly configured.

Current route cache defaults, after inheritance:

- TTL: `1s`
- max entries: `4096`

Matcher errors still are not cached: if an OP_RULE matcher returns an error, the
route result for that packet is not written to the whole-route cache. `Close`
clears the route cache. Route cache pruning uses the same expired-first,
half-capacity fallback strategy as the OP_RULE cache.

### Single-Entry Cache Fast Paths

The OP_RULE and route-result caches keep an atomic single-entry last-result fast
path in front of their existing mutex-protected maps. Repeated same-flow cache
hits still check entry expiry, then return without taking the cache mutex or
doing a map lookup. The map remains the source of truth for general flow reuse,
eviction, and cleanup.

### Lazy Packet Address Strings

String and regexp address bytecode ops still use `netip.Addr.String()`, but the
result is now cached on the per-packet evaluator. A packet that checks both
`ADDR_S` and `ADDR_RE` for the same address formats it once.

### Numeric Split Packet Fast Paths

Split routing now stores parsed packet ports as `uint16`, matching bytecode port
parameters and cache-key fields. It also precomputes split-router IPv4 subnet
masks and masked addresses during construction, so `SNET4` and `LSNET4` no
longer rebuild masks per packet. The public `IPv4Subnet` table and RouterCfg
path are unchanged.

### Short-Circuit Split Route Segments

Split route bytecode is now also compiled into terminal condition segments. The
common parser output shape:

```text
A
B
AND
C
AND
SLOT 2
```

is evaluated as left-to-right short-circuiting `AND`/`OR` predicates, so a cheap
false guard can skip later expensive OP_RULE checks. The compiler folds
split-router constants such as `FQDN` and `LFQDN`, flattens simple `AND`/`OR`
chains into a fast predicate loop, and keeps the older stack evaluator as a
fallback for uncommon shapes it cannot safely compile.

There is also a direct fast path for the single-predicate `RULE -> SLOT` case so
the repeated and cold OP_RULE benchmarks do not pay for the generic predicate
loop.

## Important Semantics

- Non-native packets still skip OP_RULE and return false.
- Malformed or non-TCP/UDP packets do not call matchers.
- Compiled split route `AND` and `OR` conditions now short-circuit left to right.
  A skipped OP_RULE does not call the matcher and therefore cannot observe a
  matcher error for that skipped predicate.
- The cross-packet cache is intentionally flow-keyed, not packet-keyed.
- The whole-route cache key includes native state, ports-present state, and
  flow eligibility, so non-native packets and malformed TCP/UDP packets do not
  reuse native/well-formed flow results.
- Whole-route cache entries can become stale for the same owner-reuse reasons as
  OP_RULE cache entries. The TTL bounds this window.
- Cached false results can become stale if a local port is quickly reused by a
  different owner. The TTL bounds this window.
- The whole-route cache is correct for the current SplitRouter bytecode because
  packet routing can observe only native state, protocol, endpoint addresses,
  ports, address/string/regexp tables, and OP_RULE results keyed by the same
  flow. If future split opcodes observe payload bytes, packet length, flags, or
  other header fields, the route-cache key must be extended or the opcode must
  bypass whole-route caching.
- Existing bytecode format and public constructor shape remain compatible except
  for the added optional cache fields.

## Attempted But Rejected

I tried replacing address string comparisons and regexp matches with byte slices
using `netip.Addr.AppendTo` and `Regexp.Match`. That removed some string work in
theory, but the larger evaluator state escaped to the heap and regressed all
benchmarks to roughly `480 B/op`. Do not retry that exact approach without first
checking escape analysis.

## Good Next Optimization Targets

### Avoid Cold OP_RULE FlowTuple Allocations

Cold OP_RULE still calls `sockowner.FlowTupleFromOutgoingIPPacket`, which copies
IP addresses into `net.IP` slices for the `sysnet.Matcher` interface. Repeated
flows avoid this via cache, but cold paths still allocate.

A clean fix likely needs a new matcher path that accepts `netip.Addr` and ports,
or a package-level helper in gonnect that can build `FlowTuple` with fewer
allocations safely. Be careful: arbitrary matchers may retain or mutate
`net.IP`, so stack-backed or packet-buffer-backed slices would be risky with the
current interface.

### Cache Tuning From Real Traffic

The default `1s` TTL and `4096` entries are conservative guesses. Real packet
traffic should drive these values.

Data worth collecting:

- OP_RULE cache hit ratio,
- whole-route cache hit ratio,
- average and p99 matcher latency,
- eviction rate,
- number of active flow keys,
- false-positive risk from local port reuse.

Consider separate TTLs for positive and negative results if stale false results
are more harmful than stale true results.

### Cache Contention

The cross-packet OP_RULE and whole-route caches are each protected by one mutex.
`tun.Splitter` currently calls router `Lock`, routes a backend batch, then
`Unlock`, but callers can still use the router directly or concurrently.

If profiling shows cache mutex contention:

- shard the cache by hash of flow key,
- keep a short-lived batch-local cache in `Lock`/`Unlock`,
- add cheap hit/miss counters to verify contention before changing design.

### Precompute More Operand Data

`splitInstr` currently stores only opcode and `uint16` parameter. There may be
small wins from compiling more direct operand data:

- direct regexp pointers,
- direct string pointers,
- specialized instruction structs for common ops.

This should be benchmarked carefully; larger instruction structs can hurt cache
locality.

### Specialize Common Programs

If most deployed rulesets are simple, consider selecting specialized evaluators
at construction time:

- no OP_RULE,
- no strings/regexps,
- IPv4-only,
- single slot rule,
- single OP_RULE rule.

This could reduce branch density in the main evaluator, but it adds complexity.
Only do this with benchmark evidence from real rulesets.

## Verification Checklist For Future Work

Run these after each optimization:

```sh
go test -count=1 ./...
go test -run '^$' -bench 'BenchmarkBytecodeSplitRouterRoute' -benchmem ./...
```

For allocation-related changes, also inspect escape analysis around
`split_bytecode.go`:

```sh
go test -run '^$' -bench 'BenchmarkBytecodeSplitRouterRouteStatic$' \
  -benchmem -gcflags='-m=2' ./... 2>&1 | rg 'split_bytecode.go|escapes|moved to heap'
```

Avoid accepting a change that improves one complex benchmark while making the
bytecode-only or repeated-RULE hot paths allocate again.
