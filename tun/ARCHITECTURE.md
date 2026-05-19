# tun package architecture

## Tun concept and contract

`Tun` is the package's core abstraction for packet-oriented virtual network
devices. It follows the wireguard-go style interface: callers read and write
batches of complete packets, with implementation-specific read and write
offsets (`MRO` and `MWO`) reserved for platform headers or caller-owned scratch
space.

`Tun.IsNative()` reports whether a `Tun` provides direct access to an OS TUN
device. Native Tuns may expose an OS file descriptor through `File()`, may
reserve offset space for platform headers, and may be consumed by code that
intentionally performs low-level optimized operations outside the ordinary
`Tun` methods. Virtual Tuns emulate or wrap packet transport in user space and
must report `false`; bypassing their methods would skip the emulation or wrapper
behavior. Every implementation currently provided by this package is virtual
and reports `IsNative() == false`.

Callers should size read batches from the source `Tun.BatchSize()` and chunk
writes for the destination `Tun.BatchSize()`. Batch sizes are not assumed to be
symmetric across implementations.

`EventDown` means the interface is down, not closed. A down `Tun` remains an
open object and may later report `EventUp`; depending on the implementation,
`Read` or `Write` may continue to block or otherwise behave like the underlying
device. `Close` is permanent: implementations should unblock pending I/O when
possible, close `Events()`, and make future `Read` and `Write` return errors
matching `os.ErrClosed`.

## IsTunTermError

`IsTunTermError(err)` classifies whether a read error should stop use of the
current `Tun` data path. It returns `false` for `nil` and for errors after which
the same `Tun` can still be used, including temporary/deadline errors and known
read capacity errors such as "too many segments" or "need more buffers".

It returns `true` for all other errors, including closed-device errors. Copying
and forwarding loops use this function to decide whether to retry a read or
tear down the current path.

## Internal channel paths

The public package contract is method based: `Tun.Read`, `Tun.Write`,
`Tun.Events`, and the metadata methods are the only API consumers need to know.
Some wrappers, however, need detach/attach behavior while still being able to
unblock their own pending reads and writes. For an arbitrary `Tun`, that cannot
be done only with the public methods because `Tun` has no context or deadline
parameter. The current solution is to put a private channel based data path
behind such wrappers.

`DetachedTun` is the first implementation of this pattern. A root
`DetachedTun`, created by `Detach` around a non-detached `Tun`, owns two pump
goroutines:

- `readPump` reads from the wrapped `Tun`, copies packet payloads out of the
  pump-owned buffers, and sends `detachedTunRead` values on the wrapper's read
  channel.
- `writePump` receives `detachedTunWrite` requests, writes copied packet data
  to the wrapped `Tun`, and replies through the request's response channel.

The public `DetachedTun.Read` and `DetachedTun.Write` methods wait on those
private channels plus the wrapper's current `done` channel. `Down` closes the
current `done` channel, which releases pending public I/O with
`ErrDetachedTunDown` without closing the wrapped `Tun`. `Close` does the same
permanently and closes events. If the wrapped `Tun` is blocked internally, a
pump may stay blocked until the underlying operation returns, but caller buffers
are not retained by that pump because packet data is copied at the wrapper
boundary.

Nested detached wrappers do not create another pair of pumps. When `Detach`
receives an existing `*DetachedTun`, it creates a child with `parent` set and
`ownsPumps == false`. The child obtains a snapshot of the parent's active
channel path through `sourceSnapshot`: read channel, write channel, and the
parent's effective done channel. The child then creates its own
`effectiveDone`, which closes when either the child is taken down/closed or the
parent path stops. This preserves independent `Up`, `Down`, and `Close` state
for each wrapper while keeping the packet path flat:

```text
public child Read/Write -> root read/write channels -> root pumps -> wrapped Tun
```

instead of:

```text
child pumps -> parent public Read/Write -> parent pumps -> wrapped Tun
```

`Joiner` also implements the private channel source pattern, but it is not just
a stoppable wrapper. It owns one read goroutine per attached nested `Tun`, plus
a single write pump for consumers that attach to it through `Detach`. Nested
reads are copied into `detachedTunRead` values tagged with their
`joinerNested` owner; `Joiner.Read` buffers those packets, drops packets whose
owner has since been detached, and learns IPv4/IPv6 source addresses for later
routing. `Joiner.Write` uses the learned destination route when available and
falls back to the current default nested `Tun`; malformed or unrouted packets
are dropped when no default exists.

Because `Joiner` must unblock goroutines blocked inside arbitrary nested
`Tun.Read` and `Tun.Write` calls, detaching a nested `Tun` closes that nested
`Tun`. This differs from `DetachedTun`, whose `Down` and `Close` only affect the
wrapper and leave the wrapped `Tun` open. `Joiner.sourceSnapshot` exposes the
joiner's own read, write, and done channels so `Detach(NewJoiner())` can add
wrapper-local down/close state without adding another packet-copy pump around
the joiner.

`Splitter` is the inverse shape for one backend `Tun` and up to sixteen virtual
frontend `Tun` values. It owns one backend read goroutine, one backend event
goroutine, and one backend write pump. Backend read batches are routed under the
current `SplitRouter` lock, then delivered to the selected frontend read
channel; packets routed to invalid, down, closed, or never-created frontends are
dropped. Frontend writes all share the splitter write pump and are forwarded to
the current backend, or dropped successfully when no backend is attached.
Detaching or replacing the backend closes it to unblock backend I/O, including
terminal-error auto-detaches. Closing or taking down a frontend only closes that
frontend's local done channel and does not affect the splitter or backend.
`SplitFrontend.sourceSnapshot` exposes the frontend read channel, splitter write
channel, and frontend effective done channel so `Detach(splitter.Get(n))` can
reuse the existing data path instead of adding another pump layer.

The reusable internal surface is the combination of:

- a receive-only channel carrying already-copied read batches;
- a send-only channel accepting write requests with per-request responses;
- a done channel that describes when the currently usable path is no longer
  valid;
- wrapper-local state and events layered outside that data path.

Future `Tun` based wrappers that also need channels internally can share this
kind of path with nested implementations instead of wrapping only the public
`Read` and `Write` methods. The usual shape is:

1. Keep the public type implementing `Tun`; do not expose the channel interface
   outside the package.
2. Give the type an unexported method that returns a snapshot of its current
   internal read channel, write channel, and done channel, or an appropriate
   closed/down error.
3. In constructors, detect wrapped values that support that private snapshot
   method. If present, use the returned channels as the child data path. If not,
   create root pumps around the public `Tun` methods.
4. Combine parent and child lifetimes with a child-local effective done channel
   so parent detach/close and child detach/close both unblock child I/O.
5. Copy packet data at every boundary where caller-owned buffers could outlive
   the call. A shared channel path must not retain user buffers from public
   `Read` or `Write`.
6. Keep metadata and events wrapper-local unless they are intentionally
   delegated. `DetachedTun` forwards wrapped events to subscribers while adding
   its own `EventUp`/`EventDown` transitions for wrapper state.

This pattern is useful only when a wrapper can safely share the same packet
stream as its parent. It must not be used to create multiple independent active
consumers of the same underlying `Tun`: that has the same packet stealing and
ordering problems as concurrent direct calls to `Tun.Read` or `Tun.Write`.

## Public API map

- `Tun`, `Event`, `EventUp`, `EventDown`, `EventMTUUpdate`: `tun.go`
- `IsTunTermError`: `batch.go`
- `Copy`: `copy.go`
- `Channel`, `NewChan`, `ErrReadOnClosedChan`, `ErrWriteOnClosedChan`: `chan.go`
- `Pipe`, `ErrReadOnClosedPipe`, `ErrWriteOnClosedPipe`: `pipe.go`
- `DetachedTun`, `Detach`, `ErrDetachedTunDown`, `ErrDetachedTunClosed`:
  `detachable.go`
- `Joiner`, `NewJoiner`: `joiner.go`
- `Splitter`, `SplitFrontend`, `SplitRouter`, `NewSplitter`: `splitter.go`
- `IO`, `NewIO`: `io.go`
- `Forwarder`, `NewForwarder`: `forwarder.go`
- `Point2Point`, `NewP2P`: `p2p.go`
- `CallbackTUN`: `callback.go`
