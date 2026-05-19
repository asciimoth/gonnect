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

## Public API map

- `Tun`, `Event`, `EventUp`, `EventDown`, `EventMTUUpdate`: `tun.go`
- `IsTunTermError`: `batch.go`
- `Copy`: `copy.go`
- `Channel`, `NewChan`, `ErrReadOnClosedChan`, `ErrWriteOnClosedChan`: `chan.go`
- `Pipe`, `ErrReadOnClosedPipe`, `ErrWriteOnClosedPipe`: `pipe.go`
- `DetachedTun`, `Detach`, `ErrDetachedTunDown`, `ErrDetachedTunClosed`:
  `detachable.go`
- `IO`, `NewIO`: `io.go`
- `Forwarder`, `NewForwarder`: `forwarder.go`
- `Point2Point`, `NewP2P`: `p2p.go`
- `CallbackTUN`: `callback.go`
