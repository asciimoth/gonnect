package gonnect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	// RouterSlots is the number of backend slots available in a Router.
	RouterSlots = 16

	routerDefaultSlot = 1
)

var _ interface {
	Network
	UpDown
	io.Closer
	CloserSubscriber
	UpDownSubscriber
} = (*Router)(nil)

// RouterCfg selects the backend slot used for routed operations.
//
// Slots are numbered from 1 through 16. Returning any other slot, or returning
// a slot without an attached backend, makes the Router fail the operation with
// the same canonical error a RejectNetwork would return for that operation.
type RouterCfg interface {
	DialTCP(network, laddr, raddr string) (slot int)
	ListenTCP(network, laddr string) (slot int)
	DialUDP(network, laddr, raddr string) (slot int)
	RouteUDP(network string, laddr, raddr net.Addr) (slot int)
	Lookup(network, address string) (slot int)
}

// Router is a Network implementation that routes frontend operations to one of
// sixteen replaceable backend Network instances.
//
// Backends can be attached, detached, or replaced while the Router is in use.
// Detaching or replacing a backend closes all connections, listeners, accepted
// connections, and UDP backend sockets that were opened through that slot. Close
// and Down stop the Router itself, cancel pending operations, and close all
// objects returned by the Router.
//
// A Router is operational only when it has not been forced down with Down and at
// least one attached backend slot is operational. Empty slots and attached
// UpDown backends that are down or closed do not keep the Router up. Attached
// backends that do not implement UpDown are treated as always operational.
// Backend shutdown can make the Router go down, but it does not close the
// Router; subscribed closers run only when the Router itself is closed.
//
// UDP listeners are frontend objects owned by the Router. For every alive
// frontend UDP listener, the Router keeps one backend UDP listener per attached
// backend slot. Reads fan in packets from all backend sockets, while writes are
// routed per packet with RouterCfg.RouteUDP.
type Router struct {
	mu      sync.Mutex
	wantUp  bool
	autoUp  bool
	up      bool
	closed  bool
	gen     uint64
	done    chan struct{}
	nextID  uint64
	cfg     RouterCfg
	res     Resolver
	spawner Spawner
	slots   [RouterSlots]Network
	slotUp  [RouterSlots]bool
	slotGen [RouterSlots]uint64
	slotSub [RouterSlots]func()
	closers map[uint64]io.Closer
	bySlot  [RouterSlots]map[uint64]io.Closer
	udp     map[uint64]*routerUDPConn

	nextUpDownID uint64
	updowns      map[uint64]UpDown

	nextCloseSubID uint64
	closeSubs      map[uint64]io.Closer
}

// NewRouter creates an empty Router. Without a RouterCfg, operations route to
// slot 1.
func NewRouter(spawner Spawner) *Router {
	return &Router{
		wantUp:    true,
		gen:       1,
		done:      make(chan struct{}),
		spawner:   spawner,
		closers:   make(map[uint64]io.Closer),
		udp:       make(map[uint64]*routerUDPConn),
		updowns:   make(map[uint64]UpDown),
		closeSubs: make(map[uint64]io.Closer),
	}
}

// IsNative always reports false. Router is a frontend over other Networks.
func (r *Router) IsNative() bool { return false }

// SetCfg replaces the routing config. Passing nil restores default routing to
// slot 1.
func (r *Router) SetCfg(cfg RouterCfg) {
	r.mu.Lock()
	r.cfg = cfg
	r.mu.Unlock()
}

// GetCfg returns the currently installed routing config.
func (r *Router) GetCfg() RouterCfg {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

// SetResolver replaces the optional resolver used by this Router. Passing nil
// removes it. When set, all Lookup operations go directly to this resolver and
// Dial/Listen operations pre-resolve host and service names through it before
// slot selection.
func (r *Router) SetResolver(res Resolver) {
	r.mu.Lock()
	r.res = res
	r.mu.Unlock()
}

// GetResolver returns the currently installed optional resolver.
func (r *Router) GetResolver() Resolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.res
}

// Attach installs backend in slot. Slots are numbered 1 through 16. Attaching
// nil is equivalent to Detach. Replacing a backend closes every object opened
// through the previous backend in that slot.
func (r *Router) Attach(slot int, backend Network) error {
	if backend == nil {
		return r.Detach(slot)
	}
	if !routerValidSlot(slot) {
		return routerSlotError(slot)
	}

	backendUp := routerBackendIsUp(backend)
	var udp []*routerUDPConn
	oldClosers, stopped := r.replaceSlot(slot, backend, backendUp, &udp)
	if oldClosers == nil && udp == nil && stopped.done == nil {
		return net.ErrClosed
	}
	err := r.closeTransition(stopped)
	err = errors.Join(err, closeAll(oldClosers))
	err = errors.Join(err, r.watchSlot(slot, backend))
	for _, c := range udp {
		c.detachBackend(slot)
		c.attachBackend(slot, backend, r.spawner)
	}
	return err
}

// Detach removes the backend in slot and closes every object opened through it.
func (r *Router) Detach(slot int) error {
	if !routerValidSlot(slot) {
		return routerSlotError(slot)
	}
	var udp []*routerUDPConn
	oldClosers, stopped := r.replaceSlot(slot, nil, false, &udp)
	if oldClosers == nil && stopped.done == nil {
		return net.ErrClosed
	}
	err := r.closeTransition(stopped)
	err = errors.Join(err, closeAll(oldClosers))
	for _, c := range udp {
		c.detachBackend(slot)
	}
	return err
}

func (r *Router) replaceSlot(
	slot int,
	backend Network,
	up bool,
	udpOut *[]*routerUDPConn,
) ([]io.Closer, routerTransition) {
	idx := slot - 1
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, routerTransition{}
	}
	unsub := r.slotSub[idx]
	r.slotSub[idx] = nil
	r.slotGen[idx]++
	r.slots[idx] = backend
	r.slotUp[idx] = up
	old := make([]io.Closer, 0, len(r.bySlot[idx]))
	for id, c := range r.bySlot[idx] {
		delete(r.closers, id)
		delete(r.bySlot[idx], id)
		old = append(old, c)
	}
	if udpOut != nil {
		*udpOut = make([]*routerUDPConn, 0, len(r.udp))
		for _, c := range r.udp {
			*udpOut = append(*udpOut, c)
		}
	}
	stopped := r.applyAutoStateLocked()
	r.mu.Unlock()
	if unsub != nil {
		unsub()
	}
	return old, stopped
}

type routerTransition struct {
	done    chan struct{}
	closers []io.Closer
	updowns []UpDown
	up      bool
}

func (r *Router) watchSlot(slot int, backend Network) error {
	idx := slot - 1
	r.mu.Lock()
	gen := r.slotGen[idx]
	r.mu.Unlock()

	var unsubscribe func()
	var err error
	if sub, ok := backend.(UpDownSubscriber); ok {
		unsubscribe, err = sub.SubscribeUpDown(&routerSlotUpDown{
			router: r,
			slot:   slot,
			gen:    gen,
		})
	}
	up := routerBackendIsUp(backend)
	return errors.Join(err, r.setSlotUp(slot, gen, up, unsubscribe))
}

func routerBackendIsUp(backend Network) bool {
	u, ok := backend.(UpDown)
	if !ok {
		return true
	}
	up, err := u.IsUp()
	return err == nil && up
}

type routerSlotUpDown struct {
	router *Router
	slot   int
	gen    uint64
}

func (u *routerSlotUpDown) Up() error {
	return u.router.setSlotUp(u.slot, u.gen, true, nil)
}

func (u *routerSlotUpDown) Down() error {
	return u.router.setSlotUp(u.slot, u.gen, false, nil)
}

func (u *routerSlotUpDown) IsUp() (bool, error) {
	u.router.mu.Lock()
	defer u.router.mu.Unlock()
	idx := u.slot - 1
	return u.router.slotGen[idx] == u.gen && u.router.slotUp[idx], nil
}

func (r *Router) setSlotUp(
	slot int,
	gen uint64,
	up bool,
	unsubscribe func(),
) error {
	idx := slot - 1
	r.mu.Lock()
	if r.closed || r.slotGen[idx] != gen {
		r.mu.Unlock()
		if unsubscribe != nil {
			unsubscribe()
		}
		return nil
	}
	if unsubscribe != nil {
		old := r.slotSub[idx]
		r.slotSub[idx] = unsubscribe
		if old != nil {
			defer old()
		}
	}
	r.slotUp[idx] = up
	transition := r.applyAutoStateLocked()
	r.mu.Unlock()
	return r.closeTransition(transition)
}

func (r *Router) applyAutoStateLocked() routerTransition {
	autoUp := false
	for i, backend := range r.slots {
		if backend != nil && r.slotUp[i] {
			autoUp = true
			break
		}
	}
	r.autoUp = autoUp
	return r.applyEffectiveStateLocked()
}

func (r *Router) applyEffectiveStateLocked() routerTransition {
	up := r.wantUp && r.autoUp && !r.closed
	if r.up == up {
		return routerTransition{}
	}
	r.up = up
	r.gen++
	if up {
		r.done = make(chan struct{})
		r.closers = make(map[uint64]io.Closer)
		r.udp = make(map[uint64]*routerUDPConn)
		return routerTransition{
			updowns: r.updownsSnapshotLocked(),
			up:      true,
		}
	}
	transition := routerTransition{
		done:    r.done,
		closers: r.drainTrackedLocked(),
		updowns: r.updownsSnapshotLocked(),
	}
	return transition
}

func (r *Router) updownsSnapshotLocked() []UpDown {
	updowns := make([]UpDown, 0, len(r.updowns))
	for _, u := range r.updowns {
		updowns = append(updowns, u)
	}
	return updowns
}

func (r *Router) drainTrackedLocked() []io.Closer {
	closers := make([]io.Closer, 0, len(r.closers))
	for id, c := range r.closers {
		delete(r.closers, id)
		closers = append(closers, c)
	}
	for i := range r.bySlot {
		clear(r.bySlot[i])
	}
	r.udp = make(map[uint64]*routerUDPConn)
	return closers
}

func (r *Router) closeTransition(transition routerTransition) error {
	if transition.done != nil {
		close(transition.done)
	}
	if transition.up {
		return upAll(transition.updowns)
	}
	return errors.Join(
		closeAll(transition.closers),
		downAll(transition.updowns),
	)
}

// Up re-enables a stopped Router. Backend attachments and RouterCfg are kept.
func (r *Router) Up() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.wantUp = true
	transition := r.applyEffectiveStateLocked()
	r.mu.Unlock()
	return r.closeTransition(transition)
}

// Down stops the Router, cancels pending operations, and closes all Router
// owned objects. It does not call Down or Close on attached backend Networks.
func (r *Router) Down() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.wantUp = false
	transition := r.applyEffectiveStateLocked()
	r.mu.Unlock()

	return r.closeTransition(transition)
}

// Close permanently closes this Router.
func (r *Router) Close() error {
	closers, updowns, closeSubs, slotSubs, done := r.closePrep()
	if done != nil {
		close(done)
	}
	for _, unsubscribe := range slotSubs {
		unsubscribe()
	}
	return errors.Join(closeAll(closers), downAll(updowns), closeAll(closeSubs))
}

// SubscribeCloser registers c to be closed when this Router is closed.
//
// The returned unsubscribe function removes c without closing it. If the Router
// is already closed, c is closed before SubscribeCloser returns net.ErrClosed.
func (r *Router) SubscribeCloser(c io.Closer) (func(), error) {
	return r.subscribeCloser(c, 0)
}

func (r *Router) subscribeCloser(c io.Closer, slot int) (func(), error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	if slot > 0 && !r.up {
		r.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	if slot > 0 {
		id := r.nextID
		r.nextID++
		r.closers[id] = c
		idx := slot - 1
		if r.bySlot[idx] == nil {
			r.bySlot[idx] = make(map[uint64]io.Closer)
		}
		r.bySlot[idx][id] = c
		r.mu.Unlock()

		var once sync.Once
		return func() {
			once.Do(func() { r.unregister(id, slot) })
		}, nil
	} else {
		id := r.nextCloseSubID
		r.nextCloseSubID++
		if r.closeSubs == nil {
			r.closeSubs = make(map[uint64]io.Closer)
		}
		r.closeSubs[id] = c
		r.mu.Unlock()

		var once sync.Once
		return func() {
			once.Do(func() { r.unregisterCloseSub(id) })
		}, nil
	}
}

// SubscribeUpDown registers u to follow this Router's up/down state.
//
// The returned unsubscribe function removes u without changing it. The
// subscription persists across Down and Up cycles. If the Router is already
// down or closed, u.Down is called before SubscribeUpDown returns.
func (r *Router) SubscribeUpDown(u UpDown) (func(), error) {
	r.mu.Lock()
	id := r.nextUpDownID
	r.nextUpDownID++
	if r.updowns == nil {
		r.updowns = make(map[uint64]UpDown)
	}
	r.updowns[id] = u
	down := !r.up || r.closed
	r.mu.Unlock()

	var err error
	if down {
		err = u.Down()
	}

	var once sync.Once
	return func() {
		once.Do(func() { r.unregisterUpDown(id) })
	}, err
}

// IsUp reports whether this Router is currently up.
func (r *Router) IsUp() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up && !r.closed, nil
}

func (r *Router) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if IsUDPNetwork(network) {
		return r.DialUDP(ctx, network, "", address)
	}
	return r.DialTCP(ctx, network, "", address)
}

func (r *Router) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	return r.ListenTCP(ctx, network, address)
}

func (r *Router) PacketDial(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	return r.DialUDP(ctx, network, "", address)
}

func (r *Router) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	return r.ListenUDP(ctx, network, address)
}

func (r *Router) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	var err error
	laddr, err = r.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	raddr, err = r.resolveNetAddr(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	slot, backend, ctx, cancel, gen, done, err := r.beginRouted(
		ctx,
		func(cfg RouterCfg) int {
			if cfg == nil {
				return routerDefaultSlot
			}
			return cfg.DialTCP(network, laddr, raddr)
		},
		func() error { return dialError(network, raddr) },
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		r.spawner,
		ctx,
		done,
		func(ctx context.Context) (TCPConn, error) {
			return backend.DialTCP(ctx, network, laddr, raddr)
		},
		func(c TCPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return r.trackTCPConn(gen, slot, c)
}

func (r *Router) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	var err error
	laddr, err = r.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	slot, backend, ctx, cancel, gen, done, err := r.beginRouted(
		ctx,
		func(cfg RouterCfg) int {
			if cfg == nil {
				return routerDefaultSlot
			}
			return cfg.ListenTCP(network, laddr)
		},
		func() error { return listenError(network, laddr) },
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	l, err := runDetachedOp(
		r.spawner,
		ctx,
		done,
		func(ctx context.Context) (TCPListener, error) {
			return backend.ListenTCP(ctx, network, laddr)
		},
		func(l TCPListener) { _ = l.Close() },
	)
	if err != nil {
		return nil, err
	}
	return r.trackTCPListener(gen, slot, l)
}

func (r *Router) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	var err error
	laddr, err = r.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	raddr, err = r.resolveNetAddr(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	slot, backend, ctx, cancel, gen, done, err := r.beginRouted(
		ctx,
		func(cfg RouterCfg) int {
			if cfg == nil {
				return routerDefaultSlot
			}
			return cfg.DialUDP(network, laddr, raddr)
		},
		func() error { return dialError(network, raddr) },
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		r.spawner,
		ctx,
		done,
		func(ctx context.Context) (UDPConn, error) {
			return backend.DialUDP(ctx, network, laddr, raddr)
		},
		func(c UDPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return r.trackUDPConn(gen, slot, c)
}

func (r *Router) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	if !IsUDPNetwork(network) {
		return nil, net.UnknownNetworkError(network)
	}
	var err error
	laddr, err = r.resolveNetAddr(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(laddr); err != nil {
		return nil, listenError(network, laddr)
	}
	ctx, cancel, gen, done, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	c, err := runDetachedOp(
		r.spawner,
		ctx,
		done,
		func(ctx context.Context) (*routerUDPConn, error) {
			return newRouterUDPConn(r, network, laddr), nil
		},
		func(c *routerUDPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return r.trackRouterUDPConn(gen, c)
}

func (r *Router) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	return r.ListenPacket(ctx, network, address)
}

func (r *Router) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	return r.ListenUDP(ctx, network, laddr)
}

func (r *Router) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	return nil, ErrUnsupported
}

func (r *Router) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return routerLookupSlice(ctx, r, network, address,
		func(res Resolver) ([]net.IP, error) {
			return res.LookupIP(ctx, network, address)
		},
		func(n Network) ([]net.IP, error) {
			return n.LookupIP(ctx, network, address)
		},
		func() error { return NoSuchHost(address, "rejectdns") },
	)
}

func (r *Router) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	return routerLookupSlice(ctx, r, "", host,
		func(res Resolver) ([]net.IPAddr, error) {
			return res.LookupIPAddr(ctx, host)
		},
		func(n Network) ([]net.IPAddr, error) {
			return n.LookupIPAddr(ctx, host)
		},
		func() error { return NoSuchHost(host, "rejectdns") },
	)
}

func (r *Router) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	return routerLookupSlice(ctx, r, network, host,
		func(res Resolver) ([]netip.Addr, error) {
			return res.LookupNetIP(ctx, network, host)
		},
		func(n Network) ([]netip.Addr, error) {
			return n.LookupNetIP(ctx, network, host)
		},
		func() error { return NoSuchHost(host, "rejectdns") },
	)
}

func (r *Router) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	return routerLookupSlice(ctx, r, "", host,
		func(res Resolver) ([]string, error) {
			return res.LookupHost(ctx, host)
		},
		func(n Network) ([]string, error) {
			return n.LookupHost(ctx, host)
		},
		func() error { return NoSuchHost(host, "rejectdns") },
	)
}

func (r *Router) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return routerLookupSlice(ctx, r, "", addr,
		func(res Resolver) ([]string, error) {
			return res.LookupAddr(ctx, addr)
		},
		func(n Network) ([]string, error) {
			return n.LookupAddr(ctx, addr)
		},
		func() error { return NoSuchHost(addr, "rejectdns") },
	)
}

func (r *Router) LookupCNAME(ctx context.Context, host string) (string, error) {
	return routerLookupOne(ctx, r, "", host,
		func(res Resolver) (string, error) {
			return res.LookupCNAME(ctx, host)
		},
		func(n Network) (string, error) {
			return n.LookupCNAME(ctx, host)
		},
		func() error { return NoSuchHost(host, "rejectdns") },
	)
}

func (r *Router) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return routerLookupOne(ctx, r, network, service,
		func(res Resolver) (int, error) {
			return res.LookupPort(ctx, network, service)
		},
		func(n Network) (int, error) {
			return n.LookupPort(ctx, network, service)
		},
		func() error { return NoSuchHost(service, "rejectdns") },
	)
}

func (r *Router) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return routerLookupSlice(ctx, r, "", name,
		func(res Resolver) ([]string, error) {
			return res.LookupTXT(ctx, name)
		},
		func(n Network) ([]string, error) {
			return n.LookupTXT(ctx, name)
		},
		func() error { return NoSuchHost(name, "rejectdns") },
	)
}

func (r *Router) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return routerLookupSlice(ctx, r, "", name,
		func(res Resolver) ([]*net.MX, error) {
			return res.LookupMX(ctx, name)
		},
		func(n Network) ([]*net.MX, error) {
			return n.LookupMX(ctx, name)
		},
		func() error { return NoSuchHost(name, "rejectdns") },
	)
}

func (r *Router) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return routerLookupSlice(ctx, r, "", name,
		func(res Resolver) ([]*net.NS, error) {
			return res.LookupNS(ctx, name)
		},
		func(n Network) ([]*net.NS, error) {
			return n.LookupNS(ctx, name)
		},
		func() error { return NoSuchHost(name, "rejectdns") },
	)
}

func (r *Router) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	type result struct {
		cname string
		addrs []*net.SRV
	}
	rejectName := "_" + service + "._" + proto + "." + name
	res, err := routerLookupOne(ctx, r, proto, name,
		func(res Resolver) (result, error) {
			cname, addrs, err := res.LookupSRV(ctx, service, proto, name)
			return result{cname: cname, addrs: addrs}, err
		},
		func(n Network) (result, error) {
			cname, addrs, err := n.LookupSRV(ctx, service, proto, name)
			return result{cname: cname, addrs: addrs}, err
		},
		func() error { return NoSuchHost(rejectName, "rejectdns") },
	)
	return res.cname, res.addrs, err
}

func (r *Router) Interfaces() ([]NetworkInterface, error) {
	return routerCollect(r, func(n Network) ([]NetworkInterface, error) {
		return n.Interfaces()
	})
}

func (r *Router) InterfaceAddrs() ([]net.Addr, error) {
	return routerCollect(r, func(n Network) ([]net.Addr, error) {
		return n.InterfaceAddrs()
	})
}

func (r *Router) InterfaceMulticastAddrs() ([]net.Addr, error) {
	return routerCollect(r, func(n Network) ([]net.Addr, error) {
		return n.InterfaceMulticastAddrs()
	})
}

func (r *Router) InterfacesByIndex(index int) ([]NetworkInterface, error) {
	return routerCollect(r, func(n Network) ([]NetworkInterface, error) {
		return n.InterfacesByIndex(index)
	})
}

func (r *Router) InterfacesByName(name string) ([]NetworkInterface, error) {
	return routerCollect(r, func(n Network) ([]NetworkInterface, error) {
		return n.InterfacesByName(name)
	})
}

func (r *Router) beginRouted(
	ctx context.Context,
	selectSlot func(RouterCfg) int,
	rejectErr func() error,
) (
	slot int,
	backend Network,
	opCtx context.Context,
	cancel context.CancelFunc,
	gen uint64,
	done <-chan struct{},
	err error,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		err = net.ErrClosed
		return
	}
	cfg := r.cfg
	r.mu.Unlock()

	slot = selectSlot(cfg)
	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		err = net.ErrClosed
		return
	}
	if !routerValidSlot(slot) || r.slots[slot-1] == nil {
		r.mu.Unlock()
		err = rejectErr()
		return
	}
	backend = r.slots[slot-1]
	done = r.done
	gen = r.gen
	r.mu.Unlock()

	opCtx, cancel = context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			cancel()
		case <-opCtx.Done():
		}
	}()
	return
}

func (r *Router) begin(
	ctx context.Context,
) (context.Context, context.CancelFunc, uint64, <-chan struct{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		return nil, nil, 0, nil, net.ErrClosed
	}
	done := r.done
	gen := r.gen
	r.mu.Unlock()

	opCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			cancel()
		case <-opCtx.Done():
		}
	}()
	return opCtx, cancel, gen, done, nil
}

func (r *Router) beginLookup(
	ctx context.Context,
	network, address string,
	rejectErr func() error,
) (
	backend Network,
	opCtx context.Context,
	cancel context.CancelFunc,
	done <-chan struct{},
	err error,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		err = net.ErrClosed
		return
	}
	cfg := r.cfg
	r.mu.Unlock()

	slot := routerDefaultSlot
	if cfg != nil {
		slot = cfg.Lookup(network, address)
	}

	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		err = net.ErrClosed
		return
	}
	if !routerValidSlot(slot) || r.slots[slot-1] == nil {
		r.mu.Unlock()
		err = rejectErr()
		return
	}
	backend = r.slots[slot-1]
	done = r.done
	r.mu.Unlock()

	opCtx, cancel = context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			cancel()
		case <-opCtx.Done():
		}
	}()
	return
}

func (r *Router) resolverSnapshot() Resolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up || r.closed {
		return nil
	}
	return r.res
}

func (r *Router) resolveNetAddr(
	ctx context.Context,
	network, address string,
) (string, error) {
	if address == "" {
		return "", nil
	}
	res := r.resolverSnapshot()
	if res == nil {
		return address, nil
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}

	if _, err := strconv.Atoi(service); err != nil {
		port, err := res.LookupPort(ctx, NormalNet(network), service)
		if err != nil {
			return "", err
		}
		service = strconv.Itoa(port)
	}

	if host == "" || net.ParseIP(host) != nil {
		return net.JoinHostPort(host, service), nil
	}

	lookupHost := host
	hosts, err := res.LookupHost(ctx, lookupHost)
	if err != nil {
		return "", err
	}
	host = routerPickResolvedHost(network, hosts)
	if host == "" {
		return "", NoSuchHost(lookupHost, "routerdns")
	}
	return net.JoinHostPort(host, service), nil
}

func (r *Router) routeUDP(
	network string,
	laddr, raddr net.Addr,
) (int, Network) {
	r.mu.Lock()
	if !r.up || r.closed {
		r.mu.Unlock()
		return 0, nil
	}
	cfg := r.cfg
	r.mu.Unlock()

	slot := routerDefaultSlot
	if cfg != nil {
		slot = cfg.RouteUDP(network, laddr, raddr)
	}
	if !routerValidSlot(slot) {
		return slot, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up || r.closed {
		return slot, nil
	}
	return slot, r.slots[slot-1]
}

func (r *Router) trackTCPConn(
	gen uint64,
	slot int,
	c TCPConn,
) (TCPConn, error) {
	id, err := r.reserveTracked(gen)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c = TCPConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { r.unregister(id, slot) },
	})
	if err := r.finishTracked(gen, slot, id, c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (r *Router) trackUDPConn(
	gen uint64,
	slot int,
	c UDPConn,
) (UDPConn, error) {
	id, err := r.reserveTracked(gen)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c = UDPConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { r.unregister(id, slot) },
	})
	if err := r.finishTracked(gen, slot, id, c); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (r *Router) trackTCPListener(
	gen uint64,
	slot int,
	l TCPListener,
) (TCPListener, error) {
	id, err := r.reserveTracked(gen)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	l = TCPListenerWithCallbacks(l, &Callbacks{
		BeforeClose: func() { r.unregister(id, slot) },
		OnAccept:    r.acceptConnCallback(slot),
		OnAcceptTCP: r.acceptTCPConnCallback(slot),
	})
	if err := r.finishTracked(gen, slot, id, l); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func (r *Router) trackRouterUDPConn(
	gen uint64,
	c *routerUDPConn,
) (UDPConn, error) {
	id, err := r.reserveTracked(gen)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.id = id
	c.beforeClose = func() { r.unregister(id, 0) }
	r.mu.Lock()
	if !r.up || r.closed || r.gen != gen {
		r.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	r.closers[id] = c
	r.udp[id] = c
	backends := make([]Network, RouterSlots)
	copy(backends, r.slots[:])
	r.mu.Unlock()

	for i, backend := range backends {
		if backend != nil {
			c.attachBackend(i+1, backend, r.spawner)
		}
	}
	return c, nil
}

func (r *Router) reserveTracked(gen uint64) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up || r.closed || r.gen != gen {
		return 0, net.ErrClosed
	}
	id := r.nextID
	r.nextID++
	return id, nil
}

func (r *Router) finishTracked(
	gen uint64,
	slot int,
	id uint64,
	c io.Closer,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up || r.closed || r.gen != gen {
		return net.ErrClosed
	}
	r.closers[id] = c
	if slot > 0 {
		idx := slot - 1
		if r.bySlot[idx] == nil {
			r.bySlot[idx] = make(map[uint64]io.Closer)
		}
		r.bySlot[idx][id] = c
	}
	return nil
}

func (r *Router) unregister(id uint64, slot int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.closers, id)
	delete(r.udp, id)
	if slot > 0 {
		delete(r.bySlot[slot-1], id)
	}
}

func (r *Router) unregisterUpDown(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.updowns, id)
}

func (r *Router) unregisterCloseSub(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.closeSubs, id)
}

func (r *Router) closePrep() (
	closers []io.Closer,
	updowns []UpDown,
	closeSubs []io.Closer,
	slotSubs []func(),
	done chan struct{},
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, nil, nil, nil
	}
	wasUp := r.up
	r.closed = true
	r.wantUp = false
	r.autoUp = false
	r.up = false
	r.gen++
	if wasUp {
		done = r.done
	}
	closers = make([]io.Closer, 0, len(r.closers))
	for id, c := range r.closers {
		delete(r.closers, id)
		closers = append(closers, c)
	}
	for i := range r.bySlot {
		clear(r.bySlot[i])
	}
	r.udp = make(map[uint64]*routerUDPConn)
	if wasUp {
		updowns = make([]UpDown, 0, len(r.updowns))
		for _, u := range r.updowns {
			updowns = append(updowns, u)
		}
	}
	closeSubs = make([]io.Closer, 0, len(r.closeSubs))
	for id, c := range r.closeSubs {
		delete(r.closeSubs, id)
		closeSubs = append(closeSubs, c)
	}
	slotSubs = make([]func(), 0, RouterSlots)
	for i, unsubscribe := range r.slotSub {
		if unsubscribe != nil {
			r.slotSub[i] = nil
			slotSubs = append(slotSubs, unsubscribe)
		}
	}
	return closers, updowns, closeSubs, slotSubs, done
}

func (r *Router) acceptConnCallback(slot int) func(net.Conn) (net.Conn, error) {
	return func(c net.Conn) (net.Conn, error) {
		unsub, err := r.subscribeCloser(c, slot)
		if err != nil {
			return nil, err
		}
		return ConnWithCallbacks(c, &Callbacks{BeforeClose: unsub}), nil
	}
}

func (r *Router) acceptTCPConnCallback(
	slot int,
) func(TCPConn) (TCPConn, error) {
	return func(c TCPConn) (TCPConn, error) {
		unsub, err := r.subscribeCloser(c, slot)
		if err != nil {
			return nil, err
		}
		return TCPConnWithCallbacks(c, &Callbacks{BeforeClose: unsub}), nil
	}
}

type routerUDPPacket struct {
	data []byte
	addr net.Addr
}

type routerUDPConn struct {
	router *Router
	id     uint64

	network string
	laddr   net.Addr

	mu            sync.Mutex
	backends      [RouterSlots]UDPConn
	closed        bool
	closeCh       chan struct{}
	closeOnce     sync.Once
	beforeClose   func()
	readDeadline  time.Time
	writeDeadline time.Time

	readCh chan routerUDPPacket
}

func newRouterUDPConn(r *Router, network, laddr string) *routerUDPConn {
	return &routerUDPConn{
		router:  r,
		network: network,
		laddr:   &NetAddr{Net: network, Addr: laddr},
		closeCh: make(chan struct{}),
		readCh:  make(chan routerUDPPacket, runtime.GOMAXPROCS(0)),
	}
}

func (c *routerUDPConn) attachBackend(
	slot int,
	backend Network,
	spawner Spawner,
) {
	if backend == nil || !routerValidSlot(slot) {
		return
	}
	bc, err := backend.ListenUDP(
		context.Background(),
		c.network,
		c.laddr.String(),
	)
	if err != nil {
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = bc.Close()
		return
	}
	old := c.backends[slot-1]
	c.backends[slot-1] = bc
	if routerAddrUsesPortZero(c.laddr.String()) {
		c.laddr = bc.LocalAddr()
	}
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if err := spawn(spawner, func() {
		c.readBackend(slot, bc)
	}, "gonnect.Router.udp.readBackend"); err != nil {
		c.mu.Lock()
		if c.backends[slot-1] == bc {
			c.backends[slot-1] = nil
		}
		c.mu.Unlock()
		_ = bc.Close()
	}
}

func (c *routerUDPConn) detachBackend(slot int) {
	if !routerValidSlot(slot) {
		return
	}
	c.mu.Lock()
	bc := c.backends[slot-1]
	c.backends[slot-1] = nil
	c.mu.Unlock()
	if bc != nil {
		_ = bc.Close()
	}
}

func (c *routerUDPConn) readBackend(slot int, bc UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := bc.ReadFrom(buf)
		if err != nil {
			c.closeBackend(slot, bc)
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case c.readCh <- routerUDPPacket{data: data, addr: addr}:
		case <-c.closeCh:
			return
		}
	}
}

func (c *routerUDPConn) closeBackend(slot int, bc UDPConn) {
	c.mu.Lock()
	if routerValidSlot(slot) && c.backends[slot-1] == bc {
		c.backends[slot-1] = nil
	}
	c.mu.Unlock()
	_ = bc.Close()
}

func (c *routerUDPConn) Close() error {
	var closers []io.Closer
	c.closeOnce.Do(func() {
		if c.beforeClose != nil {
			c.beforeClose()
		}
		c.mu.Lock()
		c.closed = true
		close(c.closeCh)
		for i, bc := range c.backends {
			if bc != nil {
				closers = append(closers, bc)
				c.backends[i] = nil
			}
		}
		c.mu.Unlock()
	})
	return closeAll(closers)
}

func (c *routerUDPConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.laddr
}

func (c *routerUDPConn) RemoteAddr() net.Addr { return nil }

func (c *routerUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *routerUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, ConnClosed("read", c.network, c.laddr, nil)
	}
	rd := c.readDeadline
	c.mu.Unlock()

	var timer <-chan time.Time
	if !rd.IsZero() {
		timer = timerForDeadline(rd)
	}
	select {
	case pkt := <-c.readCh:
		return copy(b, pkt.data), pkt.addr, nil
	case <-timer:
		return 0, nil, routerTimeout("read", c.network)
	case <-c.closeCh:
		return 0, nil, ConnClosed("read", c.network, c.LocalAddr(), nil)
	}
}

func (c *routerUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
	if err != nil {
		return 0, nil, err
	}
	return n, udpAddr, nil
}

func (c *routerUDPConn) ReadFromUDPAddrPort(
	b []byte,
) (int, netip.AddrPort, error) {
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, ap, nil
}

func (c *routerUDPConn) Write(b []byte) (int, error) {
	return 0, &net.OpError{
		Op:  "write",
		Net: c.network,
		Err: errors.New("not connected"),
	}
}

func (c *routerUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ConnClosed("write", c.network, c.laddr, addr)
	}
	wd := c.writeDeadline
	c.mu.Unlock()

	slot, backend := c.router.routeUDP(c.network, c.LocalAddr(), addr)
	if !routerValidSlot(slot) || backend == nil {
		return 0, dialError(c.network, addr.String())
	}

	c.mu.Lock()
	bc := c.backends[slot-1]
	c.mu.Unlock()
	if bc == nil {
		c.attachBackend(slot, backend, c.router.spawner)
		c.mu.Lock()
		bc = c.backends[slot-1]
		c.mu.Unlock()
	}
	if bc == nil {
		return 0, dialError(c.network, addr.String())
	}
	if !wd.IsZero() {
		_ = bc.SetWriteDeadline(wd)
	}
	n, err := bc.WriteTo(b, addr)
	if err != nil {
		c.closeBackend(slot, bc)
		return 0, err
	}
	return n, nil
}

func (c *routerUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.WriteTo(b, addr)
}

func (c *routerUDPConn) WriteToUDPAddrPort(
	b []byte,
	addr netip.AddrPort,
) (int, error) {
	return c.WriteTo(b, &NetAddr{Net: c.network, Addr: addr.String()})
}

func (c *routerUDPConn) ReadMsgUDP(
	b, oob []byte,
) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, addr, err = c.ReadFromUDP(b)
	return
}

func (c *routerUDPConn) ReadMsgUDPAddrPort(
	b, oob []byte,
) (n, oobn, flags int, addr netip.AddrPort, err error) {
	n, addr, err = c.ReadFromUDPAddrPort(b)
	return
}

func (c *routerUDPConn) WriteMsgUDP(
	b, oob []byte,
	addr *net.UDPAddr,
) (n, oobn int, err error) {
	n, err = c.WriteToUDP(b, addr)
	return
}

func (c *routerUDPConn) WriteMsgUDPAddrPort(
	b, oob []byte,
	addr netip.AddrPort,
) (n, oobn int, err error) {
	n, err = c.WriteToUDPAddrPort(b, addr)
	return
}

func (c *routerUDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *routerUDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *routerUDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func routerLookupSlice[T any](
	ctx context.Context,
	r *Router,
	network, address string,
	callResolver func(Resolver) ([]T, error),
	callBackend func(Network) ([]T, error),
	rejectErr func() error,
) ([]T, error) {
	res := r.resolverSnapshot()
	if res != nil {
		opCtx, cancel, _, done, err := r.begin(ctx)
		if err != nil {
			return nil, err
		}
		defer cancel()
		return runDetachedOp(
			r.spawner,
			opCtx,
			done,
			func(context.Context) ([]T, error) {
				return callResolver(res)
			},
			func([]T) {},
		)
	}

	backend, opCtx, cancel, done, err := r.beginLookup(
		ctx,
		network,
		address,
		rejectErr,
	)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		r.spawner,
		opCtx,
		done,
		func(context.Context) ([]T, error) {
			return callBackend(backend)
		},
		func([]T) {},
	)
}

func routerLookupOne[T any](
	ctx context.Context,
	r *Router,
	network, address string,
	callResolver func(Resolver) (T, error),
	callBackend func(Network) (T, error),
	rejectErr func() error,
) (T, error) {
	res := r.resolverSnapshot()
	if res != nil {
		opCtx, cancel, _, done, err := r.begin(ctx)
		if err != nil {
			var zero T
			return zero, err
		}
		defer cancel()
		return runDetachedOp(
			r.spawner,
			opCtx,
			done,
			func(context.Context) (T, error) {
				return callResolver(res)
			},
			func(T) {},
		)
	}

	backend, opCtx, cancel, done, err := r.beginLookup(
		ctx,
		network,
		address,
		rejectErr,
	)
	if err != nil {
		var zero T
		return zero, err
	}
	defer cancel()
	return runDetachedOp(
		r.spawner,
		opCtx,
		done,
		func(context.Context) (T, error) {
			return callBackend(backend)
		},
		func(T) {},
	)
}

func routerCollect[T any](
	r *Router,
	call func(Network) ([]T, error),
) ([]T, error) {
	backends, err := r.backendsSnapshot()
	if err != nil {
		return nil, err
	}
	if len(backends) == 0 {
		return []T{}, nil
	}
	var out []T
	var firstErr error
	var ok bool
	for _, backend := range backends {
		values, err := call(backend)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok = true
		out = append(out, values...)
	}
	if ok {
		if out == nil {
			return []T{}, nil
		}
		return out, nil
	}
	return nil, firstErr
}

func (r *Router) backendsSnapshot() ([]Network, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.up || r.closed {
		return nil, net.ErrClosed
	}
	out := make([]Network, 0, RouterSlots)
	for _, backend := range r.slots {
		if backend != nil {
			out = append(out, backend)
		}
	}
	return out, nil
}

func routerValidSlot(slot int) bool { return slot >= 1 && slot <= RouterSlots }

func routerSlotError(slot int) error {
	return &net.AddrError{
		Err:  "router slot out of range",
		Addr: strconv.Itoa(slot),
	}
}

func routerTimeout(op, network string) error {
	return &net.OpError{Op: op, Net: network, Err: errors.New("i/o timeout")}
}

func routerAddrUsesPortZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port == "0"
}

func routerPickResolvedHost(network string, hosts []string) string {
	family := FamilyFromNetwork(network)
	for _, host := range hosts {
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		switch family {
		case "ip4":
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		case "ip6":
			if ip.To4() == nil && ip.To16() != nil {
				return ip.String()
			}
		default:
			return ip.String()
		}
	}
	return ""
}
