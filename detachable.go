package gonnect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
)

var _ interface {
	Network
	UpDown
	io.Closer
	Wrapper
} = (*DetachedNetwork)(nil)

// DetachedNetwork is an independently stoppable wrapper around a Network.
//
// Down and Close affect only the wrapper: they do not call Down or Close on the
// wrapped Network. They do cancel in-flight wrapper operations and close every
// connection, packet connection, listener, and accepted connection returned via
// this wrapper. Multiple DetachedNetwork values can wrap the same Network and be
// used concurrently; stopping one wrapper does not stop the others.
//
// Long operations such as Dial, Listen, and Lookup are run without holding the
// wrapper mutex. The wrapper injects its own cancellation into the supplied
// context so a concurrent Down or Close can unblock operations that honor
// context cancellation.
type DetachedNetwork struct {
	wrapped Network

	mu      sync.Mutex
	up      bool
	gen     uint64
	done    chan struct{}
	nextID  uint64
	closers map[uint64]io.Closer
}

// DetachNetwork creates an independently stoppable wrapper around n.
func DetachNetwork(n Network) *DetachedNetwork {
	return &DetachedNetwork{
		wrapped: n,
		up:      true,
		gen:     1,
		done:    make(chan struct{}),
		closers: make(map[uint64]io.Closer),
	}
}

// GetWrapped returns the wrapped Network.
func (n *DetachedNetwork) GetWrapped() any { return n.wrapped }

// IsNative reports the wrapped Network native status.
func (n *DetachedNetwork) IsNative() bool { return n.wrapped.IsNative() }

// Up re-enables this wrapper. It does not call Up on the wrapped Network.
func (n *DetachedNetwork) Up() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up {
		return nil
	}
	n.done = make(chan struct{})
	n.gen++
	n.up = true
	return nil
}

// Down stops this wrapper, cancels pending wrapper operations, and closes all
// objects spawned through it. It does not call Down on the wrapped Network.
func (n *DetachedNetwork) Down() error {
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		return nil
	}
	n.up = false
	n.gen++
	done := n.done
	closers := make([]io.Closer, 0, len(n.closers))
	for id, c := range n.closers {
		delete(n.closers, id)
		closers = append(closers, c)
	}
	n.mu.Unlock()

	close(done)
	return closeAll(closers)
}

// Close is equivalent to Down.
func (n *DetachedNetwork) Close() error { return n.Down() }

// SubscribeCloser registers c to be closed when this wrapper is stopped.
//
// It is intended for callers that bypass this Network's Dial or Listen methods
// but still want their externally-created connections
// to be closed by Down or Close. The returned unsubscribe function removes c
// from this wrapper without closing it. If this Network is already down, c is
// closed before SubscribeCloser returns net.ErrClosed.
func (n *DetachedNetwork) SubscribeCloser(c io.Closer) (func(), error) {
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.closers[id] = c
	n.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() { n.unregister(id) })
	}, nil
}

// IsUp reports whether this wrapper is currently up.
func (n *DetachedNetwork) IsUp() (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up, nil
}

// Dial establishes a connection via the wrapped Network and tracks it on this
// wrapper.
func (n *DetachedNetwork) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (net.Conn, error) {
			return n.wrapped.Dial(ctx, network, address)
		},
		func(c net.Conn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackConn(gen, c)
}

// Listen creates a listener via the wrapped Network and tracks it on this
// wrapper. Accepted connections are also tracked by this wrapper.
func (n *DetachedNetwork) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	l, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (net.Listener, error) {
			return n.wrapped.Listen(ctx, network, address)
		},
		func(l net.Listener) { _ = l.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackListener(gen, l)
}

// PacketDial establishes a packet connection via the wrapped Network.
func (n *DetachedNetwork) PacketDial(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (PacketConn, error) {
			return n.wrapped.PacketDial(ctx, network, address)
		},
		func(c PacketConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackPacketConn(gen, c)
}

// ListenPacket creates and tracks a packet listener via the wrapped Network.
func (n *DetachedNetwork) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (PacketConn, error) {
			return n.wrapped.ListenPacket(ctx, network, address)
		},
		func(c PacketConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackPacketConn(gen, c)
}

// DialTCP establishes a TCP connection via the wrapped Network.
func (n *DetachedNetwork) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (TCPConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (TCPConn, error) {
			return n.wrapped.DialTCP(ctx, network, laddr, raddr)
		},
		func(c TCPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackTCPConn(gen, c)
}

// ListenTCP creates and tracks a TCP listener via the wrapped Network.
func (n *DetachedNetwork) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (TCPListener, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	l, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (TCPListener, error) {
			return n.wrapped.ListenTCP(ctx, network, laddr)
		},
		func(l TCPListener) { _ = l.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackTCPListener(gen, l)
}

// DialUDP establishes a UDP connection via the wrapped Network.
func (n *DetachedNetwork) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (UDPConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (UDPConn, error) {
			return n.wrapped.DialUDP(ctx, network, laddr, raddr)
		},
		func(c UDPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackUDPConn(gen, c)
}

// ListenUDP creates and tracks a UDP connection via the wrapped Network.
func (n *DetachedNetwork) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (UDPConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (UDPConn, error) {
			return n.wrapped.ListenUDP(ctx, network, laddr)
		},
		func(c UDPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackUDPConn(gen, c)
}

// ListenPacketConfig creates and tracks a configured packet listener via the
// wrapped Network.
func (n *DetachedNetwork) ListenPacketConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, address string,
) (PacketConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (PacketConn, error) {
			return n.wrapped.ListenPacketConfig(ctx, lc, network, address)
		},
		func(c PacketConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackPacketConn(gen, c)
}

// ListenUDPConfig creates and tracks a configured UDP listener via the wrapped
// Network.
func (n *DetachedNetwork) ListenUDPConfig(
	ctx context.Context,
	lc *ListenConfig,
	network, laddr string,
) (UDPConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (UDPConn, error) {
			return n.wrapped.ListenUDPConfig(ctx, lc, network, laddr)
		},
		func(c UDPConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackUDPConn(gen, c)
}

func (n *DetachedNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	ctx, cancel, gen, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	c, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (MulticastPacketConn, error) {
			return n.wrapped.ListenMulticastUDP(ctx, network, address, opts)
		},
		func(c MulticastPacketConn) { _ = c.Close() },
	)
	if err != nil {
		return nil, err
	}
	return n.trackMulticastPacketConn(gen, c)
}

func (n *DetachedNetwork) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]net.IP, error) {
			return n.wrapped.LookupIP(ctx, network, address)
		},
		func([]net.IP) {},
	)
}

func (n *DetachedNetwork) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]net.IPAddr, error) {
			return n.wrapped.LookupIPAddr(ctx, host)
		},
		func([]net.IPAddr) {},
	)
}

func (n *DetachedNetwork) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]netip.Addr, error) {
			return n.wrapped.LookupNetIP(ctx, network, host)
		},
		func([]netip.Addr) {},
	)
}

func (n *DetachedNetwork) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]string, error) {
			return n.wrapped.LookupHost(ctx, host)
		},
		func([]string) {},
	)
}

func (n *DetachedNetwork) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]string, error) {
			return n.wrapped.LookupAddr(ctx, addr)
		},
		func([]string) {},
	)
}

func (n *DetachedNetwork) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	return runDetachedOp(ctx, done, func(ctx context.Context) (string, error) {
		return n.wrapped.LookupCNAME(ctx, host)
	}, func(string) {})
}

func (n *DetachedNetwork) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer cancel()
	return runDetachedOp(ctx, done, func(ctx context.Context) (int, error) {
		return n.wrapped.LookupPort(ctx, network, service)
	}, func(int) {})
}

func (n *DetachedNetwork) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]string, error) {
			return n.wrapped.LookupTXT(ctx, name)
		},
		func([]string) {},
	)
}

func (n *DetachedNetwork) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]*net.MX, error) {
			return n.wrapped.LookupMX(ctx, name)
		},
		func([]*net.MX) {},
	)
}

func (n *DetachedNetwork) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) ([]*net.NS, error) {
			return n.wrapped.LookupNS(ctx, name)
		},
		func([]*net.NS) {},
	)
}

func (n *DetachedNetwork) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	ctx, cancel, _, done, err := n.begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer cancel()
	result, err := runDetachedOp(
		ctx,
		done,
		func(ctx context.Context) (struct {
			cname string
			addrs []*net.SRV
		}, error) {
			cname, addrs, err := n.wrapped.LookupSRV(ctx, service, proto, name)
			return struct {
				cname string
				addrs []*net.SRV
			}{cname: cname, addrs: addrs}, err
		},
		func(struct {
			cname string
			addrs []*net.SRV
		}) {
		},
	)
	if err != nil {
		return "", nil, err
	}
	return result.cname, result.addrs, nil
}

func (n *DetachedNetwork) Interfaces() ([]NetworkInterface, error) {
	if err := n.checkUp(); err != nil {
		return nil, err
	}
	return n.wrapped.Interfaces()
}

func (n *DetachedNetwork) InterfaceAddrs() ([]net.Addr, error) {
	if err := n.checkUp(); err != nil {
		return nil, err
	}
	return n.wrapped.InterfaceAddrs()
}

func (n *DetachedNetwork) InterfaceMulticastAddrs() ([]net.Addr, error) {
	if err := n.checkUp(); err != nil {
		return nil, err
	}
	return n.wrapped.InterfaceMulticastAddrs()
}

func (n *DetachedNetwork) InterfacesByIndex(
	index int,
) ([]NetworkInterface, error) {
	if err := n.checkUp(); err != nil {
		return nil, err
	}
	return n.wrapped.InterfacesByIndex(index)
}

func (n *DetachedNetwork) InterfacesByName(
	name string,
) ([]NetworkInterface, error) {
	if err := n.checkUp(); err != nil {
		return nil, err
	}
	return n.wrapped.InterfacesByName(name)
}

func (n *DetachedNetwork) begin(
	ctx context.Context,
) (context.Context, context.CancelFunc, uint64, <-chan struct{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		return nil, nil, 0, nil, net.ErrClosed
	}
	wrapperDone := n.done
	gen := n.gen
	n.mu.Unlock()

	opCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-wrapperDone:
			cancel()
		case <-opCtx.Done():
		}
	}()
	return opCtx, cancel, gen, wrapperDone, nil
}

func (n *DetachedNetwork) checkUp() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return net.ErrClosed
	}
	return nil
}

func (n *DetachedNetwork) unregister(id uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.closers, id)
}

func (n *DetachedNetwork) trackConn(gen uint64, c net.Conn) (net.Conn, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = ConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

func (n *DetachedNetwork) trackTCPConn(
	gen uint64,
	c TCPConn,
) (TCPConn, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = TCPConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

func (n *DetachedNetwork) trackUDPConn(
	gen uint64,
	c UDPConn,
) (UDPConn, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = UDPConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

func (n *DetachedNetwork) trackPacketConn(
	gen uint64,
	c PacketConn,
) (PacketConn, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = PacketConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

func (n *DetachedNetwork) trackMulticastPacketConn(
	gen uint64,
	c MulticastPacketConn,
) (MulticastPacketConn, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	c = &detachedMulticastPacketConn{
		MulticastPacketConn: c,
		beforeClose:         func() { n.unregister(id) },
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

type detachedMulticastPacketConn struct {
	MulticastPacketConn
	closeOnce   sync.Once
	beforeClose func()
}

func (c *detachedMulticastPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.beforeClose != nil {
			c.beforeClose()
		}
	})
	return c.MulticastPacketConn.Close()
}

func (n *DetachedNetwork) trackListener(
	gen uint64,
	l net.Listener,
) (net.Listener, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = l.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	l = ListenerWithCallbacks(l, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
		OnAccept:    n.acceptConnCallback,
		OnAcceptTCP: n.acceptTCPConnCallback,
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = l.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = l
	n.mu.Unlock()
	return l, nil
}

func (n *DetachedNetwork) trackTCPListener(
	gen uint64,
	l TCPListener,
) (TCPListener, error) {
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = l.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	l = TCPListenerWithCallbacks(l, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
		OnAccept:    n.acceptConnCallback,
		OnAcceptTCP: n.acceptTCPConnCallback,
	})
	n.mu.Lock()
	if !n.up || n.gen != gen {
		n.mu.Unlock()
		_ = l.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = l
	n.mu.Unlock()
	return l, nil
}

func (n *DetachedNetwork) acceptConnCallback(c net.Conn) (net.Conn, error) {
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = ConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

func (n *DetachedNetwork) acceptTCPConnCallback(c TCPConn) (TCPConn, error) {
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := n.nextID
	n.nextID++
	n.mu.Unlock()

	c = TCPConnWithCallbacks(c, &Callbacks{
		BeforeClose: func() { n.unregister(id) },
	})
	n.mu.Lock()
	if !n.up {
		n.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	n.closers[id] = c
	n.mu.Unlock()
	return c, nil
}

type detachedOpResult[T any] struct {
	value T
	err   error
}

func runDetachedOp[T any](
	ctx context.Context,
	wrapperDone <-chan struct{},
	call func(context.Context) (T, error),
	closeLate func(T),
) (T, error) {
	ch := make(chan detachedOpResult[T], 1)
	go func() {
		value, err := call(ctx)
		ch <- detachedOpResult[T]{value: value, err: err}
	}()

	var zero T
	select {
	case result := <-ch:
		return result.value, result.err
	case <-wrapperDone:
		go closeDetachedOpResult(ch, closeLate)
		return zero, net.ErrClosed
	case <-ctx.Done():
		go closeDetachedOpResult(ch, closeLate)
		select {
		case <-wrapperDone:
			return zero, net.ErrClosed
		default:
		}
		return zero, ctx.Err()
	}
}

func closeDetachedOpResult[T any](
	ch <-chan detachedOpResult[T],
	closeLate func(T),
) {
	result := <-ch
	if result.err == nil {
		closeLate(result.value)
	}
}

func closeAll(closers []io.Closer) error {
	var err error
	for _, c := range closers {
		err = errors.Join(err, c.Close())
	}
	return err
}
