package sniffer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
)

const (
	// RejectSlot rejects an operation instead of routing it to an output.
	RejectSlot = 0

	// DefaultSlot is the default output slot used when no control callback is
	// configured. Slots are 1-based.
	DefaultSlot = 1
)

var _ interface {
	gonnect.Network
	gonnect.UpDown
	io.Closer
	gonnect.CloserSubscriber
	gonnect.UpDownSubscriber
} = (*Sniffer)(nil)

// Operation names the gonnect.Network method currently being controlled.
type Operation string

const (
	OpDial               Operation = "Dial"
	OpListen             Operation = "Listen"
	OpPacketDial         Operation = "PacketDial"
	OpListenPacket       Operation = "ListenPacket"
	OpDialTCP            Operation = "DialTCP"
	OpListenTCP          Operation = "ListenTCP"
	OpDialUDP            Operation = "DialUDP"
	OpListenUDP          Operation = "ListenUDP"
	OpListenPacketConfig Operation = "ListenPacketConfig"
	OpListenUDPConfig    Operation = "ListenUDPConfig"
	OpListenMulticastUDP Operation = "ListenMulticastUDP"
	OpLookupIP           Operation = "LookupIP"
	OpLookupIPAddr       Operation = "LookupIPAddr"
	OpLookupNetIP        Operation = "LookupNetIP"
	OpLookupHost         Operation = "LookupHost"
	OpLookupAddr         Operation = "LookupAddr"
	OpLookupCNAME        Operation = "LookupCNAME"
	OpLookupPort         Operation = "LookupPort"
	OpLookupNS           Operation = "LookupNS"
	OpLookupMX           Operation = "LookupMX"
	OpLookupSRV          Operation = "LookupSRV"
	OpLookupTXT          Operation = "LookupTXT"
	OpInterfaces         Operation = "Interfaces"
	OpInterfaceAddrs     Operation = "InterfaceAddrs"
	OpInterfaceMcast     Operation = "InterfaceMulticastAddrs"
	OpInterfacesByIndex  Operation = "InterfacesByIndex"
	OpInterfacesByName   Operation = "InterfacesByName"
)

// Call contains the arguments for one Network method call.
//
// The control callback receives a pointer to a Call copy. It may modify fields
// before returning its Action. Sniffer uses the modified fields for routing.
// The callback must not retain the pointer.
//
// Dial-style operations use Dst for the remote address. DialTCP and DialUDP
// also use Src for the local address. Listen-style operations use Src for the
// listen address. Lookup operations use Host for the lookup name or address,
// except LookupPort, which uses Service, and LookupSRV, which uses Service,
// Proto, and Host. Interface lookups use IfIndex or IfName.
type Call struct {
	Operation Operation
	Network   string
	Src       string
	Dst       string
	Host      string
	Service   string
	Proto     string
	IfIndex   int
	IfName    string

	ListenConfig     *gonnect.ListenConfig
	MulticastOptions gonnect.MulticastOptions
}

// Action is the routing decision returned by a control callback.
//
// Slot is a 1-based output slot. Slot 0 rejects the call. Invalid slots and nil
// output slots also reject the call.
//
// Intercept is honored only for outgoing TCP Dial and DialTCP calls. When it is
// true for those calls, Sniffer returns a local mock TCP connection, sniffs
// client-first bytes from that connection, and then calls SniffControl for the
// final route. When it is true for any other call, Sniffer rejects the call as
// if Slot were RejectSlot.
type Action struct {
	Slot      int
	Intercept bool
}

// Control decides how a Network method call is processed.
type Control func(*Call) Action

// SniffResult is the output of an intercepted connection sniff.
type SniffResult struct {
	// Index is the matched classifier index, or NoMatch.
	Index int
	// Metadata is Metadata(classifier) for the matched classifier.
	Metadata any
	// Err is the read error returned by Sniff, if any.
	Err error
}

// SniffedCall is passed to SniffControl after an intercepted connection has
// been sniffed.
type SniffedCall struct {
	Call
	Result SniffResult
}

// SniffControl decides the final route for an intercepted and sniffed
// connection.
type SniffControl func(*SniffedCall) Action

// SnifferConfig configures a Sniffer Network.
type SnifferConfig struct {
	// Outputs are the immutable output slots. Slots are 1-based.
	Outputs []gonnect.Network

	// Control runs for every Network method call.
	Control Control

	// SniffControl runs after an intercepted outgoing TCP connection is
	// sniffed. If nil, the first Action is used as the final action.
	SniffControl SniffControl

	// Classifiers are used for each intercepted outgoing TCP connection.
	Classifiers []Factory

	// SniffBufferSize is the maximum byte count inspected from an intercepted
	// connection. Zero uses MinFactorySniffBufferSize(Classifiers...).
	SniffBufferSize int

	// Pool optionally provides sniff and put-back buffers.
	Pool bufpool.Pool

	// Spawner optionally starts background workers.
	Spawner gonnect.Spawner
}

// Sniffer is a gonnect.Network middleware that routes calls to immutable
// output slots and can sniff outgoing TCP dials before the final route.
//
// Sniffer does not close or move output Networks up or down. It owns only the
// connections and listeners returned by its own methods. Close permanently
// closes Sniffer, closes those owned objects, and makes future calls return
// net.ErrClosed or normal rejection errors. Down closes owned objects and
// rejects calls until Up is called.
//
// Output slot closure affects only calls routed to that output. Sniffer does
// not subscribe to output lifecycle events.
type Sniffer struct {
	mu      sync.Mutex
	up      bool
	closed  bool
	gen     uint64
	done    chan struct{}
	outputs []gonnect.Network

	control     Control
	sniffCtl    SniffControl
	factories   []Factory
	bufferSize  int
	pool        bufpool.Pool
	spawner     gonnect.Spawner
	nextID      uint64
	closers     map[uint64]io.Closer
	nextUpDown  uint64
	updowns     map[uint64]gonnect.UpDown
	nextCloseID uint64
	closeSubs   map[uint64]io.Closer
}

// NewSniffer creates a Sniffer Network.
func NewSniffer(config SnifferConfig) (*Sniffer, error) {
	if config.SniffBufferSize < 0 {
		return nil, errors.New("sniffer: negative SniffBufferSize")
	}

	factories := append([]Factory(nil), config.Classifiers...)
	for _, factory := range factories {
		if factory == nil {
			return nil, errors.New("sniffer: nil Factory")
		}
	}

	bufferSize := config.SniffBufferSize
	if bufferSize == 0 {
		bufferSize = MinFactorySniffBufferSize(factories...)
	}

	return &Sniffer{
		up:         true,
		gen:        1,
		done:       make(chan struct{}),
		outputs:    append([]gonnect.Network(nil), config.Outputs...),
		control:    config.Control,
		sniffCtl:   config.SniffControl,
		factories:  factories,
		bufferSize: bufferSize,
		pool:       config.Pool,
		spawner:    config.Spawner,
		closers:    make(map[uint64]io.Closer),
		updowns:    make(map[uint64]gonnect.UpDown),
		closeSubs:  make(map[uint64]io.Closer),
	}, nil
}

// IsNative always reports false because Sniffer can route and defer dials.
func (s *Sniffer) IsNative() bool { return false }

// Outputs returns a copy of the configured output slots.
func (s *Sniffer) Outputs() []gonnect.Network {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gonnect.Network(nil), s.outputs...)
}

// Classifiers returns a copy of the configured classifier factories.
func (s *Sniffer) Classifiers() []Factory {
	return append([]Factory(nil), s.factories...)
}

// Up re-enables Sniffer after Down.
func (s *Sniffer) Up() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.up {
		s.mu.Unlock()
		return nil
	}
	s.up = true
	s.gen++
	s.done = make(chan struct{})
	s.closers = make(map[uint64]io.Closer)
	updowns := s.updownsSnapshotLocked()
	s.mu.Unlock()
	return snifferUpAll(updowns)
}

// Down disables Sniffer and closes all objects returned by it.
func (s *Sniffer) Down() error {
	s.mu.Lock()
	if s.closed || !s.up {
		s.mu.Unlock()
		return nil
	}
	s.up = false
	s.gen++
	done := s.done
	closers := s.drainTrackedLocked()
	updowns := s.updownsSnapshotLocked()
	s.mu.Unlock()

	close(done)
	return errors.Join(snifferCloseAll(closers), snifferDownAll(updowns))
}

// Close permanently closes Sniffer. It does not close output Networks.
func (s *Sniffer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	wasUp := s.up
	s.closed = true
	s.up = false
	s.gen++
	done := s.done
	closers := s.drainTrackedLocked()
	var updowns []gonnect.UpDown
	if wasUp {
		updowns = s.updownsSnapshotLocked()
	}
	closeSubs := make([]io.Closer, 0, len(s.closeSubs))
	for id, closer := range s.closeSubs {
		delete(s.closeSubs, id)
		closeSubs = append(closeSubs, closer)
	}
	s.mu.Unlock()

	if wasUp {
		close(done)
	}
	return errors.Join(
		snifferCloseAll(closers),
		snifferDownAll(updowns),
		snifferCloseAll(closeSubs),
	)
}

// IsUp reports whether Sniffer is currently up and not closed.
func (s *Sniffer) IsUp() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.up && !s.closed, nil
}

// SubscribeCloser registers c to be closed when Sniffer is closed.
func (s *Sniffer) SubscribeCloser(c io.Closer) (func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	id := s.nextCloseID
	s.nextCloseID++
	s.closeSubs[id] = c
	s.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.closeSubs, id)
			s.mu.Unlock()
		})
	}, nil
}

// SubscribeUpDown registers u to follow Sniffer's Up and Down state.
func (s *Sniffer) SubscribeUpDown(u gonnect.UpDown) (func(), error) {
	s.mu.Lock()
	id := s.nextUpDown
	s.nextUpDown++
	s.updowns[id] = u
	down := !s.up || s.closed
	s.mu.Unlock()

	var err error
	if down {
		err = u.Down()
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.updowns, id)
			s.mu.Unlock()
		})
	}, err
}

// Dial routes or intercepts a stream dial.
func (s *Sniffer) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	call := Call{Operation: OpDial, Network: network, Dst: address}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	if action.Intercept && gonnect.IsTCPNetwork(call.Network) {
		return s.newInterceptedConn(opCtx, gen, done, call, action)
	}

	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.Dial(opCtx, call.Network, call.Dst)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (net.Conn, error) {
			return backend.Dial(ctx, call.Network, call.Dst)
		},
		func(conn net.Conn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackConn(gen, conn)
}

// Listen routes a stream listener.
func (s *Sniffer) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
	call := Call{Operation: OpListen, Network: network, Src: address}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.Listen(opCtx, call.Network, call.Src)
	}
	listener, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (net.Listener, error) {
			return backend.Listen(ctx, call.Network, call.Src)
		},
		func(listener net.Listener) { _ = listener.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackListener(gen, listener)
}

// PacketDial routes a packet dial.
func (s *Sniffer) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	call := Call{Operation: OpPacketDial, Network: network, Dst: address}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.PacketDial(opCtx, call.Network, call.Dst)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.PacketConn, error) {
			return backend.PacketDial(ctx, call.Network, call.Dst)
		},
		func(conn gonnect.PacketConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackPacketConn(gen, conn)
}

// ListenPacket routes a packet listener.
func (s *Sniffer) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
	call := Call{Operation: OpListenPacket, Network: network, Src: address}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenPacket(opCtx, call.Network, call.Src)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.PacketConn, error) {
			return backend.ListenPacket(ctx, call.Network, call.Src)
		},
		func(conn gonnect.PacketConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackPacketConn(gen, conn)
}

// DialTCP routes or intercepts an outgoing TCP dial.
func (s *Sniffer) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	call := Call{
		Operation: OpDialTCP,
		Network:   network,
		Src:       laddr,
		Dst:       raddr,
	}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	if action.Intercept && gonnect.IsTCPNetwork(call.Network) {
		return s.newInterceptedConn(opCtx, gen, done, call, action)
	}

	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.DialTCP(opCtx, call.Network, call.Src, call.Dst)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.TCPConn, error) {
			return backend.DialTCP(ctx, call.Network, call.Src, call.Dst)
		},
		func(conn gonnect.TCPConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackTCPConn(gen, conn)
}

// ListenTCP routes a TCP listener.
func (s *Sniffer) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	call := Call{Operation: OpListenTCP, Network: network, Src: laddr}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenTCP(opCtx, call.Network, call.Src)
	}
	listener, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.TCPListener, error) {
			return backend.ListenTCP(ctx, call.Network, call.Src)
		},
		func(listener gonnect.TCPListener) { _ = listener.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackTCPListener(gen, listener)
}

// DialUDP routes a UDP dial.
func (s *Sniffer) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	call := Call{
		Operation: OpDialUDP,
		Network:   network,
		Src:       laddr,
		Dst:       raddr,
	}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.DialUDP(opCtx, call.Network, call.Src, call.Dst)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.UDPConn, error) {
			return backend.DialUDP(ctx, call.Network, call.Src, call.Dst)
		},
		func(conn gonnect.UDPConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackUDPConn(gen, conn)
}

// ListenUDP routes a UDP listener.
func (s *Sniffer) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	call := Call{Operation: OpListenUDP, Network: network, Src: laddr}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenUDP(opCtx, call.Network, call.Src)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.UDPConn, error) {
			return backend.ListenUDP(ctx, call.Network, call.Src)
		},
		func(conn gonnect.UDPConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackUDPConn(gen, conn)
}

// ListenPacketConfig routes a packet listener with a ListenConfig.
func (s *Sniffer) ListenPacketConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, address string,
) (gonnect.PacketConn, error) {
	call := Call{
		Operation:    OpListenPacketConfig,
		Network:      network,
		Src:          address,
		ListenConfig: lc,
	}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenPacketConfig(
			opCtx,
			call.ListenConfig,
			call.Network,
			call.Src,
		)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.PacketConn, error) {
			return backend.ListenPacketConfig(
				ctx,
				call.ListenConfig,
				call.Network,
				call.Src,
			)
		},
		func(conn gonnect.PacketConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackPacketConn(gen, conn)
}

// ListenUDPConfig routes a UDP listener with a ListenConfig.
func (s *Sniffer) ListenUDPConfig(
	ctx context.Context,
	lc *gonnect.ListenConfig,
	network, laddr string,
) (gonnect.UDPConn, error) {
	call := Call{
		Operation:    OpListenUDPConfig,
		Network:      network,
		Src:          laddr,
		ListenConfig: lc,
	}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenUDPConfig(
			opCtx,
			call.ListenConfig,
			call.Network,
			call.Src,
		)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.UDPConn, error) {
			return backend.ListenUDPConfig(
				ctx,
				call.ListenConfig,
				call.Network,
				call.Src,
			)
		},
		func(conn gonnect.UDPConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackUDPConn(gen, conn)
}

// ListenMulticastUDP routes a multicast UDP listener.
func (s *Sniffer) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts gonnect.MulticastOptions,
) (gonnect.MulticastPacketConn, error) {
	call := Call{
		Operation:        OpListenMulticastUDP,
		Network:          network,
		Src:              address,
		MulticastOptions: opts,
	}
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return rejectNetwork.ListenMulticastUDP(
			opCtx,
			call.Network,
			call.Src,
			call.MulticastOptions,
		)
	}
	conn, err := runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (gonnect.MulticastPacketConn, error) {
			return backend.ListenMulticastUDP(
				ctx,
				call.Network,
				call.Src,
				call.MulticastOptions,
			)
		},
		func(conn gonnect.MulticastPacketConn) { _ = conn.Close() },
	)
	if err != nil {
		return nil, err
	}
	return s.trackMulticastPacketConn(gen, conn)
}

// LookupIP routes an IP lookup.
func (s *Sniffer) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	call := Call{Operation: OpLookupIP, Network: network, Host: address}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]net.IP, error) {
			return n.LookupIP(ctx, call.Network, call.Host)
		},
		func(ctx context.Context, call Call) ([]net.IP, error) {
			return rejectNetwork.LookupIP(ctx, call.Network, call.Host)
		},
	)
}

// LookupIPAddr routes an IP-address lookup.
func (s *Sniffer) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	call := Call{Operation: OpLookupIPAddr, Host: host}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]net.IPAddr, error) {
			return n.LookupIPAddr(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]net.IPAddr, error) {
			return rejectNetwork.LookupIPAddr(ctx, call.Host)
		},
	)
}

// LookupNetIP routes a netip lookup.
func (s *Sniffer) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	call := Call{Operation: OpLookupNetIP, Network: network, Host: host}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]netip.Addr, error) {
			return n.LookupNetIP(ctx, call.Network, call.Host)
		},
		func(ctx context.Context, call Call) ([]netip.Addr, error) {
			return rejectNetwork.LookupNetIP(ctx, call.Network, call.Host)
		},
	)
}

// LookupHost routes a host lookup.
func (s *Sniffer) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	call := Call{Operation: OpLookupHost, Host: host}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]string, error) {
			return n.LookupHost(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]string, error) {
			return rejectNetwork.LookupHost(ctx, call.Host)
		},
	)
}

// LookupAddr routes a reverse lookup.
func (s *Sniffer) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	call := Call{Operation: OpLookupAddr, Host: addr}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]string, error) {
			return n.LookupAddr(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]string, error) {
			return rejectNetwork.LookupAddr(ctx, call.Host)
		},
	)
}

// LookupCNAME routes a CNAME lookup.
func (s *Sniffer) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	call := Call{Operation: OpLookupCNAME, Host: host}
	return snifferLookupOne(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) (string, error) {
			return n.LookupCNAME(ctx, call.Host)
		},
		func(ctx context.Context, call Call) (string, error) {
			return rejectNetwork.LookupCNAME(ctx, call.Host)
		},
	)
}

// LookupPort routes a service lookup.
func (s *Sniffer) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	call := Call{
		Operation: OpLookupPort,
		Network:   network,
		Service:   service,
	}
	return snifferLookupOne(ctx, s, call,
		func(ctx context.Context, n gonnect.Network, call Call) (int, error) {
			return n.LookupPort(ctx, call.Network, call.Service)
		},
		func(ctx context.Context, call Call) (int, error) {
			return rejectNetwork.LookupPort(ctx, call.Network, call.Service)
		},
	)
}

// LookupNS routes an NS lookup.
func (s *Sniffer) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	call := Call{Operation: OpLookupNS, Host: name}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]*net.NS, error) {
			return n.LookupNS(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]*net.NS, error) {
			return rejectNetwork.LookupNS(ctx, call.Host)
		},
	)
}

// LookupMX routes an MX lookup.
func (s *Sniffer) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	call := Call{Operation: OpLookupMX, Host: name}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]*net.MX, error) {
			return n.LookupMX(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]*net.MX, error) {
			return rejectNetwork.LookupMX(ctx, call.Host)
		},
	)
}

// LookupSRV routes an SRV lookup.
func (s *Sniffer) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	type result struct {
		cname string
		addrs []*net.SRV
	}
	call := Call{
		Operation: OpLookupSRV,
		Service:   service,
		Proto:     proto,
		Host:      name,
	}
	res, err := snifferLookupOne(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) (result, error) {
			cname, addrs, err := n.LookupSRV(
				ctx,
				call.Service,
				call.Proto,
				call.Host,
			)
			return result{cname: cname, addrs: addrs}, err
		},
		func(ctx context.Context, call Call) (result, error) {
			cname, addrs, err := rejectNetwork.LookupSRV(
				ctx,
				call.Service,
				call.Proto,
				call.Host,
			)
			return result{cname: cname, addrs: addrs}, err
		},
	)
	return res.cname, res.addrs, err
}

// LookupTXT routes a TXT lookup.
func (s *Sniffer) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	call := Call{Operation: OpLookupTXT, Host: name}
	return snifferLookupSlice(
		ctx,
		s,
		call,
		func(ctx context.Context, n gonnect.Network, call Call) ([]string, error) {
			return n.LookupTXT(ctx, call.Host)
		},
		func(ctx context.Context, call Call) ([]string, error) {
			return rejectNetwork.LookupTXT(ctx, call.Host)
		},
	)
}

// Interfaces routes an interface list call.
func (s *Sniffer) Interfaces() ([]gonnect.NetworkInterface, error) {
	call := Call{Operation: OpInterfaces}
	return snifferCollect(s, call,
		func(n gonnect.Network, call Call) ([]gonnect.NetworkInterface, error) {
			return n.Interfaces()
		},
		func(call Call) ([]gonnect.NetworkInterface, error) {
			return rejectNetwork.Interfaces()
		},
	)
}

// InterfaceAddrs routes an interface address list call.
func (s *Sniffer) InterfaceAddrs() ([]net.Addr, error) {
	call := Call{Operation: OpInterfaceAddrs}
	return snifferCollect(s, call,
		func(n gonnect.Network, call Call) ([]net.Addr, error) {
			return n.InterfaceAddrs()
		},
		func(call Call) ([]net.Addr, error) {
			return rejectNetwork.InterfaceAddrs()
		},
	)
}

// InterfaceMulticastAddrs routes an interface multicast address list call.
func (s *Sniffer) InterfaceMulticastAddrs() ([]net.Addr, error) {
	call := Call{Operation: OpInterfaceMcast}
	return snifferCollect(s, call,
		func(n gonnect.Network, call Call) ([]net.Addr, error) {
			return n.InterfaceMulticastAddrs()
		},
		func(call Call) ([]net.Addr, error) {
			return rejectNetwork.InterfaceMulticastAddrs()
		},
	)
}

// InterfacesByIndex routes an interface lookup by index.
func (s *Sniffer) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	call := Call{Operation: OpInterfacesByIndex, IfIndex: index}
	return snifferCollect(s, call,
		func(n gonnect.Network, call Call) ([]gonnect.NetworkInterface, error) {
			return n.InterfacesByIndex(call.IfIndex)
		},
		func(call Call) ([]gonnect.NetworkInterface, error) {
			return rejectNetwork.InterfacesByIndex(call.IfIndex)
		},
	)
}

// InterfacesByName routes an interface lookup by name.
func (s *Sniffer) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	call := Call{Operation: OpInterfacesByName, IfName: name}
	return snifferCollect(s, call,
		func(n gonnect.Network, call Call) ([]gonnect.NetworkInterface, error) {
			return n.InterfacesByName(call.IfName)
		},
		func(call Call) ([]gonnect.NetworkInterface, error) {
			return rejectNetwork.InterfacesByName(call.IfName)
		},
	)
}

func (s *Sniffer) controlCall(call Call) (Call, Action) {
	var action Action
	if s.control == nil {
		action = Action{Slot: DefaultSlot}
	} else {
		action = s.control(&call)
	}
	if action.Intercept && !call.supportsInterception() {
		action = Action{Slot: RejectSlot}
	}
	return call, action
}

func (c Call) supportsInterception() bool {
	switch c.Operation {
	case OpDial, OpDialTCP:
		return gonnect.IsTCPNetwork(c.Network)
	case OpListen,
		OpPacketDial,
		OpListenPacket,
		OpListenTCP,
		OpDialUDP,
		OpListenUDP,
		OpListenPacketConfig,
		OpListenUDPConfig,
		OpListenMulticastUDP,
		OpLookupIP,
		OpLookupIPAddr,
		OpLookupNetIP,
		OpLookupHost,
		OpLookupAddr,
		OpLookupCNAME,
		OpLookupPort,
		OpLookupNS,
		OpLookupMX,
		OpLookupSRV,
		OpLookupTXT,
		OpInterfaces,
		OpInterfaceAddrs,
		OpInterfaceMcast,
		OpInterfacesByIndex,
		OpInterfacesByName:
		return false
	default:
		return false
	}
}

func (s *Sniffer) begin(
	ctx context.Context,
) (context.Context, context.CancelFunc, uint64, <-chan struct{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if !s.up || s.closed {
		s.mu.Unlock()
		return nil, nil, 0, nil, net.ErrClosed
	}
	done := s.done
	gen := s.gen
	s.mu.Unlock()

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

func (s *Sniffer) beginNoContext() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up || s.closed {
		return 0, net.ErrClosed
	}
	return s.gen, nil
}

func (s *Sniffer) backend(
	gen uint64,
	slot int,
) (gonnect.Network, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up || s.closed || s.gen != gen {
		return nil, false, net.ErrClosed
	}
	if slot <= RejectSlot || slot > len(s.outputs) {
		return nil, false, nil
	}
	backend := s.outputs[slot-1]
	if backend == nil {
		return nil, false, nil
	}
	return backend, true, nil
}

func (s *Sniffer) updownsSnapshotLocked() []gonnect.UpDown {
	updowns := make([]gonnect.UpDown, 0, len(s.updowns))
	for _, updown := range s.updowns {
		updowns = append(updowns, updown)
	}
	return updowns
}

func (s *Sniffer) drainTrackedLocked() []io.Closer {
	closers := make([]io.Closer, 0, len(s.closers))
	for id, closer := range s.closers {
		delete(s.closers, id)
		closers = append(closers, closer)
	}
	return closers
}

func (s *Sniffer) reserveTracked(gen uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up || s.closed || s.gen != gen {
		return 0, net.ErrClosed
	}
	id := s.nextID
	s.nextID++
	return id, nil
}

func (s *Sniffer) finishTracked(gen, id uint64, closer io.Closer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.up || s.closed || s.gen != gen {
		return net.ErrClosed
	}
	s.closers[id] = closer
	return nil
}

func (s *Sniffer) unregister(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.closers, id)
}

func (s *Sniffer) trackConn(gen uint64, conn net.Conn) (net.Conn, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = gonnect.ConnWithCallbacks(conn, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
	})
	if err := s.finishTracked(gen, id, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Sniffer) trackTCPConn(
	gen uint64,
	conn gonnect.TCPConn,
) (gonnect.TCPConn, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = gonnect.TCPConnWithCallbacks(conn, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
	})
	if err := s.finishTracked(gen, id, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Sniffer) trackPacketConn(
	gen uint64,
	conn gonnect.PacketConn,
) (gonnect.PacketConn, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = gonnect.PacketConnWithCallbacks(conn, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
	})
	if err := s.finishTracked(gen, id, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Sniffer) trackUDPConn(
	gen uint64,
	conn gonnect.UDPConn,
) (gonnect.UDPConn, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = gonnect.UDPConnWithCallbacks(conn, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
	})
	if err := s.finishTracked(gen, id, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Sniffer) trackListener(
	gen uint64,
	listener net.Listener,
) (net.Listener, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	listener = gonnect.ListenerWithCallbacks(listener, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
		OnAccept:    s.acceptConn,
		OnAcceptTCP: s.acceptTCPConn,
	})
	if err := s.finishTracked(gen, id, listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *Sniffer) trackTCPListener(
	gen uint64,
	listener gonnect.TCPListener,
) (gonnect.TCPListener, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	listener = gonnect.TCPListenerWithCallbacks(listener, &gonnect.Callbacks{
		BeforeClose: func() { s.unregister(id) },
		OnAccept:    s.acceptConn,
		OnAcceptTCP: s.acceptTCPConn,
	})
	if err := s.finishTracked(gen, id, listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *Sniffer) trackMulticastPacketConn(
	gen uint64,
	conn gonnect.MulticastPacketConn,
) (gonnect.MulticastPacketConn, error) {
	id, err := s.reserveTracked(gen)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	conn = &multicastPacketConnWithCallback{
		MulticastPacketConn: conn,
		beforeClose:         func() { s.unregister(id) },
	}
	if err := s.finishTracked(gen, id, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Sniffer) acceptConn(conn net.Conn) (net.Conn, error) {
	s.mu.Lock()
	if !s.up || s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	gen := s.gen
	s.mu.Unlock()
	return s.trackConn(gen, conn)
}

func (s *Sniffer) acceptTCPConn(
	conn gonnect.TCPConn,
) (gonnect.TCPConn, error) {
	s.mu.Lock()
	if !s.up || s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	gen := s.gen
	s.mu.Unlock()
	return s.trackTCPConn(gen, conn)
}

func (s *Sniffer) newInterceptedConn(
	ctx context.Context,
	gen uint64,
	done <-chan struct{},
	call Call,
	action Action,
) (gonnect.TCPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client, server := gonnect.PipeTCP()
	bridgeCtx, cancelBridge := context.WithCancel(context.Background())
	wrapped := &snifferTCPConn{
		TCPConn:      client,
		cancelBridge: cancelBridge,
		local:        netAddrOrNil(call.Network, call.Src),
		remote:       netAddrOrNil(call.Network, call.Dst),
	}
	tracked, err := s.trackTCPConn(gen, wrapped)
	if err != nil {
		_ = server.Close()
		return nil, err
	}

	if err := snifferSpawn(s.spawner, func() {
		s.serveIntercepted(bridgeCtx, gen, server, wrapped, call, action)
	}, "sniffer.Sniffer.intercept"); err != nil {
		_ = tracked.Close()
		_ = server.Close()
		return nil, err
	}

	select {
	case <-done:
		_ = tracked.Close()
		return nil, net.ErrClosed
	default:
	}
	return tracked, nil
}

func (s *Sniffer) serveIntercepted(
	ctx context.Context,
	gen uint64,
	client gonnect.TCPConn,
	returned *snifferTCPConn,
	call Call,
	action Action,
) {
	defer client.Close() //nolint:errcheck
	defer returned.cancelBridge()

	pb := putback.New(client, s.pool)
	result := s.sniff(pb)
	finalCall := call
	finalAction := action
	if s.sniffCtl != nil {
		sniffed := SniffedCall{Call: call, Result: result}
		finalAction = s.sniffCtl(&sniffed)
		finalCall = sniffed.Call
	}

	backend, ok, err := s.backend(gen, finalAction.Slot)
	if err != nil || !ok {
		return
	}

	upstream, err := s.dialIntercepted(ctx, backend, finalCall)
	if err != nil {
		return
	}
	if ctx.Err() != nil {
		_ = upstream.Close()
		return
	}
	defer upstream.Close() //nolint:errcheck
	returned.setAddrs(upstream.LocalAddr(), upstream.RemoteAddr())

	_ = gonnect.PipeConn(pb, upstream, s.spawner)
}

func (s *Sniffer) dialIntercepted(
	ctx context.Context,
	backend gonnect.Network,
	call Call,
) (net.Conn, error) {
	switch call.Operation {
	case OpDialTCP:
		return backend.DialTCP(ctx, call.Network, call.Src, call.Dst)
	case OpDial:
		return backend.Dial(ctx, call.Network, call.Dst)
	case OpListen,
		OpPacketDial,
		OpListenPacket,
		OpListenTCP,
		OpDialUDP,
		OpListenUDP,
		OpListenPacketConfig,
		OpListenUDPConfig,
		OpListenMulticastUDP,
		OpLookupIP,
		OpLookupIPAddr,
		OpLookupNetIP,
		OpLookupHost,
		OpLookupAddr,
		OpLookupCNAME,
		OpLookupPort,
		OpLookupNS,
		OpLookupMX,
		OpLookupSRV,
		OpLookupTXT,
		OpInterfaces,
		OpInterfaceAddrs,
		OpInterfaceMcast,
		OpInterfacesByIndex,
		OpInterfacesByName:
		return nil, errors.New(
			"sniffer: intercepted call must be Dial or DialTCP",
		)
	default:
		return nil, errors.New("sniffer: unknown intercepted operation")
	}
}

func (s *Sniffer) sniff(conn putback.Conn) SniffResult {
	classifiers := make([]Classifier, len(s.factories))
	for i, factory := range s.factories {
		classifiers[i] = requireClassifier(factory.NewClassifier())
	}

	buffer := bufpool.GetBuffer(s.pool, s.bufferSize)
	defer bufpool.PutBuffer(s.pool, buffer)

	index, err := Sniff(buffer, conn, classifiers...)
	result := SniffResult{Index: index, Err: err}
	if index >= 0 && index < len(classifiers) {
		result.Metadata = Metadata(classifiers[index])
	}
	return result
}

type snifferOpResult[T any] struct {
	value T
	err   error
}

func runSnifferOp[T any](
	spawner gonnect.Spawner,
	ctx context.Context,
	done <-chan struct{},
	call func(context.Context) (T, error),
	closeLate func(T),
) (T, error) {
	ch := make(chan snifferOpResult[T], 1)
	if err := snifferSpawn(spawner, func() {
		value, err := call(ctx)
		ch <- snifferOpResult[T]{value: value, err: err}
	}, "sniffer.Sniffer.operation"); err != nil {
		var zero T
		return zero, err
	}

	var zero T
	select {
	case result := <-ch:
		return result.value, result.err
	case <-done:
		go closeLateSnifferOpResult(ch, closeLate)
		return zero, net.ErrClosed
	case <-ctx.Done():
		go closeLateSnifferOpResult(ch, closeLate)
		select {
		case <-done:
			return zero, net.ErrClosed
		default:
		}
		return zero, ctx.Err()
	}
}

func closeLateSnifferOpResult[T any](
	ch <-chan snifferOpResult[T],
	closeLate func(T),
) {
	result := <-ch
	if result.err == nil {
		closeLate(result.value)
	}
}

func snifferLookupSlice[T any](
	ctx context.Context,
	s *Sniffer,
	call Call,
	lookup func(context.Context, gonnect.Network, Call) ([]T, error),
	reject func(context.Context, Call) ([]T, error),
) ([]T, error) {
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return reject(opCtx, call)
	}
	return runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) ([]T, error) {
			return lookup(ctx, backend, call)
		},
		func([]T) {},
	)
}

func snifferLookupOne[T any](
	ctx context.Context,
	s *Sniffer,
	call Call,
	lookup func(context.Context, gonnect.Network, Call) (T, error),
	reject func(context.Context, Call) (T, error),
) (T, error) {
	opCtx, cancel, gen, done, err := s.begin(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	defer cancel()

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		var zero T
		return zero, err
	}
	if !ok {
		return reject(opCtx, call)
	}
	return runSnifferOp(
		s.spawner,
		opCtx,
		done,
		func(ctx context.Context) (T, error) {
			return lookup(ctx, backend, call)
		},
		func(T) {},
	)
}

func snifferCollect[T any](
	s *Sniffer,
	call Call,
	collect func(gonnect.Network, Call) ([]T, error),
	reject func(Call) ([]T, error),
) ([]T, error) {
	gen, err := s.beginNoContext()
	if err != nil {
		return nil, err
	}

	call, action := s.controlCall(call)
	backend, ok, err := s.backend(gen, action.Slot)
	if err != nil {
		return nil, err
	}
	if !ok {
		return reject(call)
	}
	return collect(backend, call)
}

func snifferSpawn(
	spawner gonnect.Spawner,
	worker func(),
	name string,
) error {
	if spawner == nil {
		go worker()
		return nil
	}
	_, err := spawner.Spawn(worker, name)
	return err
}

func snifferCloseAll(closers []io.Closer) error {
	var err error
	for _, closer := range closers {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func snifferDownAll(updowns []gonnect.UpDown) error {
	var err error
	for _, updown := range updowns {
		err = errors.Join(err, updown.Down())
	}
	return err
}

func snifferUpAll(updowns []gonnect.UpDown) error {
	var err error
	for _, updown := range updowns {
		err = errors.Join(err, updown.Up())
	}
	return err
}

var rejectNetwork = &gonnect.RejectNetwork{}

type snifferTCPConn struct {
	gonnect.TCPConn

	mu           sync.RWMutex
	local        net.Addr
	remote       net.Addr
	cancelBridge context.CancelFunc
	closeOnce    sync.Once
}

var _ interface {
	gonnect.TCPConn
	gonnect.Wrapper
} = (*snifferTCPConn)(nil)

func (c *snifferTCPConn) GetWrapped() any { return c.TCPConn }

func (c *snifferTCPConn) LocalAddr() net.Addr {
	c.mu.RLock()
	local := c.local
	c.mu.RUnlock()
	if local != nil {
		return local
	}
	return c.TCPConn.LocalAddr()
}

func (c *snifferTCPConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	remote := c.remote
	c.mu.RUnlock()
	if remote != nil {
		return remote
	}
	return c.TCPConn.RemoteAddr()
}

func (c *snifferTCPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.cancelBridge != nil {
			c.cancelBridge()
		}
		err = c.TCPConn.Close()
	})
	return err
}

func (c *snifferTCPConn) setAddrs(local, remote net.Addr) {
	c.mu.Lock()
	c.local = local
	c.remote = remote
	c.mu.Unlock()
}

func netAddrOrNil(network, address string) net.Addr {
	if address == "" {
		return nil
	}
	return &gonnect.NetAddr{Net: network, Addr: address}
}

type multicastPacketConnWithCallback struct {
	gonnect.MulticastPacketConn

	once        sync.Once
	beforeClose func()
}

var _ interface {
	gonnect.MulticastPacketConn
	gonnect.Wrapper
} = (*multicastPacketConnWithCallback)(nil)

func (c *multicastPacketConnWithCallback) GetWrapped() any {
	return c.MulticastPacketConn
}

func (c *multicastPacketConnWithCallback) Close() error {
	var err error
	c.once.Do(func() {
		if c.beforeClose != nil {
			c.beforeClose()
		}
		err = c.MulticastPacketConn.Close()
	})
	return err
}
