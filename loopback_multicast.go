package gonnect

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _ MulticastPacketConn = &loopbackMulticastPacketConn{}

const loopbackMulticastIfName = "lo"

type loopbackMulticastPacket struct {
	data []byte
	cm   ControlMessage
	from net.Addr
}

type loopbackMulticastRegistry struct {
	mu          sync.RWMutex
	alloc       loopbackPortAllocator
	nextID      uint64
	conns       map[uint64]*loopbackMulticastPacketConn
	memberships map[string]map[uint64]*loopbackMulticastPacketConn
}

func (r *loopbackMulticastRegistry) listen(
	address string,
) (*loopbackMulticastPacketConn, error) {
	if address == "" {
		address = "[::]:0"
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.Trim(host, "[]")
	if host != "" && host != "::" && host != "::1" && host != "localhost" {
		return nil, loopbackDnsReqErr(host)
	}

	var port *uint16
	if portStr != "" && portStr != "0" {
		iport, err := LookupPortOffline("udp6", portStr)
		if err != nil {
			return nil, err
		}
		if iport < 0 || iport > 65535 {
			return nil, &net.AddrError{Err: "invalid port", Addr: portStr}
		}
		uport := uint16(iport)
		port = &uport
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		r.conns = make(map[uint64]*loopbackMulticastPacketConn)
	}
	if r.memberships == nil {
		r.memberships = make(map[string]map[uint64]*loopbackMulticastPacketConn)
	}

	var p uint16
	allocatedPort := false
	if port != nil {
		p = *port
	} else {
		p, err = r.alloc.alloc(nil)
		if err != nil {
			return nil, err
		}
		allocatedPort = true
	}
	id := r.nextID
	r.nextID++
	c := &loopbackMulticastPacketConn{
		id:            id,
		port:          p,
		allocatedPort: allocatedPort,
		reg:           r,
		laddr:         &net.UDPAddr{IP: net.IPv6zero, Port: int(p)},
		in:            make(chan loopbackMulticastPacket, 1024),
		closeCh:       make(chan struct{}),
		memberships:   make(map[string]struct{}),
	}
	r.conns[id] = c
	return c, nil
}

func (r *loopbackMulticastRegistry) unregister(c *loopbackMulticastPacketConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range c.memberships {
		delete(r.memberships[key], c.id)
		if len(r.memberships[key]) == 0 {
			delete(r.memberships, key)
		}
	}
	delete(r.conns, c.id)
	if c.allocatedPort {
		r.alloc.free(c.port)
	}
}

func (r *loopbackMulticastRegistry) join(
	c *loopbackMulticastPacketConn,
	iface NetworkInterface,
	group net.Addr,
) error {
	key, err := loopbackMulticastKey(iface, group, int(c.port))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.memberships == nil {
		r.memberships = make(map[string]map[uint64]*loopbackMulticastPacketConn)
	}
	if r.memberships[key] == nil {
		r.memberships[key] = make(map[uint64]*loopbackMulticastPacketConn)
	}
	r.memberships[key][c.id] = c
	c.mu.Lock()
	c.memberships[key] = struct{}{}
	c.mu.Unlock()
	return nil
}

func (r *loopbackMulticastRegistry) leave(
	c *loopbackMulticastPacketConn,
	iface NetworkInterface,
	group net.Addr,
) error {
	key, err := loopbackMulticastKey(iface, group, int(c.port))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.memberships[key], c.id)
	if len(r.memberships[key]) == 0 {
		delete(r.memberships, key)
	}
	c.mu.Lock()
	delete(c.memberships, key)
	c.mu.Unlock()
	return nil
}

func (r *loopbackMulticastRegistry) deliver(
	key string,
	pkt loopbackMulticastPacket,
	deadline time.Time,
) error {
	r.mu.RLock()
	var recipients []*loopbackMulticastPacketConn //nolint
	for _, c := range r.memberships[key] {
		recipients = append(recipients, c)
	}
	r.mu.RUnlock()
	if len(recipients) == 0 {
		return &net.OpError{
			Op:  "write",
			Net: "memudp6",
			Err: errors.New("no route to host"),
		}
	}

	var timer <-chan time.Time
	if !deadline.IsZero() {
		timer = timerForDeadline(deadline)
	}
	for _, dst := range recipients {
		select {
		case dst.in <- pkt:
		case <-timer:
			return &net.OpError{
				Op:  "write",
				Net: "memudp6",
				Err: errors.New("i/o timeout"),
			}
		case <-dst.closeCh:
		}
	}
	return nil
}

type loopbackMulticastPacketConn struct {
	id            uint64
	port          uint16
	allocatedPort bool
	reg           *loopbackMulticastRegistry
	laddr         *net.UDPAddr

	mu           sync.Mutex
	in           chan loopbackMulticastPacket
	closeCh      chan struct{}
	closeOnce    sync.Once
	closed       bool
	controlFlags ControlFlags
	memberships  map[string]struct{}

	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *loopbackMulticastPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		if c.reg != nil {
			c.reg.unregister(c)
		}
		close(c.closeCh)
	})
	return nil
}

func (c *loopbackMulticastPacketConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *loopbackMulticastPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *loopbackMulticastPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *loopbackMulticastPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *loopbackMulticastPacketConn) JoinGroup(
	iface NetworkInterface,
	group net.Addr,
) error {
	if c.isClosed() {
		return ConnClosed("join", "udp6", c.laddr, nil)
	}
	return c.reg.join(c, iface, group)
}

func (c *loopbackMulticastPacketConn) LeaveGroup(
	iface NetworkInterface,
	group net.Addr,
) error {
	if c.isClosed() {
		return ConnClosed("leave", "udp6", c.laddr, nil)
	}
	return c.reg.leave(c, iface, group)
}

func (c *loopbackMulticastPacketConn) SetControlMessage(
	flags ControlFlags,
	on bool,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if on {
		c.controlFlags |= flags
	} else {
		c.controlFlags &^= flags
	}
	return nil
}

func (c *loopbackMulticastPacketConn) ReadFrom(
	b []byte,
) (int, net.Addr, error) {
	n, _, from, err := c.ReadFromControl(b)
	return n, from, err
}

func (c *loopbackMulticastPacketConn) ReadFromControl(
	b []byte,
) (n int, cm ControlMessage, from net.Addr, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ControlMessage{}, nil, ConnClosed(
			"read",
			"udp6",
			c.laddr,
			nil,
		)
	}
	rd := c.readDeadline
	controlFlags := c.controlFlags
	c.mu.Unlock()

	var timer <-chan time.Time
	if !rd.IsZero() {
		timer = timerForDeadline(rd)
	}

	select {
	case pkt := <-c.in:
		n = copy(b, pkt.data)
		return n, maskControlMessage(pkt.cm, controlFlags), pkt.from, nil
	case <-timer:
		return 0, ControlMessage{}, nil, &net.OpError{
			Op:  "read",
			Net: "memudp6",
			Err: errors.New("i/o timeout"),
		}
	case <-c.closeCh:
		return 0, ControlMessage{}, nil, ConnClosed(
			"read",
			"udp6",
			c.laddr,
			nil,
		)
	}
}

func (c *loopbackMulticastPacketConn) WriteTo(
	b []byte,
	dst net.Addr,
) (int, error) {
	return c.WriteToControl(b, ControlMessage{}, dst)
}

func (c *loopbackMulticastPacketConn) WriteToControl(
	b []byte,
	cm ControlMessage,
	dst net.Addr,
) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ConnClosed("write", "udp6", c.laddr, nil)
	}
	wd := c.writeDeadline
	c.mu.Unlock()

	groupIP, port, zone, err := multicastDestination(dst)
	if err != nil {
		return 0, err
	}
	if port == 0 {
		port = int(c.port)
	}
	if cm.IfName != "" {
		zone = cm.IfName
	}
	if cm.IfIndex != 0 {
		zone = loopbackMulticastIfName
	}
	if zone == "" {
		zone = loopbackMulticastIfName
	}

	key := multicastMembershipKey(groupIP.String(), 1, port)
	data := append([]byte(nil), b...)
	dstAddr := &net.UDPAddr{IP: groupIP, Port: port, Zone: zone}
	pkt := loopbackMulticastPacket{
		data: data,
		cm: ControlMessage{
			Dst:     dstAddr,
			IfIndex: 1,
			IfName:  zone,
		},
		from: &net.UDPAddr{
			IP:   net.ParseIP("fe80::1"),
			Port: int(c.port),
			Zone: zone,
		},
	}
	if cm.Dst != nil {
		pkt.cm.Dst = cm.Dst
	}
	if err := c.reg.deliver(key, pkt, wd); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *loopbackMulticastPacketConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (ln *LoopbackNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	ln.mu.Lock()
	err := ln.checkUp()
	if err != nil {
		ln.mu.Unlock()
		return nil, loopbackListenErrWrap(err, network, address)
	}
	if ln.mcast == nil {
		ln.mcast = &loopbackMulticastRegistry{}
	}
	reg := ln.mcast
	ln.mu.Unlock()

	if network == "udp" {
		network = "udp6"
	}
	if network != "udp6" {
		return nil, net.UnknownNetworkError(network)
	}
	conn, err := reg.listen(address)
	if err != nil {
		return nil, loopbackListenErrWrap(err, network, address)
	}
	if opts.ControlFlags != 0 {
		_ = conn.SetControlMessage(opts.ControlFlags, true)
	}

	ln.mu.Lock()
	id := ln.getID()
	ln.register(id, conn)
	ln.mu.Unlock()
	return conn, nil
}

func loopbackMulticastKey(
	iface NetworkInterface,
	group net.Addr,
	port int,
) (string, error) {
	if iface != nil && iface.Index() != 1 &&
		iface.Name() != loopbackMulticastIfName {
		return "", &net.AddrError{
			Err:  "interface not found",
			Addr: iface.Name(),
		}
	}
	ip := addrIP(group)
	if ip == nil || ip.To4() != nil || !ip.IsMulticast() {
		return "", &net.AddrError{
			Err:  "not an IPv6 multicast address",
			Addr: group.String(),
		}
	}
	return multicastMembershipKey(ip.String(), 1, port), nil
}

func multicastMembershipKey(group string, ifindex, port int) string {
	return group + "%" + strconv.Itoa(ifindex) + ":" + strconv.Itoa(port)
}

func multicastDestination(addr net.Addr) (net.IP, int, string, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a.IP == nil || a.IP.To4() != nil || !a.IP.IsMulticast() {
			return nil, 0, "", &net.AddrError{
				Err:  "not an IPv6 multicast address",
				Addr: a.String(),
			}
		}
		return a.IP, a.Port, a.Zone, nil
	case *net.IPAddr:
		if a.IP == nil || a.IP.To4() != nil || !a.IP.IsMulticast() {
			return nil, 0, "", &net.AddrError{
				Err:  "not an IPv6 multicast address",
				Addr: a.String(),
			}
		}
		return a.IP, 0, a.Zone, nil
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	zone := ""
	if h, z, ok := strings.Cut(host, "%"); ok {
		host = h
		zone = z
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil || !ip.IsMulticast() {
		return nil, 0, "", &net.AddrError{
			Err:  "not an IPv6 multicast address",
			Addr: addr.String(),
		}
	}
	port := 0
	if portStr != "" {
		p, err := LookupPortOffline("udp6", portStr)
		if err != nil {
			return nil, 0, "", err
		}
		port = p
	}
	return ip, port, zone, nil
}

func maskControlMessage(cm ControlMessage, flags ControlFlags) ControlMessage {
	if flags&ControlDst == 0 {
		cm.Dst = nil
	}
	if flags&ControlInterface == 0 {
		cm.IfIndex = 0
		cm.IfName = ""
	}
	return cm
}
