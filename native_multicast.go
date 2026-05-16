package gonnect

import (
	"context"
	"net"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/ipv6"
)

var _ MulticastPacketConn = &nativeMulticastPacketConn{}

func (n *NativeNetwork) ListenMulticastUDP(
	ctx context.Context,
	network, address string,
	opts MulticastOptions,
) (MulticastPacketConn, error) {
	if network == "udp" {
		network = "udp6"
	}
	if network != "udp6" {
		return nil, net.UnknownNetworkError(network)
	}
	if address == "" {
		address = "[::]:0"
	}
	if err := n.doFilter(network, address, actionListen); err != nil {
		return nil, err
	}

	cfg := *n.getListenCfg()
	baseControl := cfg.Control
	cfg.Control = func(network, address string, c syscall.RawConn) error {
		if baseControl != nil {
			if err := baseControl(network, address, c); err != nil {
				return err
			}
		}
		return setNativeMulticastSockopts(c, opts)
	}

	c, err := cfg.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return nil, ErrUnsupported
	}
	pc := ipv6.NewPacketConn(uc)
	ret := &nativeMulticastPacketConn{
		UDPConn: uc,
		pc:      pc,
	}
	if opts.ControlFlags != 0 {
		if err := ret.SetControlMessage(opts.ControlFlags, true); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return ret, nil
}

type nativeMulticastPacketConn struct {
	*net.UDPConn
	pc *ipv6.PacketConn
}

func (c *nativeMulticastPacketConn) JoinGroup(
	iface NetworkInterface,
	group net.Addr,
) error {
	ni, err := nativeNetInterface(iface)
	if err != nil {
		return err
	}
	return c.pc.JoinGroup(ni, group)
}

func (c *nativeMulticastPacketConn) LeaveGroup(
	iface NetworkInterface,
	group net.Addr,
) error {
	ni, err := nativeNetInterface(iface)
	if err != nil {
		return err
	}
	return c.pc.LeaveGroup(ni, group)
}

func (c *nativeMulticastPacketConn) SetControlMessage(
	flags ControlFlags,
	on bool,
) error {
	return c.pc.SetControlMessage(nativeIPv6ControlFlags(flags), on)
}

func (c *nativeMulticastPacketConn) ReadFromControl(
	b []byte,
) (n int, cm ControlMessage, from net.Addr, err error) {
	var nativeCM *ipv6.ControlMessage
	n, nativeCM, from, err = c.pc.ReadFrom(b)
	if err != nil {
		return 0, ControlMessage{}, nil, err
	}
	return n, controlMessageFromNative(nativeCM), from, nil
}

func (c *nativeMulticastPacketConn) WriteToControl(
	b []byte,
	cm ControlMessage,
	dst net.Addr,
) (int, error) {
	nativeCM := controlMessageToNative(cm)
	return c.pc.WriteTo(b, nativeCM, dst)
}

func nativeIPv6ControlFlags(flags ControlFlags) ipv6.ControlFlags {
	var ret ipv6.ControlFlags
	if flags&ControlDst != 0 {
		ret |= ipv6.FlagDst
	}
	if flags&ControlInterface != 0 {
		ret |= ipv6.FlagInterface
	}
	return ret
}

func controlMessageFromNative(cm *ipv6.ControlMessage) ControlMessage {
	if cm == nil {
		return ControlMessage{}
	}
	ret := ControlMessage{IfIndex: cm.IfIndex}
	if cm.Dst != nil {
		ret.Dst = &net.IPAddr{IP: cm.Dst}
	}
	if cm.IfIndex != 0 {
		if iface, err := net.InterfaceByIndex(cm.IfIndex); err == nil {
			ret.IfName = iface.Name
		}
	}
	return ret
}

func controlMessageToNative(cm ControlMessage) *ipv6.ControlMessage {
	ret := &ipv6.ControlMessage{IfIndex: cm.IfIndex}
	if ret.IfIndex == 0 && cm.IfName != "" {
		if iface, err := net.InterfaceByName(cm.IfName); err == nil {
			ret.IfIndex = iface.Index
		}
	}
	if cm.Dst != nil {
		ret.Dst = addrIP(cm.Dst)
	}
	if ret.IfIndex == 0 && ret.Dst == nil {
		return nil
	}
	return ret
}

func nativeNetInterface(iface NetworkInterface) (*net.Interface, error) {
	if iface == nil {
		return nil, nil //nolint
	}
	if native, ok := iface.(*NativeInterface); ok {
		return &native.Iface, nil
	}
	if iface.Index() > 0 {
		if ni, err := net.InterfaceByIndex(iface.Index()); err == nil {
			return ni, nil
		}
	}
	if iface.Name() != "" {
		return net.InterfaceByName(iface.Name())
	}
	return nil, &net.AddrError{
		Err:  "interface not found",
		Addr: strconv.Itoa(iface.Index()),
	}
}

func addrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.IPNet:
		return a.IP
	}
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if h, _, ok := strings.Cut(host, "%"); ok {
		host = h
	}
	return net.ParseIP(host)
}
