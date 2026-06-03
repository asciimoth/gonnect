// Package sysnet provides an abstraction of the OS networking system so that
// each specific integration (Linux, Windows, macOS, etc.) can be implemented
// once and reused across applications. This abstraction also makes it possible
// to build virtual implementations for testing.
package sysnet

import (
	"io"
	"math"
	"net"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/tun"
)

const (
	CGROUP_UNKNOWN     = 0
	UID_UNKNOWN        = math.MaxUint64
	GID_UNKNOWN        = math.MaxUint64
	PID_UNKNOWN        = math.MinInt
	ROUTE_MARK_UNKNOWN = 0
)

// A Rule matches IP packets and connections to check if they are owned by a
// specific process, user, application, or other entity.
// For example: Type="app", Rule="org.mozilla.firefox".
// Different SysBuilder and System implementations may support different sets
// of rule types, so callers should check SysBuilder.ListRules first.
type Rule struct {
	Type, Rule string
}

// RuleTypeInfo describes a supported rule type and its human-readable description.
type RuleTypeInfo struct {
	Type, Description string
}

// NetInfo reports information that can be fetched for a connection or packet.
// Not all systems support all fields; unsupported or unknown fields should
// have their default values.
type NetInfo struct {
	Cgroup uint64 // Default 0

	UID  uint64 // Default UID_UNKNOWN
	GID  uint64 // Default GID_UNKNOWN
	User string // Default ""

	PID int // Default PID_UNKNOWN

	// RouteMark holds the packet/connection route mark value:
	// SO_MARK on Linux, SO_USER_COOKIE on FreeBSD, SO_RTABLE on OpenBSD.
	// There is no matching concept specified for other operating systems.
	// Default 0.
	RouteMark int
}

// IPMatcher matches IP packets against rules and extracts network information.
// IPMatcher must be thread safe.
type IPMatcher interface {
	Lock()
	Unlock()

	Map(rule Rule) uint64
	UnMap(rule uint64)
	UnMapAll()

	Match(pkt []byte, rule uint64) bool

	PktInfo(pkt []byte) *NetInfo

	Close() error
}

// BuildOpts specifies configuration options for building a System.
type BuildOpts struct {
	// TunNeeded specifies whether a TUN device should be created.
	TunNeeded bool
	// DnsNeeded specifies whether DNS integration should be enabled.
	DnsNeeded bool

	// TunAddrs specifies the addresses that should be owned by the TUN device,
	// for example: "10.0.0.2/32".
	TunAddrs []string

	// TunRoutes specifies the routes that should be owned by the TUN device,
	// for example: "0.0.0.0/0" for all routes.
	TunRoutes []string

	// MTU specifies the initial MTU for the TUN device.
	MTU int

	// Exclude specifies a list of rules to exclude traffic from being routed
	// through System.Tun.
	Exclude []Rule
}

func (b *BuildOpts) Copy() BuildOpts {
	c := BuildOpts{
		TunNeeded: b.TunNeeded,
		DnsNeeded: b.DnsNeeded,
		MTU:       b.MTU,
	}

	if b.TunAddrs != nil {
		c.TunAddrs = make([]string, len(b.TunAddrs))
		copy(c.TunAddrs, b.TunAddrs)
	}

	if b.TunRoutes != nil {
		c.TunRoutes = make([]string, len(b.TunRoutes))
		copy(c.TunRoutes, b.TunRoutes)
	}

	if b.Exclude != nil {
		c.Exclude = make([]Rule, len(b.Exclude))
		copy(c.Exclude, b.Exclude)
	}

	return c
}

// System holds the components for operating with the network system.
type System struct {
	// Tun is the TUN device interface, or nil if not enabled.
	Tun tun.Tun

	// OutNet and LocalNet are the outbound and local network interfaces.
	// These must never be nil; SysBuilder implementations that cannot provide
	// one should return gonnect.RejectNetwork.
	OutNet, LocalNet gonnect.Network

	// DNSOut is the interface for handling outgoing DNS requests.
	DNSOut dns.Interface
	// DNSIn is an optional callback to set the current system DNS resolver.
	DNSIn func(dns.Interface)

	// Matcher is a pointer to the IP packet matcher.
	Matcher IPMatcher
}

// SysBuilder constructs System instances for a specific platform.
type SysBuilder interface {
	io.Closer

	// AllocIP returns an IP address allocator for the system.
	AllocIP() subnet.IPAllocator
	// AllocSubnet returns a subnet allocator for the system.
	AllocSubnet() subnet.SubnetAllocator

	// ListRules returns a list of supported rule types and their descriptions.
	ListRules() []RuleTypeInfo

	// RuleVerify checks whether a rule is valid for its specified type.
	// This is intended for UI validation hints.
	RuleVerify(rule Rule) bool

	// RuleCompl returns autocompletion suggestions for a partial rule value,
	// intended for UI use. For example: Type="app", Partial="org.mozilla.fir"
	// might return []string{"org.mozilla.firefox"}.
	RuleCompl(rule Rule) []string

	// TunNameFormat returns the expected format string for TUN device names.
	TunNameFormat() string
	// TunNameVerify checks whether a TUN device name is valid.
	TunNameVerify(name string) bool

	// ConnInfo fetches network information about an incoming connection.
	ConnInfo(c net.Conn) *NetInfo
	// ConnRule matches an incoming connection against a rule.
	ConnRule(c net.Conn, rule Rule) bool

	// Build constructs a System instance with the specified options.
	// Build may be called multiple times, but only one System should be used
	// at a time. It is recommended that SysBuilder implementations close or
	// stop artifacts from a previous build when a new one is created.
	Build(opts BuildOpts) (*System, error)

	// TODO: Secondary tun factory interface
}
