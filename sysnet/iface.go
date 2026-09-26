// Package sysnet provides an abstraction of the OS networking system so that
// each specific integration (Linux, Windows, macOS, etc.) can be implemented
// once and reused across applications. This abstraction also makes it possible
// to build virtual implementations for testing.
package sysnet

import (
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/tun"
)

// TunSourceRoute selects a preferred local source address for a remote
// destination routed through a default TUN.
type TunSourceRoute struct {
	// Destination selects this source route. When more than one route matches,
	// the route with the longest prefix has priority.
	Destination netip.Prefix

	// Source is a local address assigned to the TUN.
	Source netip.Addr
}

var (
	// ErrNotSupported means that the backend does not implement the requested
	// behavior.
	ErrNotSupported = errors.New("feature is not supported")

	ErrUnknownTun = errors.New("unknown tun")
)

// Warning identifies a non-fatal runtime condition reported by a System.
//
// Warning values are stable identifiers. They are not final user-facing text.
type Warning string

const (
	// WarningDefaultTunDNSRouteNotExclusive means the System cannot prove that
	// system DNS traffic is routed only to the DefaultTun DNS provider.
	WarningDefaultTunDNSRouteNotExclusive Warning = "default_tun_dns_route_not_exclusive"
)

// A Rule matches IP packets and connections to check if they are owned by a
// specific process, user, application, or other entity.
// For example: Type="app", Rule="org.mozilla.firefox".
// Different System implementations can support different rule types and use
// contexts. Callers must inspect System.Capabilities and use CheckRule.
type Rule struct {
	Type, Rule string
}

// Matcher instance is constructed by a System from a Rule and matches
// 5-tuple flow info.
// Matcher should be used only with outgoing traffic comes form System that was
// used to build it.
type Matcher interface {
	io.Closer

	Match(flow sockowner.FlowTuple) (bool, error)
}

// MatchConn matches a connection incoming from LocalNet against provided matcher.
// It MUST NOT be used for any connections except one accepted from Listeners
// created via LocalNet owned by same System instance that was used to build
// this Matcher.
func MatchConn(c net.Conn, matcher Matcher) (bool, error) {
	if matcher == nil || c == nil {
		return false, nil
	}
	flow, err := sockowner.IncomingConnPeerFlow(c)
	if err != nil {
		return false, err
	}
	return matcher.Match(*flow)
}

// DefaultTunOpts specifies configuration options for building a DefaultTun
type DefaultTunOpts struct {
	// Name requests a specific device name. An empty name lets the backend
	// select the name.
	Name string

	// TunAddrs specifies the addresses that should be owned by the TUN device,
	// for example: "10.0.0.2/32".
	// Loopback addrs passed here should be ignored.
	// If TunAddrs is void, implementation should pick some safe addr and subnet.
	TunAddrs []string

	// TunRoutes specifies the extra routes that should be owned by the TUN device,
	// for example: "0.0.0.0/0" and "::/0" for all routes.
	// Loopback subnets passed here should be ignored.
	TunRoutes []string

	// SourceRoutes selects preferred local source addresses for remote
	// destinations. IPv4 and IPv6 routes are independent. An empty list keeps
	// the system's default source-selection behavior.
	SourceRoutes []TunSourceRoute

	// MTU specifies the initial MTU for the TUN device. If MTU is 0 or too low,
	// implementation should use a sensible default.
	MTU int

	// DnsIP is an address to host DNS server on. It should be one of TunAddrs.
	// If not provided, some of addrs owned by DefaultTun should be picked.
	// Any DnsIP not included in TunAddrs should be ignored.
	DnsIP string

	// If Strict mode enabled, all traffic that not goes to DefaultTun device
	// (e.g. excluded) should be dropped insteade of passed to some other
	// suitable network interface.
	// Note that Strict mode toggling may be not supported on some systems.
	Strict bool

	// Exclude specifies a list of rules to identify traffic that SHOULD NOT go
	// to DefaultTun.
	// If Strict is enabled, excluded traffic should not go anywhere else and
	// should be just dropped instead. Note that Strict mode toggle may be not
	// supported on some systems.
	// Exclude is mutually exclusive with Include.
	Exclude []Rule

	// Include specifies a list of rules to identify traffic that SHOULD go to
	// DefaultTun while everything else bypass it.
	// If Strict is enabled, not included traffic should not go anywhere else and
	// should be just dropped instead. Note that Strict mode toggle may be not
	// supported on some systems.
	// Include is mutually exclusive with Exclude.
	Include []Rule
}

func (b *DefaultTunOpts) Copy() DefaultTunOpts {
	c := DefaultTunOpts{
		Name:   b.Name,
		MTU:    b.MTU,
		DnsIP:  b.DnsIP,
		Strict: b.Strict,
	}

	if b.TunAddrs != nil {
		c.TunAddrs = make([]string, len(b.TunAddrs))
		copy(c.TunAddrs, b.TunAddrs)
	}

	if b.TunRoutes != nil {
		c.TunRoutes = make([]string, len(b.TunRoutes))
		copy(c.TunRoutes, b.TunRoutes)
	}

	if b.SourceRoutes != nil {
		c.SourceRoutes = make([]TunSourceRoute, len(b.SourceRoutes))
		copy(c.SourceRoutes, b.SourceRoutes)
	}

	if b.Exclude != nil {
		c.Exclude = make([]Rule, len(b.Exclude))
		copy(c.Exclude, b.Exclude)
	}

	if b.Include != nil {
		c.Include = make([]Rule, len(b.Include))
		copy(c.Include, b.Include)
	}

	return c
}

// TunOpts specifies configuration options for building a regular Tun.
type TunOpts struct {
	// Name requests a specific device name. An empty name lets the backend
	// select the name.
	Name string

	// TunAddrs specifies the addresses that should be owned by the TUN device,
	// for example: "10.0.0.2/32".
	// Loopback addrs passed here should be ignored.
	// If TunAddrs is void, there will be no
	TunAddrs []string

	// TunRoutes specifies the extra routes that should be owned by the TUN device,
	// for example: "0.0.0.0/0" and "::/0" for all routes.
	// Loopback subnets passed here should be ignored.
	TunRoutes []string

	// MTU specifies the initial MTU for the TUN device. If MTU is 0 or too low,
	// implementation should use a sensible default.
	MTU int
}

// Copy returns an independent copy of b.
func (b *TunOpts) Copy() TunOpts {
	c := TunOpts{
		Name: b.Name,
		MTU:  b.MTU,
	}

	if b.TunAddrs != nil {
		c.TunAddrs = make([]string, len(b.TunAddrs))
		copy(c.TunAddrs, b.TunAddrs)
	}

	if b.TunRoutes != nil {
		c.TunRoutes = make([]string, len(b.TunRoutes))
		copy(c.TunRoutes, b.TunRoutes)
	}

	return c
}

// DefaultTun represents a Tun device intended to use as a default route
// for system traffic. It is also responsible for DNS requests processing because
// on may systems (e.g. android, linux with systremd-resolved, etc) DNS
// configuration must be binded to specific network interface.
// Some implementation of DefaultTun automatically intercept all DNS requests
// sent via it.
type DefaultTun interface {
	tun.Tun

	// SetDNS sets the current system DNS resolver, replacing the previous
	// resolver. A nil resolver stops managed DNS requests.
	// After DefaultTun is closed, DNS configuration associated with it should be
	// removed, and the previous system DNS configuration should be restored.
	// Native resolver-change failures must be returned.
	SetDNS(resolver dns.Interface) error
}

// System provides the networking operations for one platform integration.
type System interface {
	// System closing should lead to closing all Tun and Network instances
	// created via it.
	io.Closer

	// Capabilities returns an independently owned snapshot of system
	// capabilities. It does not change host state.
	Capabilities() CapabilityReport

	// CapabilitiesForTun returns an independently owned capability snapshot for
	// a live TUN created by this System. It returns ErrUnknownTun for foreign,
	// stale, or closed objects.
	CapabilitiesForTun(tunDevice tun.Tun) (TunCapabilityReport, error)

	// CheckTunOpts validates regular TUN options without changing host state.
	CheckTunOpts(opts TunOpts) ValidationReport

	// CheckDefaultTunOpts validates default-TUN options without changing host
	// state.
	CheckDefaultTunOpts(opts DefaultTunOpts) ValidationReport

	// CheckRule validates a rule in one exact use context without changing host
	// state.
	CheckRule(rule Rule, context RuleContext) ValidationReport

	// CompleteRule returns bounded completion suggestions for a rule in one
	// exact use context.
	CompleteRule(rule Rule, context RuleContext) ([]string, error)

	// AllocIP returns an IP address allocator for the system.
	AllocIP() subnet.IPAllocator
	// AllocSubnet returns a subnet allocator for the system.
	AllocSubnet() subnet.SubnetAllocator

	// OutDNS is the interface for handling outgoing DNS requests.
	// It should bypass any DefaultTun created via this System.
	OutDNS() dns.Interface

	// OutNet is an outbound Network interface. All traffic goes through it should
	// bypass any DefaultTun instance built by this System.
	// In some System implementations OutNet MAY be a same Network instance with
	// LocalNet but users should not assume or expect this.
	// System implementations that cannot provide one should return
	// gonnect.RejectNetwork.
	OutNet() gonnect.Network

	// LocalNet is a loopback Network interface.
	// In some System implementations LocalNet MAY be a same Network instance with
	// OutNet but users should not assume or expect this.
	// System implementations that cannot provide one should return
	// gonnect.RejectNetwork.
	LocalNet() gonnect.Network

	// BuildMatcher builds a new Matcher from provided rule. Built Matcher should
	// Matcher instances created this way are intended to use for filtering
	// traffic that comes from Tuns built by this System and for Connections
	// accepted via LocalNet.
	BuildMatcher(rule Rule) (Matcher, error)

	// BuildDefaultTun constructs a DefaultTun instance with specified options.
	// BuildDefaultTun may be called multiple times, but only one latest
	// DefaultTun should be used at a time. It is recommended for System
	// implementations to close previous DefaultTun and associated artifacts when
	// a new one is created.
	BuildDefaultTun(opts DefaultTunOpts) (DefaultTun, error)

	// DefaultTunWarnings returns current warnings for a DefaultTun returned by
	// this System. Unknown, stale, closed, or unsupported DefaultTun values
	// should return nil.
	DefaultTunWarnings(defaultTun DefaultTun) []Warning

	// BuildTun constructs a tun.Tun instance with specified options.
	// BuildTun can be unsupported on some systems. Check the exact creation
	// capability and validate the options before use.
	BuildTun(opts TunOpts) (tun.Tun, error)

	// TunWarnings returns current warnings for a regular Tun returned by this
	// System. Unknown, stale, closed, or unsupported Tun values should return
	// nil.
	TunWarnings(tun tun.Tun) []Warning

	// SetTunMTU updates MTU of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// If MTU is 0 or too low, implementation should use a sensible default.
	// Dynamic Tun params update may not be available on some systems.
	SetTunMTU(tun tun.Tun, MTU int) error

	// SetTunAddrs updates list off addrs of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params update may not be available on some systems.
	SetTunAddrs(tun tun.Tun, addrs []string) error

	// AddTunAddr updates list off addrs of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params update may not be available on some systems.
	AddTunAddr(tun tun.Tun, addr string) error

	// GetTunAddrs returns list off addrs of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params fetching may not be available on some systems.
	GetTunAddrs(tun tun.Tun) ([]string, error)

	// SetTunRoutes updates list off routes of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params update may not be available on some systems.
	SetTunRoutes(tun tun.Tun, routes []string) error

	// AddTunRoute updates list off routes of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params update may not be available on some systems.
	AddTunRoute(tun tun.Tun, route string) error

	// GetTunRoutes returns the routes of the provided TUN.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params fetching may not be available on some systems.
	GetTunRoutes(tun tun.Tun) ([]string, error)

	// SetTunName updates name of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic TUN parameter updates can differ between regular and default TUNs.
	SetTunName(tun tun.Tun, name string) error
}
