// Package sysnet provides an abstraction of the OS networking system so that
// each specific integration (Linux, Windows, macOS, etc.) can be implemented
// once and reused across applications. This abstraction also makes it possible
// to build virtual implementations for testing.
package sysnet

import (
	"errors"
	"io"
	"net"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/tun"
)

var (
	// ErrNotSupported should be used by System implementation when unsupported
	// feature used.
	ErrNotSupported = errors.New("feature is not supported")

	ErrUnknownTun = errors.New("unknown tun")
)

// A Rule matches IP packets and connections to check if they are owned by a
// specific process, user, application, or other entity.
// For example: Type="app", Rule="org.mozilla.firefox".
// Different System and System implementations may support different sets
// of rule types, so callers should check System.ListRules first.
type Rule struct {
	Type, Rule string
}

// RuleTypeInfo describes a supported rule type and its human-readable description.
type RuleTypeInfo struct {
	Type, Description string
}

type RulesInfo struct {
	// TunRules that can be used in Exclude or Include lists for DefaultTun.
	TunRules []RuleTypeInfo

	// Rules that can be used in Matchers.
	MatcherRules []RuleTypeInfo
}

func (r *RulesInfo) Copy() RulesInfo {
	rules := RulesInfo{
		TunRules:     make([]RuleTypeInfo, len(r.TunRules)),
		MatcherRules: make([]RuleTypeInfo, len(r.MatcherRules)),
	}
	copy(rules.TunRules, r.TunRules)
	copy(rules.MatcherRules, r.MatcherRules)
	return rules
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
	// TunAddrs specifies the addresses that should be owned by the TUN device,
	// for example: "10.0.0.2/32".
	// Loopback addrs passed here should be ignored.
	// If TunAddrs is void, implementation should pick some safe addr and subnet.
	TunAddrs []string

	// TunRoutes specifies the extra routes that should be owned by the TUN device,
	// for example: "0.0.0.0/0" and "::/0" for all routes.
	// Loopback subnets passed here should be ignored.
	TunRoutes []string

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

func (b *TunOpts) Copy() DefaultTunOpts {
	c := DefaultTunOpts{
		MTU: b.MTU,
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

	// SetDns sets the current system DNS resolver owerwriting previous if there
	// are one.
	// When being called with nil arg, it should drop all incoming DNS requests.
	// After DefaultTun is closed, DNS configuration associated with it should be
	// removed and system dns should be rolled back to configuration existed before
	// DefaultTun creation.
	SetDns(resolver dns.Interface)
}

type Features struct {
	// Can regular Tun (not DefaultTun) be built.
	Tun bool
	// Can DefaultTun be built.
	DefaultTun bool
	// Can Tun's options be updated without its re-built.
	DynTun bool
	// Can DefaultTun's options be updated without its re-built.
	DynDefaultTun bool
	// Are custom names supported for regular Tun (not DefaultTun).
	TunNames bool
	// Are custom names supported for DefaultTun.
	DefaultTunNames bool
	// Is Strict mode supported for DefaultTun.
	StrictMode bool
}

// System constructs System instances for a specific platform.
type System interface {
	// System closing should lead to closing all Tun and Network instances
	// created via it.
	io.Closer

	// Features report info about supported features
	Features() Features

	// AllocIP returns an IP address allocator for the system.
	AllocIP() subnet.IPAllocator
	// AllocSubnet returns a subnet allocator for the system.
	AllocSubnet() subnet.SubnetAllocator

	// ListRules returns a list of supported rule types and their descriptions.
	ListRules() RulesInfo

	// RuleVerify checks whether a rule is valid for its specified type.
	// This is intended for UI validation hints.
	RuleVerify(rule Rule) bool

	// RuleCompl returns autocompletion suggestions for a partial rule value,
	// intended for UI use. For example: Type="app", Rule="org.mozilla.fir"
	// might return []string{"org.mozilla.firefox"}.
	RuleCompl(rule Rule) []string

	// TunNameVerify checks whether provided name can be used as a Tun name.
	TunNameVerify(name string) (valid bool, free bool)

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

	VerifyDefaultTunOpts(opts DefaultTunOpts) error

	// BuildTun constructs a tun.Tun instance with specified options.
	// BuildTun may be not supported on some systems, check Features.
	BuildTun(opts TunOpts) (tun.Tun, error)

	VerifyTunOpts(opts TunOpts) error

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

	// GetTunRotue returns list off routes of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// Dynamic Tun params fetching may not be available on some systems.
	GetTunRotue(tun tun.Tun) ([]string, error)

	// SetTunName updates name of provided Tun.
	// It should work only for Tuns built via this System instance. For others
	// ErrUnknownTun should be returned.
	// SetTunName should not work with DefaultTun instances.
	// Dynamic Tun params update may not be available on some systems.
	// Also on some systems SetTunName may be available for regular Tuns but not
	// for DefaultTun.
	SetTunName(tun tun.Tun, name string) ([]string, error)
}
