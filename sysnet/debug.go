package sysnet

import (
	"net"
	"slices"
	"sync"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/tun"
)

var (
	_ IPMatcher  = &DebugIPMatcher{}
	_ SysBuilder = &DebugSysBuilder{}
)

type DebugIPMatcher struct {
	sync.RWMutex
	FixedInfo NetInfo
	TrueRules []Rule

	nextID  uint64
	ruleMap map[uint64]any
}

func (d *DebugIPMatcher) UnMapAll() {
	d.ruleMap = make(map[uint64]any)
}

func (d *DebugIPMatcher) Map(rule Rule) uint64 {
	id := d.nextID
	d.nextID += 1

	for _, r := range d.TrueRules {
		if r == rule {
			d.ruleMap[id] = nil
		}
	}

	return id
}

func (d *DebugIPMatcher) UnMap(rule uint64) {
	delete(d.ruleMap, rule)
}

func (d *DebugIPMatcher) Match(pkt []byte, rule uint64) bool {
	_, ok := d.ruleMap[rule]
	return ok
}

func (d *DebugIPMatcher) PktInfo(pkt []byte) *NetInfo {
	ni := d.FixedInfo
	return &ni
}

func (d *DebugIPMatcher) Close() error { return nil }

// DebugSysBuilder is a test implementation of SysBuilder that returns
// predictable, fixed values for testing purposes. It follows the same concepts
// as DebugIPMatcher: rules in TrueRules always match any packet or connection,
// while other rules do not match. Network information is returned from fixed
// static values configured on the builder.
//
// DebugSysBuilder is not thread-safe and is intended for use in unit tests
// and development environments only.
type DebugSysBuilder struct {
	Tun tun.Tun

	// FixedInfo is the static NetInfo returned for all connections and packets.
	FixedInfo NetInfo

	// TrueRules is the list of rules that will always match any packet or
	// connection. Rules not in this list will never match.
	TrueRules []Rule

	// SupportedRules is the list of rule types reported as supported by
	// ListRules. Use this to simulate different platform capabilities.
	SupportedRules []RuleTypeInfo

	// CgroupSupported reports whether cgroup support is advertised by Cgroup().
	CgroupSupported bool

	// TunFormat is the format string returned by TunNameFormat(), e.g. "debug%d".
	TunFormat string

	// ValidTunNames is the list of TUN device names that pass TunNameVerify().
	ValidTunNames []string

	// RuleCompletions maps partial rule values to completion suggestions
	// returned by RuleCompl(). For example: "org.mozilla.fir" -> ["org.mozilla.firefox"].
	RuleCompletions map[string][]string

	IPAlloc     subnet.IPAllocator
	SubnetAlloc subnet.SubnetAllocator

	OutNet, LocalNet gonnect.Network

	DNSOut dns.Interface
	DNSIn  func(dns.Interface)
}

// NewDebugSysBuilder returns a new DebugSysBuilder initialized with sensible
// defaults for testing. Callers can modify the returned builder's exported
// fields to customize behavior for specific test scenarios.
func NewDebugSysBuilder() *DebugSysBuilder {
	return &DebugSysBuilder{
		FixedInfo: NetInfo{
			Cgroup:    CGROUP_UNKNOWN,
			UID:       UID_UNKNOWN,
			GID:       GID_UNKNOWN,
			PID:       PID_UNKNOWN,
			RouteMark: ROUTE_MARK_UNKNOWN,
		},
		TrueRules:       []Rule{},
		SupportedRules:  []RuleTypeInfo{},
		TunFormat:       "debug%d",
		ValidTunNames:   []string{},
		RuleCompletions: make(map[string][]string),
		SubnetAlloc:     subnet.NewRandomAllocator(nil),
		IPAlloc:         subnet.NewRandomIPAllocator(nil),
	}
}

func (d *DebugSysBuilder) Close() error { return nil }

func (d *DebugSysBuilder) AllocIP() subnet.IPAllocator {
	return d.IPAlloc
}

func (d *DebugSysBuilder) AllocSubnet() subnet.SubnetAllocator {
	return d.SubnetAlloc
}

// ListRules returns the list of supported rule types configured on the builder.
func (d *DebugSysBuilder) ListRules() []RuleTypeInfo {
	return d.SupportedRules
}

// RuleVerify checks whether a rule's type is listed in SupportedRules.
func (d *DebugSysBuilder) RuleVerify(rule Rule) bool {
	for _, rt := range d.SupportedRules {
		if rt.Type == rule.Type {
			return true
		}
	}
	return false
}

// RuleCompl returns autocompletion suggestions for a partial rule value,
// looked up from the RuleCompletions map. Returns nil if no suggestions exist.
func (d *DebugSysBuilder) RuleCompl(rule Rule) []string {
	return d.RuleCompletions[rule.Rule]
}

// TunNameFormat returns the configured TUN device name format string.
func (d *DebugSysBuilder) TunNameFormat() string {
	return d.TunFormat
}

// TunNameVerify checks whether the given name is in the ValidTunNames list.
func (d *DebugSysBuilder) TunNameVerify(name string) bool {
	for _, valid := range d.ValidTunNames {
		if name == valid {
			return true
		}
	}
	return false
}

// ConnInfo returns a copy of the configured FixedInfo, ignoring the connection.
func (d *DebugSysBuilder) ConnInfo(c net.Conn) *NetInfo {
	ni := d.FixedInfo
	return &ni
}

// ConnRule matches the given rule against the TrueRules list. Returns true
// if the rule is present in TrueRules, false otherwise. The connection argument
// is ignored, matching the deterministic behavior of DebugIPMatcher.
func (d *DebugSysBuilder) ConnRule(c net.Conn, rule Rule) bool {
	return slices.Contains(d.TrueRules, rule)
}

func (d *DebugSysBuilder) Build(opts BuildOpts) (*System, error) {
	return &System{
		Tun: d.Tun,

		OutNet:   d.OutNet,
		LocalNet: d.LocalNet,

		DNSOut: d.DNSOut,
		DNSIn:  d.DNSIn,

		Matcher: &DebugIPMatcher{
			FixedInfo: d.FixedInfo,
			TrueRules: d.TrueRules,
			ruleMap:   make(map[uint64]any),
		},
	}, nil
}
