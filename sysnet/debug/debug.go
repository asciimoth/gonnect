// Package sysnetdebug provides a channel-driven sysnet implementation for tests.
package sysnetdebug

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/subnet"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

const (
	defaultTunName = "defaultTun"
	defaultMTU     = 1500
	defaultBatch   = 1
)

var (
	// DefaultRules lists the process-owner rule types commonly exposed by
	// sysnet implementations.
	DefaultRules = []sysnet.RuleCapability{
		{
			Type:        "comm",
			Description: "Process command regexp matcher.",
			ValueKind:   sysnet.RuleValueRegex,
			SemanticsID: "debug.command-regexp.v1",
		},
		{
			Type:        "exec",
			Description: "Process executable path matcher.",
			ValueKind:   sysnet.RuleValuePath,
			SemanticsID: "debug.executable-path.v1",
		},
		{
			Type:        "cmd",
			Description: "Process command line regexp matcher.",
			ValueKind:   sysnet.RuleValueRegex,
			SemanticsID: "debug.command-line-regexp.v1",
		},
		{
			Type:        "pid",
			Description: "Process PID.",
			ValueKind:   sysnet.RuleValuePID,
			SemanticsID: "debug.pid.v1",
		},
		{
			Type:        "user",
			Description: "Name of user owning process.",
			ValueKind:   sysnet.RuleValueName,
			SemanticsID: "debug.user-name.v1",
		},
		{
			Type:        "uid",
			Description: "UID owning process.",
			ValueKind:   sysnet.RuleValueOpaque,
			SemanticsID: "debug.uid.v1",
		},
		{
			Type:        "group",
			Description: "Name of group owning process.",
			ValueKind:   sysnet.RuleValueName,
			SemanticsID: "debug.group-name.v1",
		},
		{
			Type:        "gid",
			Description: "GID owning process.",
			ValueKind:   sysnet.RuleValueOpaque,
			SemanticsID: "debug.gid.v1",
		},
	}
)

var _ sysnet.System = (*System)(nil)
var _ dns.Interface = (*System)(nil)

// TunConfig is a snapshot of the tun options recorded by System.
type TunConfig struct {
	// Name is the requested device name. It is empty when the backend selected
	// the name.
	Name string

	// MTU is the tun MTU after System defaulting has been applied.
	MTU int

	// TunAddrs are the addresses assigned to the tun.
	TunAddrs []string

	// TunRoutes are the routes assigned to the tun.
	TunRoutes []string

	// SourceRoutes select preferred local source addresses by destination.
	SourceRoutes []sysnet.TunSourceRoute

	// DnsIP is the DNS endpoint address requested for a default tun.
	DnsIP string

	// Strict records whether strict routing was requested for a default tun.
	Strict bool

	// Exclude records rules that should bypass a default tun.
	Exclude []sysnet.Rule

	// Include records rules that should use a default tun.
	Include []sysnet.Rule
}

// TunEntry describes a tun created by System.
type TunEntry struct {
	// Name is the current System name for the tun.
	Name string

	// Tun is the handle returned by BuildTun or BuildDefaultTun.
	Tun tun.Tun

	// Peer is the other end of the in-memory pipe when System built the tun
	// itself. It is nil when a custom builder supplied the tun.
	Peer tun.Tun

	// Default reports whether this entry was created by BuildDefaultTun.
	Default bool

	// Config is the last configuration recorded for this tun.
	Config TunConfig
}

type tunEntry struct {
	name          string
	tun           tun.Tun
	peer          tun.Tun
	defaultTun    bool
	config        TunConfig
	revision      uint64
	operations    []sysnet.OperationCapability
	operationsSet bool
}

// System is an in-memory sysnet.System implementation intended for tests.
//
// The zero value is ready to use. Its default catalog reports the implemented
// mock operations as available. It creates pipe-backed TUN devices, exposes
// loopback networks for OutNet and LocalNet, publishes DefaultRules, and
// matches no flows. Tests can set only the public fields that they need.
//
// This makes System useful as a focused test double for code that requires a
// sysnet.System implementation. For example, pass &sysnetdebug.System{} to the
// code under test, set Disable* fields to exercise unsupported paths, install
// check or builder functions to inspect options, or use GetTunPeer and
// GetDefaultTunPeer to observe virtual TUN devices.
//
// Set public configuration fields before concurrent use. Use
// SetCapabilityReport for race-free capability updates at run time.
type System struct {
	// DisableTun makes regular TUN creation unsupported.
	DisableTun bool

	// DisableDefaultTun makes default TUN creation unsupported.
	DisableDefaultTun bool

	// DisableDynTun makes dynamic regular TUN operations unsupported. Setter and
	// getter methods return sysnet.ErrNotSupported through a validation error.
	DisableDynTun bool

	// DisableDynDefaultTun makes dynamic default-TUN operations unsupported.
	DisableDynDefaultTun bool

	// DisableTunNames makes creation-time names and rename unsupported for
	// regular TUN devices.
	DisableTunNames bool

	// DisableDefaultTunNames makes creation-time names and rename unsupported for
	// default TUN devices.
	DisableDefaultTunNames bool

	// DisableStrictMode makes strict routing profiles unsupported.
	DisableStrictMode bool

	// DisableDefaultTunSourceRoutes makes default-TUN source routes unsupported.
	DisableDefaultTunSourceRoutes bool

	// Rules replaces the default rule catalog. Leave it nil to use DefaultRules.
	// Configure this field before the System is first used.
	Rules []sysnet.RuleCapability

	// RuleMatcher is an optional hook used by matchers created with
	// BuildMatcher. When omitted, matchers return false, nil.
	RuleMatcher func(rule sysnet.Rule, flow sockowner.FlowTuple) (bool, error)

	// CheckRuleHook adds context-aware validation issues after capability
	// checks. Configure it before concurrent use.
	CheckRuleHook func(sysnet.Rule, sysnet.RuleContext) sysnet.ValidationReport

	// CompleteRuleHook can inspect the exact completion context and return a
	// native error.
	CompleteRuleHook func(sysnet.Rule, sysnet.RuleContext) ([]string, error)

	// TunNameChecker is an optional hook used by option checks and SetTunName.
	// When omitted, any non-empty free name is valid.
	TunNameChecker func(name string) (valid bool)

	// OutDNSProvider is an optional DNS provider returned by OutDNS. When
	// omitted, OutDNS uses StaticDNS through an in-memory resolver.
	OutDNSProvider dns.Interface

	// StaticDNS maps host names to IP addresses for the default OutDNS resolver.
	// It can be omitted when DNS behavior is not relevant to the test.
	StaticDNS map[string]string

	// OutNetwork is an optional network returned by OutNet. When omitted, System
	// returns a loopback network that allows any host.
	OutNetwork gonnect.Network

	// LocalNetwork is an optional network returned by LocalNet. When omitted,
	// System returns a loopback network that allows any host.
	LocalNetwork gonnect.Network

	// CheckDefaultTunOptsHook adds validation issues after built-in checks.
	// Configure it before concurrent use.
	CheckDefaultTunOptsHook func(sysnet.DefaultTunOpts) sysnet.ValidationReport

	// DefaultTunBuilder is an optional hook used by BuildDefaultTun to provide a
	// custom tun implementation. When omitted, System creates an in-memory pipe
	// and exposes its peer through GetDefaultTunPeer.
	DefaultTunBuilder func(opts sysnet.DefaultTunOpts) (tun.Tun, error)

	// DefaultTunWarningsHook is an optional hook used by DefaultTunWarnings.
	// When omitted, DefaultTunWarnings returns nil.
	DefaultTunWarningsHook func(sysnet.DefaultTun) []sysnet.Warning

	// CheckTunOptsHook adds validation issues after built-in checks. Configure it
	// before concurrent use.
	CheckTunOptsHook func(sysnet.TunOpts) sysnet.ValidationReport

	// TunBuilder is an optional hook used by BuildTun to provide a custom tun
	// implementation. When omitted, System creates an in-memory pipe and exposes
	// its peer through GetTunPeer.
	TunBuilder func(opts sysnet.TunOpts) (tun.Tun, error)

	// TunWarningsHook is an optional hook used by TunWarnings. When omitted,
	// TunWarnings returns nil.
	TunWarningsHook func(tun.Tun) []sysnet.Warning

	// SetDNSHook runs before a default TUN changes its DNS provider. A returned
	// error leaves the current provider unchanged.
	SetDNSHook func(dns.Interface) error

	mu sync.Mutex

	closed bool

	alloc *subnet.CombinedAllocator

	tuns       map[string]*tunEntry
	defaultTun string
	tunSeq     int

	dns dns.Interface

	dnsCh   chan dns.Request
	dnsDone chan struct{}

	capabilities         sysnet.CapabilityReport
	capabilitiesSet      bool
	explicitCapabilities bool
}

// Close closes every tun created by System and stops DNS request routing.
// It is safe to call more than once.
func (s *System) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	currentReport := s.capabilityReportLocked()
	openReport := currentReport.Clone()
	s.closed = true
	markReportClosed(&currentReport)
	if !sameCapabilityContents(openReport, currentReport) {
		currentReport.Revision++
	}
	s.capabilities = currentReport
	s.capabilitiesSet = true
	s.explicitCapabilities = true
	entries := make([]*tunEntry, 0, len(s.tuns))
	for _, entry := range s.tuns {
		entries = append(entries, entry)
	}
	s.tuns = nil
	s.defaultTun = ""
	s.dns = nil
	if s.dnsDone != nil {
		close(s.dnsDone)
		s.dnsDone = nil
	}
	s.mu.Unlock()

	var err error
	for _, entry := range entries {
		err = errors.Join(err, closeTunEntry(entry))
	}
	return err
}

// AllocIP returns the shared in-memory IP allocator for this System.
func (s *System) AllocIP() subnet.IPAllocator {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alloc == nil {
		s.alloc = subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
	}

	return s.alloc
}

// AllocSubnet returns the shared in-memory subnet allocator for this System.
func (s *System) AllocSubnet() subnet.SubnetAllocator {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alloc == nil {
		s.alloc = subnet.NewDefaultAllocator(subnet.DefaultAllocatorConfig{})
	}

	return s.alloc
}

// OutDNS returns the DNS provider used for traffic that should bypass a default
// tun.
func (s *System) OutDNS() dns.Interface {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.OutDNSProvider != nil {
		return s.OutDNSProvider
	}

	return dns.NewResolverProvider(
		newMapResolver(s.StaticDNS),
		time.Minute,
		nil,
	)
}

// OutNet returns the outbound network configured by OutNetwork, or a permissive
// loopback network when OutNetwork is omitted.
func (s *System) OutNet() gonnect.Network {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.OutNetwork == nil {
		loop := gonnect.NewLoopbackNetwork()
		loop.AllowAnyHost = true
		return loop
	}

	return s.OutNetwork
}

// LocalNet returns the loopback network configured by LocalNetwork, or a
// permissive loopback network when LocalNetwork is omitted.
func (s *System) LocalNet() gonnect.Network {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LocalNetwork == nil {
		loop := gonnect.NewLoopbackNetwork()
		loop.AllowAnyHost = true
		return loop
	}

	return s.LocalNetwork
}

// BuildMatcher builds a matcher for rule. The matcher delegates to RuleMatcher,
// or matches nothing when RuleMatcher is omitted.
func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	s.mu.Lock()
	report := s.capabilityReportLocked()
	ruleCapability := report.Rule(rule.Type)
	usable := ruleCapability.Validation.State == sysnet.CapabilityAvailable ||
		ruleCapability.Validation.State == sysnet.CapabilityUnknown
	failure := ruleCapability.Validation
	if usable && len(ruleCapability.Matchers) != 0 {
		usable = false
		failure = sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, profile := range ruleCapability.Matchers {
			if profile.State == sysnet.CapabilityAvailable ||
				profile.State == sysnet.CapabilityUnknown {
				usable = true
				break
			}
			if profile.State == sysnet.CapabilityUnavailable ||
				(failure.State != sysnet.CapabilityUnavailable && profile.State == sysnet.CapabilityUnsupported) {
				failure = profile.Capability
			}
		}
	}
	s.mu.Unlock()
	if !usable {
		validation := sysnet.ValidationReport{}
		appendCapabilityIssue(&validation, "Type", failure)
		return nil, validation.Err()
	}
	return &matcher{
		system: s,
		rule:   rule,
	}, nil
}

// DefaultTunWarnings returns current warnings for an active default tun created
// by this System. By default it returns nil; tests can install
// DefaultTunWarningsHook to provide warnings.
func (s *System) DefaultTunWarnings(t sysnet.DefaultTun) []sysnet.Warning {
	s.mu.Lock()
	entry := s.tunEntryLocked(t)
	hook := s.DefaultTunWarningsHook
	valid := !s.closed && !s.DisableDefaultTun && entry != nil &&
		entry.defaultTun
	s.mu.Unlock()

	if !valid || hook == nil {
		return nil
	}
	return copySlice(hook(t))
}

// TunWarnings returns current warnings for an active regular tun created by
// this System. By default it returns nil; tests can install TunWarningsHook to
// provide warnings.
func (s *System) TunWarnings(t tun.Tun) []sysnet.Warning {
	s.mu.Lock()
	entry := s.tunEntryLocked(t)
	hook := s.TunWarningsHook
	valid := !s.closed && !s.DisableTun && entry != nil && !entry.defaultTun
	s.mu.Unlock()

	if !valid || hook == nil {
		return nil
	}
	return copySlice(hook(t))
}

// BuildDefaultTun creates or reconfigures the default tun for this System.
//
// With the default configuration it creates an in-memory pipe-backed tun and
// exposes the peer through GetDefaultTunPeer so tests can inspect packets. When
// DefaultTunBuilder is set, the custom builder supplies the tun and no peer is
// recorded.
func (s *System) BuildDefaultTun(
	opts sysnet.DefaultTunOpts,
) (sysnet.DefaultTun, error) {
	opts = opts.Copy()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	if err := validationErrorForBuild(
		s.checkDefaultTunOptsLocked(opts),
	); err != nil {
		return nil, err
	}
	var err error
	opts, err = s.normalizeDefaultTunOptsLocked(opts)
	if err != nil {
		return nil, err
	}

	if existing, handled, err := s.reconfigureDefaultTunLocked(opts); handled {
		return existing, err
	}

	name := opts.Name
	if name == "" {
		name = s.nextTunNameLocked(defaultTunName)
	}
	base, peer, err := s.buildDefaultTunLocked(opts)
	if err != nil {
		return nil, err
	}

	entry := &tunEntry{
		name:       name,
		defaultTun: true,
		config:     defaultTunConfig(opts),
		revision:   1,
	}
	wrapper := &defaultTunWrapper{
		tunWrapper: &tunWrapper{
			system: s,
			entry:  entry,
			base:   base,
		},
	}
	entry.tun = wrapper
	if peer != nil {
		entry.peer = &tunWrapper{
			system: s,
			entry:  entry,
			base:   peer,
		}
	}
	s.ensureTunsLocked()
	s.tuns[name] = entry
	s.defaultTun = name
	s.dns = nil

	return wrapper, nil
}

func (s *System) reconfigureDefaultTunLocked(
	opts sysnet.DefaultTunOpts,
) (sysnet.DefaultTun, bool, error) {
	if s.defaultTun == "" {
		return nil, false, nil
	}
	entry := s.tuns[s.defaultTun]
	if entry == nil {
		s.defaultTun = ""
		return nil, false, nil
	}

	family, _ := optionFamily(opts.TunAddrs, opts.TunRoutes)
	if family == sysnet.FamilyNone {
		family = sysnet.FamilyIPv4
	}
	key := sysnet.OperationKey{
		Target:    sysnet.TargetDefaultTun,
		Operation: sysnet.OpReconfigureInPlace,
		Family:    family,
	}
	if err := s.operationErrorLocked(entry, key); err != nil {
		return nil, true, err
	}
	if err := s.renameDefaultTunEntryLocked(entry, opts.Name); err != nil {
		return nil, true, err
	}

	entry.config = defaultTunConfig(opts)
	s.dns = nil
	defaultTun, ok := entry.tun.(*defaultTunWrapper)
	if !ok {
		return nil, true, sysnet.ErrUnknownTun
	}
	return defaultTun, true, nil
}

func (s *System) renameDefaultTunEntryLocked(
	entry *tunEntry,
	name string,
) error {
	if name == "" || name == entry.name {
		return nil
	}
	key := sysnet.OperationKey{
		Target:    sysnet.TargetDefaultTun,
		Operation: sysnet.OpRename,
		Family:    sysnet.FamilyNone,
	}
	if err := s.operationErrorLocked(entry, key); err != nil {
		return err
	}
	if valid, free := s.tunNameVerifyLocked(name); !valid || !free {
		return fmt.Errorf(
			"%w: invalid or occupied TUN name",
			sysnet.ErrInvalidOptions,
		)
	}
	delete(s.tuns, entry.name)
	entry.name = name
	s.tuns[entry.name] = entry
	s.defaultTun = entry.name
	return nil
}

// BuildTun creates a regular tun for this System.
//
// With the default configuration it creates an in-memory pipe-backed tun and
// exposes the peer through GetTunPeer so tests can inspect packets. When
// TunBuilder is set, the custom builder supplies the tun and no peer is
// recorded.
func (s *System) BuildTun(opts sysnet.TunOpts) (tun.Tun, error) {
	opts = opts.Copy()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	if err := validationErrorForBuild(s.checkTunOptsLocked(opts)); err != nil {
		return nil, err
	}

	name := opts.Name
	if name == "" {
		name = s.nextTunNameLocked("tun")
	}
	base, peer, err := s.buildTunLocked(opts)
	if err != nil {
		return nil, err
	}

	entry := &tunEntry{
		name:     name,
		config:   tunConfig(opts),
		revision: 1,
	}
	entry.tun = &tunWrapper{
		system: s,
		entry:  entry,
		base:   base,
	}
	if peer != nil {
		entry.peer = &tunWrapper{
			system: s,
			entry:  entry,
			base:   peer,
		}
	}
	s.ensureTunsLocked()
	s.tuns[name] = entry

	return entry.tun, nil
}

// SetTunMTU records mtu for a tun created by this System.
func (s *System) SetTunMTU(t tun.Tun, mtu int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpSetMTU,
			Family:    sysnet.FamilyNone,
		},
	); err != nil {
		return err
	}
	entry.config.MTU = normalizeMTU(mtu)
	return nil
}

// SetTunAddrs replaces the recorded addresses for a tun created by this System.
func (s *System) SetTunAddrs(t tun.Tun, addrs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	family := configFamily(entry.config)
	if len(addrs) != 0 {
		var issues []sysnet.ValidationIssue
		family, issues = optionFamily(addrs, nil)
		if len(issues) != 0 {
			return sysnet.ValidationReport{Issues: issues}.Err()
		}
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpSetAddresses,
			Family:    family,
		},
	); err != nil {
		return err
	}
	entry.config.TunAddrs = copySlice(addrs)
	return nil
}

// AddTunAddr appends addr to the recorded addresses for a tun created by this
// System.
func (s *System) AddTunAddr(t tun.Tun, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	family, issues := optionFamily([]string{addr}, nil)
	if len(issues) != 0 || family == sysnet.FamilyNone {
		return sysnet.ValidationReport{
			Issues: issuesOrInvalid(issues, "addr must be a valid prefix"),
		}.Err()
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpAddAddress,
			Family:    family,
		},
	); err != nil {
		return err
	}
	entry.config.TunAddrs = append(entry.config.TunAddrs, addr)
	return nil
}

// GetTunAddrs returns the recorded addresses for a tun created by this System.
func (s *System) GetTunAddrs(t tun.Tun) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return nil, sysnet.ErrUnknownTun
	}
	family := configFamily(entry.config)
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpGetAddresses,
			Family:    family,
		},
	); err != nil {
		return nil, err
	}
	return copySlice(entry.config.TunAddrs), nil
}

// SetTunRoutes replaces the recorded routes for a tun created by this System.
func (s *System) SetTunRoutes(t tun.Tun, routes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	family := configFamily(entry.config)
	if len(routes) != 0 {
		var issues []sysnet.ValidationIssue
		family, issues = optionFamily(nil, routes)
		if len(issues) != 0 {
			return sysnet.ValidationReport{Issues: issues}.Err()
		}
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpSetRoutes,
			Family:    family,
		},
	); err != nil {
		return err
	}
	entry.config.TunRoutes = copySlice(routes)
	return nil
}

// AddTunRoute appends route to the recorded routes for a tun created by this
// System.
func (s *System) AddTunRoute(t tun.Tun, route string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	family, issues := optionFamily(nil, []string{route})
	if len(issues) != 0 || family == sysnet.FamilyNone {
		return sysnet.ValidationReport{
			Issues: issuesOrInvalid(issues, "route must be a valid prefix"),
		}.Err()
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpAddRoute,
			Family:    family,
		},
	); err != nil {
		return err
	}
	entry.config.TunRoutes = append(entry.config.TunRoutes, route)
	return nil
}

// GetTunRoutes returns the recorded routes for a TUN created by this System.
func (s *System) GetTunRoutes(t tun.Tun) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return nil, sysnet.ErrUnknownTun
	}
	family := configFamily(entry.config)
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpGetRoutes,
			Family:    family,
		},
	); err != nil {
		return nil, err
	}
	return copySlice(entry.config.TunRoutes), nil
}

// SetTunName renames a regular or default TUN created by this System.
func (s *System) SetTunName(t tun.Tun, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return sysnet.ErrUnknownTun
	}
	if name == entry.name {
		return nil
	}
	if err := s.operationErrorLocked(
		entry,
		sysnet.OperationKey{
			Target:    entry.target(),
			Operation: sysnet.OpRename,
			Family:    sysnet.FamilyNone,
		},
	); err != nil {
		return err
	}
	if valid, free := s.tunNameVerifyLocked(name); !valid || !free {
		return fmt.Errorf(
			"%w: invalid or occupied TUN name",
			sysnet.ErrInvalidOptions,
		)
	}

	oldName := entry.name
	delete(s.tuns, oldName)
	entry.name = name
	entry.config.Name = name
	s.tuns[name] = entry
	if entry.defaultTun {
		s.defaultTun = name
	}
	return nil
}

// GetTunPeer returns a snapshot of a regular tun entry by name.
//
// This helper is not part of sysnet.System. Tests can use it to inspect the
// peer side and recorded configuration of tuns created by BuildTun.
func (s *System) GetTunPeer(name string) (TunEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tuns[name]
	if entry == nil {
		return TunEntry{}, false
	}
	return entry.snapshot(), true
}

// GetDefaultTunPeer returns a snapshot of the current default tun entry.
//
// This helper is not part of sysnet.System. Tests can use it to inspect the
// peer side and recorded configuration of the tun created by BuildDefaultTun.
func (s *System) GetDefaultTunPeer() (TunEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.defaultTun == "" {
		return TunEntry{}, false
	}
	entry := s.tuns[s.defaultTun]
	if entry == nil {
		return TunEntry{}, false
	}
	return entry.snapshot(), true
}

// Requests returns the DNS request channel for the System dns.Interface
// implementation.
//
// Requests sent here are forwarded to the resolver most recently installed by
// the current default tun's SetDNS method. Requests are dropped while no default
// tun DNS resolver is configured.
func (s *System) Requests() chan<- dns.Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dnsCh == nil {
		s.dnsCh = make(chan dns.Request)
		s.dnsDone = make(chan struct{})
		go s.routeDNS(s.dnsCh, s.dnsDone)
	}
	return s.dnsCh
}

func (s *System) routeDNS(requests <-chan dns.Request, done <-chan struct{}) {
	for {
		select {
		case req := <-requests:
			s.mu.Lock()
			upstream := s.dns
			closed := s.closed
			s.mu.Unlock()
			if closed {
				sendDNSResponse(req, nil, dns.ErrClosed)
				continue
			}
			if upstream == nil {
				continue
			}
			go forwardDNS(upstream, req)
		case <-done:
			return
		}
	}
}

func (s *System) normalizeDefaultTunOptsLocked(
	opts sysnet.DefaultTunOpts,
) (sysnet.DefaultTunOpts, error) {
	var err error
	opts.SourceRoutes, err = normalizeSourceRoutes(
		opts.TunAddrs,
		opts.SourceRoutes,
	)
	if err != nil {
		return sysnet.DefaultTunOpts{}, err
	}
	return opts, nil
}

func (s *System) buildDefaultTunLocked(
	opts sysnet.DefaultTunOpts,
) (tun.Tun, tun.Tun, error) {
	if s.DefaultTunBuilder != nil {
		t, err := s.DefaultTunBuilder(opts.Copy())
		if err == nil && t == nil {
			err = errors.New("default tun builder returned nil tun")
		}
		return t, nil, err
	}
	t, peer := tun.Pipe(defaultBatch, normalizeMTU(opts.MTU), 0, 0)
	return t, peer, nil
}

func (s *System) buildTunLocked(opts sysnet.TunOpts) (tun.Tun, tun.Tun, error) {
	if s.TunBuilder != nil {
		t, err := s.TunBuilder(opts)
		if err == nil && t == nil {
			err = errors.New("tun builder returned nil tun")
		}
		return t, nil, err
	}
	t, peer := tun.Pipe(defaultBatch, normalizeMTU(opts.MTU), 0, 0)
	return t, peer, nil
}

func (s *System) ensureTunsLocked() {
	if s.tuns == nil {
		s.tuns = make(map[string]*tunEntry)
	}
}

func (s *System) nextTunNameLocked(prefix string) string {
	s.ensureTunsLocked()
	if prefix != "" && s.tunNameFreeLocked(prefix) {
		return prefix
	}
	for {
		name := prefix + "-" + stringID(s.tunSeq)
		s.tunSeq++
		if s.tunNameFreeLocked(name) {
			return name
		}
	}
}

func (s *System) tunNameFreeLocked(name string) bool {
	if name == "" {
		return false
	}
	_, ok := s.tuns[name]
	return !ok
}

func (s *System) tunNameVerifyLocked(name string) (bool, bool) {
	if s.TunNameChecker != nil {
		return s.TunNameChecker(name), s.tunNameFreeLocked(name)
	}
	return name != "", s.tunNameFreeLocked(name)
}

func (s *System) tunEntryLocked(t tun.Tun) *tunEntry {
	if t == nil {
		return nil
	}
	for _, entry := range s.tuns {
		if entry.tun == t || entry.peer == t {
			return entry
		}
	}
	return nil
}

func (s *System) closeTun(entry *tunEntry) error {
	s.mu.Lock()
	active := !s.closed && s.tuns[entry.name] == entry
	if active {
		delete(s.tuns, entry.name)
		if entry.defaultTun && s.defaultTun == entry.name {
			s.defaultTun = ""
			s.dns = nil
		}
	}
	s.mu.Unlock()
	if !active {
		return nil
	}
	return closeTunEntry(entry)
}

func closeTunEntry(entry *tunEntry) error {
	var err error
	if entry.tun != nil {
		err = errors.Join(err, closeBaseTun(entry.tun))
	}
	if entry.peer != nil {
		err = errors.Join(err, closeBaseTun(entry.peer))
	}
	return err
}

func closeBaseTun(t tun.Tun) error {
	if wrapper, ok := t.(*tunWrapper); ok {
		return wrapper.base.Close()
	}
	if wrapper, ok := t.(*defaultTunWrapper); ok {
		return wrapper.base.Close()
	}
	return t.Close()
}

func defaultTunConfig(opts sysnet.DefaultTunOpts) TunConfig {
	return TunConfig{
		Name:         opts.Name,
		MTU:          normalizeMTU(opts.MTU),
		TunAddrs:     copySlice(opts.TunAddrs),
		TunRoutes:    copySlice(opts.TunRoutes),
		SourceRoutes: copySlice(opts.SourceRoutes),
		DnsIP:        opts.DnsIP,
		Strict:       opts.Strict,
		Exclude:      copySlice(opts.Exclude),
		Include:      copySlice(opts.Include),
	}
}

func tunConfig(opts sysnet.TunOpts) TunConfig {
	return TunConfig{
		Name:      opts.Name,
		MTU:       normalizeMTU(opts.MTU),
		TunAddrs:  copySlice(opts.TunAddrs),
		TunRoutes: copySlice(opts.TunRoutes),
	}
}

func normalizeMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}
	return mtu
}

func (entry *tunEntry) snapshot() TunEntry {
	return TunEntry{
		Name:    entry.name,
		Tun:     entry.tun,
		Peer:    entry.peer,
		Default: entry.defaultTun,
		Config:  entry.config.copy(),
	}
}

func (config TunConfig) copy() TunConfig {
	return TunConfig{
		Name:         config.Name,
		MTU:          config.MTU,
		TunAddrs:     copySlice(config.TunAddrs),
		TunRoutes:    copySlice(config.TunRoutes),
		SourceRoutes: copySlice(config.SourceRoutes),
		DnsIP:        config.DnsIP,
		Strict:       config.Strict,
		Exclude:      copySlice(config.Exclude),
		Include:      copySlice(config.Include),
	}
}

func normalizeSourceRoutes(
	tunAddrs []string,
	routes []sysnet.TunSourceRoute,
) ([]sysnet.TunSourceRoute, error) {
	if routes == nil {
		return nil, nil
	}

	assigned := make(map[netip.Addr]struct{}, len(tunAddrs))
	for _, tunAddr := range tunAddrs {
		prefix, err := netip.ParsePrefix(tunAddr)
		if err == nil {
			assigned[prefix.Addr()] = struct{}{}
		}
	}

	normalized := make([]sysnet.TunSourceRoute, 0, len(routes))
	seen := make(map[netip.Prefix]netip.Addr, len(routes))
	for i, route := range routes {
		if !route.Destination.IsValid() {
			return nil, fmt.Errorf(
				"source route %d has an invalid destination prefix",
				i,
			)
		}
		if !validSourceRouteAddr(route.Source) {
			return nil, fmt.Errorf(
				"source route %d has an invalid source address",
				i,
			)
		}
		if route.Destination.Addr().Is4() != route.Source.Is4() {
			return nil, fmt.Errorf(
				"source route %d uses different address families",
				i,
			)
		}
		if _, ok := assigned[route.Source]; !ok {
			return nil, fmt.Errorf(
				"source route %d source %s is not assigned to the TUN",
				i,
				route.Source,
			)
		}

		route.Destination = route.Destination.Masked()
		if source, ok := seen[route.Destination]; ok {
			if source != route.Source {
				return nil, fmt.Errorf(
					"source route destination %s has conflicting sources",
					route.Destination,
				)
			}
			continue
		}
		seen[route.Destination] = route.Source
		normalized = append(normalized, route)
	}

	return normalized, nil
}

func validSourceRouteAddr(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLoopback()
}

func stringID(id int) string {
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[i:])
}

func sendDNSResponse(req dns.Request, msg *dns.Message, err error) {
	if req.Reply == nil {
		return
	}
	select {
	case req.Reply <- dns.Response{Message: msg, Err: err}:
	default:
	}
}

func forwardDNS(upstream dns.Interface, req dns.Request) {
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	reply := make(chan dns.Response, 1)
	forwarded := dns.Request{
		Context: ctx,
		Message: req.Message,
		Reply:   reply,
	}
	select {
	case upstream.Requests() <- forwarded:
	case <-ctx.Done():
		sendDNSResponse(req, nil, ctx.Err())
		return
	}

	select {
	case response := <-reply:
		sendDNSResponse(req, response.Message, response.Err)
	case <-ctx.Done():
		sendDNSResponse(req, nil, ctx.Err())
	}
}

type tunWrapper struct {
	system *System
	entry  *tunEntry
	base   tun.Tun
}

func (t *tunWrapper) File() *os.File { return t.base.File() }

func (t *tunWrapper) IsNative() bool { return t.base.IsNative() }

func (t *tunWrapper) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (n int, err error) {
	return t.base.Read(bufs, sizes, offset)
}

func (t *tunWrapper) Write(bufs [][]byte, offset int) (int, error) {
	return t.base.Write(bufs, offset)
}

func (t *tunWrapper) MWO() int { return t.base.MWO() }

func (t *tunWrapper) MRO() int { return t.base.MRO() }

func (t *tunWrapper) MTU() (int, error) {
	t.system.mu.Lock()
	defer t.system.mu.Unlock()

	if t.system.tuns[t.entry.name] != t.entry {
		return 0, os.ErrClosed
	}
	return t.entry.config.MTU, nil
}

func (t *tunWrapper) Name() (string, error) {
	t.system.mu.Lock()
	defer t.system.mu.Unlock()

	if t.system.tuns[t.entry.name] != t.entry {
		return t.entry.name, os.ErrClosed
	}
	return t.entry.name, nil
}

func (t *tunWrapper) Events() <-chan tun.Event { return t.base.Events() }

func (t *tunWrapper) Close() error { return t.system.closeTun(t.entry) }

func (t *tunWrapper) BatchSize() int { return t.base.BatchSize() }

type defaultTunWrapper struct {
	*tunWrapper
}

func (t *defaultTunWrapper) SetDNS(resolver dns.Interface) error {
	t.system.mu.Lock()
	defer t.system.mu.Unlock()

	if t.system.closed || t.system.tuns[t.entry.name] != t.entry {
		return sysnet.ErrUnknownTun
	}
	family := configFamily(t.entry.config)
	if family == sysnet.FamilyDual {
		family = sysnet.FamilyIPv4
	}
	if err := t.system.operationErrorLocked(
		t.entry,
		sysnet.OperationKey{
			Target:    sysnet.TargetDefaultTun,
			Operation: sysnet.OpDNSProvider,
			Family:    family,
		},
	); err != nil {
		return err
	}
	if t.system.SetDNSHook != nil {
		if err := t.system.SetDNSHook(resolver); err != nil {
			return err
		}
	}
	t.system.dns = resolver
	return nil
}
