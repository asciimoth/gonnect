// Package sysnetdebug provides a channel-driven sysnet implementation for tests.
package sysnetdebug

import (
	"context"
	"errors"
	"net"
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
	DefaultRules = []sysnet.RuleTypeInfo{
		{Type: "comm", Description: "Process command regexp matcher."},
		{Type: "exec", Description: "Process executable path matcher."},
		{Type: "cmd", Description: "Process command line regexp matcher."},
		{Type: "pid", Description: "Process PID."},
		{Type: "user", Description: "Name of user owning process."},
		{Type: "uid", Description: "UID owning process."},
		{Type: "group", Description: "Name of group owning process."},
		{Type: "gid", Description: "GID owning process."},
	}
)

var _ sysnet.System = (*System)(nil)
var _ dns.Interface = (*System)(nil)

// TunConfig is a snapshot of the tun options recorded by System.
type TunConfig struct {
	// MTU is the tun MTU after System defaulting has been applied.
	MTU int

	// TunAddrs are the addresses assigned to the tun.
	TunAddrs []string

	// TunRoutes are the routes assigned to the tun.
	TunRoutes []string

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
	name       string
	tun        tun.Tun
	peer       tun.Tun
	defaultTun bool
	config     TunConfig
}

// System is an in-memory sysnet.System implementation intended for tests.
//
// The zero value is ready to use. By default it reports every sysnet feature as
// supported, creates pipe-backed tun devices, exposes loopback networks for
// OutNet and LocalNet, accepts every rule, and matches no flows. Tests can
// provide only the public fields that matter for the behavior under test and
// leave all other fields omitted.
//
// This makes System useful as a focused test double for code that requires a
// sysnet.System implementation. For example, pass &sysnetdebug.System{} to the
// code under test, set Disable* fields to exercise unsupported-feature paths,
// install verifier or builder functions to assert requested options, or inspect
// GetTunPeer and GetDefaultTunPeer to observe created virtual tun devices.
type System struct {
	// DisableTun makes Features report regular tun creation as unsupported and
	// makes VerifyTunOpts and BuildTun return sysnet.ErrNotSupported.
	DisableTun bool

	// DisableDefaultTun makes Features report default tun creation as
	// unsupported and makes VerifyDefaultTunOpts and BuildDefaultTun return
	// sysnet.ErrNotSupported.
	DisableDefaultTun bool

	// DisableDynTun makes Features report dynamic regular tun updates as
	// unsupported. It is informational; setter methods still update the in-memory
	// state so tests can decide which behavior they need to assert.
	DisableDynTun bool

	// DisableDynDefaultTun makes Features report dynamic default tun updates as
	// unsupported.
	DisableDynDefaultTun bool

	// DisableTunNames makes Features report regular tun naming as unsupported
	// and makes SetTunName return sysnet.ErrNotSupported.
	DisableTunNames bool

	// DisableDefaultTunNames makes Features report default tun naming as
	// unsupported.
	DisableDefaultTunNames bool

	// DisableStrictMode makes Features report default tun strict mode as
	// unsupported.
	DisableStrictMode bool

	// Rules is the optional rule catalog returned by ListRules for both tun
	// rules and matcher rules. Leave it nil when the test does not care about
	// advertised rule types.
	Rules []sysnet.RuleTypeInfo

	// RuleMatcher is an optional hook used by matchers created with
	// BuildMatcher. When omitted, matchers return false, nil.
	RuleMatcher func(rule sysnet.Rule, flow sockowner.FlowTuple) (bool, error)

	// RuleVerifyer is an optional hook used by RuleVerify. When omitted, every
	// rule is considered valid.
	RuleVerifyer func(rule sysnet.Rule) bool

	// RuleCompletion is an optional hook used by RuleCompl. When omitted, no
	// completion suggestions are returned.
	RuleCompletion func(rule sysnet.Rule) []string

	// TunNameVerifyer is an optional hook used by TunNameVerify and SetTunName.
	// When omitted, any non-empty free name is valid.
	TunNameVerifyer func(name string) (valid bool)

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

	// DefaultTunOptsVerifyer is an optional hook used by VerifyDefaultTunOpts and
	// BuildDefaultTun. Use it in tests to assert or reject requested default tun
	// options.
	DefaultTunOptsVerifyer func(opts sysnet.DefaultTunOpts) error

	// DefaultTunBuilder is an optional hook used by BuildDefaultTun to provide a
	// custom tun implementation. When omitted, System creates an in-memory pipe
	// and exposes its peer through GetDefaultTunPeer.
	DefaultTunBuilder func(opts sysnet.DefaultTunOpts) (tun.Tun, error)

	// TunOptsVerifyer is an optional hook used by VerifyTunOpts and BuildTun. Use
	// it in tests to assert or reject requested regular tun options.
	TunOptsVerifyer func(opts sysnet.TunOpts) error

	// TunBuilder is an optional hook used by BuildTun to provide a custom tun
	// implementation. When omitted, System creates an in-memory pipe and exposes
	// its peer through GetTunPeer.
	TunBuilder func(opts sysnet.TunOpts) (tun.Tun, error)

	mu sync.Mutex

	closed bool

	alloc *subnet.CombinedAllocator

	tuns       map[string]*tunEntry
	defaultTun string
	tunSeq     int

	dns dns.Interface

	dnsCh   chan dns.Request
	dnsDone chan struct{}
}

// Close closes every tun created by System and stops DNS request routing.
// It is safe to call more than once.
func (s *System) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	s.closed = true
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

// Features reports the sysnet feature set described by the Disable* fields.
func (s *System) Features() sysnet.Features {
	return sysnet.Features{
		Tun:             !s.DisableTun,
		DefaultTun:      !s.DisableDefaultTun,
		DynTun:          !s.DisableDynTun,
		DynDefaultTun:   !s.DisableDynDefaultTun,
		TunNames:        !s.DisableTunNames,
		DefaultTunNames: !s.DisableDefaultTunNames,
		StrictMode:      !s.DisableStrictMode,
	}
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

// ListRules returns Rules for both tun rule and matcher rule support.
func (s *System) ListRules() sysnet.RulesInfo {
	return sysnet.RulesInfo{
		TunRules:     copySlice(s.Rules),
		MatcherRules: copySlice(s.Rules),
	}
}

// RuleVerify validates rule using RuleVerifyer, or accepts it when no hook is
// configured.
func (s *System) RuleVerify(rule sysnet.Rule) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.RuleVerifyer != nil {
		return s.RuleVerifyer(rule)
	}

	return true
}

// RuleCompl returns completion suggestions from RuleCompletion, or nil when no
// hook is configured.
func (s *System) RuleCompl(rule sysnet.Rule) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.RuleCompletion != nil {
		return s.RuleCompletion(rule)
	}

	return nil
}

// TunNameVerify reports whether name is valid and not already used by this
// System.
func (s *System) TunNameVerify(name string) (valid bool, free bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TunNameVerifyer != nil {
		return s.TunNameVerifyer(name), s.tunNameFreeLocked(name)
	}

	return name != "", s.tunNameFreeLocked(name)
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
	)
}

// OutNet returns the outbound network configured by OutNetwork, or a permissive
// loopback network when OutNetwork is omitted.
func (s *System) OutNet() gonnect.Network {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.OutNetwork == nil {
		loop := gonnect.NewLoopbackNetwok()
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
		loop := gonnect.NewLoopbackNetwok()
		loop.AllowAnyHost = true
		return loop
	}

	return s.LocalNetwork
}

// BuildMatcher builds a matcher for rule. The matcher delegates to RuleMatcher,
// or matches nothing when RuleMatcher is omitted.
func (s *System) BuildMatcher(rule sysnet.Rule) (sysnet.Matcher, error) {
	return &matcher{
		system: s,
		rule:   rule,
	}, nil
}

// VerifyDefaultTunOpts validates opts for BuildDefaultTun. It returns
// sysnet.ErrNotSupported when DisableDefaultTun is set, delegates to
// DefaultTunOptsVerifyer when provided, and otherwise accepts opts.
func (s *System) VerifyDefaultTunOpts(opts sysnet.DefaultTunOpts) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.DisableDefaultTun {
		return sysnet.ErrNotSupported
	}

	if s.DefaultTunOptsVerifyer != nil {
		return s.DefaultTunOptsVerifyer(opts)
	}

	return nil
}

// VerifyTunOpts validates opts for BuildTun. It returns sysnet.ErrNotSupported
// when DisableTun is set, delegates to TunOptsVerifyer when provided, and
// otherwise accepts opts.
func (s *System) VerifyTunOpts(opts sysnet.TunOpts) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.DisableTun {
		return sysnet.ErrNotSupported
	}

	if s.TunOptsVerifyer != nil {
		return s.TunOptsVerifyer(opts)
	}

	return nil
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	if err := s.verifyDefaultTunOptsLocked(opts); err != nil {
		return nil, err
	}

	if s.defaultTun != "" {
		entry := s.tuns[s.defaultTun]
		if entry == nil {
			s.defaultTun = ""
		} else {
			entry.config = defaultTunConfig(opts)
			s.dns = nil
			if dtun, ok := entry.tun.(*defaultTunWrapper); ok {
				return dtun, nil
			}
			return nil, sysnet.ErrUnknownTun
		}
	}

	name := s.nextTunNameLocked(defaultTunName)
	base, peer, err := s.buildDefaultTunLocked(opts)
	if err != nil {
		return nil, err
	}

	entry := &tunEntry{
		name:       name,
		defaultTun: true,
		config:     defaultTunConfig(opts),
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

// BuildTun creates a regular tun for this System.
//
// With the default configuration it creates an in-memory pipe-backed tun and
// exposes the peer through GetTunPeer so tests can inspect packets. When
// TunBuilder is set, the custom builder supplies the tun and no peer is
// recorded.
func (s *System) BuildTun(opts sysnet.TunOpts) (tun.Tun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	if err := s.verifyTunOptsLocked(opts); err != nil {
		return nil, err
	}

	name := s.nextTunNameLocked("tun")
	base, peer, err := s.buildTunLocked(opts)
	if err != nil {
		return nil, err
	}

	entry := &tunEntry{
		name:   name,
		config: tunConfig(opts),
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
	entry.config.TunRoutes = append(entry.config.TunRoutes, route)
	return nil
}

// GetTunRotue returns the recorded routes for a tun created by this System.
//
// The method name follows the sysnet.System interface spelling.
func (s *System) GetTunRotue(t tun.Tun) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil {
		return nil, sysnet.ErrUnknownTun
	}
	return copySlice(entry.config.TunRoutes), nil
}

// SetTunName renames a regular tun created by this System.
//
// Default tun handles and unknown tun handles return sysnet.ErrUnknownTun.
// DisableTunNames makes this method return sysnet.ErrNotSupported.
func (s *System) SetTunName(t tun.Tun, name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.tunEntryLocked(t)
	if entry == nil || entry.defaultTun {
		return nil, sysnet.ErrUnknownTun
	}
	if name == entry.name {
		return []string{name}, nil
	}
	if s.DisableTunNames {
		return nil, sysnet.ErrNotSupported
	}
	if valid, free := s.tunNameVerifyLocked(name); !valid || !free {
		return nil, sysnet.ErrUnknownTun
	}

	oldName := entry.name
	delete(s.tuns, oldName)
	entry.name = name
	s.tuns[name] = entry
	return []string{name}, nil
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
// the current default tun's SetDns method. Requests are dropped while no default
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

func (s *System) verifyDefaultTunOptsLocked(opts sysnet.DefaultTunOpts) error {
	if s.DisableDefaultTun {
		return sysnet.ErrNotSupported
	}
	if s.DefaultTunOptsVerifyer != nil {
		return s.DefaultTunOptsVerifyer(opts)
	}
	return nil
}

func (s *System) verifyTunOptsLocked(opts sysnet.TunOpts) error {
	if s.DisableTun {
		return sysnet.ErrNotSupported
	}
	if s.TunOptsVerifyer != nil {
		return s.TunOptsVerifyer(opts)
	}
	return nil
}

func (s *System) buildDefaultTunLocked(
	opts sysnet.DefaultTunOpts,
) (tun.Tun, tun.Tun, error) {
	if s.DefaultTunBuilder != nil {
		t, err := s.DefaultTunBuilder(opts)
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
	if s.TunNameVerifyer != nil {
		return s.TunNameVerifyer(name), s.tunNameFreeLocked(name)
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
		MTU:       normalizeMTU(opts.MTU),
		TunAddrs:  copySlice(opts.TunAddrs),
		TunRoutes: copySlice(opts.TunRoutes),
		DnsIP:     opts.DnsIP,
		Strict:    opts.Strict,
		Exclude:   copySlice(opts.Exclude),
		Include:   copySlice(opts.Include),
	}
}

func tunConfig(opts sysnet.TunOpts) TunConfig {
	return TunConfig{
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
		MTU:       config.MTU,
		TunAddrs:  copySlice(config.TunAddrs),
		TunRoutes: copySlice(config.TunRoutes),
		DnsIP:     config.DnsIP,
		Strict:    config.Strict,
		Exclude:   copySlice(config.Exclude),
		Include:   copySlice(config.Include),
	}
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

func (t *defaultTunWrapper) SetDns(resolver dns.Interface) {
	t.system.mu.Lock()
	defer t.system.mu.Unlock()

	if t.system.closed || t.system.tuns[t.entry.name] != t.entry {
		return
	}
	t.system.dns = resolver
}
