// nolint
package sysnetdebug

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

func TestBuildTunPeerRenameAndClose(t *testing.T) {
	system := &System{}
	tunDev, err := system.BuildTun(sysnet.TunOpts{
		MTU:      1400,
		TunAddrs: []string{"10.0.0.2/32"},
	})
	if err != nil {
		t.Fatalf("BuildTun error = %v", err)
	}

	entry, ok := system.GetTunPeer("tun")
	if !ok {
		t.Fatal("GetTunPeer(tun) not found")
	}
	if entry.Tun != tunDev || entry.Peer == nil {
		t.Fatalf(
			"GetTunPeer returned unexpected handles: tun=%v peer=%v",
			entry.Tun,
			entry.Peer,
		)
	}

	names, err := system.SetTunName(tunDev, "renamed0")
	if err != nil {
		t.Fatalf("SetTunName error = %v", err)
	}
	if len(names) != 1 || names[0] != "renamed0" {
		t.Fatalf("SetTunName names = %v, want [renamed0]", names)
	}
	name, err := tunDev.Name()
	if err != nil {
		t.Fatalf("Tun.Name error = %v", err)
	}
	if name != "renamed0" {
		t.Fatalf("Tun.Name = %q, want renamed0", name)
	}
	if _, ok := system.GetTunPeer("tun"); ok {
		t.Fatal("old tun name still present")
	}

	if err := tunDev.Close(); err != nil {
		t.Fatalf("Tun.Close error = %v", err)
	}
	if _, ok := system.GetTunPeer("renamed0"); ok {
		t.Fatal("closed tun still present")
	}
	if err := system.SetTunMTU(
		tunDev,
		1200,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunMTU(closed) = %v, want ErrUnknownTun", err)
	}
}

func TestDefaultTunRebuildClearsDNSAndCloseRemovesEntry(t *testing.T) {
	system := &System{}
	first, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{MTU: 1300})
	if err != nil {
		t.Fatalf("BuildDefaultTun error = %v", err)
	}
	entry, ok := system.GetDefaultTunPeer()
	if !ok || entry.Peer == nil || !entry.Default {
		t.Fatalf(
			"GetDefaultTunPeer = (%+v, %v), want default entry with peer",
			entry,
			ok,
		)
	}

	provider := newFakeDNS()
	first.SetDns(provider)
	second, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		MTU:       1200,
		TunRoutes: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatalf("rebuild BuildDefaultTun error = %v", err)
	}
	if second != first {
		t.Fatal("BuildDefaultTun rebuild returned a different tun")
	}
	if got, err := second.MTU(); err != nil || got != 1200 {
		t.Fatalf("rebuilt MTU = %d, %v; want 1200, nil", got, err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Millisecond,
	)
	defer cancel()
	reply := make(chan dns.Response, 1)
	system.Requests() <- dns.Request{Context: ctx, Reply: reply}
	select {
	case <-reply:
		t.Fatal("DNS request was routed after rebuild cleared resolver")
	case <-ctx.Done():
	}
	if provider.requestsSeen() != 0 {
		t.Fatalf("provider saw %d requests, want 0", provider.requestsSeen())
	}

	second.SetDns(provider)
	reply = make(chan dns.Response, 1)
	system.Requests() <- dns.Request{Context: context.Background(), Reply: reply}
	select {
	case response := <-reply:
		if response.Err != nil {
			t.Fatalf("routed DNS response error = %v", response.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for routed DNS response")
	}
	if provider.requestsSeen() != 1 {
		t.Fatalf("provider saw %d requests, want 1", provider.requestsSeen())
	}

	if err := second.Close(); err != nil {
		t.Fatalf("DefaultTun.Close error = %v", err)
	}
	if _, ok := system.GetDefaultTunPeer(); ok {
		t.Fatal("closed default tun still present")
	}
}

func TestWarningsNilByDefault(t *testing.T) {
	system := &System{}
	defer system.Close()

	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("BuildDefaultTun error = %v", err)
	}
	if got := system.DefaultTunWarnings(defaultTun); got != nil {
		t.Fatalf("DefaultTunWarnings = %v, want nil", got)
	}

	tunDev, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun error = %v", err)
	}
	if got := system.TunWarnings(tunDev); got != nil {
		t.Fatalf("TunWarnings = %v, want nil", got)
	}
}

func TestTunWrapperDelegatesBaseMethods(t *testing.T) {
	system := &System{}
	defer system.Close()

	tunDev, err := system.BuildTun(sysnet.TunOpts{MTU: 1400})
	if err != nil {
		t.Fatalf("BuildTun error = %v", err)
	}
	entry, ok := system.GetTunPeer("tun")
	if !ok {
		t.Fatal("GetTunPeer(tun) not found")
	}

	if tunDev.File() != nil {
		t.Fatal("File() = non-nil, want nil for pipe tun")
	}
	if tunDev.IsNative() {
		t.Fatal("IsNative() = true, want false")
	}
	if tunDev.MWO() != 0 || tunDev.MRO() != 0 {
		t.Fatalf("offsets = %d/%d, want 0/0", tunDev.MWO(), tunDev.MRO())
	}
	if tunDev.BatchSize() != 1 {
		t.Fatalf("BatchSize() = %d, want 1", tunDev.BatchSize())
	}
	select {
	case event := <-tunDev.Events():
		if event != tun.EventUp {
			t.Fatalf("Events() first event = %v, want EventUp", event)
		}
	default:
		t.Fatal("Events() had no initial EventUp")
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := tunDev.Write([][]byte{[]byte("packet")}, 0)
		writeDone <- err
	}()

	buf := [][]byte{make([]byte, 16)}
	sizes := make([]int, 1)
	n, err := entry.Peer.Read(buf, sizes, 0)
	if err != nil {
		t.Fatalf("peer Read error = %v", err)
	}
	if n != 1 || sizes[0] != len("packet") ||
		string(buf[0][:sizes[0]]) != "packet" {
		t.Fatalf(
			"peer Read = n %d size %d data %q",
			n,
			sizes[0],
			buf[0][:sizes[0]],
		)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("Write error = %v", err)
	}

	readDone := make(chan struct {
		n    int
		size int
		data string
		err  error
	}, 1)
	go func() {
		buf := [][]byte{make([]byte, 16)}
		sizes := make([]int, 1)
		n, err := tunDev.Read(buf, sizes, 0)
		readDone <- struct {
			n    int
			size int
			data string
			err  error
		}{n: n, size: sizes[0], data: string(buf[0][:sizes[0]]), err: err}
	}()
	if _, err := entry.Peer.Write([][]byte{[]byte("reply")}, 0); err != nil {
		t.Fatalf("peer Write error = %v", err)
	}
	got := <-readDone
	if got.err != nil {
		t.Fatalf("Read error = %v", got.err)
	}
	if got.n != 1 || got.size != len("reply") || got.data != "reply" {
		t.Fatalf("Read = n %d size %d data %q", got.n, got.size, got.data)
	}
}

func TestOutDNSAndStringID(t *testing.T) {
	provider := newFakeDNS()
	system := &System{OutDNSProvider: provider}
	if got := system.OutDNS(); got != provider {
		t.Fatal("OutDNS() did not return configured provider")
	}

	system = &System{StaticDNS: map[string]string{"example.test": "192.0.2.10"}}
	if got := system.OutDNS(); got == nil {
		t.Fatal("OutDNS() returned nil default provider")
	}

	tests := map[int]string{
		0:     "0",
		7:     "7",
		12345: "12345",
	}
	for in, want := range tests {
		if got := stringID(in); got != want {
			t.Fatalf("stringID(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestWarningsHooksRequireCurrentMatchingTun(t *testing.T) {
	warning := sysnet.WarningDefaultTunDNSRouteNotExclusive
	system := &System{
		DefaultTunWarningsHook: func(sysnet.DefaultTun) []sysnet.Warning {
			return []sysnet.Warning{warning}
		},
		TunWarningsHook: func(tun.Tun) []sysnet.Warning {
			return []sysnet.Warning{warning}
		},
	}
	defer system.Close()

	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("BuildDefaultTun error = %v", err)
	}
	tunDev, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun error = %v", err)
	}

	assertWarnings(
		t,
		"DefaultTunWarnings(active)",
		system.DefaultTunWarnings(defaultTun),
		[]sysnet.Warning{warning},
	)
	assertWarnings(
		t,
		"TunWarnings(active)",
		system.TunWarnings(tunDev),
		[]sysnet.Warning{warning},
	)

	got := system.DefaultTunWarnings(defaultTun)
	got[0] = "mutated"
	assertWarnings(
		t,
		"DefaultTunWarnings(after caller mutation)",
		system.DefaultTunWarnings(defaultTun),
		[]sysnet.Warning{warning},
	)

	if got := system.TunWarnings(defaultTun); got != nil {
		t.Fatalf("TunWarnings(default tun) = %v, want nil", got)
	}

	system.DisableDefaultTun = true
	if got := system.DefaultTunWarnings(defaultTun); got != nil {
		t.Fatalf("DefaultTunWarnings(unsupported) = %v, want nil", got)
	}
	system.DisableDefaultTun = false

	system.DisableTun = true
	if got := system.TunWarnings(tunDev); got != nil {
		t.Fatalf("TunWarnings(unsupported) = %v, want nil", got)
	}
	system.DisableTun = false

	other := &System{}
	defer other.Close()
	unknownDefaultTun, err := other.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("other BuildDefaultTun error = %v", err)
	}
	unknownTun, err := other.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("other BuildTun error = %v", err)
	}
	if got := system.DefaultTunWarnings(unknownDefaultTun); got != nil {
		t.Fatalf("DefaultTunWarnings(unknown) = %v, want nil", got)
	}
	if got := system.TunWarnings(unknownTun); got != nil {
		t.Fatalf("TunWarnings(unknown) = %v, want nil", got)
	}

	if err := defaultTun.Close(); err != nil {
		t.Fatalf("DefaultTun.Close error = %v", err)
	}
	if got := system.DefaultTunWarnings(defaultTun); got != nil {
		t.Fatalf("DefaultTunWarnings(closed) = %v, want nil", got)
	}
	replacementDefaultTun, err := system.BuildDefaultTun(
		sysnet.DefaultTunOpts{},
	)
	if err != nil {
		t.Fatalf("replacement BuildDefaultTun error = %v", err)
	}
	if got := system.DefaultTunWarnings(defaultTun); got != nil {
		t.Fatalf("DefaultTunWarnings(stale) = %v, want nil", got)
	}
	if err := replacementDefaultTun.Close(); err != nil {
		t.Fatalf("replacement DefaultTun.Close error = %v", err)
	}

	if err := tunDev.Close(); err != nil {
		t.Fatalf("Tun.Close error = %v", err)
	}
	if got := system.TunWarnings(tunDev); got != nil {
		t.Fatalf("TunWarnings(closed) = %v, want nil", got)
	}
	replacementTun, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("replacement BuildTun error = %v", err)
	}
	if got := system.TunWarnings(tunDev); got != nil {
		t.Fatalf("TunWarnings(stale) = %v, want nil", got)
	}
	if err := replacementTun.Close(); err != nil {
		t.Fatalf("replacement Tun.Close error = %v", err)
	}
}

func TestSystemFeatureHooksAndCopies(t *testing.T) {
	rule := sysnet.Rule{Type: "uid", Rule: "1000"}
	system := &System{
		DisableTun:             true,
		DisableDefaultTun:      true,
		DisableDynTun:          true,
		DisableDynDefaultTun:   true,
		DisableTunNames:        true,
		DisableDefaultTunNames: true,
		DisableStrictMode:      true,
		Rules: []sysnet.RuleTypeInfo{{
			Type:        "uid",
			Description: "user id",
		}},
		RuleVerifyer: func(got sysnet.Rule) bool {
			return got == rule
		},
		RuleCompletion: func(got sysnet.Rule) []string {
			if got != rule {
				t.Fatalf("RuleCompl rule = %+v, want %+v", got, rule)
			}
			return []string{"1000"}
		},
		TunNameVerifyer: func(name string) bool {
			return name == "tun0"
		},
	}

	features := system.Features()
	if features.Tun || features.DefaultTun || features.DynTun ||
		features.DynDefaultTun || features.TunNames ||
		features.DefaultTunNames || features.StrictMode {
		t.Fatalf("Features() = %+v, want all disabled", features)
	}
	if !system.RuleVerify(rule) || system.RuleVerify(sysnet.Rule{Type: "uid"}) {
		t.Fatal("RuleVerify() did not use hook")
	}
	if got := system.RuleCompl(rule); len(got) != 1 || got[0] != "1000" {
		t.Fatalf("RuleCompl() = %v, want [1000]", got)
	}

	rules := system.ListRules()
	rules.TunRules[0].Type = "changed"
	if got := system.ListRules(); got.TunRules[0].Type != "uid" {
		t.Fatalf("ListRules() returned aliased rules: %+v", got)
	}

	valid, free := system.TunNameVerify("tun0")
	if !valid || !free {
		t.Fatalf("TunNameVerify(tun0) = %v, %v", valid, free)
	}
	valid, free = system.TunNameVerify("")
	if valid || free {
		t.Fatalf("TunNameVerify(empty) = %v, %v", valid, free)
	}
}

func TestSystemAllocatorsAndDefaultNetworks(t *testing.T) {
	system := &System{}
	defer system.Close()

	if system.AllocIP() != system.AllocIP() {
		t.Fatal("AllocIP() did not return shared allocator")
	}
	if system.AllocSubnet() != system.AllocSubnet() {
		t.Fatal("AllocSubnet() did not return shared allocator")
	}
	if !system.OutNet().IsNative() && !system.LocalNet().IsNative() {
		return
	}
	t.Fatal("debug default networks must not be native")
}

func TestSystemDefaultHooksNetworksAndCloseBranches(t *testing.T) {
	system := &System{}

	if !system.RuleVerify(sysnet.Rule{}) {
		t.Fatal("RuleVerify() default = false, want true")
	}
	if got := system.RuleCompl(sysnet.Rule{}); got != nil {
		t.Fatalf("RuleCompl() default = %v, want nil", got)
	}
	valid, free := system.TunNameVerify("tun0")
	if !valid || !free {
		t.Fatalf(
			"TunNameVerify(tun0) default = %v, %v; want true, true",
			valid,
			free,
		)
	}
	if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{}); err != nil {
		t.Fatalf("VerifyDefaultTunOpts() default error = %v", err)
	}
	if err := system.VerifyTunOpts(sysnet.TunOpts{}); err != nil {
		t.Fatalf("VerifyTunOpts() default error = %v", err)
	}

	subnetAlloc := (&System{}).AllocSubnet()
	if subnetAlloc == nil {
		t.Fatal("AllocSubnet() default returned nil")
	}

	out := gonnect.NewLoopbackNetwork()
	local := gonnect.NewLoopbackNetwork()
	configured := &System{OutNetwork: out, LocalNetwork: local}
	if got := configured.OutNet(); got != out {
		t.Fatal("OutNet() did not return configured network")
	}
	if got := configured.LocalNet(); got != local {
		t.Fatal("LocalNet() did not return configured network")
	}

	_ = system.Requests()
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestSystemMatcherHookAndClose(t *testing.T) {
	rule := sysnet.Rule{Type: "uid", Rule: "1000"}
	flow := sockowner.FlowTuple{
		Proto:      "tcp",
		LocalIP:    net.ParseIP("192.0.2.1"),
		LocalPort:  1000,
		RemoteIP:   net.ParseIP("192.0.2.2"),
		RemotePort: 443,
	}
	system := &System{
		RuleMatcher: func(gotRule sysnet.Rule, gotFlow sockowner.FlowTuple) (bool, error) {
			if gotRule != rule || gotFlow.LocalPort != flow.LocalPort {
				t.Fatalf(
					"RuleMatcher args = %+v %+v, want %+v %+v",
					gotRule,
					gotFlow,
					rule,
					flow,
				)
			}
			return true, nil
		},
	}

	matcher, err := system.BuildMatcher(rule)
	if err != nil {
		t.Fatalf("BuildMatcher() error = %v", err)
	}
	if matched, err := matcher.Match(flow); err != nil || !matched {
		t.Fatalf("Match() = %v, %v; want true, nil", matched, err)
	}
	if err := matcher.Close(); err != nil {
		t.Fatalf("matcher Close() error = %v", err)
	}
	if _, err := matcher.Match(flow); err == nil {
		t.Fatal("Match() after matcher Close() error = nil")
	}

	matcher, err = system.BuildMatcher(rule)
	if err != nil {
		t.Fatalf("BuildMatcher() after close error = %v", err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("System.Close() error = %v", err)
	}
	if _, err := matcher.Match(flow); err == nil {
		t.Fatal("Match() after System.Close() error = nil")
	}
}

func TestSystemMatcherDefaultDoesNotMatch(t *testing.T) {
	system := &System{}
	defer system.Close()

	matcher, err := system.BuildMatcher(sysnet.Rule{})
	if err != nil {
		t.Fatalf("BuildMatcher() error = %v", err)
	}
	matched, err := matcher.Match(sockowner.FlowTuple{})
	if err != nil || matched {
		t.Fatalf("Match() default = %v, %v; want false, nil", matched, err)
	}
}

func TestSystemTunSettersAndConfigCopies(t *testing.T) {
	system := &System{}
	defer system.Close()

	tunDev, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	if err := system.SetTunMTU(tunDev, 0); err != nil {
		t.Fatalf("SetTunMTU() error = %v", err)
	}
	if got, err := tunDev.MTU(); err != nil || got != 1500 {
		t.Fatalf("MTU() = %d, %v; want 1500, nil", got, err)
	}

	addrs := []string{"10.0.0.2/32"}
	if err := system.SetTunAddrs(tunDev, addrs); err != nil {
		t.Fatalf("SetTunAddrs() error = %v", err)
	}
	addrs[0] = "changed"
	if err := system.AddTunAddr(tunDev, "10.0.0.3/32"); err != nil {
		t.Fatalf("AddTunAddr() error = %v", err)
	}
	gotAddrs, err := system.GetTunAddrs(tunDev)
	if err != nil {
		t.Fatalf("GetTunAddrs() error = %v", err)
	}
	gotAddrs[0] = "mutated"
	gotAddrsAgain, err := system.GetTunAddrs(tunDev)
	if err != nil {
		t.Fatalf("GetTunAddrs() second error = %v", err)
	}
	if len(gotAddrsAgain) != 2 || gotAddrsAgain[0] != "10.0.0.2/32" ||
		gotAddrsAgain[1] != "10.0.0.3/32" {
		t.Fatalf("GetTunAddrs() = %v", gotAddrsAgain)
	}

	routes := []string{"0.0.0.0/0"}
	if err := system.SetTunRoutes(tunDev, routes); err != nil {
		t.Fatalf("SetTunRoutes() error = %v", err)
	}
	routes[0] = "changed"
	if err := system.AddTunRoute(tunDev, "192.0.2.0/24"); err != nil {
		t.Fatalf("AddTunRoute() error = %v", err)
	}
	gotRoutes, err := system.GetTunRotue(tunDev)
	if err != nil {
		t.Fatalf("GetTunRotue() error = %v", err)
	}
	gotRoutes[0] = "mutated"
	gotRoutesAgain, err := system.GetTunRotue(tunDev)
	if err != nil {
		t.Fatalf("GetTunRotue() second error = %v", err)
	}
	if len(gotRoutesAgain) != 2 || gotRoutesAgain[0] != "0.0.0.0/0" ||
		gotRoutesAgain[1] != "192.0.2.0/24" {
		t.Fatalf("GetTunRotue() = %v", gotRoutesAgain)
	}

	entry, ok := system.GetTunPeer("tun")
	if !ok {
		t.Fatal("GetTunPeer(tun) not found")
	}
	entry.Config.TunAddrs[0] = "changed"
	entryAgain, ok := system.GetTunPeer("tun")
	if !ok || entryAgain.Config.TunAddrs[0] != "10.0.0.2/32" {
		t.Fatalf("GetTunPeer() returned aliased config: %+v", entryAgain)
	}
}

func TestSystemTunSetterUnknownAndRenameBranches(t *testing.T) {
	system := &System{}
	defer system.Close()

	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	tunDev, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	secondTun, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("second BuildTun() error = %v", err)
	}
	if name, err := secondTun.Name(); err != nil || name != "tun-0" {
		t.Fatalf("second tun Name() = %q, %v; want tun-0, nil", name, err)
	}

	names, err := system.SetTunName(tunDev, "tun")
	if err != nil || len(names) != 1 || names[0] != "tun" {
		t.Fatalf("SetTunName(existing) = %v, %v; want [tun], nil", names, err)
	}
	if _, err := system.SetTunName(
		defaultTun,
		"default-as-regular",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunName(default tun) = %v, want ErrUnknownTun", err)
	}
	system.DisableTunNames = true
	if _, err := system.SetTunName(
		tunDev,
		"renamed",
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("SetTunName(disabled) = %v, want ErrNotSupported", err)
	}
	system.DisableTunNames = false
	if _, err := system.SetTunName(
		tunDev,
		"tun-0",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunName(duplicate) = %v, want ErrUnknownTun", err)
	}
	system.TunNameVerifyer = func(string) bool { return false }
	if _, err := system.SetTunName(
		tunDev,
		"blocked",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunName(invalid) = %v, want ErrUnknownTun", err)
	}

	if err := secondTun.Close(); err != nil {
		t.Fatalf("second tun Close() error = %v", err)
	}
	if err := system.SetTunAddrs(
		secondTun,
		nil,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunAddrs(closed) = %v, want ErrUnknownTun", err)
	}
	if err := system.AddTunAddr(
		secondTun,
		"10.0.0.4/32",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("AddTunAddr(closed) = %v, want ErrUnknownTun", err)
	}
	if _, err := system.GetTunAddrs(
		secondTun,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("GetTunAddrs(closed) = %v, want ErrUnknownTun", err)
	}
	if err := system.SetTunRoutes(
		secondTun,
		nil,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("SetTunRoutes(closed) = %v, want ErrUnknownTun", err)
	}
	if err := system.AddTunRoute(
		secondTun,
		"192.0.2.0/24",
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("AddTunRoute(closed) = %v, want ErrUnknownTun", err)
	}
	if _, err := system.GetTunRotue(
		secondTun,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("GetTunRotue(closed) = %v, want ErrUnknownTun", err)
	}
	if got, err := secondTun.MTU(); got != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed tun MTU() = %d, %v; want 0, os.ErrClosed", got, err)
	}
	if name, err := secondTun.Name(); name != "tun-0" ||
		!errors.Is(err, os.ErrClosed) {
		t.Fatalf(
			"closed tun Name() = %q, %v; want tun-0, os.ErrClosed",
			name,
			err,
		)
	}

	defaultTun.SetDns(newFakeDNS())
	if err := defaultTun.Close(); err != nil {
		t.Fatalf("default tun Close() error = %v", err)
	}
	defaultTun.SetDns(newFakeDNS())
}

func TestSystemVerifyAndBuildFailures(t *testing.T) {
	errVerify := errors.New("verify failed")
	system := &System{
		DefaultTunOptsVerifyer: func(sysnet.DefaultTunOpts) error {
			return errVerify
		},
		TunOptsVerifyer: func(sysnet.TunOpts) error {
			return errVerify
		},
	}
	if err := system.VerifyDefaultTunOpts(
		sysnet.DefaultTunOpts{},
	); !errors.Is(
		err,
		errVerify,
	) {
		t.Fatalf("VerifyDefaultTunOpts() error = %v, want %v", err, errVerify)
	}
	if _, err := system.BuildDefaultTun(
		sysnet.DefaultTunOpts{},
	); !errors.Is(
		err,
		errVerify,
	) {
		t.Fatalf("BuildDefaultTun() error = %v, want %v", err, errVerify)
	}
	if err := system.VerifyTunOpts(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		errVerify,
	) {
		t.Fatalf("VerifyTunOpts() error = %v, want %v", err, errVerify)
	}
	if _, err := system.BuildTun(sysnet.TunOpts{}); !errors.Is(err, errVerify) {
		t.Fatalf("BuildTun() error = %v, want %v", err, errVerify)
	}

	system = &System{DisableDefaultTun: true, DisableTun: true}
	if err := system.VerifyDefaultTunOpts(
		sysnet.DefaultTunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("VerifyDefaultTunOpts(disabled) = %v", err)
	}
	if _, err := system.BuildDefaultTun(
		sysnet.DefaultTunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("BuildDefaultTun(disabled) = %v", err)
	}
	if err := system.VerifyTunOpts(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("VerifyTunOpts(disabled) = %v", err)
	}
	if _, err := system.BuildTun(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("BuildTun(disabled) = %v", err)
	}

	system = &System{
		DefaultTunBuilder: func(sysnet.DefaultTunOpts) (tun.Tun, error) {
			return nil, nil
		},
		TunBuilder: func(sysnet.TunOpts) (tun.Tun, error) {
			return nil, nil
		},
	}
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{}); err == nil {
		t.Fatal("BuildDefaultTun(nil builder result) error = nil")
	}
	if _, err := system.BuildTun(sysnet.TunOpts{}); err == nil {
		t.Fatal("BuildTun(nil builder result) error = nil")
	}

	system = &System{}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := system.BuildDefaultTun(
		sysnet.DefaultTunOpts{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("BuildDefaultTun(closed) = %v", err)
	}
	if _, err := system.BuildTun(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("BuildTun(closed) = %v", err)
	}
}

type fakeDNS struct {
	requests chan dns.Request
	seen     chan struct{}
}

func newFakeDNS() *fakeDNS {
	f := &fakeDNS{
		requests: make(chan dns.Request),
		seen:     make(chan struct{}, 8),
	}
	go func() {
		for req := range f.requests {
			f.seen <- struct{}{}
			if req.Reply != nil {
				req.Reply <- dns.Response{}
			}
		}
	}()
	return f
}

func (f *fakeDNS) Requests() chan<- dns.Request { return f.requests }

func (f *fakeDNS) Close() error {
	close(f.requests)
	return nil
}

func (f *fakeDNS) requestsSeen() int {
	return len(f.seen)
}

func assertWarnings(
	t *testing.T,
	name string,
	got, want []sysnet.Warning,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}
