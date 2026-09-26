//nolint:testpackage // These tests verify the mock's internal state is unchanged.
package sysnetdebug

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

func TestDefaultCapabilityReportIsValidAndExact(t *testing.T) {
	system := &System{}
	report := system.Capabilities()
	if err := report.Validate(); err != nil {
		t.Fatalf("default report validation error = %v", err)
	}
	if report.SchemaVersion != sysnet.CapabilitySchemaVersion ||
		report.Revision == 0 {
		t.Fatalf(
			"default report header = schema %d revision %d",
			report.SchemaVersion,
			report.Revision,
		)
	}

	weakDNS := report.Operation(
		sysnet.OperationKey{
			Target:    sysnet.TargetDefaultTun,
			Operation: sysnet.OpDNSConfigure,
			Family:    sysnet.FamilyIPv4,
		},
	)
	strongDNS := report.Operation(
		sysnet.OperationKey{
			Target:    sysnet.TargetDefaultTun,
			Operation: sysnet.OpDNSSystemExclusive,
			Family:    sysnet.FamilyIPv4,
		},
	)
	if weakDNS.State != sysnet.CapabilityAvailable ||
		strongDNS.State != sysnet.CapabilityUnsupported {
		t.Fatalf(
			"DNS capabilities = configure %+v, system-exclusive %+v",
			weakDNS,
			strongDNS,
		)
	}

	strict := &System{DisableStrictMode: true}
	strictReport := strict.Capabilities()
	nonStrictKey := sysnet.RoutingProfileKey{
		Family: sysnet.FamilyIPv4,
		Mode:   sysnet.RoutingExclude,
	}
	strictKey := nonStrictKey
	strictKey.Strict = true
	if strictReport.DefaultTunProfile(
		nonStrictKey,
	).State != sysnet.CapabilityAvailable ||
		strictReport.DefaultTunProfile(
			strictKey,
		).State != sysnet.CapabilityUnsupported {
		t.Fatal("strict profile state leaked into the non-strict profile")
	}

	disabledRoutes := &System{DisableDefaultTunSourceRoutes: true}
	disabledReport := disabledRoutes.Capabilities()
	if disabledReport.Operation(
		sysnet.OperationKey{
			Target:    sysnet.TargetDefaultTun,
			Operation: sysnet.OpCreate,
			Family:    sysnet.FamilyIPv4,
		},
	).State != sysnet.CapabilityAvailable ||
		disabledReport.Operation(
			sysnet.OperationKey{
				Target:    sysnet.TargetDefaultTun,
				Operation: sysnet.OpSourceRoutes,
				Family:    sysnet.FamilyIPv4,
			},
		).State != sysnet.CapabilityUnsupported {
		t.Fatal(
			"source-route configuration disabled unrelated default-TUN creation",
		)
	}
}

func TestCapabilityReportRevisionCopiesAndConcurrentUpdates(t *testing.T) {
	system := &System{}
	initial := system.Capabilities()
	if err := system.SetCapabilityReport(initial); err != nil {
		t.Fatalf("SetCapabilityReport(equal) error = %v", err)
	}
	if got := system.Capabilities().Revision; got != initial.Revision {
		t.Fatalf("equal report revision = %d, want %d", got, initial.Revision)
	}

	changed := initial.Clone()
	changed.Operations[0].Detail = "changed"
	if err := system.SetCapabilityReport(changed); err != nil {
		t.Fatalf("SetCapabilityReport(changed) error = %v", err)
	}
	changedSnapshot := system.Capabilities()
	if changedSnapshot.Revision != initial.Revision+1 {
		t.Fatalf(
			"changed report revision = %d, want %d",
			changedSnapshot.Revision,
			initial.Revision+1,
		)
	}
	changedSnapshot.Operations[0].Detail = "caller mutation"
	if got := system.Capabilities().Operations[0].Detail; got != "changed" {
		t.Fatalf("caller mutation changed backend report to %q", got)
	}

	first := initial.Clone()
	first.Operations[0].Detail = "first"
	second := initial.Clone()
	second.Operations[0].Detail = "second"
	errCh := make(chan error, 8)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				report := system.Capabilities()
				if err := report.Validate(); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			report := first
			if i%2 != 0 {
				report = second
			}
			if err := system.SetCapabilityReport(report); err != nil {
				errCh <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent capability operation error = %v", err)
	}
}

func TestUnknownBuildCanResolveAndCurrentUnavailableStateWins(t *testing.T) {
	var builds atomic.Int32
	system := &System{TunBuilder: func(sysnet.TunOpts) (tun.Tun, error) {
		builds.Add(1)
		left, _ := tun.Pipe(1, 1500, 0, 0)
		return left, nil
	}}
	report := system.Capabilities()
	key := sysnet.OperationKey{
		Target:    sysnet.TargetTun,
		Operation: sysnet.OpCreate,
		Family:    sysnet.FamilyNone,
	}
	setOperationCapability(
		t,
		&report,
		key,
		sysnet.Capability{
			State:   sysnet.CapabilityUnknown,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonProbeNotRun},
		},
	)
	if err := system.SetCapabilityReport(report); err != nil {
		t.Fatalf("SetCapabilityReport(unknown) error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{}).
		Err(); !errors.Is(
		err,
		sysnet.ErrCapabilityUnknown,
	) {
		t.Fatalf("CheckTunOpts() error = %v, want ErrCapabilityUnknown", err)
	}
	created, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun(unknown preflight) error = %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatalf("created.Close() error = %v", err)
	}

	staleAvailable := system.Capabilities()
	setOperationCapability(
		t,
		&staleAvailable,
		key,
		sysnet.Capability{State: sysnet.CapabilityAvailable},
	)
	if err := system.SetCapabilityReport(staleAvailable); err != nil {
		t.Fatalf("SetCapabilityReport(available) error = %v", err)
	}
	if err := system.CheckTunOpts(sysnet.TunOpts{}).Err(); err != nil {
		t.Fatalf("CheckTunOpts(available) error = %v", err)
	}
	current := system.Capabilities()
	setOperationCapability(
		t,
		&current,
		key,
		sysnet.Capability{
			State:   sysnet.CapabilityUnavailable,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonResourceBusy},
		},
	)
	if err := system.SetCapabilityReport(current); err != nil {
		t.Fatalf("SetCapabilityReport(unavailable) error = %v", err)
	}
	if _, err := system.BuildTun(
		sysnet.TunOpts{},
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf(
			"BuildTun(stale snapshot) error = %v, want ErrUnavailable",
			err,
		)
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("builder calls = %d, want 1", got)
	}
}

func TestCapabilitiesAndValidationDoNotCallBuilders(t *testing.T) {
	var builds atomic.Int32
	system := &System{
		TunBuilder: func(sysnet.TunOpts) (tun.Tun, error) {
			builds.Add(1)
			return nil, errors.New("must not run")
		},
		DefaultTunBuilder: func(sysnet.DefaultTunOpts) (tun.Tun, error) {
			builds.Add(1)
			return nil, errors.New("must not run")
		},
	}
	_ = system.Capabilities()
	_ = system.CheckTunOpts(sysnet.TunOpts{Name: "tun0"})
	_ = system.CheckDefaultTunOpts(sysnet.DefaultTunOpts{})
	if got := builds.Load(); got != 0 {
		t.Fatalf("read-only calls invoked builders %d times", got)
	}
}

func TestCapabilitiesForTunOwnershipNarrowingAndCopies(t *testing.T) {
	system := &System{}
	tunDev, err := system.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	other := &System{}
	foreign, err := other.BuildTun(sysnet.TunOpts{})
	if err != nil {
		t.Fatalf("other.BuildTun() error = %v", err)
	}
	t.Cleanup(func() {
		if err := other.Close(); err != nil {
			t.Errorf("other.Close() error = %v", err)
		}
	})
	if _, err := system.CapabilitiesForTun(
		foreign,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("CapabilitiesForTun(foreign) error = %v", err)
	}

	key := sysnet.OperationKey{
		Target:    sysnet.TargetTun,
		Operation: sysnet.OpRename,
		Family:    sysnet.FamilyNone,
	}
	narrow := sysnet.TunCapabilityReport{
		Operations: []sysnet.OperationCapability{{
			Key: key,
			Capability: sysnet.Capability{
				State:   sysnet.CapabilityUnavailable,
				Reasons: []sysnet.CapabilityReason{sysnet.ReasonResourceBusy},
			},
		}},
	}
	before, err := system.CapabilitiesForTun(tunDev)
	if err != nil {
		t.Fatalf("CapabilitiesForTun() error = %v", err)
	}
	if err := system.SetTunCapabilityReport(tunDev, narrow); err != nil {
		t.Fatalf("SetTunCapabilityReport() error = %v", err)
	}
	after, err := system.CapabilitiesForTun(tunDev)
	if err != nil {
		t.Fatalf("CapabilitiesForTun(narrowed) error = %v", err)
	}
	if after.InstanceRevision != before.InstanceRevision+1 ||
		after.Operation(key).State != sysnet.CapabilityUnavailable {
		t.Fatalf("narrowed report = %+v, before %+v", after, before)
	}
	after.Operations[0].Reasons[0] = sysnet.ReasonProbeFailed
	again, err := system.CapabilitiesForTun(tunDev)
	if err != nil ||
		again.Operations[0].Reasons[0] != sysnet.ReasonResourceBusy {
		t.Fatalf("per-TUN report aliases backend: %+v, %v", again, err)
	}
	if err := system.SetTunName(
		tunDev,
		"blocked",
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("SetTunName() error = %v, want ErrUnavailable", err)
	}

	badTarget := narrow.Clone()
	badTarget.Operations[0].Key.Target = sysnet.TargetDefaultTun
	if err := system.SetTunCapabilityReport(
		tunDev,
		badTarget,
	); !errors.Is(
		err,
		sysnet.ErrInvalidCapabilityReport,
	) {
		t.Fatalf("SetTunCapabilityReport(bad target) error = %v", err)
	}
	if err := tunDev.Close(); err != nil {
		t.Fatalf("tun.Close() error = %v", err)
	}
	if _, err := system.CapabilitiesForTun(
		tunDev,
	); !errors.Is(
		err,
		sysnet.ErrUnknownTun,
	) {
		t.Fatalf("CapabilitiesForTun(closed) error = %v", err)
	}
}

func TestRuleCapabilitiesAreContextSpecific(t *testing.T) {
	system := &System{}
	report := system.Capabilities()
	for i := range report.DefaultTunProfiles {
		for j := range report.DefaultTunProfiles[i].Rules {
			binding := &report.DefaultTunProfiles[i].Rules[j]
			if binding.Type == "pid" {
				binding.Capability = sysnet.Capability{
					State: sysnet.CapabilityUnsupported,
					Reasons: []sysnet.CapabilityReason{
						sysnet.ReasonUnsupportedCombination,
					},
				}
			}
		}
	}
	for i := range report.Rules {
		if report.Rules[i].Type == "exec" {
			for j := range report.Rules[i].Matchers {
				report.Rules[i].Matchers[j].Capability = sysnet.Capability{
					State: sysnet.CapabilityUnsupported,
					Reasons: []sysnet.CapabilityReason{
						sysnet.ReasonUnsupportedCombination,
					},
				}
			}
			report.Rules[i].Completion = sysnet.Capability{
				State: sysnet.CapabilityUnavailable,
				Reasons: []sysnet.CapabilityReason{
					sysnet.ReasonMissingDependency,
				},
			}
		}
	}
	if err := system.SetCapabilityReport(report); err != nil {
		t.Fatalf("SetCapabilityReport() error = %v", err)
	}
	routingKey := sysnet.RoutingProfileKey{
		Family: sysnet.FamilyIPv4,
		Mode:   sysnet.RoutingExclude,
	}
	matcherKey := sysnet.MatcherProfileKey{
		Family:    sysnet.FamilyIPv4,
		Transport: sysnet.TransportTCP,
	}
	routing := sysnet.RuleContext{Routing: &routingKey}
	matcher := sysnet.RuleContext{Matcher: &matcherKey}
	if err := system.CheckRule(sysnet.Rule{Type: "pid", Rule: "10"}, routing).
		Err(); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("PID routing error = %v, want ErrNotSupported", err)
	}
	if err := system.CheckRule(sysnet.Rule{Type: "pid", Rule: "10"}, matcher).
		Err(); err != nil {
		t.Fatalf("PID matcher error = %v", err)
	}
	if err := system.CheckRule(sysnet.Rule{Type: "exec", Rule: "/bin/app"}, routing).
		Err(); err != nil {
		t.Fatalf("exec routing error = %v", err)
	}
	if err := system.CheckRule(sysnet.Rule{Type: "exec", Rule: "/bin/app"}, matcher).
		Err(); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("exec matcher error = %v, want ErrNotSupported", err)
	}
	if _, err := system.CompleteRule(
		sysnet.Rule{Type: "exec"},
		routing,
	); !errors.Is(
		err,
		sysnet.ErrUnavailable,
	) {
		t.Fatalf("CompleteRule() error = %v, want ErrUnavailable", err)
	}
}

func TestValidationOrderPathsAndUnsupportedBuild(t *testing.T) {
	var builds atomic.Int32
	system := &System{
		DisableStrictMode: true,
		DefaultTunBuilder: func(sysnet.DefaultTunOpts) (tun.Tun, error) {
			builds.Add(1)
			return nil, errors.New("must not run")
		},
	}
	report := system.CheckDefaultTunOpts(sysnet.DefaultTunOpts{
		TunAddrs: []string{"not-a-prefix"},
		Strict:   true,
		Exclude:  []sysnet.Rule{{Type: "uid", Rule: "1000"}},
		Include:  []sysnet.Rule{{Type: "uid", Rule: "1001"}},
	})
	if len(report.Issues) < 2 || report.Issues[0].Path != "Include" ||
		report.Issues[1].Path != "TunAddrs[0]" {
		t.Fatalf("validation issue order = %+v", report.Issues)
	}
	if !errors.Is(report.Err(), sysnet.ErrInvalidOptions) ||
		!errors.Is(report.Err(), sysnet.ErrNotSupported) {
		t.Fatalf("validation error = %v", report.Err())
	}
	if _, err := system.BuildDefaultTun(
		sysnet.DefaultTunOpts{Strict: true},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("BuildDefaultTun(strict disabled) error = %v", err)
	}
	if got := builds.Load(); got != 0 {
		t.Fatalf("unsupported build called host mutator %d times", got)
	}
}

func TestDisabledDynamicOperationDoesNotMutateTun(t *testing.T) {
	system := &System{DisableDynTun: true}
	tunDev, err := system.BuildTun(sysnet.TunOpts{MTU: 1400})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("system.Close() error = %v", err)
		}
	})
	if err := system.SetTunMTU(
		tunDev,
		1200,
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("SetTunMTU() error = %v, want ErrNotSupported", err)
	}
	if got, err := tunDev.MTU(); err != nil || got != 1400 {
		t.Fatalf("MTU after rejected update = %d, %v; want 1400, nil", got, err)
	}
	if err := system.SetTunAddrs(
		tunDev,
		[]string{"10.0.0.2/32"},
	); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("SetTunAddrs() error = %v, want ErrNotSupported", err)
	}
	entry, ok := system.GetTunPeer("tun")
	if !ok || entry.Config.TunAddrs != nil {
		t.Fatalf("rejected address update changed config: %+v", entry.Config)
	}
}

func TestCreationNamesDefaultRenameAndDNSFailures(t *testing.T) {
	system := &System{}
	regular, err := system.BuildTun(sysnet.TunOpts{Name: "named-tun"})
	if err != nil {
		t.Fatalf("BuildTun(named) error = %v", err)
	}
	if name, err := regular.Name(); err != nil || name != "named-tun" {
		t.Fatalf("regular.Name() = %q, %v", name, err)
	}
	defaultTun, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}

	report := system.Capabilities()
	for i := range report.Operations {
		operation := &report.Operations[i]
		if operation.Key.Target == sysnet.TargetDefaultTun &&
			operation.Key.Operation == sysnet.OpCreateNamed {
			operation.Capability = sysnet.Capability{
				State:   sysnet.CapabilityUnsupported,
				Reasons: []sysnet.CapabilityReason{sysnet.ReasonNotImplemented},
			}
		}
	}
	if err := system.SetCapabilityReport(report); err != nil {
		t.Fatalf("SetCapabilityReport() error = %v", err)
	}
	if err := system.CheckDefaultTunOpts(sysnet.DefaultTunOpts{Name: "new-default"}).
		Err(); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("named default creation error = %v", err)
	}
	if err := system.SetTunName(defaultTun, "renamed-default"); err != nil {
		t.Fatalf("SetTunName(default) error = %v", err)
	}

	native := errors.New("resolver update failed")
	provider := newFakeDNS()
	if err := defaultTun.SetDNS(provider); err != nil {
		t.Fatalf("SetDNS(provider) error = %v", err)
	}
	system.SetDNSHook = func(next dns.Interface) error {
		if next != nil {
			return native
		}
		return nil
	}
	if err := defaultTun.SetDNS(newFakeDNS()); !errors.Is(err, native) {
		t.Fatalf("SetDNS(failure) error = %v", err)
	}
	system.mu.Lock()
	gotProvider := system.dns
	system.mu.Unlock()
	if gotProvider != provider {
		t.Fatal("failed SetDNS changed the active provider")
	}
	if err := defaultTun.SetDNS(nil); err != nil {
		t.Fatalf("SetDNS(nil) error = %v", err)
	}
	system.mu.Lock()
	gotProvider = system.dns
	system.mu.Unlock()
	if gotProvider != nil {
		t.Fatal("SetDNS(nil) did not stop managed requests")
	}
}

func TestClosedSystemReportUsesClosedReason(t *testing.T) {
	system := &System{}
	before := system.Capabilities()
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	after := system.Capabilities()
	if after.Revision <= before.Revision {
		t.Fatalf(
			"closed revision = %d, want greater than %d",
			after.Revision,
			before.Revision,
		)
	}
	operation := after.Operation(
		sysnet.OperationKey{
			Target:    sysnet.TargetTun,
			Operation: sysnet.OpCreate,
			Family:    sysnet.FamilyIPv4,
		},
	)
	if operation.State != sysnet.CapabilityUnavailable ||
		len(operation.Reasons) != 1 ||
		operation.Reasons[0] != sysnet.ReasonSystemClosed {
		t.Fatalf("closed create capability = %+v", operation)
	}
	unsupported := after.Operation(
		sysnet.OperationKey{
			Target:    sysnet.TargetDefaultTun,
			Operation: sysnet.OpDNSSystemExclusive,
			Family:    sysnet.FamilyIPv4,
		},
	)
	if unsupported.State != sysnet.CapabilityUnsupported {
		t.Fatalf("closed unsupported capability = %+v", unsupported)
	}
}

func setOperationCapability(
	t *testing.T,
	report *sysnet.CapabilityReport,
	key sysnet.OperationKey,
	capability sysnet.Capability,
) {
	t.Helper()
	for i := range report.Operations {
		if report.Operations[i].Key == key {
			report.Operations[i].Capability = capability
			return
		}
	}
	t.Fatalf("operation key %+v was not found", key)
}
