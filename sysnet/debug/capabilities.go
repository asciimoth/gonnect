package sysnetdebug

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

// SetCapabilityReport atomically replaces the report used by validation and
// operations. The System assigns its own monotonic revision. Equal semantic
// contents keep the current revision.
func (s *System) SetCapabilityReport(report sysnet.CapabilityReport) error {
	report = report.Clone()
	if err := report.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.capabilityReportLocked()
	revision := current.Revision
	if !sameCapabilityContents(current, report) {
		revision++
	}
	report.Revision = revision
	if s.closed {
		markReportClosed(&report)
	}
	s.capabilities = report
	s.capabilitiesSet = true
	s.explicitCapabilities = true
	return nil
}

// UseDefaultCapabilityReport returns the System to its documented default
// capability catalog. Disable* fields and Rules configure that catalog.
func (s *System) UseDefaultCapabilityReport() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.explicitCapabilities = false
	s.refreshDefaultCapabilitiesLocked()
}

// Capabilities returns an independent capability snapshot.
func (s *System) Capabilities() sysnet.CapabilityReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capabilityReportLocked().Clone()
}

// CapabilitiesForTun returns capabilities for a live TUN created by s.
func (s *System) CapabilitiesForTun(
	t tun.Tun,
) (sysnet.TunCapabilityReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.tunEntryLocked(t)
	if s.closed || entry == nil || entry.tun != t {
		return sysnet.TunCapabilityReport{}, sysnet.ErrUnknownTun
	}
	report := s.capabilityReportLocked()
	operations := entry.operations
	if !entry.operationsSet {
		target := sysnet.TargetTun
		if entry.defaultTun {
			target = sysnet.TargetDefaultTun
		}
		for _, operation := range report.Operations {
			if operation.Key.Target == target &&
				isInstanceOperation(operation.Key.Operation) {
				operations = append(operations, operation)
			}
		}
	}
	result := sysnet.TunCapabilityReport{
		SystemRevision:   report.Revision,
		InstanceRevision: entry.revision,
		Operations:       operations,
	}
	return result.Clone(), nil
}

// SetTunCapabilityReport atomically narrows the operations for one live TUN.
// The SystemRevision and InstanceRevision fields in report are ignored.
func (s *System) SetTunCapabilityReport(
	t tun.Tun,
	report sysnet.TunCapabilityReport,
) error {
	report = report.Clone()
	if err := report.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.tunEntryLocked(t)
	if s.closed || entry == nil || entry.tun != t {
		return sysnet.ErrUnknownTun
	}
	systemReport := s.capabilityReportLocked()
	wantTarget := entry.target()
	for _, operation := range report.Operations {
		if !isInstanceOperation(operation.Key.Operation) {
			return fmt.Errorf(
				"%w: operation %q does not apply to a live TUN",
				sysnet.ErrInvalidCapabilityReport,
				operation.Key.Operation,
			)
		}
		if operation.Key.Target != wantTarget {
			return fmt.Errorf(
				"%w: per-TUN operation target %q does not match %q",
				sysnet.ErrInvalidCapabilityReport,
				operation.Key.Target,
				wantTarget,
			)
		}
		systemCapability := systemReport.Operation(operation.Key)
		if systemCapability.State == sysnet.CapabilityUnsupported &&
			operation.State == sysnet.CapabilityAvailable {
			return fmt.Errorf(
				"%w: per-TUN operation %+v widens an unsupported system operation",
				sysnet.ErrInvalidCapabilityReport,
				operation.Key,
			)
		}
	}
	current := s.tunOperationsLocked(entry, systemReport)
	operations := report.Operations
	if !reflect.DeepEqual(current, operations) {
		entry.revision++
	}
	entry.operations = operations
	entry.operationsSet = true
	return nil
}

func (s *System) capabilityReportLocked() sysnet.CapabilityReport {
	if !s.explicitCapabilities {
		s.refreshDefaultCapabilitiesLocked()
	} else if !s.capabilitiesSet {
		s.capabilities = s.defaultCapabilityReportLocked()
		s.capabilities.Revision = 1
		s.capabilitiesSet = true
	}
	return s.capabilities
}

func (s *System) refreshDefaultCapabilitiesLocked() {
	next := s.defaultCapabilityReportLocked()
	if s.closed {
		markReportClosed(&next)
	}
	if !s.capabilitiesSet {
		next.Revision = 1
		s.capabilities = next
		s.capabilitiesSet = true
		return
	}
	next.Revision = s.capabilities.Revision
	if !sameCapabilityContents(s.capabilities, next) {
		next.Revision++
	}
	s.capabilities = next
}

func (s *System) defaultCapabilityReportLocked() sysnet.CapabilityReport {
	report := sysnet.CapabilityReport{
		SchemaVersion: sysnet.CapabilitySchemaVersion,
	}
	available := sysnet.Capability{State: sysnet.CapabilityAvailable}

	addOperation := func(
		target sysnet.Target,
		operation sysnet.Operation,
		family sysnet.AddressFamily,
		capability sysnet.Capability,
	) {
		report.Operations = append(
			report.Operations,
			sysnet.OperationCapability{
				Key: sysnet.OperationKey{
					Target:    target,
					Operation: operation,
					Family:    family,
				},
				Capability: capability,
			},
		)
	}
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		addOperation(
			sysnet.TargetSystem,
			sysnet.OpAllocateIP,
			family,
			available,
		)
		addOperation(
			sysnet.TargetSystem,
			sysnet.OpAllocateSubnet,
			family,
			available,
		)
	}

	regularCreate := configuredCapability(!s.DisableTun)
	regularName := combineConfigured(regularCreate, !s.DisableTunNames)
	defaultCreate := configuredCapability(!s.DisableDefaultTun)
	defaultName := combineConfigured(defaultCreate, !s.DisableDefaultTunNames)
	regularDynamic := combineConfigured(regularCreate, !s.DisableDynTun)
	defaultDynamic := combineConfigured(defaultCreate, !s.DisableDynDefaultTun)

	createFamilies := []sysnet.AddressFamily{
		sysnet.FamilyNone,
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	}
	for _, family := range createFamilies {
		addOperation(sysnet.TargetTun, sysnet.OpCreate, family, regularCreate)
		addOperation(
			sysnet.TargetTun,
			sysnet.OpCreateNamed,
			family,
			regularName,
		)
	}
	addOperation(
		sysnet.TargetTun,
		sysnet.OpSetMTU,
		sysnet.FamilyNone,
		regularDynamic,
	)
	addOperation(
		sysnet.TargetTun,
		sysnet.OpRename,
		sysnet.FamilyNone,
		combineConfigured(regularDynamic, !s.DisableTunNames),
	)
	dynamicOperations := []sysnet.Operation{
		sysnet.OpSetAddresses,
		sysnet.OpAddAddress,
		sysnet.OpGetAddresses,
		sysnet.OpSetRoutes,
		sysnet.OpAddRoute,
		sysnet.OpGetRoutes,
	}
	for _, family := range []sysnet.AddressFamily{
		sysnet.FamilyIPv4,
		sysnet.FamilyIPv6,
		sysnet.FamilyDual,
	} {
		for _, operation := range dynamicOperations {
			addOperation(sysnet.TargetTun, operation, family, regularDynamic)
		}

		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpCreate,
			family,
			defaultCreate,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpCreateNamed,
			family,
			defaultName,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpReconfigureInPlace,
			family,
			defaultDynamic,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpSourceRoutes,
			family,
			combineConfigured(defaultCreate, !s.DisableDefaultTunSourceRoutes),
		)
		for _, operation := range dynamicOperations {
			addOperation(
				sysnet.TargetDefaultTun,
				operation,
				family,
				defaultDynamic,
			)
		}
	}
	addOperation(
		sysnet.TargetDefaultTun,
		sysnet.OpSetMTU,
		sysnet.FamilyNone,
		defaultDynamic,
	)
	addOperation(
		sysnet.TargetDefaultTun,
		sysnet.OpRename,
		sysnet.FamilyNone,
		combineConfigured(defaultDynamic, !s.DisableDefaultTunNames),
	)
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSProvider,
			family,
			defaultCreate,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSConfigure,
			family,
			defaultCreate,
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSPort53Exclusive,
			family,
			unsupportedCapability(sysnet.ReasonNotImplemented),
		)
		addOperation(
			sysnet.TargetDefaultTun,
			sysnet.OpDNSSystemExclusive,
			family,
			unsupportedCapability(sysnet.ReasonNotImplemented),
		)
	}

	for _, target := range []sysnet.Target{sysnet.TargetOutNet, sysnet.TargetLocalNet} {
		for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
			networkOperations := []sysnet.Operation{
				sysnet.OpDialTCP,
				sysnet.OpDialUDP,
				sysnet.OpPacketDialUDP,
				sysnet.OpListenTCP,
				sysnet.OpListenUDP,
				sysnet.OpListenPacketUDP,
				sysnet.OpMulticastUDP,
			}
			for _, operation := range networkOperations {
				addOperation(target, operation, family, available)
			}
		}
		addOperation(target, sysnet.OpResolve, sysnet.FamilyNone, available)
		addOperation(target, sysnet.OpInterfaces, sysnet.FamilyNone, available)
	}
	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6} {
		addOperation(sysnet.TargetOutDNS, sysnet.OpQueryUDP, family, available)
		addOperation(sysnet.TargetOutDNS, sysnet.OpQueryTCP, family, available)
	}

	rules := s.Rules
	if rules == nil {
		rules = DefaultRules
	}
	report.Rules = make([]sysnet.RuleCapability, len(rules))
	matcherKeys := []sysnet.MatcherProfileKey{
		{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportTCP},
		{Family: sysnet.FamilyIPv4, Transport: sysnet.TransportUDP},
		{Family: sysnet.FamilyIPv6, Transport: sysnet.TransportTCP},
		{Family: sysnet.FamilyIPv6, Transport: sysnet.TransportUDP},
	}
	for i, rule := range rules {
		rule.Validation = available
		rule.Completion = available
		rule.Matchers = make([]sysnet.MatcherProfile, len(matcherKeys))
		for j, key := range matcherKeys {
			rule.Matchers[j] = sysnet.MatcherProfile{
				Key:        key,
				Capability: available,
				Quality:    sysnet.MatchQualityBestEffortTuple,
			}
		}
		report.Rules[i] = rule
	}

	for _, family := range []sysnet.AddressFamily{sysnet.FamilyIPv4, sysnet.FamilyIPv6, sysnet.FamilyDual} {
		for _, mode := range []sysnet.RoutingMode{sysnet.RoutingFull, sysnet.RoutingExclude, sysnet.RoutingInclude} {
			for _, strict := range []bool{false, true} {
				capability := defaultCreate
				if strict {
					capability = combineConfigured(
						capability,
						!s.DisableStrictMode,
					)
				}
				profile := sysnet.DefaultTunProfile{
					Key: sysnet.RoutingProfileKey{
						Family: family,
						Mode:   mode,
						Strict: strict,
					},
					Capability: capability,
				}
				if mode != sysnet.RoutingFull {
					for _, rule := range report.Rules {
						profile.Rules = append(
							profile.Rules,
							sysnet.RuleBinding{
								Type:       rule.Type,
								Capability: capability,
							},
						)
					}
					if capability.State == sysnet.CapabilityAvailable &&
						len(profile.Rules) == 0 {
						profile.Capability = unsupportedCapability(
							sysnet.ReasonNotImplemented,
						)
					}
				}
				report.DefaultTunProfiles = append(
					report.DefaultTunProfiles,
					profile,
				)
			}
		}
	}

	for _, key := range matcherKeys {
		report.Ownership = append(report.Ownership, sysnet.OwnerCapability{
			Key:        key,
			Capability: available,
			Quality:    sysnet.MatchQualityBestEffortTuple,
			Fields: []sysnet.OwnerFieldCapability{
				{Field: sysnet.OwnerPID, Capability: available},
				{Field: sysnet.OwnerProcessName, Capability: available},
				{Field: sysnet.OwnerExecutablePath, Capability: available},
				{Field: sysnet.OwnerUID, Capability: available},
				{Field: sysnet.OwnerGID, Capability: available},
				{
					Field: sysnet.OwnerUserSID,
					Capability: unsupportedCapability(
						sysnet.ReasonNotImplemented,
					),
				},
			},
		})
	}
	return report
}

func configuredCapability(enabled bool) sysnet.Capability {
	if enabled {
		return sysnet.Capability{State: sysnet.CapabilityAvailable}
	}
	return unsupportedCapability(sysnet.ReasonDisabledByConfig)
}

func combineConfigured(base sysnet.Capability, enabled bool) sysnet.Capability {
	if base.State != sysnet.CapabilityAvailable {
		return base
	}
	return configuredCapability(enabled)
}

func unsupportedCapability(reason sysnet.CapabilityReason) sysnet.Capability {
	return sysnet.Capability{
		State:   sysnet.CapabilityUnsupported,
		Reasons: []sysnet.CapabilityReason{reason},
	}
}

func sameCapabilityContents(left, right sysnet.CapabilityReport) bool {
	left.Revision = 0
	right.Revision = 0
	return reflect.DeepEqual(left, right)
}

func markReportClosed(report *sysnet.CapabilityReport) {
	closed := func(capability *sysnet.Capability) {
		if capability.State == sysnet.CapabilityUnsupported {
			return
		}
		*capability = sysnet.Capability{
			State:   sysnet.CapabilityUnavailable,
			Reasons: []sysnet.CapabilityReason{sysnet.ReasonSystemClosed},
		}
	}
	for i := range report.Operations {
		closed(&report.Operations[i].Capability)
	}
	for i := range report.DefaultTunProfiles {
		closed(&report.DefaultTunProfiles[i].Capability)
		for j := range report.DefaultTunProfiles[i].Rules {
			closed(&report.DefaultTunProfiles[i].Rules[j].Capability)
		}
	}
	for i := range report.Rules {
		closed(&report.Rules[i].Validation)
		closed(&report.Rules[i].Completion)
		for j := range report.Rules[i].Matchers {
			closed(&report.Rules[i].Matchers[j].Capability)
		}
	}
	for i := range report.Ownership {
		closed(&report.Ownership[i].Capability)
		for j := range report.Ownership[i].Fields {
			closed(&report.Ownership[i].Fields[j].Capability)
		}
	}
}

// CheckTunOpts validates opts without creating or changing a TUN.
func (s *System) CheckTunOpts(opts sysnet.TunOpts) sysnet.ValidationReport {
	opts = opts.Copy()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkTunOptsLocked(opts)
}

func (s *System) checkTunOptsLocked(
	opts sysnet.TunOpts,
) sysnet.ValidationReport {
	report := s.capabilityReportLocked()
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	family, issues := optionFamily(opts.TunAddrs, opts.TunRoutes)
	result.Issues = append(result.Issues, issues...)
	operation := sysnet.OpCreate
	if opts.Name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(
		&result,
		"",
		report.Operation(
			sysnet.OperationKey{
				Target:    sysnet.TargetTun,
				Operation: operation,
				Family:    family,
			},
		),
	)
	if opts.Name != "" {
		if valid, free := s.tunNameVerifyLocked(opts.Name); !valid || !free {
			result.Issues = append(
				result.Issues,
				invalidIssue(
					"Name",
					"TUN name is invalid or already in use",
					nil,
				),
			)
		}
	}
	if s.CheckTunOptsHook != nil {
		hookReport := s.CheckTunOptsHook(opts.Copy())
		result.Issues = append(result.Issues, hookReport.Clone().Issues...)
	}
	return result
}

// CheckDefaultTunOpts validates opts without creating or changing a TUN.
func (s *System) CheckDefaultTunOpts(
	opts sysnet.DefaultTunOpts,
) sysnet.ValidationReport {
	opts = opts.Copy()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkDefaultTunOptsLocked(opts)
}

func (s *System) checkDefaultTunOptsLocked(
	opts sysnet.DefaultTunOpts,
) sysnet.ValidationReport {
	report := s.capabilityReportLocked()
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	if len(opts.Exclude) != 0 && len(opts.Include) != 0 {
		result.Issues = append(
			result.Issues,
			invalidIssue(
				"Include",
				"Include and Exclude are mutually exclusive",
				nil,
			),
		)
	}
	family, issues := optionFamily(opts.TunAddrs, opts.TunRoutes)
	if family == sysnet.FamilyNone {
		family = sysnet.FamilyIPv4
	}
	result.Issues = append(result.Issues, issues...)
	operation := sysnet.OpCreate
	if opts.Name != "" {
		operation = sysnet.OpCreateNamed
	}
	appendCapabilityIssue(
		&result,
		"",
		report.Operation(
			sysnet.OperationKey{
				Target:    sysnet.TargetDefaultTun,
				Operation: operation,
				Family:    family,
			},
		),
	)
	mode := sysnet.RoutingFull
	rules := opts.Exclude
	path := "Exclude"
	if len(opts.Exclude) != 0 {
		mode = sysnet.RoutingExclude
	} else if len(opts.Include) != 0 {
		mode = sysnet.RoutingInclude
		rules = opts.Include
		path = "Include"
	}
	profileKey := sysnet.RoutingProfileKey{
		Family: family,
		Mode:   mode,
		Strict: opts.Strict,
	}
	profile := report.DefaultTunProfile(profileKey)
	appendCapabilityIssue(&result, "", profile.Capability)
	for i, rule := range rules {
		context := sysnet.RuleContext{Routing: &profileKey}
		ruleReport := s.checkRuleLocked(rule, context)
		for _, issue := range ruleReport.Issues {
			if issue.Path == "" {
				issue.Path = fmt.Sprintf("%s[%d]", path, i)
			} else {
				issue.Path = fmt.Sprintf("%s[%d].%s", path, i, issue.Path)
			}
			result.Issues = append(result.Issues, issue)
		}
	}
	if len(opts.SourceRoutes) != 0 {
		appendCapabilityIssue(
			&result,
			"SourceRoutes",
			report.Operation(
				sysnet.OperationKey{
					Target:    sysnet.TargetDefaultTun,
					Operation: sysnet.OpSourceRoutes,
					Family:    family,
				},
			),
		)
		result.Issues = append(
			result.Issues,
			sourceRouteIssues(opts.TunAddrs, opts.SourceRoutes)...)
	}
	if opts.Name != "" {
		valid, free := s.tunNameVerifyLocked(opts.Name)
		if s.defaultTun == opts.Name {
			free = true
		}
		if !valid || !free {
			result.Issues = append(
				result.Issues,
				invalidIssue(
					"Name",
					"TUN name is invalid or already in use",
					nil,
				),
			)
		}
	}
	if s.CheckDefaultTunOptsHook != nil {
		hookOpts := opts.Copy()
		if normalized, err := normalizeSourceRoutes(
			hookOpts.TunAddrs,
			hookOpts.SourceRoutes,
		); err == nil {
			hookOpts.SourceRoutes = normalized
		}
		hookReport := s.CheckDefaultTunOptsHook(hookOpts)
		result.Issues = append(result.Issues, hookReport.Clone().Issues...)
	}
	return result
}

// CheckRule validates a rule in one exact use context.
func (s *System) CheckRule(
	rule sysnet.Rule,
	context sysnet.RuleContext,
) sysnet.ValidationReport {
	context = context.Clone()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkRuleLocked(rule, context)
}

func (s *System) checkRuleLocked(
	rule sysnet.Rule,
	context sysnet.RuleContext,
) sysnet.ValidationReport {
	report := s.capabilityReportLocked()
	result := sysnet.ValidationReport{CapabilityRevision: report.Revision}
	if (context.Routing == nil) == (context.Matcher == nil) {
		result.Issues = append(
			result.Issues,
			invalidIssue(
				"Context",
				"exactly one rule context must be set",
				nil,
			),
		)
		return result
	}
	if rule.Type == "" {
		result.Issues = append(
			result.Issues,
			invalidIssue("Type", "rule type is empty", nil),
		)
		return result
	}
	ruleCapability := report.Rule(rule.Type)
	appendCapabilityIssue(&result, "Type", ruleCapability.Validation)
	if context.Routing != nil {
		profile := report.DefaultTunProfile(*context.Routing)
		appendCapabilityIssue(&result, "Context", profile.Capability)
		binding := sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, candidate := range profile.Rules {
			if candidate.Type == rule.Type {
				binding = candidate.Capability
				break
			}
		}
		appendCapabilityIssue(&result, "Type", binding)
	} else {
		matcher := sysnet.Capability{State: sysnet.CapabilityUnknown}
		for _, candidate := range ruleCapability.Matchers {
			if candidate.Key == *context.Matcher {
				matcher = candidate.Capability
				break
			}
		}
		appendCapabilityIssue(&result, "Context", matcher)
	}
	if s.CheckRuleHook != nil {
		hookReport := s.CheckRuleHook(rule, context.Clone())
		result.Issues = append(result.Issues, hookReport.Clone().Issues...)
	}
	return result
}

// CompleteRule returns completion suggestions for one exact use context.
func (s *System) CompleteRule(
	rule sysnet.Rule,
	context sysnet.RuleContext,
) ([]string, error) {
	context = context.Clone()
	s.mu.Lock()
	defer s.mu.Unlock()
	report := s.capabilityReportLocked()
	if issue := contextCapabilityIssue(
		report,
		rule.Type,
		context,
		true,
	); issue != nil {
		validation := sysnet.ValidationReport{
			CapabilityRevision: report.Revision,
			Issues:             []sysnet.ValidationIssue{*issue},
		}
		return nil, validation.Err()
	}
	if s.CompleteRuleHook != nil {
		values, err := s.CompleteRuleHook(rule, context)
		return copySlice(values), err
	}
	return nil, nil
}

func contextCapabilityIssue(
	report sysnet.CapabilityReport,
	ruleType string,
	context sysnet.RuleContext,
	completion bool,
) *sysnet.ValidationIssue {
	if (context.Routing == nil) == (context.Matcher == nil) {
		issue := invalidIssue(
			"Context",
			"exactly one rule context must be set",
			nil,
		)
		return &issue
	}
	rule := report.Rule(ruleType)
	capability := rule.Validation
	if completion {
		capability = rule.Completion
	}
	if issue := issueForCapability("Type", capability); issue != nil {
		return issue
	}
	if context.Routing != nil {
		profile := report.DefaultTunProfile(*context.Routing)
		if issue := issueForCapability(
			"Context",
			profile.Capability,
		); issue != nil {
			return issue
		}
		for _, binding := range profile.Rules {
			if binding.Type == ruleType {
				return issueForCapability("Type", binding.Capability)
			}
		}
		return issueForCapability(
			"Type",
			sysnet.Capability{State: sysnet.CapabilityUnknown},
		)
	}
	for _, matcher := range rule.Matchers {
		if matcher.Key == *context.Matcher {
			return issueForCapability("Context", matcher.Capability)
		}
	}
	return issueForCapability(
		"Context",
		sysnet.Capability{State: sysnet.CapabilityUnknown},
	)
}

func optionFamily(
	addrs, routes []string,
) (sysnet.AddressFamily, []sysnet.ValidationIssue) {
	has4, has6 := false, false
	issues := make([]sysnet.ValidationIssue, 0)
	parse := func(path string, values []string) {
		for i, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				issues = append(
					issues,
					invalidIssue(
						fmt.Sprintf("%s[%d]", path, i),
						"invalid IP prefix",
						err,
					),
				)
				continue
			}
			if prefix.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
	}
	parse("TunAddrs", addrs)
	parse("TunRoutes", routes)
	switch {
	case has4 && has6:
		return sysnet.FamilyDual, issues
	case has4:
		return sysnet.FamilyIPv4, issues
	case has6:
		return sysnet.FamilyIPv6, issues
	default:
		return sysnet.FamilyNone, issues
	}
}

func sourceRouteIssues(
	addrs []string,
	routes []sysnet.TunSourceRoute,
) []sysnet.ValidationIssue {
	assigned := make(map[netip.Addr]struct{}, len(addrs))
	for _, value := range addrs {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			assigned[prefix.Addr()] = struct{}{}
		}
	}
	seen := make(map[netip.Prefix]netip.Addr, len(routes))
	var issues []sysnet.ValidationIssue
	for i, route := range routes {
		base := fmt.Sprintf("SourceRoutes[%d]", i)
		if !route.Destination.IsValid() {
			issues = append(
				issues,
				invalidIssue(
					base+".Destination",
					"invalid destination prefix",
					nil,
				),
			)
			continue
		}
		if !validSourceRouteAddr(route.Source) {
			issues = append(
				issues,
				invalidIssue(base+".Source", "invalid source address", nil),
			)
			continue
		}
		if route.Destination.Addr().Is4() != route.Source.Is4() {
			issues = append(
				issues,
				invalidIssue(
					base+".Source",
					"destination and source use different address families",
					nil,
				),
			)
		}
		if _, exists := assigned[route.Source]; !exists {
			issues = append(
				issues,
				invalidIssue(
					base+".Source",
					"source address is not assigned to the TUN",
					nil,
				),
			)
		}
		masked := route.Destination.Masked()
		if previous, exists := seen[masked]; exists &&
			previous != route.Source {
			issues = append(
				issues,
				invalidIssue(
					base+".Destination",
					"destination has conflicting sources",
					nil,
				),
			)
		} else {
			seen[masked] = route.Source
		}
	}
	return issues
}

func appendCapabilityIssue(
	report *sysnet.ValidationReport,
	path string,
	capability sysnet.Capability,
) {
	if issue := issueForCapability(path, capability); issue != nil {
		report.Issues = append(report.Issues, *issue)
	}
}

func issueForCapability(
	path string,
	capability sysnet.Capability,
) *sysnet.ValidationIssue {
	if capability.State == sysnet.CapabilityAvailable {
		return nil
	}
	issue := sysnet.ValidationIssue{
		Path:   path,
		State:  capability.State,
		Detail: capability.Detail,
	}
	if len(capability.Reasons) != 0 {
		issue.Reason = capability.Reasons[0]
	}
	return &issue
}

func invalidIssue(path, detail string, cause error) sysnet.ValidationIssue {
	if cause == nil {
		cause = sysnet.ErrInvalidOptions
	} else if !errors.Is(cause, sysnet.ErrInvalidOptions) {
		cause = errors.Join(sysnet.ErrInvalidOptions, cause)
	}
	return sysnet.ValidationIssue{
		Path:   path,
		State:  sysnet.CapabilityUnknown,
		Detail: detail,
		Err:    cause,
	}
}

func validationErrorForBuild(report sysnet.ValidationReport) error {
	filtered := sysnet.ValidationReport{
		CapabilityRevision: report.CapabilityRevision,
	}
	for _, issue := range report.Issues {
		if issue.State == sysnet.CapabilityUnknown &&
			!errors.Is(issue.Err, sysnet.ErrInvalidOptions) {
			continue
		}
		filtered.Issues = append(filtered.Issues, issue)
	}
	return filtered.Err()
}

func (s *System) operationErrorLocked(
	entry *tunEntry,
	key sysnet.OperationKey,
) error {
	capability := sysnet.Capability{State: sysnet.CapabilityUnknown}
	if entry.operationsSet {
		for _, operation := range entry.operations {
			if operation.Key == key {
				capability = operation.Capability
				break
			}
		}
	} else {
		capability = s.capabilityReportLocked().Operation(key)
	}
	if capability.State == sysnet.CapabilityAvailable ||
		capability.State == sysnet.CapabilityUnknown {
		return nil
	}
	report := sysnet.ValidationReport{}
	appendCapabilityIssue(&report, "", capability)
	return report.Err()
}

func (s *System) tunOperationsLocked(
	entry *tunEntry,
	report sysnet.CapabilityReport,
) []sysnet.OperationCapability {
	if entry.operationsSet {
		return sysnet.TunCapabilityReport{
			Operations: entry.operations,
		}.Clone().Operations
	}
	var operations []sysnet.OperationCapability
	for _, operation := range report.Operations {
		if operation.Key.Target == entry.target() &&
			isInstanceOperation(operation.Key.Operation) {
			operations = append(operations, operation)
		}
	}
	return sysnet.TunCapabilityReport{Operations: operations}.Clone().Operations
}

func isInstanceOperation(operation sysnet.Operation) bool {
	return operation != sysnet.OpCreate && operation != sysnet.OpCreateNamed
}

func (entry *tunEntry) target() sysnet.Target {
	if entry.defaultTun {
		return sysnet.TargetDefaultTun
	}
	return sysnet.TargetTun
}

func configFamily(config TunConfig) sysnet.AddressFamily {
	family, _ := optionFamily(config.TunAddrs, config.TunRoutes)
	if family == sysnet.FamilyNone {
		return sysnet.FamilyIPv4
	}
	return family
}

func issuesOrInvalid(
	issues []sysnet.ValidationIssue,
	detail string,
) []sysnet.ValidationIssue {
	if len(issues) != 0 {
		return issues
	}
	return []sysnet.ValidationIssue{invalidIssue("", detail, nil)}
}
