package sysnet

import (
	"errors"
	"fmt"
)

// CapabilitySchemaVersion is the schema version used by CapabilityReport.
const CapabilitySchemaVersion uint32 = 1

// CapabilityState describes whether a capability can be used on the current
// host. The zero value is intentionally unknown.
type CapabilityState uint8

const (
	CapabilityUnknown CapabilityState = iota
	CapabilityUnsupported
	CapabilityUnavailable
	CapabilityAvailable
)

// CapabilityReason is a stable, localizable reason code.
type CapabilityReason string

// LimitationID identifies a documented limitation that does not weaken the
// named behavior.
type LimitationID string

const (
	ReasonNotImplemented           CapabilityReason = "not_implemented"
	ReasonUnsupportedPlatform      CapabilityReason = "unsupported_platform"
	ReasonUnsupportedCombination   CapabilityReason = "unsupported_combination"
	ReasonDisabledByConfig         CapabilityReason = "disabled_by_config"
	ReasonMissingDependency        CapabilityReason = "missing_dependency"
	ReasonDependencyIncompatible   CapabilityReason = "dependency_incompatible"
	ReasonPermissionDenied         CapabilityReason = "permission_denied"
	ReasonResourceBusy             CapabilityReason = "resource_busy"
	ReasonNoUnderlay               CapabilityReason = "no_underlay"
	ReasonAddressFamilyUnavailable CapabilityReason = "address_family_unavailable"
	ReasonRecoveryRequired         CapabilityReason = "recovery_required"
	ReasonSystemClosed             CapabilityReason = "system_closed"
	ReasonProbeNotRun              CapabilityReason = "probe_not_run"
	ReasonProbeFailed              CapabilityReason = "probe_failed"
)

// Capability describes one exact behavior and scope.
type Capability struct {
	State       CapabilityState
	Reasons     []CapabilityReason
	Detail      string
	Limitations []LimitationID
}

// Clone returns an independent copy of c.
func (c Capability) Clone() Capability {
	c.Reasons = cloneSlice(c.Reasons)
	c.Limitations = cloneSlice(c.Limitations)
	return c
}

type Target string
type Operation string
type AddressFamily string
type RoutingMode string
type Transport string
type MatchQuality string
type RuleValueKind string
type OwnerField string

const (
	TargetSystem     Target = "system"
	TargetTun        Target = "tun"
	TargetDefaultTun Target = "default_tun"
	TargetOutNet     Target = "out_net"
	TargetLocalNet   Target = "local_net"
	TargetOutDNS     Target = "out_dns"
)

const (
	OpAllocateIP         Operation = "allocate_ip"
	OpAllocateSubnet     Operation = "allocate_subnet"
	OpCreate             Operation = "create"
	OpCreateNamed        Operation = "create_named"
	OpSetMTU             Operation = "set_mtu"
	OpRename             Operation = "rename"
	OpSetAddresses       Operation = "set_addresses"
	OpAddAddress         Operation = "add_address"
	OpGetAddresses       Operation = "get_addresses"
	OpSetRoutes          Operation = "set_routes"
	OpAddRoute           Operation = "add_route"
	OpGetRoutes          Operation = "get_routes"
	OpReconfigureInPlace Operation = "reconfigure_in_place"
	OpSourceRoutes       Operation = "source_routes"
	OpDNSProvider        Operation = "dns_provider"
	OpDNSConfigure       Operation = "dns_configure"
	OpDNSPort53Exclusive Operation = "dns_port53_exclusive"
	OpDNSSystemExclusive Operation = "dns_system_exclusive"
	OpDialTCP            Operation = "dial_tcp"
	OpDialUDP            Operation = "dial_udp"
	OpPacketDialUDP      Operation = "packet_dial_udp"
	OpListenTCP          Operation = "listen_tcp"
	OpListenUDP          Operation = "listen_udp"
	OpListenPacketUDP    Operation = "listen_packet_udp"
	OpMulticastUDP       Operation = "multicast_udp"
	OpResolve            Operation = "resolve"
	OpInterfaces         Operation = "interfaces"
	OpQueryUDP           Operation = "query_udp"
	OpQueryTCP           Operation = "query_tcp"
)

const (
	FamilyNone AddressFamily = "none"
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
	FamilyDual AddressFamily = "dual"
)

const (
	RoutingFull    RoutingMode = "full"
	RoutingExclude RoutingMode = "exclude"
	RoutingInclude RoutingMode = "include"
)

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

const (
	MatchQualityUnknown                 MatchQuality = "unknown"
	MatchQualityBestEffortTuple         MatchQuality = "best_effort_tuple"
	MatchQualityBestEffortLocalEndpoint MatchQuality = "best_effort_local_endpoint"
)

const (
	RuleValuePath   RuleValueKind = "path"
	RuleValuePID    RuleValueKind = "pid"
	RuleValueName   RuleValueKind = "name"
	RuleValueRegex  RuleValueKind = "regex"
	RuleValueOpaque RuleValueKind = "opaque"
)

// Alternate names keep the OwnerField and RuleValueKind type names visible at
// call sites.
const (
	RuleValueKindPath   = RuleValuePath
	RuleValueKindPID    = RuleValuePID
	RuleValueKindName   = RuleValueName
	RuleValueKindRegex  = RuleValueRegex
	RuleValueKindOpaque = RuleValueOpaque
)

const (
	OwnerPID            OwnerField = "pid"
	OwnerProcessName    OwnerField = "process_name"
	OwnerExecutablePath OwnerField = "executable_path"
	OwnerUID            OwnerField = "uid"
	OwnerGID            OwnerField = "gid"
	OwnerUserSID        OwnerField = "user_sid"
)

const (
	OwnerFieldPID            = OwnerPID
	OwnerFieldProcessName    = OwnerProcessName
	OwnerFieldExecutablePath = OwnerExecutablePath
	OwnerFieldUID            = OwnerUID
	OwnerFieldGID            = OwnerGID
	OwnerFieldUserSID        = OwnerUserSID
)

type OperationKey struct {
	Target    Target
	Operation Operation
	Family    AddressFamily
}

type OperationCapability struct {
	Key OperationKey
	Capability
}

type RoutingProfileKey struct {
	Family AddressFamily
	Mode   RoutingMode
	Strict bool
}

type RuleBinding struct {
	Type string
	Capability
}

type DefaultTunProfile struct {
	Key RoutingProfileKey
	Capability
	Rules []RuleBinding
}

type MatcherProfileKey struct {
	Family    AddressFamily
	Transport Transport
}

type MatcherProfile struct {
	Key MatcherProfileKey
	Capability
	Quality MatchQuality
}

type RuleCapability struct {
	Type        string
	Description string
	ValueKind   RuleValueKind
	SemanticsID string
	Validation  Capability
	Completion  Capability
	Matchers    []MatcherProfile
}

type OwnerFieldCapability struct {
	Field OwnerField
	Capability
}

type OwnerCapability struct {
	Key MatcherProfileKey
	Capability
	Quality MatchQuality
	Fields  []OwnerFieldCapability
}

type CapabilityReport struct {
	SchemaVersion      uint32
	Revision           uint64
	Operations         []OperationCapability
	DefaultTunProfiles []DefaultTunProfile
	Rules              []RuleCapability
	Ownership          []OwnerCapability
}

type TunCapabilityReport struct {
	SystemRevision   uint64
	InstanceRevision uint64
	Operations       []OperationCapability
}

// Clone returns a deep copy of r.
func (r CapabilityReport) Clone() CapabilityReport {
	clone := r
	clone.Operations = cloneSlice(r.Operations)
	for i, operation := range r.Operations {
		operation.Capability = operation.Clone()
		clone.Operations[i] = operation
	}
	clone.DefaultTunProfiles = cloneSlice(r.DefaultTunProfiles)
	for i, profile := range r.DefaultTunProfiles {
		profile.Capability = profile.Clone()
		profile.Rules = cloneSlice(profile.Rules)
		for j, rule := range r.DefaultTunProfiles[i].Rules {
			rule.Capability = rule.Clone()
			profile.Rules[j] = rule
		}
		clone.DefaultTunProfiles[i] = profile
	}
	clone.Rules = cloneSlice(r.Rules)
	for i, rule := range r.Rules {
		rule.Validation = rule.Validation.Clone()
		rule.Completion = rule.Completion.Clone()
		rule.Matchers = cloneSlice(rule.Matchers)
		for j, matcher := range r.Rules[i].Matchers {
			matcher.Capability = matcher.Clone()
			rule.Matchers[j] = matcher
		}
		clone.Rules[i] = rule
	}
	clone.Ownership = cloneSlice(r.Ownership)
	for i, owner := range r.Ownership {
		owner.Capability = owner.Clone()
		owner.Fields = cloneSlice(owner.Fields)
		for j, field := range r.Ownership[i].Fields {
			field.Capability = field.Clone()
			owner.Fields[j] = field
		}
		clone.Ownership[i] = owner
	}
	return clone
}

// Clone returns a deep copy of r.
func (r TunCapabilityReport) Clone() TunCapabilityReport {
	clone := r
	clone.Operations = cloneSlice(r.Operations)
	for i, operation := range r.Operations {
		operation.Capability = operation.Clone()
		clone.Operations[i] = operation
	}
	return clone
}

// Validate checks per-TUN report consistency.
func (r TunCapabilityReport) Validate() error {
	operations := make(map[OperationKey]struct{}, len(r.Operations))
	for i, operation := range r.Operations {
		if operation.Key.Target == "" || operation.Key.Operation == "" ||
			operation.Key.Family == "" {
			return invalidReport("Operations[%d] has an empty key field", i)
		}
		if _, exists := operations[operation.Key]; exists {
			return invalidReport(
				"Operations[%d] duplicates key %+v",
				i,
				operation.Key,
			)
		}
		operations[operation.Key] = struct{}{}
		if err := validateCapability(operation.Capability); err != nil {
			return invalidReport("Operations[%d]: %v", i, err)
		}
	}
	return nil
}

// ValidateTunCapabilityReport checks per-TUN report consistency.
func ValidateTunCapabilityReport(
	r TunCapabilityReport,
) error {
	return r.Validate()
}

// Operation returns the exact operation capability. A missing key is unknown.
func (r CapabilityReport) Operation(key OperationKey) Capability {
	for _, operation := range r.Operations {
		if operation.Key == key {
			return operation.Clone()
		}
	}
	return Capability{State: CapabilityUnknown}
}

// Operation returns the exact per-TUN operation capability. A missing key is
// unknown.
func (r TunCapabilityReport) Operation(key OperationKey) Capability {
	for _, operation := range r.Operations {
		if operation.Key == key {
			return operation.Clone()
		}
	}
	return Capability{State: CapabilityUnknown}
}

// DefaultTunProfile returns the exact routing profile. A missing key is
// unknown.
func (r CapabilityReport) DefaultTunProfile(
	key RoutingProfileKey,
) DefaultTunProfile {
	for _, profile := range r.DefaultTunProfiles {
		if profile.Key == key {
			clone := CapabilityReport{
				DefaultTunProfiles: []DefaultTunProfile{profile},
			}.Clone()
			return clone.DefaultTunProfiles[0]
		}
	}
	return DefaultTunProfile{
		Key:        key,
		Capability: Capability{State: CapabilityUnknown},
	}
}

// Rule returns the rule catalog entry. A missing type is unknown.
func (r CapabilityReport) Rule(ruleType string) RuleCapability {
	for _, rule := range r.Rules {
		if rule.Type == ruleType {
			clone := CapabilityReport{Rules: []RuleCapability{rule}}.Clone()
			return clone.Rules[0]
		}
	}
	return RuleCapability{
		Type:       ruleType,
		Validation: Capability{State: CapabilityUnknown},
		Completion: Capability{State: CapabilityUnknown},
	}
}

// ErrInvalidCapabilityReport identifies an inconsistent capability report.
var ErrInvalidCapabilityReport = errors.New("invalid capability report")

// Validate checks report consistency. Extension key values are accepted.
func (r CapabilityReport) Validate() error {
	if r.SchemaVersion != CapabilitySchemaVersion {
		return invalidReport(
			"schema version is %d, want %d",
			r.SchemaVersion,
			CapabilitySchemaVersion,
		)
	}
	catalogRules := make(map[string]struct{}, len(r.Rules))
	for _, rule := range r.Rules {
		catalogRules[rule.Type] = struct{}{}
	}
	operations := make(map[OperationKey]struct{}, len(r.Operations))
	for i, operation := range r.Operations {
		if operation.Key.Target == "" || operation.Key.Operation == "" ||
			operation.Key.Family == "" {
			return invalidReport("Operations[%d] has an empty key field", i)
		}
		if _, exists := operations[operation.Key]; exists {
			return invalidReport(
				"Operations[%d] duplicates key %+v",
				i,
				operation.Key,
			)
		}
		operations[operation.Key] = struct{}{}
		if err := validateCapability(operation.Capability); err != nil {
			return invalidReport("Operations[%d]: %v", i, err)
		}
	}
	profiles := make(map[RoutingProfileKey]struct{}, len(r.DefaultTunProfiles))
	for i, profile := range r.DefaultTunProfiles {
		if profile.Key.Family == "" || profile.Key.Mode == "" {
			return invalidReport(
				"DefaultTunProfiles[%d] has an empty key field",
				i,
			)
		}
		if _, exists := profiles[profile.Key]; exists {
			return invalidReport(
				"DefaultTunProfiles[%d] duplicates key %+v",
				i,
				profile.Key,
			)
		}
		profiles[profile.Key] = struct{}{}
		if err := validateCapability(profile.Capability); err != nil {
			return invalidReport("DefaultTunProfiles[%d]: %v", i, err)
		}
		if profile.Key.Mode == RoutingFull && len(profile.Rules) != 0 {
			return invalidReport(
				"DefaultTunProfiles[%d] full profile has rules",
				i,
			)
		}
		bindings := make(map[string]struct{}, len(profile.Rules))
		availableBinding := false
		for j, binding := range profile.Rules {
			if binding.Type == "" {
				return invalidReport(
					"DefaultTunProfiles[%d].Rules[%d] has an empty type",
					i,
					j,
				)
			}
			if _, exists := bindings[binding.Type]; exists {
				return invalidReport(
					"DefaultTunProfiles[%d].Rules[%d] duplicates type %q",
					i,
					j,
					binding.Type,
				)
			}
			bindings[binding.Type] = struct{}{}
			if _, exists := catalogRules[binding.Type]; !exists {
				return invalidReport(
					"DefaultTunProfiles[%d].Rules[%d] references unknown rule type %q",
					i,
					j,
					binding.Type,
				)
			}
			if err := validateCapability(binding.Capability); err != nil {
				return invalidReport(
					"DefaultTunProfiles[%d].Rules[%d]: %v",
					i,
					j,
					err,
				)
			}
			availableBinding = availableBinding ||
				binding.State == CapabilityAvailable
		}
		if profile.State == CapabilityAvailable &&
			profile.Key.Mode != RoutingFull &&
			!availableBinding {
			return invalidReport(
				"DefaultTunProfiles[%d] is available without an available rule",
				i,
			)
		}
	}
	rules := make(map[string]struct{}, len(r.Rules))
	for i, rule := range r.Rules {
		if rule.Type == "" {
			return invalidReport("Rules[%d] has an empty type", i)
		}
		if _, exists := rules[rule.Type]; exists {
			return invalidReport("Rules[%d] duplicates type %q", i, rule.Type)
		}
		rules[rule.Type] = struct{}{}
		if err := validateCapability(rule.Validation); err != nil {
			return invalidReport("Rules[%d].Validation: %v", i, err)
		}
		if err := validateCapability(rule.Completion); err != nil {
			return invalidReport("Rules[%d].Completion: %v", i, err)
		}
		matchers := make(map[MatcherProfileKey]struct{}, len(rule.Matchers))
		for j, matcher := range rule.Matchers {
			if matcher.Key.Family == "" || matcher.Key.Transport == "" {
				return invalidReport(
					"Rules[%d].Matchers[%d] has an empty key field",
					i,
					j,
				)
			}
			if _, exists := matchers[matcher.Key]; exists {
				return invalidReport(
					"Rules[%d].Matchers[%d] duplicates key %+v",
					i,
					j,
					matcher.Key,
				)
			}
			matchers[matcher.Key] = struct{}{}
			if err := validateCapability(matcher.Capability); err != nil {
				return invalidReport("Rules[%d].Matchers[%d]: %v", i, j, err)
			}
		}
	}
	owners := make(map[MatcherProfileKey]struct{}, len(r.Ownership))
	for i, owner := range r.Ownership {
		if owner.Key.Family == "" || owner.Key.Transport == "" {
			return invalidReport("Ownership[%d] has an empty key field", i)
		}
		if _, exists := owners[owner.Key]; exists {
			return invalidReport(
				"Ownership[%d] duplicates key %+v",
				i,
				owner.Key,
			)
		}
		owners[owner.Key] = struct{}{}
		if err := validateCapability(owner.Capability); err != nil {
			return invalidReport("Ownership[%d]: %v", i, err)
		}
		fields := make(map[OwnerField]struct{}, len(owner.Fields))
		for j, field := range owner.Fields {
			if field.Field == "" {
				return invalidReport(
					"Ownership[%d].Fields[%d] has an empty field",
					i,
					j,
				)
			}
			if _, exists := fields[field.Field]; exists {
				return invalidReport(
					"Ownership[%d].Fields[%d] duplicates field %q",
					i,
					j,
					field.Field,
				)
			}
			fields[field.Field] = struct{}{}
			if err := validateCapability(field.Capability); err != nil {
				return invalidReport("Ownership[%d].Fields[%d]: %v", i, j, err)
			}
		}
	}
	return nil
}

// ValidateCapabilityReport checks report consistency.
func ValidateCapabilityReport(r CapabilityReport) error { return r.Validate() }

func validateCapability(capability Capability) error {
	if capability.State > CapabilityAvailable {
		return fmt.Errorf("invalid state %d", capability.State)
	}
	seenReasons := make(map[CapabilityReason]struct{}, len(capability.Reasons))
	for _, reason := range capability.Reasons {
		if reason == "" {
			return errors.New("empty reason")
		}
		if _, exists := seenReasons[reason]; exists {
			return fmt.Errorf("duplicate reason %q", reason)
		}
		seenReasons[reason] = struct{}{}
	}
	seenLimits := make(map[LimitationID]struct{}, len(capability.Limitations))
	for _, limitation := range capability.Limitations {
		if limitation == "" {
			return errors.New("empty limitation")
		}
		if _, exists := seenLimits[limitation]; exists {
			return fmt.Errorf("duplicate limitation %q", limitation)
		}
		seenLimits[limitation] = struct{}{}
	}
	return nil
}

func invalidReport(format string, args ...any) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidCapabilityReport,
		fmt.Sprintf(format, args...),
	)
}

func cloneSlice[T any](src []T) []T {
	if src == nil {
		return nil
	}
	return append([]T(nil), src...)
}
