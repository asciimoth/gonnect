//nolint:testpackage // These tests validate package-level error construction.
package sysnet

import (
	"errors"
	"reflect"
	"testing"
)

func TestCapabilityReportMissingLookupsAreUnknown(t *testing.T) {
	var report CapabilityReport
	if got := report.Operation(OperationKey{}); got.State != CapabilityUnknown {
		t.Fatalf("Operation() state = %v, want unknown", got.State)
	}
	profile := report.DefaultTunProfile(
		RoutingProfileKey{Family: FamilyIPv4, Mode: RoutingFull},
	)
	if profile.State != CapabilityUnknown {
		t.Fatalf("DefaultTunProfile() state = %v, want unknown", profile.State)
	}
	rule := report.Rule("future-rule")
	if rule.Validation.State != CapabilityUnknown ||
		rule.Completion.State != CapabilityUnknown {
		t.Fatalf("Rule() = %+v, want unknown validation and completion", rule)
	}
	if CapabilityState(255) == CapabilityAvailable {
		t.Fatal("future state became available")
	}
}

func TestCapabilityReportCloneAndLookupsAreIndependent(t *testing.T) {
	operationKey := OperationKey{
		Target:    TargetTun,
		Operation: OpCreate,
		Family:    FamilyIPv4,
	}
	profileKey := RoutingProfileKey{Family: FamilyIPv4, Mode: RoutingExclude}
	matcherKey := MatcherProfileKey{Family: FamilyIPv4, Transport: TransportTCP}
	report := CapabilityReport{
		SchemaVersion: CapabilitySchemaVersion,
		Revision:      9,
		Operations: []OperationCapability{{
			Key: operationKey,
			Capability: Capability{
				State:       CapabilityUnavailable,
				Reasons:     []CapabilityReason{ReasonResourceBusy},
				Limitations: []LimitationID{"test.limit"},
			},
		}},
		DefaultTunProfiles: []DefaultTunProfile{{
			Key:        profileKey,
			Capability: Capability{State: CapabilityAvailable},
			Rules: []RuleBinding{
				{
					Type: "uid",
					Capability: Capability{
						State:   CapabilityAvailable,
						Reasons: []CapabilityReason{"test.reason"},
					},
				},
			},
		}},
		Rules: []RuleCapability{{
			Type:       "uid",
			Validation: Capability{State: CapabilityAvailable},
			Completion: Capability{State: CapabilityAvailable},
			Matchers: []MatcherProfile{
				{
					Key:        matcherKey,
					Capability: Capability{State: CapabilityAvailable},
				},
			},
		}},
		Ownership: []OwnerCapability{{
			Key:        matcherKey,
			Capability: Capability{State: CapabilityAvailable},
			Fields: []OwnerFieldCapability{
				{
					Field:      OwnerUID,
					Capability: Capability{State: CapabilityAvailable},
				},
			},
		}},
	}

	clone := report.Clone()
	clone.Operations[0].Reasons[0] = ReasonProbeFailed
	clone.Operations[0].Limitations[0] = "changed"
	clone.DefaultTunProfiles[0].Rules[0].Type = "changed"
	clone.Rules[0].Matchers[0].State = CapabilityUnsupported
	clone.Ownership[0].Fields[0].Field = OwnerGID

	if report.Operations[0].Reasons[0] != ReasonResourceBusy ||
		report.Operations[0].Limitations[0] != "test.limit" ||
		report.DefaultTunProfiles[0].Rules[0].Type != "uid" ||
		report.Rules[0].Matchers[0].State != CapabilityAvailable ||
		report.Ownership[0].Fields[0].Field != OwnerUID {
		t.Fatalf("Clone() aliases source: %+v", report)
	}

	operation := report.Operation(operationKey)
	operation.Reasons[0] = ReasonProbeFailed
	profile := report.DefaultTunProfile(profileKey)
	profile.Rules[0].Type = "changed"
	rule := report.Rule("uid")
	rule.Matchers[0].State = CapabilityUnsupported
	if report.Operations[0].Reasons[0] != ReasonResourceBusy ||
		report.DefaultTunProfiles[0].Rules[0].Type != "uid" ||
		report.Rules[0].Matchers[0].State != CapabilityAvailable {
		t.Fatal("lookup result aliases report")
	}
}

func TestCapabilityReportValidateRejectsInconsistency(t *testing.T) {
	available := Capability{State: CapabilityAvailable}
	op := OperationCapability{
		Key: OperationKey{
			Target:    TargetTun,
			Operation: OpCreate,
			Family:    FamilyIPv4,
		},
		Capability: available,
	}
	profile := DefaultTunProfile{
		Key:        RoutingProfileKey{Family: FamilyIPv4, Mode: RoutingExclude},
		Capability: available,
		Rules:      []RuleBinding{{Type: "uid", Capability: available}},
	}
	rule := RuleCapability{
		Type:       "uid",
		Validation: available,
		Completion: available,
	}
	owner := OwnerCapability{
		Key: MatcherProfileKey{
			Family:    FamilyIPv4,
			Transport: TransportTCP,
		},
		Capability: available,
	}
	base := CapabilityReport{
		SchemaVersion:      CapabilitySchemaVersion,
		Operations:         []OperationCapability{op},
		DefaultTunProfiles: []DefaultTunProfile{profile},
		Rules:              []RuleCapability{rule},
		Ownership:          []OwnerCapability{owner},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Validate() valid report error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CapabilityReport)
	}{
		{
			name:   "schema",
			mutate: func(r *CapabilityReport) { r.SchemaVersion = 0 },
		},
		{
			name:   "operation duplicate",
			mutate: func(r *CapabilityReport) { r.Operations = append(r.Operations, r.Operations[0]) },
		},
		{name: "profile duplicate", mutate: func(r *CapabilityReport) {
			r.DefaultTunProfiles = append(
				r.DefaultTunProfiles,
				r.DefaultTunProfiles[0],
			)
		}},
		{name: "binding duplicate", mutate: func(r *CapabilityReport) {
			r.DefaultTunProfiles[0].Rules = append(
				r.DefaultTunProfiles[0].Rules,
				r.DefaultTunProfiles[0].Rules[0],
			)
		}},
		{
			name:   "binding without catalog rule",
			mutate: func(r *CapabilityReport) { r.DefaultTunProfiles[0].Rules[0].Type = "missing" },
		},
		{
			name:   "rule duplicate",
			mutate: func(r *CapabilityReport) { r.Rules = append(r.Rules, r.Rules[0]) },
		},
		{
			name:   "owner duplicate",
			mutate: func(r *CapabilityReport) { r.Ownership = append(r.Ownership, r.Ownership[0]) },
		},
		{
			name:   "future state",
			mutate: func(r *CapabilityReport) { r.Operations[0].State = CapabilityState(99) },
		},
		{name: "duplicate reason", mutate: func(r *CapabilityReport) {
			r.Operations[0].Reasons = []CapabilityReason{
				ReasonProbeFailed,
				ReasonProbeFailed,
			}
		}},
		{
			name:   "available selection without rule",
			mutate: func(r *CapabilityReport) { r.DefaultTunProfiles[0].Rules = nil },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := base.Clone()
			test.mutate(&report)
			if err := report.Validate(); !errors.Is(
				err,
				ErrInvalidCapabilityReport,
			) {
				t.Fatalf(
					"Validate() error = %v, want ErrInvalidCapabilityReport",
					err,
				)
			}
		})
	}
}

func TestTunCapabilityReportValidateAndClone(t *testing.T) {
	operation := OperationCapability{
		Key: OperationKey{
			Target:    TargetTun,
			Operation: OpRename,
			Family:    FamilyNone,
		},
		Capability: Capability{
			State:   CapabilityUnavailable,
			Reasons: []CapabilityReason{ReasonResourceBusy},
		},
	}
	report := TunCapabilityReport{
		SystemRevision:   2,
		InstanceRevision: 3,
		Operations:       []OperationCapability{operation},
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	clone := report.Clone()
	clone.Operations[0].Reasons[0] = ReasonProbeFailed
	if report.Operations[0].Reasons[0] != ReasonResourceBusy {
		t.Fatal("Clone() aliases source")
	}
	report.Operations = append(report.Operations, operation)
	if err := report.Validate(); !errors.Is(err, ErrInvalidCapabilityReport) {
		t.Fatalf("Validate() duplicate error = %v", err)
	}
}

func TestValidationReportErrPreservesCategoriesCausesAndIssues(t *testing.T) {
	native := errors.New("native failure")
	report := ValidationReport{Issues: []ValidationIssue{
		{
			Path:   "Exclude[0]",
			State:  CapabilityUnsupported,
			Reason: ReasonNotImplemented,
		},
		{
			Path:   "Driver",
			State:  CapabilityUnavailable,
			Reason: ReasonResourceBusy,
			Err:    native,
		},
		{Path: "Probe", State: CapabilityUnknown, Reason: ReasonProbeNotRun},
		{
			Path:   "TunAddrs[0]",
			State:  CapabilityUnknown,
			Detail: "bad prefix",
			Err:    ErrInvalidOptions,
		},
	}}
	err := report.Err()
	for _, target := range []error{ErrNotSupported, ErrUnavailable, ErrCapabilityUnknown, ErrInvalidOptions, native} {
		if !errors.Is(err, target) {
			t.Fatalf("errors.Is(%v) = false for %v", err, target)
		}
	}
	var typed *ValidationError
	if !errors.As(err, &typed) || typed.Issue.Path != "Exclude[0]" {
		t.Fatalf("errors.As() = %+v", typed)
	}
	if got := (ValidationReport{}).Err(); got != nil {
		t.Fatalf("empty report error = %v", got)
	}
	clone := report.Clone()
	clone.Issues[0].Path = "changed"
	if reflect.DeepEqual(clone, report) {
		t.Fatal("Clone() did not copy issues")
	}
}
