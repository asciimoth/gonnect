package sysnet

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUnavailable means that the backend implements the behavior, but a
	// known host condition blocks it.
	ErrUnavailable = errors.New("capability is unavailable")

	// ErrCapabilityUnknown means that the backend cannot establish whether the
	// behavior is currently available.
	ErrCapabilityUnknown = errors.New("capability availability is unknown")

	// ErrInvalidOptions means that input is structurally or syntactically
	// invalid.
	ErrInvalidOptions = errors.New("invalid options")
)

// RuleContext selects the exact use of a rule. Exactly one field must be set.
type RuleContext struct {
	Routing *RoutingProfileKey
	Matcher *MatcherProfileKey
}

// Clone returns an independent copy of c.
func (c RuleContext) Clone() RuleContext {
	clone := c
	if c.Routing != nil {
		key := *c.Routing
		clone.Routing = &key
	}
	if c.Matcher != nil {
		key := *c.Matcher
		clone.Matcher = &key
	}
	return clone
}

// ValidationIssue describes one blocking or indeterminate validation result.
type ValidationIssue struct {
	Path   string
	Reason CapabilityReason
	State  CapabilityState
	Detail string
	Err    error
}

// ValidationReport is an advisory validation result tied to one capability
// snapshot.
type ValidationReport struct {
	CapabilityRevision uint64
	Issues             []ValidationIssue
}

// Clone returns an independent copy of r. Error values are immutable and are
// shared.
func (r ValidationReport) Clone() ValidationReport {
	clone := r
	clone.Issues = cloneSlice(r.Issues)
	return clone
}

// ValidationError is the typed form of one ValidationIssue.
type ValidationError struct {
	Issue ValidationIssue
}

func (e *ValidationError) Error() string {
	if e == nil {
		return "validation error"
	}
	var parts []string
	switch {
	case e.Issue.Detail != "":
		parts = append(parts, e.Issue.Detail)
	case e.Issue.Reason != "":
		parts = append(parts, string(e.Issue.Reason))
	case e.Issue.Err != nil:
		parts = append(parts, e.Issue.Err.Error())
	}
	if e.Issue.Path != "" {
		parts = append([]string{e.Issue.Path}, parts...)
	}
	if len(parts) == 0 {
		parts = append(parts, "validation failed")
	}
	return strings.Join(parts, ": ")
}

// Unwrap preserves both the category sentinel and an underlying native cause.
func (e *ValidationError) Unwrap() []error {
	if e == nil {
		return nil
	}
	category := validationCategory(e.Issue)
	if e.Issue.Err == nil {
		if category == nil {
			return nil
		}
		return []error{category}
	}
	if category == nil || errors.Is(e.Issue.Err, category) {
		return []error{e.Issue.Err}
	}
	return []error{category, e.Issue.Err}
}

// Err converts all issues to a joined typed error. It returns nil when the
// report has no issues.
func (r ValidationReport) Err() error {
	if len(r.Issues) == 0 {
		return nil
	}
	errs := make([]error, 0, len(r.Issues))
	for _, issue := range r.Issues {
		errs = append(errs, &ValidationError{Issue: issue})
	}
	return errors.Join(errs...)
}

func validationCategory(issue ValidationIssue) error {
	if errors.Is(issue.Err, ErrInvalidOptions) {
		return ErrInvalidOptions
	}
	switch issue.State {
	case CapabilityUnsupported:
		return ErrNotSupported
	case CapabilityUnavailable:
		return ErrUnavailable
	case CapabilityUnknown:
		return ErrCapabilityUnknown
	case CapabilityAvailable:
		if issue.Err != nil {
			return ErrInvalidOptions
		}
		return nil
	default:
		if issue.Err != nil {
			return ErrInvalidOptions
		}
		return fmt.Errorf("validation issue has state %d", issue.State)
	}
}
