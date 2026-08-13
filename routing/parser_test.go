// nolint
//
//nolint:testpackage
package routing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func TestNewBytecodeRulesParsesProgramsAndDeduplicatesResources(t *testing.T) {
	rules, err := NewBytecodeRules(
		`
# comment
addr_s example.com
ADDR_RE ^api\.
addr4 192.0.2.10
snet4 10.0.0.0/8
PORT 443
AND
AND
AND
AND
SLOT 2
`,
		"LADDR_S example.com\nLADDR_RE ^api\\.\nLPORT 443\nAND\nAND\nSLOT 2\n",
		"",
		"",
		"FQDN\nADDR_S example.com\nADDR_RE ^api\\.\nOR\nAND\nSLOT 2\n",
	)
	if err != nil {
		t.Fatalf("NewBytecodeRules() error = %v", err)
	}

	if got, want := rules.Strings, []string{
		"example.com",
	}; !stringSlicesEqual(
		got,
		want,
	) {
		t.Fatalf("Strings = %#v, want %#v", got, want)
	}
	if len(rules.Regexps) != 1 || rules.Regexps[0].String() != `^api\.` {
		t.Fatalf("Regexps = %#v, want one ^api\\. regexp", rules.Regexps)
	}
	if len(rules.IPv4Addrs) != 1 || rules.IPv4Addrs[0] != ip4(192, 0, 2, 10) {
		t.Fatalf("IPv4Addrs = %#v, want 192.0.2.10", rules.IPv4Addrs)
	}
	if len(rules.IPv4Subnets) != 1 ||
		rules.IPv4Subnets[0] != (IPv4Subnet{Addr: ip4(10, 0, 0, 0), Bits: 8}) {
		t.Fatalf("IPv4Subnets = %#v, want 10.0.0.0/8", rules.IPv4Subnets)
	}
	if !bytes.Equal(
		rules.Lookup,
		append(
			append([]byte{OP_FQDN}, param16(OP_ADDR_S, 0)...),
			append(param16(OP_ADDR_RE, 0), OP_OR, OP_AND, OP_SLOT, 2)...),
	) {
		t.Fatalf("Lookup bytecode = %#v", rules.Lookup)
	}
}

func TestNewBytecodeRulesParsesRouterMethodOps(t *testing.T) {
	rules, err := NewBytecodeRules(
		"DIAL\nSLOT 2\n",
		"LISTEN\nSLOT 3\n",
		"DIAL\nSLOT 4\n",
		"DIAL\nLISTEN\nLOOKUP\nOR\nOR\nNOT\nSLOT 5\nDIAL\nSLOT 6\n",
		"LOOKUP\nSLOT 7\n",
	)
	if err != nil {
		t.Fatalf("NewBytecodeRules() error = %v", err)
	}

	checks := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "DialTCP",
			got:  rules.DialTCP,
			want: []byte{OP_DIAL, OP_SLOT, 2},
		},
		{
			name: "ListenTCP",
			got:  rules.ListenTCP,
			want: []byte{OP_LISTEN, OP_SLOT, 3},
		},
		{
			name: "DialUDP",
			got:  rules.DialUDP,
			want: []byte{OP_DIAL, OP_SLOT, 4},
		},
		{
			name: "RouteUDP",
			got:  rules.RouteUDP,
			want: []byte{
				OP_DIAL, OP_LISTEN, OP_LOOKUP, OP_OR, OP_OR, OP_NOT, OP_SLOT, 5,
				OP_DIAL, OP_SLOT, 6,
			},
		},
		{
			name: "Lookup",
			got:  rules.Lookup,
			want: []byte{OP_LOOKUP, OP_SLOT, 7},
		},
	}
	for _, check := range checks {
		if !bytes.Equal(check.got, check.want) {
			t.Fatalf(
				"%s bytecode = %#v, want %#v",
				check.name,
				check.got,
				check.want,
			)
		}
	}
}

func TestNewBytecodeRulesProgramFiltersSegmentsByMethod(t *testing.T) {
	rules, err := NewBytecodeRulesProgram(`
# no method operations, so this segment belongs to every method
TRUE
SLOT 1

DIAL
SLOT 2

LISTEN
slot 3

LOOKUP
DROP
`)
	if err != nil {
		t.Fatalf("NewBytecodeRulesProgram() error = %v", err)
	}

	checks := []struct {
		name string
		got  []byte
		want []byte
	}{
		{
			name: "DialTCP",
			got:  rules.DialTCP,
			want: []byte{OP_TRUE, OP_SLOT, 1, OP_DIAL, OP_SLOT, 2},
		},
		{
			name: "ListenTCP",
			got:  rules.ListenTCP,
			want: []byte{OP_TRUE, OP_SLOT, 1, OP_LISTEN, OP_SLOT, 3},
		},
		{
			name: "DialUDP",
			got:  rules.DialUDP,
			want: []byte{OP_TRUE, OP_SLOT, 1, OP_DIAL, OP_SLOT, 2},
		},
		{
			name: "RouteUDP",
			got:  rules.RouteUDP,
			want: []byte{OP_TRUE, OP_SLOT, 1, OP_DIAL, OP_SLOT, 2},
		},
		{
			name: "Lookup",
			got:  rules.Lookup,
			want: []byte{OP_TRUE, OP_SLOT, 1, OP_LOOKUP, OP_DROP},
		},
	}
	for _, check := range checks {
		if !bytes.Equal(check.got, check.want) {
			t.Fatalf(
				"%s bytecode = %#v, want %#v",
				check.name,
				check.got,
				check.want,
			)
		}
	}
}

func TestNewBytecodeRulesProgramKeepsConservativeSegments(t *testing.T) {
	rules, err := NewBytecodeRulesProgram(`
DIAL
ADDR_S example.com
OR
SLOT 2

DIAL
LISTEN
OR
LOOKUP
OR
NOT
SLOT 3
`)
	if err != nil {
		t.Fatalf("NewBytecodeRulesProgram() error = %v", err)
	}

	dialOrAddr := append(
		append([]byte{OP_DIAL}, param16(OP_ADDR_S, 0)...),
		OP_OR,
		OP_SLOT,
		2,
	)
	noneOfTheMethods := []byte{
		OP_DIAL, OP_LISTEN, OP_OR, OP_LOOKUP, OP_OR, OP_NOT, OP_SLOT, 3,
	}
	if !bytes.Equal(rules.DialTCP, dialOrAddr) {
		t.Fatalf("DialTCP bytecode = %#v, want %#v", rules.DialTCP, dialOrAddr)
	}
	if !bytes.Equal(rules.ListenTCP, dialOrAddr) {
		t.Fatalf(
			"ListenTCP bytecode = %#v, want %#v",
			rules.ListenTCP,
			dialOrAddr,
		)
	}
	if !bytes.Equal(rules.Lookup, dialOrAddr) {
		t.Fatalf("Lookup bytecode = %#v, want %#v", rules.Lookup, dialOrAddr)
	}
	if !bytes.Equal(rules.RouteUDP, dialOrAddr) {
		t.Fatalf(
			"RouteUDP bytecode = %#v, want %#v",
			rules.RouteUDP,
			dialOrAddr,
		)
	}
	if bytes.Contains(rules.RouteUDP, noneOfTheMethods) {
		t.Fatalf("RouteUDP kept impossible segment %#v", noneOfTheMethods)
	}
}

func TestNewBytecodeRulesProgramCanGuardLookupInvalidOps(t *testing.T) {
	rules, err := NewBytecodeRulesProgram(`
DIAL
LADDR_S 127.0.0.1
AND
SLOT 2

LOOKUP
ADDR_S example.com
AND
SLOT 3
`)
	if err != nil {
		t.Fatalf("NewBytecodeRulesProgram() error = %v", err)
	}

	wantDial := append(
		append([]byte{OP_DIAL}, param16(OP_LADDR_S, 0)...),
		OP_AND,
		OP_SLOT,
		2,
	)
	wantLookup := append(
		append([]byte{OP_LOOKUP}, param16(OP_ADDR_S, 1)...),
		OP_AND,
		OP_SLOT,
		3,
	)
	if !bytes.Equal(rules.DialTCP, wantDial) {
		t.Fatalf("DialTCP bytecode = %#v, want %#v", rules.DialTCP, wantDial)
	}
	if !bytes.Equal(rules.Lookup, wantLookup) {
		t.Fatalf("Lookup bytecode = %#v, want %#v", rules.Lookup, wantLookup)
	}
}

func TestNewBytecodeRulesProgramReportsParseAndValidationErrors(t *testing.T) {
	_, err := NewBytecodeRulesProgram("BOGUS\nSLOT 1\n")
	if err == nil ||
		!strings.Contains(err.Error(), `unknown operation "BOGUS"`) {
		t.Fatalf(
			"NewBytecodeRulesProgram() parse error = %v, want unknown operation",
			err,
		)
	}

	_, err = NewBytecodeRulesProgram("LADDR_S 127.0.0.1\nSLOT 1\n")
	if err == nil ||
		!strings.Contains(err.Error(), "local-address opcode is not valid") {
		t.Fatalf(
			"NewBytecodeRulesProgram() validation error = %v, want local-address error",
			err,
		)
	}

	_, err = NewBytecodeRulesProgram("TRUE\nSLOT 1\nTRUE\nOR\nSLOT 2\n")
	if err == nil || !strings.Contains(err.Error(), "stack underflow") {
		t.Fatalf(
			"NewBytecodeRulesProgram() validation error = %v, want stack underflow",
			err,
		)
	}
}

func TestBytecodeSegmentCanTriggerKeepsMalformedSegments(t *testing.T) {
	tests := []struct {
		name    string
		segment []bytecodeRuleLine
	}{
		{
			name:    "unknown operation",
			segment: []bytecodeRuleLine{{no: 1, text: "BOGUS"}},
		},
		{
			name:    "terminal stack underflow",
			segment: []bytecodeRuleLine{{no: 1, text: "SLOT 1"}},
		},
		{
			name: "false without method op",
			segment: []bytecodeRuleLine{
				{no: 1, text: "FALSE"},
				{no: 2, text: "SLOT 1"},
			},
		},
		{
			name:    "not stack underflow",
			segment: []bytecodeRuleLine{{no: 1, text: "NOT"}},
		},
		{
			name: "and stack underflow",
			segment: []bytecodeRuleLine{
				{no: 1, text: "TRUE"},
				{no: 2, text: "AND"},
			},
		},
		{
			name: "or stack underflow",
			segment: []bytecodeRuleLine{
				{no: 1, text: "TRUE"},
				{no: 2, text: "OR"},
			},
		},
	}
	for _, tt := range tests {
		if !bytecodeSegmentCanTrigger(tt.segment, bytecodeMethodDial) {
			t.Fatalf(
				"%s: bytecodeSegmentCanTrigger() = false, want true",
				tt.name,
			)
		}
	}
}

func TestBytecodeBoolStateOperations(t *testing.T) {
	notChecks := []struct {
		in   bytecodeBoolState
		want bytecodeBoolState
	}{
		{in: bytecodeBoolFalse, want: bytecodeBoolTrue},
		{in: bytecodeBoolTrue, want: bytecodeBoolFalse},
		{in: bytecodeBoolUnknown, want: bytecodeBoolUnknown},
	}
	for _, check := range notChecks {
		if got := bytecodeBoolNot(check.in); got != check.want {
			t.Fatalf(
				"bytecodeBoolNot(%d) = %d, want %d",
				check.in,
				got,
				check.want,
			)
		}
	}

	andChecks := []struct {
		a, b bytecodeBoolState
		want bytecodeBoolState
	}{
		{a: bytecodeBoolFalse, b: bytecodeBoolUnknown, want: bytecodeBoolFalse},
		{a: bytecodeBoolUnknown, b: bytecodeBoolFalse, want: bytecodeBoolFalse},
		{a: bytecodeBoolTrue, b: bytecodeBoolTrue, want: bytecodeBoolTrue},
		{
			a:    bytecodeBoolTrue,
			b:    bytecodeBoolUnknown,
			want: bytecodeBoolUnknown,
		},
	}
	for _, check := range andChecks {
		if got := bytecodeBoolAnd(check.a, check.b); got != check.want {
			t.Fatalf(
				"bytecodeBoolAnd(%d, %d) = %d, want %d",
				check.a,
				check.b,
				got,
				check.want,
			)
		}
	}
}

func TestNewBytecodeRulesRejectsInlineCommentOnNoArgOperation(t *testing.T) {
	_, err := NewBytecodeRules(
		"TRUE # inline comments are not comments\n",
		"",
		"",
		"",
		"",
	)
	if err == nil ||
		!strings.Contains(err.Error(), "does not accept an argument") {
		t.Fatalf(
			"NewBytecodeRules() error = %v, want no-arg argument error",
			err,
		)
	}
}

func TestNewBytecodeRulesRejectsOPPrefix(t *testing.T) {
	_, err := NewBytecodeRules("OP_TRUE\n", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("NewBytecodeRules() error = %v, want unknown operation", err)
	}
}

func TestNewBytecodeRulesRejectsSplitOnlyOps(t *testing.T) {
	_, err := NewBytecodeRules("RULE test value\n", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "not valid for RouterCfg") {
		t.Fatalf(
			"NewBytecodeRules() error = %v, want RouterCfg validation error",
			err,
		)
	}
}

func TestBytecodeRulesRejectSnifferOnlyOps(t *testing.T) {
	_, err := NewBytecodeRules("TRUE\nINTERCEPT\n", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "not valid for RouterCfg") {
		t.Fatalf(
			"NewBytecodeRules() error = %v, want RouterCfg validation error",
			err,
		)
	}

	_, err = NewSplitBytecodeRules(&sysnetdebug.System{}, "TRUE\nINTERCEPT\n")
	if err == nil ||
		!strings.Contains(err.Error(), "not valid for SplitRouter") {
		t.Fatalf(
			"NewSplitBytecodeRules() error = %v, want SplitRouter validation error",
			err,
		)
	}
}

func TestNewSplitBytecodeRulesParsesSplitOnlyOps(t *testing.T) {
	rules, err := NewSplitBytecodeRules(&sysnetdebug.System{}, `
rule test arbitrary text
RULE test arbitrary text
AND
SLOT 3
`)
	if err != nil {
		t.Fatalf("NewSplitBytecodeRules() error = %v", err)
	}
	if got, want := rules.Rules, []sysnet.Rule{
		{Type: "test", Rule: "arbitrary text"},
	}; !reflectRulesEqual(got, want) {
		t.Fatalf("Rules = %#v, want %#v", got, want)
	}
	if !bytes.Equal(
		rules.Route,
		append(
			append(param16(OP_RULE, 0), param16(OP_RULE, 0)...),
			OP_AND, OP_SLOT, 3,
		),
	) {
		t.Fatalf("Route bytecode = %#v", rules.Route)
	}
}

func TestNewSplitBytecodeRulesPreservesRuleTextWhitespace(t *testing.T) {
	rules, err := NewSplitBytecodeRules(
		&sysnetdebug.System{},
		"RULE app value  with\tspaces\nSLOT 3\n",
	)
	if err != nil {
		t.Fatalf("NewSplitBytecodeRules() error = %v", err)
	}
	want := []sysnet.Rule{{Type: "app", Rule: "value  with\tspaces"}}
	if !reflectRulesEqual(rules.Rules, want) {
		t.Fatalf("Rules = %#v, want %#v", rules.Rules, want)
	}
}

func TestNewSplitBytecodeRulesRejectsRuleWithoutText(t *testing.T) {
	_, err := NewSplitBytecodeRules(&sysnetdebug.System{}, `
RULE app
SLOT 3
`)
	if err == nil ||
		!strings.Contains(err.Error(), "requires a rule type and rule text") {
		t.Fatalf(
			"NewSplitBytecodeRules() error = %v, want rule text error",
			err,
		)
	}
}

func TestNewSplitBytecodeRulesRejectsRouterMethodOps(t *testing.T) {
	_, err := NewSplitBytecodeRules(&sysnetdebug.System{}, "DIAL\nSLOT 1\n")
	if err == nil ||
		!strings.Contains(err.Error(), "not valid for SplitRouter") {
		t.Fatalf(
			"NewSplitBytecodeRules() error = %v, want SplitRouter validation error",
			err,
		)
	}
}

func TestNewSplitBytecodeRulesRejectsStackUnderflowAfterTerminalSegment(
	t *testing.T,
) {
	_, err := NewSplitBytecodeRules(&sysnetdebug.System{}, `
TRUE
SLOT 1

RULE cmd chrome
OR
SLOT 2
`)
	if err == nil || !strings.Contains(err.Error(), "stack underflow") {
		t.Fatalf(
			"NewSplitBytecodeRules() error = %v, want stack underflow",
			err,
		)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func reflectRulesEqual(a, b []sysnet.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
