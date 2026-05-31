// nolint
package routing

import (
	"bytes"
	"strings"
	"testing"
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
	_, err := NewBytecodeRules("RULE 1\n", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "not valid for RouterCfg") {
		t.Fatalf(
			"NewBytecodeRules() error = %v, want RouterCfg validation error",
			err,
		)
	}
}

func TestNewSplitBytecodeRulesParsesSplitOnlyOps(t *testing.T) {
	rules, err := NewSplitBytecodeRules(&testIPMatcher{}, `
rule 99
RULE 99
AND
UNAME alice
UEXP ^ali
AND
MARK -7
AND
OR
SLOT 3
`)
	if err != nil {
		t.Fatalf("NewSplitBytecodeRules() error = %v", err)
	}
	if got, want := rules.Strings, []string{
		"alice",
	}; !stringSlicesEqual(
		got,
		want,
	) {
		t.Fatalf("Strings = %#v, want %#v", got, want)
	}
	if len(rules.Regexps) != 1 || rules.Regexps[0].String() != `^ali` {
		t.Fatalf("Regexps = %#v, want one ^ali regexp", rules.Regexps)
	}
}

func TestNewSplitBytecodeRulesParsesHexMarkAsRawUint32(t *testing.T) {
	rules, err := NewSplitBytecodeRules(&testIPMatcher{}, `
MARK 0x0111010
SLOT 3
`)
	if err != nil {
		t.Fatalf("NewSplitBytecodeRules() error = %v", err)
	}
	want := append(param32(OP_MARK, 0x0111010), OP_SLOT, 3)
	if !bytes.Equal(rules.Route, want) {
		t.Fatalf("Route bytecode = %#v, want %#v", rules.Route, want)
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
