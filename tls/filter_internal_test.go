package tls

import (
	"errors"
	"path"
	"testing"

	"github.com/asciimoth/gonnect/sniffer"
)

func TestInterceptionPatternAdditionalBranches(t *testing.T) {
	pattern, err := compileInterceptionPattern(`a\*b[0-9][^x]?`)
	if err != nil {
		t.Fatalf("compileInterceptionPattern() error = %v", err)
	}
	if !pattern.match("a*b5ya") {
		t.Fatal("compiled pattern did not match expected value")
	}
	if pattern.match("a*b5xa") {
		t.Fatal("negated class matched forbidden value")
	}

	badPatterns := []string{`\`, `[`, `[]`, `[z-a]`, `[a-]`, `[\`}
	for _, bad := range badPatterns {
		if _, err := compileInterceptionPattern(bad); err == nil {
			t.Fatalf("compileInterceptionPattern(%q) error = nil", bad)
		}
	}

	if _, _, err := readInterceptionPatternClassByte(
		"-",
		0,
	); !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("readInterceptionPatternClassByte('-') = %v", err)
	}
}

func TestInterceptionRuleMatchWithoutClientHello(t *testing.T) {
	anyRule := compiledInterceptionRule{}
	if !anyRule.matchWithoutClientHello() {
		t.Fatal("empty rule should match without ClientHello")
	}
	if !anyRule.match(interceptionConnInfo{network: "tcp"}, nil) {
		t.Fatal("empty rule should match connection without ClientHello")
	}

	rule := compiledInterceptionRule{
		sniAvailable: InterceptionFlagRequired,
	}
	if rule.matchWithoutClientHello() {
		t.Fatal("SNI-required rule matched without ClientHello")
	}

	hello := sniffer.TLSClientHelloInfo{
		SNIHostname:   "Example.TEST.",
		ALPNProtocols: []string{"h2"},
		Versions:      []uint16{0x0304},
	}
	matcher, err := newPatternMatcher("sni", []string{"example.test"}, true)
	if err != nil {
		t.Fatalf("newPatternMatcher() error = %v", err)
	}
	alpn, err := newPatternMatcher("alpn", []string{"h?"}, false)
	if err != nil {
		t.Fatalf("newPatternMatcher(alpn) error = %v", err)
	}
	rule = compiledInterceptionRule{
		sniAvailable: InterceptionFlagRequired,
		sniEncrypted: InterceptionFlagForbidden,
		sniHosts:     matcher,
		alpns:        alpn,
		tlsVersions:  newTLSVersionMatcher([]uint16{0, 0x0304}),
	}
	if !rule.matchClientHello(hello) {
		t.Fatal("rule did not match expected ClientHello")
	}
	hello.SNIEncrypted = true
	if rule.matchClientHello(hello) {
		t.Fatal("rule matched encrypted SNI when forbidden")
	}
}
