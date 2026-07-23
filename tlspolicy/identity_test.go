package tlspolicy //nolint:testpackage // Uses shared in-package TLS fixtures.

import (
	"net/netip"
	"testing"
)

func TestParseServerIdentityAndScopes(t *testing.T) {
	t.Parallel()

	id, err := ParseServerIdentity("API.Example.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id.String(), "api.example.test"; got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}
	if id.Kind() != IdentityDNS {
		t.Fatalf("kind = %v, want DNS", id.Kind())
	}

	scope, err := NewDNSDomainScope("example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := scope.Allows(id)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("subdomain scope did not allow api.example.test")
	}

	outside, err := ParseServerIdentity("badexample.test")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = scope.Allows(outside)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("scope crossed a DNS label boundary")
	}

	ip, err := ParseServerIdentity("[2001:db8::25]")
	if err != nil {
		t.Fatal(err)
	}
	prefixScope, err := NewIPPrefixScope(netip.MustParsePrefix("2001:db8::/32"))
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = prefixScope.Allows(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("IPv6 prefix did not allow contained address")
	}
}

func TestScopeValidationRejectsAmbiguity(t *testing.T) {
	t.Parallel()

	if err := (Scope{Any: true, DNS: []DNSRule{{Domain: "example.test"}}}).Validate(); err == nil {
		t.Fatal("Any combined with DNS unexpectedly validated")
	}
	if _, err := NewDNSDomainScope("*.example.test", true); err == nil {
		t.Fatal("wildcard policy domain unexpectedly validated")
	}
	if _, err := ParseServerIdentity("bücher.example"); err == nil {
		t.Fatal("Unicode DNS name unexpectedly validated")
	}
	if err := (Scope{}).Validate(); err != nil {
		t.Fatalf("zero scope should be a valid match-nothing value: %v", err)
	}
}
