package tlspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// IdentityKind identifies the representation used by a ServerIdentity.
type IdentityKind uint8

const (
	// IdentityInvalid is the kind of the zero ServerIdentity value.
	IdentityInvalid IdentityKind = iota

	// IdentityDNS identifies a canonical ASCII DNS name.
	IdentityDNS

	// IdentityIP identifies an IPv4 or IPv6 address.
	IdentityIP
)

// String returns a stable human-readable name for k.
func (k IdentityKind) String() string {
	switch k {
	case IdentityInvalid:
		return "invalid"
	case IdentityDNS:
		return "dns"
	case IdentityIP:
		return "ip"
	default:
		return fmt.Sprintf("IdentityKind(%d)", uint8(k))
	}
}

// ServerIdentity is the expected DNS name or IP address of a remote TLS
// server. It is used for scoped trust-anchor, authority-constraint, and pin
// matching.
//
// Values are immutable and comparable. The zero value is invalid. Use
// ParseServerIdentity to construct one.
type ServerIdentity struct { //nolint:recvcheck // Unmarshal mutates.
	kind IdentityKind
	dns  string
	ip   netip.Addr
}

// ParseServerIdentity parses a DNS name or IP address without a port.
//
// DNS names must be ASCII A-labels. They are lowercased and one final root dot
// is removed. IPv6 addresses may be bracketed. IPv6 zone identifiers are
// rejected because they are routing details, not certificate identities.
func ParseServerIdentity(value string) (ServerIdentity, error) {
	if value == "" {
		return ServerIdentity{}, errors.New(
			"tlspolicy: server identity is empty",
		)
	}
	if strings.TrimSpace(value) != value {
		return ServerIdentity{}, errors.New(
			"tlspolicy: server identity contains leading or trailing whitespace",
		)
	}

	ipText := value
	if len(ipText) >= 2 && ipText[0] == '[' && ipText[len(ipText)-1] == ']' {
		ipText = ipText[1 : len(ipText)-1]
	}
	if addr, err := netip.ParseAddr(ipText); err == nil {
		if addr.Zone() != "" {
			return ServerIdentity{}, fmt.Errorf(
				"tlspolicy: IP identity %q contains a zone identifier",
				value,
			)
		}
		return ServerIdentity{kind: IdentityIP, ip: addr.Unmap()}, nil
	}

	dns, err := canonicalDNSName(value)
	if err != nil {
		return ServerIdentity{}, err
	}
	return ServerIdentity{kind: IdentityDNS, dns: dns}, nil
}

// Kind returns whether id contains a DNS name or an IP address.
func (id ServerIdentity) Kind() IdentityKind {
	return id.kind
}

// Valid reports whether id contains a parsed DNS name or IP address.
func (id ServerIdentity) Valid() bool {
	return id.kind == IdentityDNS || id.kind == IdentityIP
}

// DNSName returns the canonical DNS name and true when id is a DNS identity.
func (id ServerIdentity) DNSName() (string, bool) {
	return id.dns, id.kind == IdentityDNS
}

// IP returns the address and true when id is an IP identity.
func (id ServerIdentity) IP() (netip.Addr, bool) {
	return id.ip, id.kind == IdentityIP
}

// String returns the canonical DNS name or IP address. It returns an empty
// string for the zero value.
func (id ServerIdentity) String() string {
	switch id.kind {
	case IdentityInvalid:
		return ""
	case IdentityDNS:
		return id.dns
	case IdentityIP:
		return id.ip.String()
	default:
		return ""
	}
}

// MarshalText implements encoding.TextMarshaler.
func (id ServerIdentity) MarshalText() ([]byte, error) {
	if !id.Valid() {
		return nil, errors.New(
			"tlspolicy: cannot marshal invalid ServerIdentity",
		)
	}
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *ServerIdentity) UnmarshalText(text []byte) error {
	if id == nil {
		return errors.New(
			"tlspolicy: cannot unmarshal ServerIdentity into a nil receiver",
		)
	}

	parsed, err := ParseServerIdentity(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// DNSRule matches one DNS domain in a Scope.
//
// Domain must be an ASCII DNS A-label name and must not contain a wildcard. If
// IncludeSubdomains is false, only the exact domain matches. If true, both the
// domain and names below it match. For example, a rule for example.test with
// IncludeSubdomains set matches example.test and a.b.example.test, but not
// badexample.test.
type DNSRule struct {
	// Domain is the DNS domain to match.
	Domain string

	// IncludeSubdomains extends the match to names below Domain.
	IncludeSubdomains bool
}

// Scope is a set of remote-server identities for which a rule is active.
//
// The entries in DNS and IPPrefixes are alternatives. Any makes the scope
// unrestricted and cannot be combined with other entries. The zero value
// matches nothing and is rejected when used in a compiled policy rule.
type Scope struct {
	// Any matches every valid server identity.
	Any bool

	// DNS contains exact-domain or domain-subtree rules.
	DNS []DNSRule

	// IPPrefixes contains IPv4 or IPv6 network prefixes. An exact address uses a
	// /32 IPv4 prefix or a /128 IPv6 prefix.
	IPPrefixes []netip.Prefix
}

// AnyServerScope returns a scope that matches every valid server identity.
func AnyServerScope() Scope {
	return Scope{Any: true}
}

// NewDNSDomainScope returns a scope for domain. When includeSubdomains is true,
// the scope also matches every DNS name below domain.
func NewDNSDomainScope(domain string, includeSubdomains bool) (Scope, error) {
	dns, err := canonicalDNSName(domain)
	if err != nil {
		return Scope{}, err
	}
	return Scope{
		DNS: []DNSRule{{Domain: dns, IncludeSubdomains: includeSubdomains}},
	}, nil
}

// NewIPPrefixScope returns a scope containing prefix.
//
// IPv4-mapped IPv6 prefixes and prefixes with a zone identifier are rejected;
// callers should normalize them to ordinary IPv4 or unzoned IPv6 values.
func NewIPPrefixScope(prefix netip.Prefix) (Scope, error) {
	compiled, err := compileScope(
		Scope{IPPrefixes: []netip.Prefix{prefix}},
		false,
	)
	if err != nil {
		return Scope{}, err
	}
	return Scope{
		IPPrefixes: append([]netip.Prefix(nil), compiled.ipPrefixes...),
	}, nil
}

// NewExactServerScope returns a scope that matches exactly identity.
func NewExactServerScope(identity string) (Scope, error) {
	parsed, err := ParseServerIdentity(identity)
	if err != nil {
		return Scope{}, err
	}

	switch parsed.kind {
	case IdentityInvalid:
		return Scope{}, errors.New("tlspolicy: invalid exact server identity")
	case IdentityDNS:
		return Scope{DNS: []DNSRule{{Domain: parsed.dns}}}, nil
	case IdentityIP:
		prefix := netip.PrefixFrom(parsed.ip, parsed.ip.BitLen())
		return Scope{IPPrefixes: []netip.Prefix{prefix}}, nil
	default:
		return Scope{}, errors.New("tlspolicy: invalid exact server identity")
	}
}

// Validate checks that s is well formed. Unlike policy compilation, Validate
// permits the zero scope, which is a useful representation of “matches
// nothing”.
func (s Scope) Validate() error {
	_, err := compileScope(s, true)
	return err
}

// Allows reports whether s contains identity.
//
// An invalid scope or invalid identity produces an error. A valid zero scope
// returns false.
func (s Scope) Allows(identity ServerIdentity) (bool, error) {
	if !identity.Valid() {
		return false, errors.New(
			"tlspolicy: cannot match an invalid ServerIdentity",
		)
	}

	compiled, err := compileScope(s, true)
	if err != nil {
		return false, err
	}
	return compiled.allows(identity), nil
}

type compiledScope struct {
	any        bool
	dns        []DNSRule
	ipPrefixes []netip.Prefix
}

func compileScope(scope Scope, allowEmpty bool) (compiledScope, error) {
	if scope.Any {
		if len(scope.DNS) != 0 || len(scope.IPPrefixes) != 0 {
			return compiledScope{}, errors.New(
				"tlspolicy: Scope.Any cannot be combined with DNS or IP prefixes",
			)
		}
		return compiledScope{any: true}, nil
	}

	compiled := compiledScope{}
	seenDNS := make(map[string]struct{}, len(scope.DNS))
	for i, rule := range scope.DNS {
		domain, err := canonicalDNSName(rule.Domain)
		if err != nil {
			return compiledScope{}, fmt.Errorf(
				"tlspolicy: DNS scope rule %d: %w",
				i,
				err,
			)
		}

		key := domain + "\x00"
		if rule.IncludeSubdomains {
			key += "subdomains"
		}
		if _, duplicate := seenDNS[key]; duplicate {
			continue
		}
		seenDNS[key] = struct{}{}
		compiled.dns = append(compiled.dns, DNSRule{
			Domain:            domain,
			IncludeSubdomains: rule.IncludeSubdomains,
		})
	}

	seenPrefix := make(map[netip.Prefix]struct{}, len(scope.IPPrefixes))
	for i, prefix := range scope.IPPrefixes {
		if !prefix.IsValid() {
			return compiledScope{}, fmt.Errorf(
				"tlspolicy: IP scope prefix %d is invalid",
				i,
			)
		}
		addr := prefix.Addr()
		if addr.Zone() != "" {
			return compiledScope{}, fmt.Errorf(
				"tlspolicy: IP scope prefix %d contains a zone identifier",
				i,
			)
		}
		if addr.Is4In6() {
			return compiledScope{}, fmt.Errorf(
				"tlspolicy: IP scope prefix %d is IPv4-mapped IPv6; use an IPv4 prefix",
				i,
			)
		}

		prefix = prefix.Masked()
		if _, duplicate := seenPrefix[prefix]; duplicate {
			continue
		}
		seenPrefix[prefix] = struct{}{}
		compiled.ipPrefixes = append(compiled.ipPrefixes, prefix)
	}

	if !allowEmpty && len(compiled.dns) == 0 && len(compiled.ipPrefixes) == 0 {
		return compiledScope{}, errors.New(
			"tlspolicy: policy rule has an empty Scope that matches no server",
		)
	}
	return compiled, nil
}

func (scope compiledScope) allows(identity ServerIdentity) bool {
	if scope.any {
		return identity.Valid()
	}

	switch identity.kind {
	case IdentityInvalid:
		return false
	case IdentityDNS:
		for _, rule := range scope.dns {
			if identity.dns == rule.Domain {
				return true
			}
			if rule.IncludeSubdomains &&
				strings.HasSuffix(identity.dns, "."+rule.Domain) {
				return true
			}
		}
	case IdentityIP:
		for _, prefix := range scope.ipPrefixes {
			if prefix.Contains(identity.ip) {
				return true
			}
		}
	}
	return false
}

func canonicalDNSName(value string) (string, error) {
	if value == "" {
		return "", errors.New("tlspolicy: DNS name is empty")
	}
	if strings.TrimSpace(value) != value {
		return "", errors.New(
			"tlspolicy: DNS name contains leading or trailing whitespace",
		)
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", errors.New(
			"tlspolicy: DNS name is empty after removing the root dot",
		)
	}

	value = strings.ToLower(value)
	if len(value) > 253 {
		return "", fmt.Errorf(
			"tlspolicy: DNS name is %d bytes; maximum is 253",
			len(value),
		)
	}

	labels := strings.SplitSeq(value, ".")
	for label := range labels {
		if len(label) == 0 {
			return "", fmt.Errorf(
				"tlspolicy: DNS name %q contains an empty label",
				value,
			)
		}
		if len(label) > 63 {
			return "", fmt.Errorf(
				"tlspolicy: DNS label %q is longer than 63 bytes",
				label,
			)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf(
				"tlspolicy: DNS label %q begins or ends with a hyphen",
				label,
			)
		}
		for _, character := range []byte(label) {
			if (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') ||
				character == '-' {
				continue
			}
			return "", fmt.Errorf(
				"tlspolicy: DNS name %q contains non-ASCII or invalid character %q; use an IDNA A-label",
				value,
				character,
			)
		}
	}
	return value, nil
}
