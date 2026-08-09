package tls

import (
	"errors"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/sniffer"
)

// InterceptionFilterMode selects how InterceptionFilter rules are used.
type InterceptionFilterMode uint8

const (
	// InterceptionFilterOff disables interception filtering. This is the
	// default and keeps the historical behavior: every interceptable TLS
	// ClientHello is intercepted.
	InterceptionFilterOff InterceptionFilterMode = iota

	// InterceptionFilterInclusive intercepts only connections that match at
	// least one rule. Valid TLS connections that do not match are passed
	// through unchanged.
	InterceptionFilterInclusive

	// InterceptionFilterExclusive filters out connections that match at least
	// one rule. Other TLS connections use the default interception behavior.
	InterceptionFilterExclusive
)

// InterceptionFlag is a tri-state boolean matcher used by InterceptionRule.
//
// The zero value is a wildcard. Required matches when the observed value is
// true. Forbidden matches when the observed value is false.
type InterceptionFlag uint8

const (
	// InterceptionFlagAny accepts both true and false.
	InterceptionFlagAny InterceptionFlag = iota

	// InterceptionFlagRequired requires the observed value to be true.
	InterceptionFlagRequired

	// InterceptionFlagForbidden requires the observed value to be false.
	InterceptionFlagForbidden
)

// InterceptionFilter controls which TLS connections Network intercepts.
//
// Rules are ORed. In inclusive mode, a connection is selected for interception
// when any rule matches. In exclusive mode, a connection is passed through
// unchanged when any rule matches. A selected TLS ClientHello still must have a
// visible SNI host and no ECH signal before Network can intercept it.
//
// Empty Rules are valid. They make inclusive mode pass all TLS connections
// through and make exclusive mode use the default interception behavior.
type InterceptionFilter struct {
	// Mode selects inclusive or exclusive filtering. The zero value disables
	// filtering and requires Rules to be empty.
	Mode InterceptionFilterMode

	// Rules is the list of match rules.
	Rules []InterceptionRule
}

// InterceptionRule matches one TLS connection.
//
// Empty field groups are wildcards. Non-empty values in one field group are
// ORed, and all configured field groups must match.
//
// Networks are exact or glob patterns over the dial network string, such as
// "tcp", "tcp4", or "tcp*".
//
// ConnSrcs match the requested DialTCP local address and the actual local
// socket address after dialing. Dial has no requested local address. ConnDsts
// match the requested remote address and the actual remote socket address after
// dialing. Source and destination patterns use the same syntax as
// gonnect.FilterFromString: host, host:port, IP, IP:port, CIDR, and host
// wildcards are supported.
//
// SNIHosts match the visible SNI host_name. Matching is case-insensitive.
// ALPNs match any ALPN protocol name. Matching is case-sensitive. Both fields
// use whole-value glob patterns where * matches any byte sequence, ? matches
// one byte, and character classes use path.Match syntax.
//
// SNIAvailable and SNIEncrypted match the visible ClientHello flags.
// SNIEncrypted only reports that the encrypted_client_hello extension is
// present. Network cannot decrypt ECH or intercept a connection that has ECH.
//
// TLSVersions match protocol versions offered by the ClientHello. If the
// supported_versions extension is present, it is used. Otherwise the
// ClientHello legacy_version field is used.
type InterceptionRule struct {
	Networks []string

	ConnSrcs []string
	ConnDsts []string

	SNIHosts []string
	ALPNs    []string

	SNIAvailable InterceptionFlag
	SNIEncrypted InterceptionFlag

	TLSVersions []uint16
}

type interceptionConnInfo struct {
	network      string
	requestedSrc string
	requestedDst string
	actualSrc    string
	actualDst    string
}

type compiledInterceptionFilter struct {
	mode  InterceptionFilterMode
	rules []compiledInterceptionRule
}

func compileInterceptionFilter(
	filter InterceptionFilter,
) (compiledInterceptionFilter, error) {
	if filter.Mode == InterceptionFilterOff {
		if len(filter.Rules) != 0 {
			return compiledInterceptionFilter{}, errors.New(
				"gonnect/tls: InterceptionFilter rules require a mode",
			)
		}
		return compiledInterceptionFilter{}, nil
	}
	if filter.Mode != InterceptionFilterInclusive &&
		filter.Mode != InterceptionFilterExclusive {
		return compiledInterceptionFilter{}, fmt.Errorf(
			"gonnect/tls: invalid InterceptionFilter mode %d",
			filter.Mode,
		)
	}

	rules := make([]compiledInterceptionRule, len(filter.Rules))
	for i, rule := range filter.Rules {
		compiled, err := compileInterceptionRule(rule)
		if err != nil {
			return compiledInterceptionFilter{}, fmt.Errorf(
				"gonnect/tls: compile InterceptionFilter rule %d: %w",
				i,
				err,
			)
		}
		rules[i] = compiled
	}

	return compiledInterceptionFilter{
		mode:  filter.Mode,
		rules: rules,
	}, nil
}

func (f compiledInterceptionFilter) enabled() bool {
	return f.mode != InterceptionFilterOff
}

func (f compiledInterceptionFilter) intercepts(
	conn interceptionConnInfo,
	hello *sniffer.TLSClientHelloInfo,
) bool {
	if !f.enabled() {
		return true
	}

	matched := false
	for _, rule := range f.rules {
		if rule.match(conn, hello) {
			matched = true
			break
		}
	}

	switch f.mode {
	case InterceptionFilterOff:
		return true
	case InterceptionFilterInclusive:
		return matched
	case InterceptionFilterExclusive:
		return !matched
	default:
		panic("gonnect/tls: invalid compiled InterceptionFilter mode")
	}
}

type compiledInterceptionRule struct {
	networks patternMatcher
	connSrcs addressMatcher
	connDsts addressMatcher
	sniHosts patternMatcher
	alpns    patternMatcher

	sniAvailable InterceptionFlag
	sniEncrypted InterceptionFlag

	tlsVersions tlsVersionMatcher
}

func compileInterceptionRule(
	rule InterceptionRule,
) (compiledInterceptionRule, error) {
	if err := checkInterceptionFlag(
		"SNIAvailable",
		rule.SNIAvailable,
	); err != nil {
		return compiledInterceptionRule{}, err
	}
	if err := checkInterceptionFlag(
		"SNIEncrypted",
		rule.SNIEncrypted,
	); err != nil {
		return compiledInterceptionRule{}, err
	}
	networks, err := newPatternMatcher("network", rule.Networks, false)
	if err != nil {
		return compiledInterceptionRule{}, err
	}
	sniHosts, err := newPatternMatcher("SNI host", rule.SNIHosts, true)
	if err != nil {
		return compiledInterceptionRule{}, err
	}
	alpns, err := newPatternMatcher("ALPN", rule.ALPNs, false)
	if err != nil {
		return compiledInterceptionRule{}, err
	}

	return compiledInterceptionRule{
		networks: networks,
		connSrcs: newAddressMatcher(rule.ConnSrcs),
		connDsts: newAddressMatcher(rule.ConnDsts),
		sniHosts: sniHosts,
		alpns:    alpns,

		sniAvailable: rule.SNIAvailable,
		sniEncrypted: rule.SNIEncrypted,

		tlsVersions: newTLSVersionMatcher(rule.TLSVersions),
	}, nil
}

func (r compiledInterceptionRule) match(
	conn interceptionConnInfo,
	hello *sniffer.TLSClientHelloInfo,
) bool {
	if !r.networks.match(conn.network) {
		return false
	}
	if !r.connSrcs.match(
		conn.network,
		conn.requestedSrc,
		conn.actualSrc,
	) {
		return false
	}
	if !r.connDsts.match(
		conn.network,
		conn.requestedDst,
		conn.actualDst,
	) {
		return false
	}

	if hello == nil {
		return r.matchWithoutClientHello()
	}
	return r.matchClientHello(*hello)
}

func (r compiledInterceptionRule) matchWithoutClientHello() bool {
	return r.sniAvailable == InterceptionFlagAny &&
		r.sniEncrypted == InterceptionFlagAny &&
		!r.sniHosts.configured() &&
		!r.alpns.configured() &&
		!r.tlsVersions.configured()
}

func (r compiledInterceptionRule) matchClientHello(
	hello sniffer.TLSClientHelloInfo,
) bool {
	if !r.sniAvailable.match(hello.SNIHostname != "") {
		return false
	}
	if !r.sniEncrypted.match(hello.SNIEncrypted) {
		return false
	}
	if !r.sniHosts.match(hello.SNIHostname) {
		return false
	}
	if !r.alpns.matchAny(hello.ALPNProtocols) {
		return false
	}
	if !r.tlsVersions.matchAny(hello.Versions) {
		return false
	}
	return true
}

func checkInterceptionFlag(name string, flag InterceptionFlag) error {
	if flag <= InterceptionFlagForbidden {
		return nil
	}
	return fmt.Errorf("invalid %s flag %d", name, flag)
}

func (f InterceptionFlag) match(value bool) bool {
	switch f {
	case InterceptionFlagAny:
		return true
	case InterceptionFlagRequired:
		return value
	case InterceptionFlagForbidden:
		return !value
	default:
		panic("gonnect/tls: invalid InterceptionFlag")
	}
}

type patternMatcher struct {
	patterns []interceptionPattern
	foldCase bool
}

func newPatternMatcher(
	name string,
	patterns []string,
	foldCase bool,
) (patternMatcher, error) {
	matcher := patternMatcher{foldCase: foldCase}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if foldCase {
			pattern = strings.ToLower(pattern)
			pattern = strings.TrimRight(pattern, ".")
		}
		compiled, err := compileInterceptionPattern(pattern)
		if err != nil {
			return patternMatcher{}, fmt.Errorf(
				"invalid %s pattern %q: %w",
				name,
				pattern,
				err,
			)
		}
		matcher.patterns = append(matcher.patterns, compiled)
	}
	return matcher, nil
}

func (m patternMatcher) configured() bool {
	return len(m.patterns) != 0
}

func (m patternMatcher) match(value string) bool {
	if !m.configured() {
		return true
	}
	if value == "" {
		return false
	}
	if m.foldCase {
		value = strings.ToLower(value)
		value = strings.TrimRight(value, ".")
	}
	for _, pattern := range m.patterns {
		if pattern.match(value) {
			return true
		}
	}
	return false
}

func (m patternMatcher) matchAny(values []string) bool {
	if !m.configured() {
		return true
	}
	for _, value := range values {
		if m.match(value) {
			return true
		}
	}
	return false
}

type interceptionPatternTokenKind uint8

const (
	interceptionPatternLiteral interceptionPatternTokenKind = iota
	interceptionPatternAny
	interceptionPatternStar
	interceptionPatternClass
)

type interceptionPatternRange struct {
	lo byte
	hi byte
}

type interceptionPatternToken struct {
	kind    interceptionPatternTokenKind
	literal byte
	ranges  []interceptionPatternRange
	negated bool
}

type interceptionPattern []interceptionPatternToken

func compileInterceptionPattern(pattern string) (interceptionPattern, error) {
	compiled := make(interceptionPattern, 0, len(pattern))
	for i := 0; i < len(pattern); {
		switch b := pattern[i]; b {
		case '*':
			compiled = append(compiled, interceptionPatternToken{
				kind: interceptionPatternStar,
			})
			i++
		case '?':
			compiled = append(compiled, interceptionPatternToken{
				kind: interceptionPatternAny,
			})
			i++
		case '\\':
			i++
			if i == len(pattern) {
				return nil, path.ErrBadPattern
			}
			compiled = append(compiled, interceptionPatternToken{
				kind:    interceptionPatternLiteral,
				literal: pattern[i],
			})
			i++
		case '[':
			token, next, err := compileInterceptionPatternClass(
				pattern,
				i+1,
			)
			if err != nil {
				return nil, err
			}
			compiled = append(compiled, token)
			i = next
		default:
			compiled = append(compiled, interceptionPatternToken{
				kind:    interceptionPatternLiteral,
				literal: b,
			})
			i++
		}
	}
	return compiled, nil
}

func compileInterceptionPatternClass(
	pattern string,
	i int,
) (interceptionPatternToken, int, error) {
	token := interceptionPatternToken{kind: interceptionPatternClass}
	if i < len(pattern) && pattern[i] == '^' {
		token.negated = true
		i++
	}

	for first := true; i < len(pattern); first = false {
		if pattern[i] == ']' && !first {
			return token, i + 1, nil
		}

		lo, next, err := readInterceptionPatternClassByte(pattern, i)
		if err != nil {
			return interceptionPatternToken{}, 0, err
		}
		i = next

		hi := lo
		if i < len(pattern) && pattern[i] == '-' {
			i++
			if i == len(pattern) || pattern[i] == ']' {
				return interceptionPatternToken{}, 0, path.ErrBadPattern
			}
			hi, next, err = readInterceptionPatternClassByte(pattern, i)
			if err != nil {
				return interceptionPatternToken{}, 0, err
			}
			if hi < lo {
				return interceptionPatternToken{}, 0, path.ErrBadPattern
			}
			i = next
		}

		token.ranges = append(token.ranges, interceptionPatternRange{
			lo: lo,
			hi: hi,
		})
	}

	return interceptionPatternToken{}, 0, path.ErrBadPattern
}

func readInterceptionPatternClassByte(
	pattern string,
	i int,
) (byte, int, error) {
	if i == len(pattern) {
		return 0, 0, path.ErrBadPattern
	}
	if pattern[i] == '\\' {
		i++
		if i == len(pattern) {
			return 0, 0, path.ErrBadPattern
		}
		return pattern[i], i + 1, nil
	}
	if pattern[i] == '-' || pattern[i] == ']' {
		return 0, 0, path.ErrBadPattern
	}
	return pattern[i], i + 1, nil
}

func (p interceptionPattern) match(value string) bool {
	patternIndex := 0
	valueIndex := 0
	starIndex := -1
	starValueIndex := 0

	for valueIndex < len(value) {
		if patternIndex < len(p) &&
			p[patternIndex].matches(value[valueIndex]) {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(p) &&
			p[patternIndex].kind == interceptionPatternStar {
			starIndex = patternIndex
			patternIndex++
			starValueIndex = valueIndex
			continue
		}
		if starIndex != -1 {
			patternIndex = starIndex + 1
			starValueIndex++
			valueIndex = starValueIndex
			continue
		}
		return false
	}

	for patternIndex < len(p) &&
		p[patternIndex].kind == interceptionPatternStar {
		patternIndex++
	}
	return patternIndex == len(p)
}

func (t interceptionPatternToken) matches(b byte) bool {
	switch t.kind {
	case interceptionPatternLiteral:
		return t.literal == b
	case interceptionPatternAny:
		return true
	case interceptionPatternClass:
		matched := false
		for _, r := range t.ranges {
			if r.lo <= b && b <= r.hi {
				matched = true
				break
			}
		}
		return matched != t.negated
	case interceptionPatternStar:
		return false
	default:
		panic("gonnect/tls: invalid interception pattern token")
	}
}

type addressMatcher struct {
	filter     gonnect.CustomFilter
	configured bool
}

func newAddressMatcher(patterns []string) addressMatcher {
	var matcher addressMatcher
	for _, pattern := range patterns {
		filter := gonnect.FilterFromString(pattern)
		matcher.filter.Hosts = append(matcher.filter.Hosts, filter.Hosts...)
		matcher.filter.IPs = append(matcher.filter.IPs, filter.IPs...)
		matcher.filter.CIDRs = append(matcher.filter.CIDRs, filter.CIDRs...)
	}
	matcher.configured = len(matcher.filter.Hosts) != 0 ||
		len(matcher.filter.IPs) != 0 ||
		len(matcher.filter.CIDRs) != 0
	return matcher
}

func (m addressMatcher) match(
	network string,
	addresses ...string,
) bool {
	if !m.configured {
		return true
	}
	for _, address := range addresses {
		if address != "" && m.filter.Filter(network, address) {
			return true
		}
	}
	return false
}

type tlsVersionMatcher struct {
	versions []uint16
}

func newTLSVersionMatcher(versions []uint16) tlsVersionMatcher {
	matcher := tlsVersionMatcher{}
	for _, version := range versions {
		if version == 0 {
			continue
		}
		matcher.versions = append(matcher.versions, version)
	}
	return matcher
}

func (m tlsVersionMatcher) configured() bool {
	return len(m.versions) != 0
}

func (m tlsVersionMatcher) matchAny(values []uint16) bool {
	if !m.configured() {
		return true
	}
	for _, want := range m.versions {
		for _, got := range values {
			if got == want {
				return true
			}
		}
	}
	return false
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
