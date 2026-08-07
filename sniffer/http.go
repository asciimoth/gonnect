package sniffer

import (
	"bytes"
	"net/url"
	"strings"
)

// DefaultHTTPRequestLineMaxBytes is the default HTTP request-line inspection
// limit used by HTTP and HTTPFactory.
//
// The limit includes the line-ending byte. A request line that does not end
// with LF within this many bytes mismatches.
const DefaultHTTPRequestLineMaxBytes = 4096

// DefaultHTTPHeaderMaxBytes is the default HTTP header inspection limit.
//
// The limit applies only when the classifier must inspect headers, such as
// when Hostname, Hostnames, or HostnamePatterns is set.
const DefaultHTTPHeaderMaxBytes = 8192

// HTTPConfig configures an HTTP request classifier.
//
// Empty field groups are wildcards. Non-empty values in a field group are ORed
// within that group, and all configured groups must match. For example,
// Methods {"GET", "POST"} and URLPatterns {"/api/*"} matches GET or POST
// requests whose request-target matches /api/*.
//
// The singular Method, URL, Version, and Hostname fields are exact-match
// shortcuts. They are ORed with their plural exact-match fields. Empty strings
// in plural fields are ignored.
//
// URL and URLPatterns match the request-target exactly as sent on the wire,
// such as /path?q=1 or http://example.com/path. Version and Versions match the
// HTTP-version token, such as HTTP/1.1. Leave Version and Versions empty to
// accept any HTTP-version token that starts with HTTP/.
//
// URLPatterns and HostnamePatterns are byte-oriented glob patterns. A pattern
// must match the whole value. In a pattern, * matches any byte sequence, ?
// matches one byte, and \ escapes the next byte.
//
// Hostname, Hostnames, and HostnamePatterns match a normalized hostname from
// the absolute-form request-target or the Host header. Matching is
// case-insensitive, and an optional port is removed before matching.
//
// MaxRequestLineBytes bounds how many request-line bytes the classifier may
// inspect, including LF. MaxHeaderBytes bounds bytes after the request line
// when hostname matching must inspect headers. Zero values use the defaults. A
// negative value is a programming error and causes a panic.
type HTTPConfig struct {
	MaxRequestLineBytes int
	MaxHeaderBytes      int

	Method  string
	Methods []string

	URL         string
	URLs        []string
	URLPatterns []string

	Version  string
	Versions []string

	Hostname         string
	Hostnames        []string
	HostnamePatterns []string
}

// HTTP returns a classifier that matches an HTTP request line.
//
// The classifier accepts any syntactically valid method token, non-empty
// request-target, and HTTP-version token that starts with "HTTP/". Use
// HTTPWithConfig when the route must match specific methods, URL
// request-targets, HTTP versions, hostnames, or byte limits.
func HTTP() Classifier {
	return newHTTPClassifier(normalizeHTTPConfig(HTTPConfig{}))
}

// HTTPWithConfig returns a classifier that matches an HTTP request and the
// fields requested by config.
func HTTPWithConfig(config HTTPConfig) Classifier {
	return newHTTPClassifier(normalizeHTTPConfig(config))
}

// HTTPFactory returns a factory for HTTP classifiers with the default config.
func HTTPFactory() Factory {
	return HTTPFactoryWithConfig(HTTPConfig{})
}

// HTTPFactoryWithConfig returns a factory for HTTP classifiers that use config.
func HTTPFactoryWithConfig(config HTTPConfig) Factory {
	normalized := normalizeHTTPConfig(config)
	return FactoryWithMinSniffBufferSize(
		normalized.minSniffBufferSize(),
		FactoryFunc(func() Classifier {
			return newHTTPClassifier(normalized)
		}),
	)
}

type normalizedHTTPConfig struct {
	maxRequestLineBytes int
	maxHeaderBytes      int
	method              httpStringMatcher
	url                 httpStringMatcher
	version             httpStringMatcher
	hostname            httpStringMatcher
}

func (c normalizedHTTPConfig) minSniffBufferSize() int {
	size := c.maxRequestLineBytes
	if c.hostname.configured() {
		size += c.maxHeaderBytes
	}
	return size
}

func normalizeHTTPConfig(config HTTPConfig) normalizedHTTPConfig {
	if config.MaxRequestLineBytes < 0 {
		panic("sniffer: negative HTTP request-line byte limit")
	}
	if config.MaxHeaderBytes < 0 {
		panic("sniffer: negative HTTP header byte limit")
	}

	maxRequestLineBytes := config.MaxRequestLineBytes
	if maxRequestLineBytes == 0 {
		maxRequestLineBytes = DefaultHTTPRequestLineMaxBytes
	}

	maxHeaderBytes := config.MaxHeaderBytes
	if maxHeaderBytes == 0 {
		maxHeaderBytes = DefaultHTTPHeaderMaxBytes
	}

	return normalizedHTTPConfig{
		maxRequestLineBytes: maxRequestLineBytes,
		maxHeaderBytes:      maxHeaderBytes,
		method: newHTTPStringMatcher(
			config.Method,
			config.Methods,
			nil,
			nil,
		),
		url: newHTTPStringMatcher(
			config.URL,
			config.URLs,
			config.URLPatterns,
			nil,
		),
		version: newHTTPStringMatcher(
			config.Version,
			config.Versions,
			nil,
			nil,
		),
		hostname: newHTTPStringMatcher(
			config.Hostname,
			config.Hostnames,
			config.HostnamePatterns,
			strings.ToLower,
		),
	}
}

func newHTTPClassifier(config normalizedHTTPConfig) Classifier {
	return &httpClassifier{
		config: config,
		line:   make([]byte, 0, 128),
		state:  NeedMore,
	}
}

type httpParsePhase uint8

const (
	httpRequestLinePhase httpParsePhase = iota
	httpHeaderPhase
)

type httpClassifier struct {
	config      normalizedHTTPConfig
	phase       httpParsePhase
	line        []byte
	headerBytes int
	state       State
}

func (c *httpClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		var state State
		switch c.phase {
		case httpRequestLinePhase:
			state = c.feedRequestLineByte(b)
		case httpHeaderPhase:
			state = c.feedHeaderByte(b)
		default:
			panic("sniffer: invalid HTTP parser phase")
		}

		if state != NeedMore {
			c.state = state
			return c.state
		}
	}

	return NeedMore
}

func (c *httpClassifier) MinSniffBufferSize() int {
	return c.config.minSniffBufferSize()
}

func (c *httpClassifier) feedRequestLineByte(b byte) State {
	if len(c.line) == c.config.maxRequestLineBytes {
		return Mismatch
	}
	if len(c.line) != 0 &&
		c.line[len(c.line)-1] == '\r' &&
		b != '\n' {
		return Mismatch
	}
	if b != '\r' && b != '\n' && isHTTPRequestLineControl(b) {
		return Mismatch
	}

	c.line = append(c.line, b)
	if b == '\n' {
		return c.matchRequestLine()
	}
	if len(c.line) == c.config.maxRequestLineBytes {
		return Mismatch
	}
	return NeedMore
}

func (c *httpClassifier) feedHeaderByte(b byte) State {
	if c.headerBytes == c.config.maxHeaderBytes {
		return Mismatch
	}
	if len(c.line) != 0 &&
		c.line[len(c.line)-1] == '\r' &&
		b != '\n' {
		return Mismatch
	}
	if b != '\t' && b != '\r' && b != '\n' && b < ' ' {
		return Mismatch
	}
	if b == 0x7f {
		return Mismatch
	}

	c.headerBytes++
	c.line = append(c.line, b)
	if b == '\n' {
		state := c.matchHeaderLine()
		if state != NeedMore {
			return state
		}
		if c.headerBytes == c.config.maxHeaderBytes {
			return Mismatch
		}
		return NeedMore
	}
	if c.headerBytes == c.config.maxHeaderBytes {
		return Mismatch
	}
	return NeedMore
}

func (c *httpClassifier) matchRequestLine() State {
	line := bytes.TrimSuffix(c.line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})

	method, rest, ok := bytes.Cut(line, []byte{' '})
	if !ok || !validHTTPMethod(method) {
		return Mismatch
	}

	target, version, ok := bytes.Cut(rest, []byte{' '})
	if !ok ||
		!validHTTPRequestTarget(target) ||
		!validHTTPVersion(version) {
		return Mismatch
	}

	if !c.config.method.match(string(method)) ||
		!c.config.url.match(string(target)) ||
		!c.config.version.match(string(version)) {
		return Mismatch
	}

	if !c.config.hostname.configured() {
		return Match
	}
	if hostname, ok := hostnameFromAbsoluteRequestTarget(target); ok &&
		c.config.hostname.match(hostname) {
		return Match
	}

	c.phase = httpHeaderPhase
	c.line = c.line[:0]
	return NeedMore
}

func (c *httpClassifier) matchHeaderLine() State {
	line := bytes.TrimSuffix(c.line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})
	c.line = c.line[:0]

	if len(line) == 0 {
		return Mismatch
	}

	name, value, ok := bytes.Cut(line, []byte{':'})
	if !ok || !validHTTPHeaderFieldName(name) {
		return Mismatch
	}
	if !bytes.EqualFold(name, []byte("Host")) {
		return NeedMore
	}

	hostname, ok := hostnameFromHostHeaderValue(value)
	if !ok || !c.config.hostname.match(hostname) {
		return Mismatch
	}
	return Match
}

func validHTTPMethod(method []byte) bool {
	if len(method) == 0 {
		return false
	}
	for _, b := range method {
		if !isHTTPTokenByte(b) {
			return false
		}
	}
	return true
}

func validHTTPRequestTarget(target []byte) bool {
	if len(target) == 0 {
		return false
	}
	for _, b := range target {
		if b <= ' ' || b == 0x7f {
			return false
		}
	}
	return true
}

func validHTTPVersion(version []byte) bool {
	if !bytes.HasPrefix(version, []byte("HTTP/")) ||
		len(version) == len("HTTP/") {
		return false
	}
	for _, b := range version[len("HTTP/"):] {
		if b <= ' ' || b == 0x7f {
			return false
		}
	}
	return true
}

func validHTTPHeaderFieldName(name []byte) bool {
	return validHTTPMethod(name)
}

func hostnameFromAbsoluteRequestTarget(target []byte) (string, bool) {
	parsed, err := url.Parse(string(target))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", false
	}
	return normalizeHTTPHostname(parsed.Host)
}

func hostnameFromHostHeaderValue(value []byte) (string, bool) {
	value = bytes.Trim(value, " \t")
	if len(value) == 0 {
		return "", false
	}
	return normalizeHTTPHostname(string(value))
}

func normalizeHTTPHostname(host string) (string, bool) {
	if host == "" || strings.ContainsAny(host, " \t\r\n") {
		return "", false
	}

	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return "", false
	}
	return strings.ToLower(hostname), true
}

func isHTTPRequestLineControl(b byte) bool {
	return b < ' ' || b == 0x7f
}

func isHTTPTokenByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	}

	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`',
		'|', '~':
		return true
	default:
		return false
	}
}

type httpStringMatcher struct {
	exact    []string
	patterns []httpGlobPattern
}

func newHTTPStringMatcher(
	exact string,
	exacts []string,
	patterns []string,
	canonicalize func(string) string,
) httpStringMatcher {
	matcher := httpStringMatcher{}
	addExact := func(value string) {
		if value == "" {
			return
		}
		if canonicalize != nil {
			value = canonicalize(value)
		}
		matcher.exact = append(matcher.exact, value)
	}
	addExact(exact)
	for _, value := range exacts {
		addExact(value)
	}

	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if canonicalize != nil {
			pattern = canonicalize(pattern)
		}
		matcher.patterns = append(matcher.patterns, compileHTTPGlob(pattern))
	}

	return matcher
}

func (m httpStringMatcher) configured() bool {
	return len(m.exact) != 0 || len(m.patterns) != 0
}

func (m httpStringMatcher) match(value string) bool {
	if !m.configured() {
		return true
	}
	for _, exact := range m.exact {
		if value == exact {
			return true
		}
	}
	for _, pattern := range m.patterns {
		if pattern.match(value) {
			return true
		}
	}
	return false
}

type httpGlobTokenKind uint8

const (
	httpGlobLiteral httpGlobTokenKind = iota
	httpGlobAny
	httpGlobStar
)

type httpGlobToken struct {
	kind httpGlobTokenKind
	b    byte
}

type httpGlobPattern []httpGlobToken

func compileHTTPGlob(pattern string) httpGlobPattern {
	tokens := make(httpGlobPattern, 0, len(pattern))
	escaped := false
	for i := range len(pattern) {
		b := pattern[i]
		if escaped {
			tokens = append(tokens, httpGlobToken{
				kind: httpGlobLiteral,
				b:    b,
			})
			escaped = false
			continue
		}

		switch b {
		case '\\':
			escaped = true
		case '*':
			tokens = append(tokens, httpGlobToken{kind: httpGlobStar})
		case '?':
			tokens = append(tokens, httpGlobToken{kind: httpGlobAny})
		default:
			tokens = append(tokens, httpGlobToken{
				kind: httpGlobLiteral,
				b:    b,
			})
		}
	}
	if escaped {
		tokens = append(tokens, httpGlobToken{
			kind: httpGlobLiteral,
			b:    '\\',
		})
	}
	return tokens
}

func (p httpGlobPattern) match(value string) bool {
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
			p[patternIndex].kind == httpGlobStar {
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

	for patternIndex < len(p) && p[patternIndex].kind == httpGlobStar {
		patternIndex++
	}
	return patternIndex == len(p)
}

func (t httpGlobToken) matches(b byte) bool {
	switch t.kind {
	case httpGlobAny:
		return true
	case httpGlobLiteral:
		return t.b == b
	case httpGlobStar:
		return false
	default:
		panic("sniffer: invalid HTTP glob token")
	}
}
