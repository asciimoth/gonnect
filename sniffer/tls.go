package sniffer

import (
	"encoding/binary"
	"strings"

	"github.com/asciimoth/gonnect/putback"
)

// DefaultTLSClientHelloMaxBytes is the default TLS ClientHello inspection
// limit used by TLS and TLSFactory.
//
// The limit applies to bytes read from the stream while parsing the first
// ClientHello. It includes TLS record headers, handshake headers, and
// ClientHello data. A ClientHello that is not complete within this many bytes
// mismatches.
const DefaultTLSClientHelloMaxBytes = 64 * 1024

const (
	tlsContentTypeHandshake = 22

	tlsHandshakeTypeClientHello = 1

	tlsRecordHeaderBytes    = 5
	tlsHandshakeHeaderBytes = 4
	tlsPlaintextMaxBytes    = 1 << 14

	tlsExtensionServerName           uint16 = 0
	tlsExtensionApplicationProtocols uint16 = 16
	tlsExtensionSupportedVersions    uint16 = 43
	tlsExtensionEncryptedClientHello uint16 = 0xfe0d

	tlsServerNameTypeHostName = 0
)

// TLSFlag is a boolean filter used by TLSConfig.
//
// The zero value is a wildcard. Required matches when the observed flag is
// true. Forbidden matches when the observed flag is false.
type TLSFlag uint8

const (
	// TLSFlagAny accepts both true and false.
	TLSFlagAny TLSFlag = iota

	// TLSFlagRequired requires the observed flag to be true.
	TLSFlagRequired

	// TLSFlagForbidden requires the observed flag to be false.
	TLSFlagForbidden
)

// TLSConfig configures a TLS ClientHello classifier.
//
// Empty field groups are wildcards. Non-empty values in a field group are ORed
// within that group, and all configured groups must match. For example,
// Versions {tls.VersionTLS12, tls.VersionTLS13}, HostnamePatterns
// {"*.example.test"}, and ALPNs {"h2", "http/1.1"} match a TLS ClientHello
// that offers TLS 1.2 or TLS 1.3, has a visible SNI hostname below
// example.test, and offers h2 or http/1.1 by ALPN.
//
// Version and Versions match protocol versions offered by the ClientHello. If
// the supported_versions extension is present, it is used. Otherwise the
// ClientHello legacy_version field is used. The server-selected TLS version is
// not visible before routing.
//
// SNIAvailable matches whether a visible SNI host_name is present. SNIEncrypted
// matches whether the encrypted_client_hello extension is present. This is an
// observable ECH signal only; the classifier cannot verify that the server
// accepts ECH or reveal an encrypted inner hostname.
//
// Hostname, Hostnames, and HostnamePatterns match the visible SNI hostname.
// Matching is case-insensitive. If ECH is present, the visible hostname is the
// outer ClientHello hostname, when the client sends one.
//
// ALPN, ALPNs, and ALPNPatterns match any protocol name in the ALPN extension.
// Matching is case-sensitive.
//
// HostnamePatterns and ALPNPatterns are byte-oriented glob patterns. A pattern
// must match the whole value. In a pattern, * matches any byte sequence, ?
// matches one byte, and \ escapes the next byte.
//
// MaxClientHelloBytes bounds bytes inspected while parsing the first
// ClientHello. Zero uses DefaultTLSClientHelloMaxBytes. A negative value is a
// programming error and causes a panic.
type TLSConfig struct {
	MaxClientHelloBytes int

	Version  uint16
	Versions []uint16

	SNIAvailable TLSFlag
	SNIEncrypted TLSFlag

	Hostname         string
	Hostnames        []string
	HostnamePatterns []string

	ALPN         string
	ALPNs        []string
	ALPNPatterns []string
}

// TLSClientHelloInfo is the visible metadata from a TLS ClientHello.
//
// Versions contains the protocol versions offered by the client. If the
// supported_versions extension is present, it is used. Otherwise Versions
// contains the legacy_version field.
//
// SNIHostname is the normalized visible SNI host_name, if one is present. It
// is lower-case and never has a trailing dot. When ECH is present, this is the
// outer ClientHello hostname.
//
// SNIEncrypted reports whether the encrypted_client_hello extension is present.
// This is only the visible ECH signal. It does not prove that the server will
// accept ECH and it cannot reveal an encrypted inner hostname.
//
// ALPNProtocols contains the ALPN protocols offered by the client, in wire
// order.
type TLSClientHelloInfo struct {
	Versions      []uint16
	SNIHostname   string
	SNIEncrypted  bool
	ALPNProtocols []string
}

// TLS returns a classifier that matches a syntactically valid TLS ClientHello.
//
// Use TLSWithConfig when the route must match offered TLS versions, SNI
// availability, ECH presence, SNI hostnames, ALPN protocols, or byte limits.
func TLS() Classifier {
	return newTLSClassifier(normalizeTLSConfig(TLSConfig{}))
}

// TLSWithConfig returns a classifier that matches a TLS ClientHello and the
// fields requested by config.
func TLSWithConfig(config TLSConfig) Classifier {
	return newTLSClassifier(normalizeTLSConfig(config))
}

// SniffTLSClientHello sniffs a syntactically valid TLS ClientHello and returns
// its visible metadata.
//
// buffer is both scratch storage and the total byte budget. Its length limits
// how many bytes this function may inspect. All bytes read from conn are put
// back before this function returns, including on no-match and read-error
// paths.
//
// The ok result is true only when a full valid TLS ClientHello was parsed
// within buffer. Non-TLS data, malformed TLS data, and TLS data that is over
// the byte budget return ok false with a nil error. Read errors are returned
// unchanged.
func SniffTLSClientHello(
	buffer []byte,
	conn putback.Conn,
) (info TLSClientHelloInfo, ok bool, err error) {
	classifier := newTLSClassifier(normalizeTLSConfig(TLSConfig{
		MaxClientHelloBytes: len(buffer),
	}))
	index, err := Sniff(buffer, conn, classifier)
	if index != 0 {
		return TLSClientHelloInfo{}, false, err
	}
	return cloneTLSClientHelloInfo(classifier.info), true, err
}

// TLSFactory returns a factory for TLS classifiers with the default config.
func TLSFactory() Factory {
	return TLSFactoryWithConfig(TLSConfig{})
}

// TLSFactoryWithConfig returns a factory for TLS classifiers that use config.
func TLSFactoryWithConfig(config TLSConfig) Factory {
	normalized := normalizeTLSConfig(config)
	return FactoryWithMinSniffBufferSize(
		normalized.minSniffBufferSize(),
		FactoryFunc(func() Classifier {
			return newTLSClassifier(normalized)
		}),
	)
}

type normalizedTLSConfig struct {
	maxClientHelloBytes int
	version             tlsVersionMatcher
	sniAvailable        TLSFlag
	sniEncrypted        TLSFlag
	hostname            httpStringMatcher
	alpn                httpStringMatcher
}

func (c normalizedTLSConfig) minSniffBufferSize() int {
	return c.maxClientHelloBytes
}

func normalizeTLSConfig(config TLSConfig) normalizedTLSConfig {
	if config.MaxClientHelloBytes < 0 {
		panic("sniffer: negative TLS ClientHello byte limit")
	}

	maxClientHelloBytes := config.MaxClientHelloBytes
	if maxClientHelloBytes == 0 {
		maxClientHelloBytes = DefaultTLSClientHelloMaxBytes
	}

	return normalizedTLSConfig{
		maxClientHelloBytes: maxClientHelloBytes,
		version: newTLSVersionMatcher(
			config.Version,
			config.Versions,
		),
		sniAvailable: checkedTLSFlag(
			"SNI available",
			config.SNIAvailable,
		),
		sniEncrypted: checkedTLSFlag(
			"SNI encrypted",
			config.SNIEncrypted,
		),
		hostname: newHTTPStringMatcher(
			config.Hostname,
			config.Hostnames,
			config.HostnamePatterns,
			normalizeTLSHostnamePattern,
		),
		alpn: newHTTPStringMatcher(
			config.ALPN,
			config.ALPNs,
			config.ALPNPatterns,
			nil,
		),
	}
}

func checkedTLSFlag(name string, flag TLSFlag) TLSFlag {
	if flag > TLSFlagForbidden {
		panic("sniffer: invalid TLS " + name + " flag")
	}
	return flag
}

func newTLSClassifier(config normalizedTLSConfig) *tlsClassifier {
	return &tlsClassifier{
		config:    config,
		buf:       make([]byte, 0, 512),
		needBytes: tlsRecordHeaderBytes,
		state:     NeedMore,
	}
}

type tlsClassifier struct {
	config    normalizedTLSConfig
	buf       []byte
	needBytes int
	state     State
	info      TLSClientHelloInfo
}

func (c *tlsClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	if len(p) != 0 {
		remaining := c.config.maxClientHelloBytes - len(c.buf)
		if remaining <= 0 {
			c.state = Mismatch
			return c.state
		}
		if len(p) > remaining {
			c.buf = append(c.buf, p[:remaining]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}

	if len(c.buf) < c.needBytes {
		if len(c.buf) == c.config.maxClientHelloBytes {
			c.state = Mismatch
			return c.state
		}
		return NeedMore
	}

	info, state, needBytes := parseTLSClientHello(c.buf)
	if state == NeedMore {
		c.needBytes = needBytes
		if c.needBytes > c.config.maxClientHelloBytes ||
			len(c.buf) == c.config.maxClientHelloBytes {
			c.state = Mismatch
			return c.state
		}
		return NeedMore
	}
	if state == Mismatch {
		c.state = Mismatch
		return c.state
	}

	c.info = cloneTLSClientHelloInfo(info)
	if !c.matchClientHello(info) {
		c.state = Mismatch
		return c.state
	}
	c.state = Match
	return c.state
}

func (c *tlsClassifier) MinSniffBufferSize() int {
	return c.config.minSniffBufferSize()
}

func (c *tlsClassifier) Metadata() any {
	if c.state != Match {
		return nil
	}
	return cloneTLSClientHelloInfo(c.info)
}

func (c *tlsClassifier) matchClientHello(info TLSClientHelloInfo) bool {
	if !c.config.version.match(info.Versions) {
		return false
	}
	if !c.config.sniAvailable.match(info.SNIHostname != "") {
		return false
	}
	if !c.config.sniEncrypted.match(info.SNIEncrypted) {
		return false
	}
	if !c.config.hostname.match(info.SNIHostname) {
		return false
	}
	if !c.config.alpn.matchAny(info.ALPNProtocols) {
		return false
	}
	return true
}

func parseTLSClientHello(data []byte) (TLSClientHelloInfo, State, int) {
	var info TLSClientHelloInfo
	var handshake []byte
	recordOffset := 0

	for {
		if len(data) < recordOffset+tlsRecordHeaderBytes {
			return info, NeedMore, recordOffset + tlsRecordHeaderBytes
		}

		header := data[recordOffset : recordOffset+tlsRecordHeaderBytes]
		if header[0] != tlsContentTypeHandshake {
			return info, Mismatch, 0
		}
		if !validTLSRecordVersion(binary.BigEndian.Uint16(header[1:3])) {
			return info, Mismatch, 0
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > tlsPlaintextMaxBytes {
			return info, Mismatch, 0
		}

		fragmentStart := recordOffset + tlsRecordHeaderBytes
		fragmentEnd := fragmentStart + recordLength
		availableEnd := fragmentEnd
		if availableEnd > len(data) {
			availableEnd = len(data)
		}

		handshakeBeforeRecord := len(handshake)
		handshake = append(handshake, data[fragmentStart:availableEnd]...)
		state := checkTLSClientHelloHeader(handshake)
		if state == Mismatch {
			return info, Mismatch, 0
		}
		if state == Match {
			helloLength := tlsHandshakeHeaderBytes + tlsUint24(handshake[1:4])
			parsed, ok := parseTLSClientHelloBody(
				handshake[tlsHandshakeHeaderBytes:helloLength],
			)
			if !ok {
				return info, Mismatch, 0
			}
			return parsed, Match, 0
		}

		if availableEnd < fragmentEnd {
			return info, NeedMore, tlsClientHelloNeedBytes(
				handshake,
				handshakeBeforeRecord,
				fragmentStart,
				fragmentEnd,
			)
		}

		recordOffset = fragmentEnd
	}
}

func tlsClientHelloNeedBytes(
	handshake []byte,
	handshakeBeforeRecord int,
	fragmentStart int,
	fragmentEnd int,
) int {
	neededHandshakeBytes := tlsHandshakeHeaderBytes
	if len(handshake) >= tlsHandshakeHeaderBytes {
		neededHandshakeBytes = tlsHandshakeHeaderBytes +
			tlsUint24(handshake[1:4])
	}

	neededInRecord := neededHandshakeBytes - handshakeBeforeRecord
	if neededInRecord > 0 && fragmentStart+neededInRecord <= fragmentEnd {
		return fragmentStart + neededInRecord
	}
	return fragmentEnd + tlsRecordHeaderBytes
}

func checkTLSClientHelloHeader(handshake []byte) State {
	if len(handshake) == 0 {
		return NeedMore
	}
	if handshake[0] != tlsHandshakeTypeClientHello {
		return Mismatch
	}
	if len(handshake) < tlsHandshakeHeaderBytes {
		return NeedMore
	}

	helloLength := tlsUint24(handshake[1:4])
	if helloLength == 0 {
		return Mismatch
	}
	if len(handshake) < tlsHandshakeHeaderBytes+helloLength {
		return NeedMore
	}
	return Match
}

func parseTLSClientHelloBody(body []byte) (TLSClientHelloInfo, bool) {
	var info TLSClientHelloInfo
	if len(body) < 34 {
		return info, false
	}

	legacyVersion := binary.BigEndian.Uint16(body[:2])
	if !validTLSClientHelloVersion(legacyVersion) {
		return info, false
	}
	info.Versions = []uint16{legacyVersion}

	offset := 34
	sessionIDLen := int(body[offset])
	offset++
	if sessionIDLen > 32 || !tlsHasBytes(body, offset, sessionIDLen) {
		return info, false
	}
	offset += sessionIDLen

	if !tlsHasBytes(body, offset, 2) {
		return info, false
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2
	if cipherSuitesLen < 2 ||
		cipherSuitesLen%2 != 0 ||
		!tlsHasBytes(body, offset, cipherSuitesLen) {
		return info, false
	}
	offset += cipherSuitesLen

	if !tlsHasBytes(body, offset, 1) {
		return info, false
	}
	compressionMethodsLen := int(body[offset])
	offset++
	if compressionMethodsLen == 0 ||
		!tlsHasBytes(body, offset, compressionMethodsLen) {
		return info, false
	}
	offset += compressionMethodsLen

	if offset == len(body) {
		return info, true
	}
	if !tlsHasBytes(body, offset, 2) {
		return info, false
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2
	if extensionsLen == 0 || !tlsHasBytes(body, offset, extensionsLen) {
		return info, false
	}
	if offset+extensionsLen != len(body) {
		return info, false
	}

	if !parseTLSClientHelloExtensions(body[offset:], &info) {
		return info, false
	}
	return info, true
}

func parseTLSClientHelloExtensions(
	extensions []byte,
	info *TLSClientHelloInfo,
) bool {
	seen := make(map[uint16]struct{})
	for offset := 0; offset < len(extensions); {
		if !tlsHasBytes(extensions, offset, 4) {
			return false
		}

		extensionType := binary.BigEndian.Uint16(extensions[offset:])
		offset += 2
		extensionLen := int(binary.BigEndian.Uint16(extensions[offset:]))
		offset += 2
		if _, ok := seen[extensionType]; ok {
			return false
		}
		seen[extensionType] = struct{}{}
		if !tlsHasBytes(extensions, offset, extensionLen) {
			return false
		}

		extensionData := extensions[offset : offset+extensionLen]
		switch extensionType {
		case tlsExtensionServerName:
			hostname, ok := parseTLSServerNameExtension(extensionData)
			if !ok {
				return false
			}
			info.SNIHostname = hostname
		case tlsExtensionApplicationProtocols:
			protocols, ok := parseTLSALPNExtension(extensionData)
			if !ok {
				return false
			}
			info.ALPNProtocols = protocols
		case tlsExtensionSupportedVersions:
			versions, ok := parseTLSSupportedVersionsExtension(
				extensionData,
			)
			if !ok {
				return false
			}
			info.Versions = versions
		case tlsExtensionEncryptedClientHello:
			info.SNIEncrypted = true
		}

		offset += extensionLen
	}
	return true
}

func cloneTLSClientHelloInfo(info TLSClientHelloInfo) TLSClientHelloInfo {
	return TLSClientHelloInfo{
		Versions:      append([]uint16(nil), info.Versions...),
		SNIHostname:   info.SNIHostname,
		SNIEncrypted:  info.SNIEncrypted,
		ALPNProtocols: append([]string(nil), info.ALPNProtocols...),
	}
}

func parseTLSServerNameExtension(data []byte) (string, bool) {
	if !tlsHasBytes(data, 0, 2) {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data))
	if listLen == 0 || listLen != len(data)-2 {
		return "", false
	}

	var hostname string
	for offset := 2; offset < len(data); {
		if !tlsHasBytes(data, offset, 3) {
			return "", false
		}
		nameType := data[offset]
		offset++
		nameLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if nameLen == 0 || !tlsHasBytes(data, offset, nameLen) {
			return "", false
		}

		if nameType == tlsServerNameTypeHostName {
			if hostname != "" {
				return "", false
			}
			normalized, ok := normalizeTLSHostname(
				string(data[offset : offset+nameLen]),
			)
			if !ok {
				return "", false
			}
			hostname = normalized
		}
		offset += nameLen
	}
	return hostname, true
}

func parseTLSALPNExtension(data []byte) ([]string, bool) {
	if !tlsHasBytes(data, 0, 2) {
		return nil, false
	}
	listLen := int(binary.BigEndian.Uint16(data))
	if listLen == 0 || listLen != len(data)-2 {
		return nil, false
	}

	protocols := make([]string, 0, 2)
	for offset := 2; offset < len(data); {
		protocolLen := int(data[offset])
		offset++
		if protocolLen == 0 || !tlsHasBytes(data, offset, protocolLen) {
			return nil, false
		}
		protocols = append(protocols, string(data[offset:offset+protocolLen]))
		offset += protocolLen
	}
	return protocols, true
}

func parseTLSSupportedVersionsExtension(data []byte) ([]uint16, bool) {
	if len(data) < 3 {
		return nil, false
	}
	listLen := int(data[0])
	if listLen < 2 || listLen%2 != 0 || listLen != len(data)-1 {
		return nil, false
	}

	versions := make([]uint16, 0, listLen/2)
	for offset := 1; offset < len(data); offset += 2 {
		versions = append(
			versions,
			binary.BigEndian.Uint16(data[offset:]),
		)
	}
	return versions, true
}

func validTLSRecordVersion(version uint16) bool {
	major := byte(version >> 8)
	minor := byte(version)
	return major == 3 && minor <= 4
}

func validTLSClientHelloVersion(version uint16) bool {
	return validTLSRecordVersion(version)
}

func tlsHasBytes(data []byte, offset int, count int) bool {
	return count >= 0 && offset >= 0 && offset <= len(data) &&
		count <= len(data)-offset
}

func tlsUint24(data []byte) int {
	return int(data[0])<<16 | int(data[1])<<8 | int(data[2])
}

func normalizeTLSHostnamePattern(pattern string) string {
	normalized, ok := normalizeTLSHostname(pattern)
	if !ok {
		return strings.ToLower(pattern)
	}
	return normalized
}

func normalizeTLSHostname(hostname string) (string, bool) {
	if hostname == "" || strings.HasSuffix(hostname, ".") {
		return "", false
	}
	for i := range len(hostname) {
		b := hostname[i]
		if b <= ' ' || b == 0x7f {
			return "", false
		}
		switch b {
		case '/', '\\', ':', '[', ']', '@':
			return "", false
		}
	}
	return strings.ToLower(hostname), true
}

type tlsVersionMatcher struct {
	versions []uint16
}

func newTLSVersionMatcher(version uint16, versions []uint16) tlsVersionMatcher {
	matcher := tlsVersionMatcher{}
	addVersion := func(value uint16) {
		if value == 0 {
			return
		}
		matcher.versions = append(matcher.versions, value)
	}
	addVersion(version)
	for _, value := range versions {
		addVersion(value)
	}
	return matcher
}

func (m tlsVersionMatcher) match(offered []uint16) bool {
	if len(m.versions) == 0 {
		return true
	}
	for _, want := range m.versions {
		for _, got := range offered {
			if got == want {
				return true
			}
		}
	}
	return false
}

func (f TLSFlag) match(value bool) bool {
	switch f {
	case TLSFlagAny:
		return true
	case TLSFlagRequired:
		return value
	case TLSFlagForbidden:
		return !value
	default:
		panic("sniffer: invalid TLS flag")
	}
}

func (m httpStringMatcher) matchAny(values []string) bool {
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
