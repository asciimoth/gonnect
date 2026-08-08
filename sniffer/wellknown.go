package sniffer

import (
	"bytes"
	"encoding/binary"
)

const (
	rtspRequestLineMaxBytes       = 1024
	sipRequestLineMaxBytes        = 1024
	stunHeaderBytes               = 20
	rdpConnectionRequestMinBytes  = 11
	smbOverTCPRequestMinBytes     = 24
	ldapMessagePrefixMaxBytes     = 16
	cassandraRequestHeaderBytes   = 9
	memcachedBinaryHeaderBytes    = 24
	memcachedASCIIRequestMaxBytes = 512

	stunMagicCookie = 0x2112a442
)

var (
	rtspRequestMethods = []string{
		"ANNOUNCE",
		"DESCRIBE",
		"GET_PARAMETER",
		"OPTIONS",
		"PAUSE",
		"PLAY",
		"PLAY_NOTIFY",
		"RECORD",
		"REDIRECT",
		"SETUP",
		"SET_PARAMETER",
		"TEARDOWN",
	}

	sipRequestMethods = []string{
		"ACK",
		"BYE",
		"CANCEL",
		"INFO",
		"INVITE",
		"MESSAGE",
		"NOTIFY",
		"OPTIONS",
		"PRACK",
		"PUBLISH",
		"REFER",
		"REGISTER",
		"SUBSCRIBE",
		"UPDATE",
	}
)

// RTSP returns a classifier for RTSP request lines.
//
// It matches a known RTSP method, a non-empty request URI, and the RTSP/1.0
// version token on the first CRLF-terminated line. It does not inspect RTSP
// headers, Transport parameters, CSeq, or message bodies.
func RTSP() Classifier {
	return newTextRequestLineClassifier(
		rtspRequestLineMaxBytes,
		rtspRequestMethods,
		"RTSP/1.0",
	)
}

// RTSPFactory returns a factory for RTSP classifiers.
func RTSPFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		rtspRequestLineMaxBytes,
		FactoryFunc(RTSP),
	)
}

// SIP returns a classifier for SIP request lines.
//
// It matches a known SIP method, a non-empty Request-URI, and the SIP/2.0
// version token on the first CRLF-terminated line. It does not inspect Via,
// To, From, Call-ID, CSeq, or message bodies.
func SIP() Classifier {
	return newTextRequestLineClassifier(
		sipRequestLineMaxBytes,
		sipRequestMethods,
		"SIP/2.0",
	)
}

// SIPFactory returns a factory for SIP classifiers.
func SIPFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		sipRequestLineMaxBytes,
		FactoryFunc(SIP),
	)
}

// STUN returns a classifier for STUN and TURN messages.
//
// It validates the fixed 20-byte STUN header: message type top bits, message
// length alignment, magic cookie, and known method. It accepts STUN methods
// used by TURN as well. It does not inspect attributes or integrity.
func STUN() Classifier {
	return newProtocolPrefixClassifier(stunHeaderBytes, matchSTUNHeaderPrefix)
}

// STUNFactory returns a factory for STUN classifiers.
func STUNFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		stunHeaderBytes,
		FactoryFunc(STUN),
	)
}

// RDP returns a classifier for RDP connection requests over TPKT.
//
// It validates the TPKT header and the X.224 Connection Request fixed fields.
// It matches before optional cookies, routing tokens, or negotiation data are
// parsed.
func RDP() Classifier {
	return newProtocolPrefixClassifier(
		rdpConnectionRequestMinBytes,
		matchRDPConnectionRequestPrefix,
	)
}

// RDPFactory returns a factory for RDP classifiers.
func RDPFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		rdpConnectionRequestMinBytes,
		FactoryFunc(RDP),
	)
}

// SMB returns a classifier for SMB over TCP client negotiate requests.
//
// It validates the NetBIOS Session Service header and the start of an SMB1 or
// SMB2/3 negotiate request. It does not inspect dialects, security modes,
// capabilities, or later SMB messages.
func SMB() Classifier {
	return newProtocolPrefixClassifier(
		smbOverTCPRequestMinBytes,
		matchSMBOverTCPRequestPrefix,
	)
}

// SMBFactory returns a factory for SMB classifiers.
func SMBFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		smbOverTCPRequestMinBytes,
		FactoryFunc(SMB),
	)
}

// LDAP returns a classifier for LDAP client messages.
//
// It validates enough BER to find a non-zero message ID and a client request
// protocolOp tag. It does not parse request fields, controls, filters, or
// authentication data.
func LDAP() Classifier {
	return newProtocolPrefixClassifier(
		ldapMessagePrefixMaxBytes,
		matchLDAPMessagePrefix,
	)
}

// LDAPFactory returns a factory for LDAP classifiers.
func LDAPFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		ldapMessagePrefixMaxBytes,
		FactoryFunc(LDAP),
	)
}

// Cassandra returns a classifier for Cassandra native protocol startup
// requests.
//
// It validates a v3, v4, or v5 request header and accepts STARTUP or OPTIONS,
// which are the normal first client messages on a Cassandra connection. It does
// not inspect the body string map or compression.
func Cassandra() Classifier {
	return newProtocolPrefixClassifier(
		cassandraRequestHeaderBytes,
		matchCassandraRequestHeaderPrefix,
	)
}

// CassandraFactory returns a factory for Cassandra classifiers.
func CassandraFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		cassandraRequestHeaderBytes,
		FactoryFunc(Cassandra),
	)
}

// MemcachedBinary returns a classifier for memcached binary protocol requests.
//
// It validates the fixed 24-byte request header, request magic, known opcode,
// data type, extras length, key presence rules, and body length. It does not
// inspect the key, value, CAS, or opaque fields.
func MemcachedBinary() Classifier {
	return newProtocolPrefixClassifier(
		memcachedBinaryHeaderBytes,
		matchMemcachedBinaryHeaderPrefix,
	)
}

// MemcachedBinaryFactory returns a factory for memcached binary classifiers.
func MemcachedBinaryFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		memcachedBinaryHeaderBytes,
		FactoryFunc(MemcachedBinary),
	)
}

// MemcachedASCII returns a classifier for memcached text protocol requests.
//
// It validates the first CRLF-terminated command line for common storage,
// retrieval, counter, delete, touch, flush, stats, version, quit, and verbosity
// commands. It matches before reading any value bytes after a storage command.
func MemcachedASCII() Classifier {
	return newBoundedCRLFLineClassifier(
		memcachedASCIIRequestMaxBytes,
		validMemcachedASCIIRequestLine,
	)
}

// MemcachedASCIIFactory returns a factory for memcached text classifiers.
func MemcachedASCIIFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		memcachedASCIIRequestMaxBytes,
		FactoryFunc(MemcachedASCII),
	)
}

// Memcached returns a classifier for memcached binary or text protocol
// requests.
func Memcached() Classifier {
	return Or(MemcachedBinary(), MemcachedASCII())
}

// MemcachedFactory returns a factory for memcached binary or text classifiers.
func MemcachedFactory() Factory {
	return OrFactory(MemcachedBinaryFactory(), MemcachedASCIIFactory())
}

type protocolPrefixClassifier struct {
	buf      []byte
	maxBytes int
	match    func([]byte) State
	state    State
}

func newProtocolPrefixClassifier(
	maxBytes int,
	match func([]byte) State,
) Classifier {
	if maxBytes < 0 {
		panic("sniffer: negative protocol prefix byte limit")
	}
	if match == nil {
		panic("sniffer: nil protocol prefix matcher")
	}
	return &protocolPrefixClassifier{
		buf:      make([]byte, 0, maxBytes),
		maxBytes: maxBytes,
		match:    match,
		state:    NeedMore,
	}
}

func (c *protocolPrefixClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == c.maxBytes {
			c.state = Mismatch
			return c.state
		}
		c.buf = append(c.buf, b)

		state := checkedState(c.match(c.buf))
		if state != NeedMore {
			c.state = state
			return c.state
		}
	}

	if len(c.buf) == c.maxBytes {
		c.state = Mismatch
	}
	return c.state
}

func (c *protocolPrefixClassifier) MinSniffBufferSize() int {
	return c.maxBytes
}

type boundedCRLFLineClassifier struct {
	line     []byte
	maxBytes int
	valid    func([]byte) bool
	state    State
}

func newBoundedCRLFLineClassifier(
	maxBytes int,
	valid func([]byte) bool,
) Classifier {
	if maxBytes < 0 {
		panic("sniffer: negative CRLF line byte limit")
	}
	if valid == nil {
		panic("sniffer: nil CRLF line validator")
	}
	return &boundedCRLFLineClassifier{
		line:     make([]byte, 0, 128),
		maxBytes: maxBytes,
		valid:    valid,
		state:    NeedMore,
	}
}

func (c *boundedCRLFLineClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.line) == c.maxBytes {
			c.state = Mismatch
			return c.state
		}
		if len(c.line) != 0 && c.line[len(c.line)-1] == '\r' && b != '\n' {
			c.state = Mismatch
			return c.state
		}
		if (b < ' ' && b != '\r' && b != '\n') || b == 0x7f {
			c.state = Mismatch
			return c.state
		}

		c.line = append(c.line, b)
		if b == '\n' {
			switch {
			case len(c.line) < 2 || c.line[len(c.line)-2] != '\r':
				c.state = Mismatch
			case c.valid(c.line[:len(c.line)-2]):
				c.state = Match
			default:
				c.state = Mismatch
			}
			return c.state
		}
	}

	if len(c.line) == c.maxBytes {
		c.state = Mismatch
	}
	return c.state
}

func (c *boundedCRLFLineClassifier) MinSniffBufferSize() int {
	return c.maxBytes
}

func newTextRequestLineClassifier(
	maxBytes int,
	methods []string,
	version string,
) Classifier {
	return newBoundedCRLFLineClassifier(
		maxBytes,
		func(line []byte) bool {
			return validTextRequestLine(line, methods, version)
		},
	)
}

func validTextRequestLine(
	line []byte,
	methods []string,
	version string,
) bool {
	if bytes.Count(line, []byte(" ")) != 2 {
		return false
	}

	firstSpace := bytes.IndexByte(line, ' ')
	lastSpace := bytes.LastIndexByte(line, ' ')
	if firstSpace <= 0 ||
		lastSpace <= firstSpace+1 ||
		lastSpace == len(line)-1 {
		return false
	}

	method := line[:firstSpace]
	target := line[firstSpace+1 : lastSpace]
	gotVersion := line[lastSpace+1:]
	if !bytes.Equal(gotVersion, []byte(version)) ||
		!validTextRequestTarget(target) {
		return false
	}

	for _, known := range methods {
		if bytes.Equal(method, []byte(known)) {
			return true
		}
	}
	return false
}

func validTextRequestTarget(target []byte) bool {
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

func matchSTUNHeaderPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0]&0xc0 != 0 {
		return Mismatch
	}
	if len(data) >= 2 && !validSTUNMessageType(binary.BigEndian.Uint16(data)) {
		return Mismatch
	}
	if len(data) >= 4 && binary.BigEndian.Uint16(data[2:4])%4 != 0 {
		return Mismatch
	}
	if len(data) >= 8 &&
		binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return Mismatch
	}
	if len(data) < stunHeaderBytes {
		return NeedMore
	}
	return Match
}

func validSTUNMessageType(messageType uint16) bool {
	if messageType&0xc000 != 0 {
		return false
	}

	method := (messageType & 0x000f) |
		((messageType & 0x00e0) >> 1) |
		((messageType & 0x3e00) >> 2)
	switch method {
	case 0x001, 0x002, 0x003, 0x004, 0x006, 0x007,
		0x008, 0x009, 0x00a, 0x00b, 0x00c:
		return true
	default:
		return false
	}
}

func matchRDPConnectionRequestPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	switch len(data) {
	case 1:
		if data[0] != 3 {
			return Mismatch
		}
	case 2:
		if data[1] != 0 {
			return Mismatch
		}
	case 4:
		if binary.BigEndian.Uint16(data[2:4]) < rdpConnectionRequestMinBytes {
			return Mismatch
		}
	case 5:
		if data[4] < 6 {
			return Mismatch
		}
	case 6:
		if data[5]&0xf0 != 0xe0 {
			return Mismatch
		}
	}

	if len(data) < rdpConnectionRequestMinBytes {
		return NeedMore
	}
	if validRDPConnectionRequestHeader(data) {
		return Match
	}
	return Mismatch
}

func validRDPConnectionRequestHeader(header []byte) bool {
	if len(header) != rdpConnectionRequestMinBytes ||
		header[0] != 3 ||
		header[1] != 0 ||
		header[5]&0xf0 != 0xe0 {
		return false
	}

	tpktLen := int(binary.BigEndian.Uint16(header[2:4]))
	cotpHeaderBytes := int(header[4]) + 1
	if tpktLen < rdpConnectionRequestMinBytes ||
		cotpHeaderBytes < 7 ||
		cotpHeaderBytes > tpktLen-4 {
		return false
	}
	if binary.BigEndian.Uint16(header[6:8]) != 0 {
		return false
	}
	return header[10]&0xf0 == 0
}

func matchSMBOverTCPRequestPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0] != 0 {
		return Mismatch
	}
	if len(data) >= 2 && data[1]&0xfe != 0 {
		return Mismatch
	}
	if len(data) >= 8 {
		protocolID := string(data[4:8])
		if protocolID != "\xffSMB" && protocolID != "\xfeSMB" {
			return Mismatch
		}
	}

	if len(data) < smbOverTCPRequestMinBytes {
		return NeedMore
	}
	if validSMBOverTCPRequestHeader(data) {
		return Match
	}
	return Mismatch
}

func validSMBOverTCPRequestHeader(header []byte) bool {
	if len(header) != smbOverTCPRequestMinBytes {
		return false
	}

	payloadLen := ((int(header[1]) & 0x01) << 16) |
		int(binary.BigEndian.Uint16(header[2:4]))
	switch string(header[4:8]) {
	case "\xffSMB":
		return payloadLen >= 32 &&
			header[8] == 0x72 &&
			header[13]&0x80 == 0
	case "\xfeSMB":
		return payloadLen >= 64 &&
			binary.LittleEndian.Uint16(header[8:10]) == 64 &&
			binary.LittleEndian.Uint16(header[16:18]) == 0 &&
			binary.LittleEndian.Uint32(header[20:24])&0x00000001 == 0
	default:
		return false
	}
}

func matchLDAPMessagePrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0] != 0x30 {
		return Mismatch
	}

	messageLen, offset, state := parseBERDefiniteLength(data, 1, 4)
	if state != Match {
		return state
	}
	if messageLen < 5 {
		return Mismatch
	}
	if !protocolHasBytes(data, offset, 1) {
		return NeedMore
	}
	if data[offset] != 0x02 {
		return Mismatch
	}

	messageIDLen, valueOffset, state :=
		parseBERDefiniteLength(data, offset+1, 1)
	if state != Match {
		return state
	}
	if messageIDLen == 0 || messageIDLen > 5 {
		return Mismatch
	}
	if valueOffset+messageIDLen > offset+messageLen {
		return Mismatch
	}
	if !protocolHasBytes(data, valueOffset, messageIDLen) {
		return NeedMore
	}
	if !validLDAPMessageID(data[valueOffset : valueOffset+messageIDLen]) {
		return Mismatch
	}

	opOffset := valueOffset + messageIDLen
	if opOffset >= offset+messageLen {
		return Mismatch
	}
	if !protocolHasBytes(data, opOffset, 1) {
		return NeedMore
	}
	if validLDAPClientProtocolOpTag(data[opOffset]) {
		return Match
	}
	return Mismatch
}

func parseBERDefiniteLength(
	data []byte,
	offset int,
	maxLengthOctets int,
) (value int, next int, state State) {
	if !protocolHasBytes(data, offset, 1) {
		return 0, 0, NeedMore
	}

	first := data[offset]
	if first < 0x80 {
		return int(first), offset + 1, Match
	}
	if first == 0x80 || first == 0xff {
		return 0, 0, Mismatch
	}

	lengthOctets := int(first & 0x7f)
	if lengthOctets == 0 || lengthOctets > maxLengthOctets {
		return 0, 0, Mismatch
	}
	if !protocolHasBytes(data, offset+1, lengthOctets) {
		return 0, 0, NeedMore
	}
	if data[offset+1] == 0 {
		return 0, 0, Mismatch
	}

	for _, b := range data[offset+1 : offset+1+lengthOctets] {
		value = value<<8 | int(b)
	}
	return value, offset + 1 + lengthOctets, Match
}

func validLDAPMessageID(encoded []byte) bool {
	if len(encoded) == 0 || encoded[0]&0x80 != 0 {
		return false
	}
	nonZero := false
	for _, b := range encoded {
		if b != 0 {
			nonZero = true
			break
		}
	}
	return nonZero
}

func validLDAPClientProtocolOpTag(tag byte) bool {
	switch tag {
	case 0x60, 0x42, 0x63, 0x66, 0x68,
		0x4a, 0x6c, 0x6e, 0x50, 0x77:
		return true
	default:
		return false
	}
}

func matchCassandraRequestHeaderPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if len(data) >= 1 && !validCassandraRequestVersion(data[0]) {
		return Mismatch
	}
	if len(data) >= 2 && data[1]&0xf0 != 0 {
		return Mismatch
	}
	if len(data) >= 5 && data[4] != 0x01 && data[4] != 0x05 {
		return Mismatch
	}
	if len(data) < cassandraRequestHeaderBytes {
		return NeedMore
	}
	if validCassandraRequestHeader(data) {
		return Match
	}
	return Mismatch
}

func validCassandraRequestVersion(version byte) bool {
	return version == 3 || version == 4 || version == 5
}

func validCassandraRequestHeader(header []byte) bool {
	if len(header) != cassandraRequestHeaderBytes ||
		!validCassandraRequestVersion(header[0]) ||
		header[1]&0xf0 != 0 {
		return false
	}

	bodyLen := binary.BigEndian.Uint32(header[5:9])
	if bodyLen > 1<<31-1 {
		return false
	}

	switch header[4] {
	case 0x01:
		return bodyLen >= 2
	case 0x05:
		return bodyLen == 0
	default:
		return false
	}
}

type memcachedBinaryKeyMode uint8

const (
	memcachedBinaryKeyOptional memcachedBinaryKeyMode = iota
	memcachedBinaryKeyRequired
	memcachedBinaryKeyForbidden
)

func matchMemcachedBinaryHeaderPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0] != 0x80 {
		return Mismatch
	}
	if len(data) >= 2 && !knownMemcachedBinaryRequestOpcode(data[1]) {
		return Mismatch
	}
	if len(data) >= 6 && data[5] != 0 {
		return Mismatch
	}
	if len(data) < memcachedBinaryHeaderBytes {
		return NeedMore
	}
	if validMemcachedBinaryHeader(data) {
		return Match
	}
	return Mismatch
}

func validMemcachedBinaryHeader(header []byte) bool {
	if len(header) != memcachedBinaryHeaderBytes ||
		header[0] != 0x80 ||
		header[5] != 0 {
		return false
	}

	keyMode, extrasA, extrasB, ok :=
		memcachedBinaryRequestOpcodeRules(header[1])
	if !ok || !memcachedBinaryExtrasLengthOK(header[4], extrasA, extrasB) {
		return false
	}

	keyLen := uint32(binary.BigEndian.Uint16(header[2:4]))
	extrasLen := uint32(header[4])
	bodyLen := binary.BigEndian.Uint32(header[8:12])
	if bodyLen < keyLen+extrasLen {
		return false
	}

	return memcachedBinaryKeyLengthOK(keyMode, keyLen)
}

func memcachedBinaryKeyLengthOK(
	keyMode memcachedBinaryKeyMode,
	keyLen uint32,
) bool {
	switch keyMode {
	case memcachedBinaryKeyRequired:
		return keyLen > 0
	case memcachedBinaryKeyForbidden:
		return keyLen == 0
	case memcachedBinaryKeyOptional:
		return true
	default:
		panic("sniffer: invalid memcached binary key mode")
	}
}

func knownMemcachedBinaryRequestOpcode(opcode byte) bool {
	_, _, _, ok := memcachedBinaryRequestOpcodeRules(opcode)
	return ok
}

func memcachedBinaryRequestOpcodeRules(
	opcode byte,
) (keyMode memcachedBinaryKeyMode, extrasA int, extrasB int, ok bool) {
	switch opcode {
	case 0x00, 0x04, 0x09, 0x0c, 0x0d,
		0x0e, 0x0f, 0x14, 0x19, 0x1a,
		0x21, 0x22:
		return memcachedBinaryKeyRequired, 0, -1, true
	case 0x01, 0x02, 0x03, 0x11, 0x12, 0x13:
		return memcachedBinaryKeyRequired, 8, -1, true
	case 0x05, 0x06, 0x15, 0x16:
		return memcachedBinaryKeyRequired, 20, -1, true
	case 0x1c, 0x1d, 0x1e:
		return memcachedBinaryKeyRequired, 4, -1, true
	case 0x07, 0x0a, 0x0b, 0x17, 0x20:
		return memcachedBinaryKeyForbidden, 0, -1, true
	case 0x08, 0x18:
		return memcachedBinaryKeyForbidden, 0, 4, true
	case 0x1b:
		return memcachedBinaryKeyForbidden, 4, -1, true
	case 0x10:
		return memcachedBinaryKeyOptional, 0, -1, true
	default:
		return 0, 0, 0, false
	}
}

func memcachedBinaryExtrasLengthOK(
	got byte,
	wantA int,
	wantB int,
) bool {
	return int(got) == wantA || (wantB >= 0 && int(got) == wantB)
}

func validMemcachedASCIIRequestLine(line []byte) bool {
	tokens := bytes.Split(line, []byte(" "))
	if len(tokens) == 0 || hasEmptyToken(tokens) {
		return false
	}

	switch string(tokens[0]) {
	case "get", "gets":
		return len(tokens) >= 2 && validMemcachedKeys(tokens[1:])
	case "set", "add", "replace", "append", "prepend":
		return validMemcachedStorageCommand(tokens, 5)
	case "cas":
		return validMemcachedStorageCommand(tokens, 6)
	case "delete":
		return (len(tokens) == 2 || validMemcachedNoReply(tokens, 2)) &&
			validMemcachedKey(tokens[1])
	case "incr", "decr":
		return (len(tokens) == 3 || validMemcachedNoReply(tokens, 3)) &&
			validMemcachedKey(tokens[1]) &&
			validMemcachedDecimal(tokens[2])
	case "touch":
		return (len(tokens) == 3 || validMemcachedNoReply(tokens, 3)) &&
			validMemcachedKey(tokens[1]) &&
			validMemcachedDecimal(tokens[2])
	case "flush_all":
		return validMemcachedFlushAll(tokens)
	case "stats":
		return validMemcachedTokens(tokens[1:])
	case "version", "quit":
		return len(tokens) == 1
	case "verbosity":
		return (len(tokens) == 2 || validMemcachedNoReply(tokens, 2)) &&
			validMemcachedDecimal(tokens[1])
	default:
		return false
	}
}

func hasEmptyToken(tokens [][]byte) bool {
	for _, token := range tokens {
		if len(token) == 0 {
			return true
		}
	}
	return false
}

func validMemcachedStorageCommand(tokens [][]byte, baseTokens int) bool {
	if len(tokens) != baseTokens && !validMemcachedNoReply(tokens, baseTokens) {
		return false
	}
	if !validMemcachedKey(tokens[1]) {
		return false
	}
	for _, token := range tokens[2:baseTokens] {
		if !validMemcachedDecimal(token) {
			return false
		}
	}
	return true
}

func validMemcachedNoReply(tokens [][]byte, baseTokens int) bool {
	return len(tokens) == baseTokens+1 &&
		bytes.Equal(tokens[baseTokens], []byte("noreply"))
}

func validMemcachedFlushAll(tokens [][]byte) bool {
	switch len(tokens) {
	case 1:
		return true
	case 2:
		return bytes.Equal(tokens[1], []byte("noreply")) ||
			validMemcachedDecimal(tokens[1])
	case 3:
		return validMemcachedDecimal(tokens[1]) &&
			bytes.Equal(tokens[2], []byte("noreply"))
	default:
		return false
	}
}

func validMemcachedKeys(tokens [][]byte) bool {
	if len(tokens) == 0 {
		return false
	}
	for _, token := range tokens {
		if !validMemcachedKey(token) {
			return false
		}
	}
	return true
}

func validMemcachedTokens(tokens [][]byte) bool {
	for _, token := range tokens {
		if !validMemcachedToken(token) {
			return false
		}
	}
	return true
}

func validMemcachedKey(key []byte) bool {
	return len(key) <= 250 && validMemcachedToken(key)
}

func validMemcachedToken(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	for _, b := range token {
		if b <= ' ' || b == 0x7f {
			return false
		}
	}
	return true
}

func validMemcachedDecimal(token []byte) bool {
	if len(token) == 0 || len(token) > 20 {
		return false
	}
	for _, b := range token {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
