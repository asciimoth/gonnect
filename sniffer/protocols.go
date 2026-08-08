package sniffer

import "encoding/binary"

const (
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	amqpHeaderBytes  = 8
	amqp091Header    = "AMQP\x00\x00\x09\x01"
	amqp10Header     = "AMQP\x00\x01\x00\x00"
	amqp10SASLHeader = "AMQP\x03\x01\x00\x00"

	mqttConnectPacketTypeFlags      = 0x10
	mqttConnectMaxPrefixBytes       = 17
	mqttRemainingLengthMaxBytes     = 4
	mqttProtocolNameMinBytes        = 4
	mqttProtocolNameMaxBytes        = 6
	mqttConnectV311HeaderMinBytes   = 10
	mqttConnectClientIDLengthBytes  = 2
	mqttConnectV5PropertiesMinBytes = 1

	postgresqlHeaderBytes        = 8
	postgresqlCancelRequestBytes = 16
	postgresqlProtocol3          = 196608
	postgresqlCancelRequest      = 80877102
	postgresqlSSLRequest         = 80877103
	postgresqlGSSENCRequest      = 80877104

	mongoDBHeaderBytes = 16

	redisRESPMaxDecimalDigits      = 10
	redisRESPCommandMaxBytes       = 128
	redisRESPRequestMaxPrefixBytes = 1 +
		redisRESPMaxDecimalDigits + 2 +
		1 + redisRESPMaxDecimalDigits + 2 +
		redisRESPCommandMaxBytes + 2

	proxyProtocolV1Prefix      = "PROXY "
	proxyProtocolV2Signature   = "\r\n\r\n\x00\r\nQUIT\n"
	proxyProtocolV2HeaderBytes = 16

	socks4HeaderBytes      = 8
	socks5GreetingMinBytes = 2
	socks5GreetingMaxBytes = socks5GreetingMinBytes + 255

	dnsOverTCPLengthBytes     = 2
	dnsHeaderBytes            = 12
	dnsOverTCPMaxMessageBytes = 1<<16 - 1
)

// DefaultDNSOverTCPMessageMaxBytes is the default DNS-over-TCP message
// inspection limit used by DNSOverTCP and DNSOverTCPFactory.
//
// The limit applies to the DNS message bytes after the two-byte TCP length
// prefix. A message that declares a larger size mismatches.
const DefaultDNSOverTCPMessageMaxBytes = 4096

// HTTP2 returns a classifier for cleartext HTTP/2 prior knowledge.
//
// It matches the HTTP/2 client connection preface at stream offset zero. TLS
// connections that negotiate HTTP/2 by ALPN are still TLS streams; use TLS with
// an ALPN filter for those connections.
func HTTP2() Classifier {
	return Prefix([]byte(http2ClientPreface))
}

// HTTP2Factory returns a factory for HTTP2 classifiers.
func HTTP2Factory() Factory {
	return PrefixFactory([]byte(http2ClientPreface))
}

// AMQP returns a classifier for AMQP protocol headers.
//
// It matches the eight-byte protocol header for AMQP 0-9-1, AMQP 1.0, or
// AMQP 1.0 SASL negotiation. It does not inspect later connection tuning,
// SASL frames, or AMQP frames.
func AMQP() Classifier {
	return Or(
		Prefix([]byte(amqp091Header)),
		Prefix([]byte(amqp10Header)),
		Prefix([]byte(amqp10SASLHeader)),
	)
}

// AMQPFactory returns a factory for AMQP classifiers.
func AMQPFactory() Factory {
	return OrFactory(
		PrefixFactory([]byte(amqp091Header)),
		PrefixFactory([]byte(amqp10Header)),
		PrefixFactory([]byte(amqp10SASLHeader)),
	)
}

// MQTT returns a classifier for MQTT CONNECT packets.
//
// It validates the fixed header packet type, decodes the Remaining Length
// field, and checks the CONNECT variable header through protocol name, version
// level, connect flags, and keep-alive. MQTT 3.1, 3.1.1, and 5 CONNECT headers
// are accepted. The classifier matches before reading the client identifier or
// other payload fields.
func MQTT() Classifier {
	return &mqttClassifier{
		buf:   make([]byte, 0, mqttConnectMaxPrefixBytes),
		state: NeedMore,
	}
}

type mqttClassifier struct {
	buf   []byte
	state State
}

func (c *mqttClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == mqttConnectMaxPrefixBytes {
			c.state = Mismatch
			return c.state
		}
		c.buf = append(c.buf, b)

		state := matchMQTTConnectPrefix(c.buf)
		if state != NeedMore {
			c.state = state
			return c.state
		}
	}

	if len(c.buf) == mqttConnectMaxPrefixBytes {
		c.state = Mismatch
	}
	return c.state
}

func (c *mqttClassifier) MinSniffBufferSize() int {
	return mqttConnectMaxPrefixBytes
}

// MQTTFactory returns a factory for MQTT classifiers.
func MQTTFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		mqttConnectMaxPrefixBytes,
		FactoryFunc(MQTT),
	)
}

func matchMQTTConnectPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0] != mqttConnectPacketTypeFlags {
		return Mismatch
	}

	remainingLength, lengthBytes, complete, valid :=
		parseMQTTRemainingLength(data)
	if !valid {
		return Mismatch
	}
	if !complete {
		return NeedMore
	}
	if remainingLength < mqttConnectV311HeaderMinBytes {
		return Mismatch
	}

	variableHeaderOffset := 1 + lengthBytes
	if !protocolHasBytes(data, variableHeaderOffset, 2) {
		return NeedMore
	}

	nameLen := int(binary.BigEndian.Uint16(data[variableHeaderOffset:]))
	if nameLen != mqttProtocolNameMinBytes &&
		nameLen != mqttProtocolNameMaxBytes {
		return Mismatch
	}

	minVariableHeaderBytes := 2 + nameLen + 1 + 1 + 2
	if remainingLength < minVariableHeaderBytes {
		return Mismatch
	}

	headerBytes := variableHeaderOffset + minVariableHeaderBytes
	if !protocolHasBytes(data, 0, headerBytes) {
		return NeedMore
	}

	nameOffset := variableHeaderOffset + 2
	name := data[nameOffset : nameOffset+nameLen]
	level := data[nameOffset+nameLen]
	flags := data[nameOffset+nameLen+1]
	if !validMQTTConnectFlags(flags) {
		return Mismatch
	}

	switch string(name) {
	case "MQIsdp":
		if level == 3 &&
			remainingLength >= minVariableHeaderBytes+
				mqttConnectClientIDLengthBytes {
			return Match
		}
	case "MQTT":
		minRemainingLength := minVariableHeaderBytes +
			mqttConnectClientIDLengthBytes
		if level == 5 {
			minRemainingLength += mqttConnectV5PropertiesMinBytes
		}
		if (level == 4 || level == 5) &&
			remainingLength >= minRemainingLength {
			return Match
		}
	}
	return Mismatch
}

func validMQTTConnectFlags(flags byte) bool {
	if flags&0x01 != 0 {
		return false
	}
	if flags&0x40 != 0 && flags&0x80 == 0 {
		return false
	}

	willFlag := flags&0x04 != 0
	willQoS := (flags >> 3) & 0x03
	willRetain := flags&0x20 != 0
	if !willFlag && (willQoS != 0 || willRetain) {
		return false
	}
	return willQoS != 3
}

func parseMQTTRemainingLength(
	data []byte,
) (value int, lengthBytes int, complete bool, valid bool) {
	multiplier := 1
	for offset := 1; offset < len(data); offset++ {
		encoded := int(data[offset])
		value += (encoded & 0x7f) * multiplier
		if encoded&0x80 == 0 {
			return value, offset, true, true
		}
		if offset == mqttRemainingLengthMaxBytes {
			return 0, 0, false, false
		}
		multiplier *= 128
	}

	return 0, 0, false, true
}

// PostgreSQL returns a classifier for PostgreSQL client startup messages.
//
// It validates the first eight bytes of the client startup packet. Normal
// protocol 3.0 startup messages, SSLRequest, GSSENCRequest, and CancelRequest
// packets are accepted. It does not inspect startup parameters, user names,
// databases, or cancellation keys.
func PostgreSQL() Classifier {
	return &postgresqlClassifier{
		buf:   make([]byte, 0, postgresqlHeaderBytes),
		state: NeedMore,
	}
}

type postgresqlClassifier struct {
	buf   []byte
	state State
}

func (c *postgresqlClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == postgresqlHeaderBytes {
			break
		}
		c.buf = append(c.buf, b)
		if len(c.buf) == 4 && postgresqlPacketLength(c.buf) < 8 {
			c.state = Mismatch
			return c.state
		}
		if len(c.buf) == postgresqlHeaderBytes {
			if validPostgreSQLStartupHeader(c.buf) {
				c.state = Match
			} else {
				c.state = Mismatch
			}
			return c.state
		}
	}

	return NeedMore
}

func (c *postgresqlClassifier) MinSniffBufferSize() int {
	return postgresqlHeaderBytes
}

// PostgreSQLFactory returns a factory for PostgreSQL classifiers.
func PostgreSQLFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		postgresqlHeaderBytes,
		FactoryFunc(PostgreSQL),
	)
}

func validPostgreSQLStartupHeader(header []byte) bool {
	if len(header) != postgresqlHeaderBytes {
		return false
	}

	length := postgresqlPacketLength(header)
	code := binary.BigEndian.Uint32(header[4:8])
	switch code {
	case postgresqlProtocol3:
		return length > postgresqlHeaderBytes
	case postgresqlSSLRequest, postgresqlGSSENCRequest:
		return length == postgresqlHeaderBytes
	case postgresqlCancelRequest:
		return length == postgresqlCancelRequestBytes
	default:
		return false
	}
}

func postgresqlPacketLength(header []byte) uint32 {
	return binary.BigEndian.Uint32(header[:4])
}

// MongoDB returns a classifier for MongoDB wire protocol request messages.
//
// It validates the 16-byte wire message header, requires a client request
// opcode, and requires responseTo to be zero. It does not inspect BSON command
// documents or compressed message bodies.
func MongoDB() Classifier {
	return &mongoDBClassifier{
		buf:   make([]byte, 0, mongoDBHeaderBytes),
		state: NeedMore,
	}
}

type mongoDBClassifier struct {
	buf   []byte
	state State
}

func (c *mongoDBClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == mongoDBHeaderBytes {
			break
		}
		c.buf = append(c.buf, b)
		if len(c.buf) == 4 && mongoDBMessageLength(c.buf) < mongoDBHeaderBytes {
			c.state = Mismatch
			return c.state
		}
		if len(c.buf) == mongoDBHeaderBytes {
			if validMongoDBHeader(c.buf) {
				c.state = Match
			} else {
				c.state = Mismatch
			}
			return c.state
		}
	}

	return NeedMore
}

func (c *mongoDBClassifier) MinSniffBufferSize() int {
	return mongoDBHeaderBytes
}

// MongoDBFactory returns a factory for MongoDB classifiers.
func MongoDBFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		mongoDBHeaderBytes,
		FactoryFunc(MongoDB),
	)
}

func validMongoDBHeader(header []byte) bool {
	if len(header) != mongoDBHeaderBytes ||
		mongoDBMessageLength(header) < mongoDBHeaderBytes {
		return false
	}

	responseTo := binary.LittleEndian.Uint32(header[8:12])
	opcode := binary.LittleEndian.Uint32(header[12:16])
	return responseTo == 0 && validMongoDBClientOpcode(opcode)
}

func mongoDBMessageLength(header []byte) uint32 {
	return binary.LittleEndian.Uint32(header[:4])
}

func validMongoDBClientOpcode(opcode uint32) bool {
	switch opcode {
	case 2001, 2002, 2004, 2005, 2006, 2007, 2012, 2013:
		return true
	default:
		return false
	}
}

// Redis returns a classifier for Redis RESP array requests.
//
// It validates the first request array and its first bulk-string command name.
// Inline Redis commands are intentionally not matched because their text forms
// are ambiguous with other line-oriented protocols. The command name must be
// non-empty, use printable non-space bytes, and be no larger than 128 bytes.
func Redis() Classifier {
	return &redisRESPClassifier{
		buf:   make([]byte, 0, redisRESPRequestMaxPrefixBytes),
		state: NeedMore,
	}
}

type redisRESPClassifier struct {
	buf   []byte
	state State
}

func (c *redisRESPClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == redisRESPRequestMaxPrefixBytes {
			c.state = Mismatch
			return c.state
		}
		c.buf = append(c.buf, b)

		state := matchRedisRESPRequestPrefix(c.buf)
		if state != NeedMore {
			c.state = state
			return c.state
		}
	}

	if len(c.buf) == redisRESPRequestMaxPrefixBytes {
		c.state = Mismatch
	}
	return c.state
}

func (c *redisRESPClassifier) MinSniffBufferSize() int {
	return redisRESPRequestMaxPrefixBytes
}

// RedisFactory returns a factory for Redis classifiers.
func RedisFactory() Factory {
	return FactoryWithMinSniffBufferSize(
		redisRESPRequestMaxPrefixBytes,
		FactoryFunc(Redis),
	)
}

func matchRedisRESPRequestPrefix(data []byte) State {
	if len(data) == 0 {
		return NeedMore
	}
	if data[0] != '*' {
		return Mismatch
	}

	_, offset, state := parsePositiveDecimalCRLF(
		data,
		1,
		redisRESPMaxDecimalDigits,
	)
	if state != Match {
		return state
	}

	if !protocolHasBytes(data, offset, 1) {
		return NeedMore
	}
	if data[offset] != '$' {
		return Mismatch
	}

	bulkLen, offset, state := parsePositiveDecimalCRLF(
		data,
		offset+1,
		redisRESPMaxDecimalDigits,
	)
	if state != Match {
		return state
	}
	if bulkLen > redisRESPCommandMaxBytes {
		return Mismatch
	}
	if !protocolHasBytes(data, offset, bulkLen+2) {
		return NeedMore
	}

	command := data[offset : offset+bulkLen]
	if !validRedisCommandName(command) ||
		data[offset+bulkLen] != '\r' ||
		data[offset+bulkLen+1] != '\n' {
		return Mismatch
	}
	return Match
}

func parsePositiveDecimalCRLF(
	data []byte,
	offset int,
	maxDigits int,
) (value int, next int, state State) {
	digits := 0
	for i := offset; i < len(data); i++ {
		b := data[i]
		switch {
		case b >= '0' && b <= '9':
			if digits == maxDigits {
				return 0, 0, Mismatch
			}
			digits++
			value = value*10 + int(b-'0')
		case b == '\r':
			if digits == 0 {
				return 0, 0, Mismatch
			}
			if i+1 == len(data) {
				return 0, 0, NeedMore
			}
			if data[i+1] != '\n' || value == 0 {
				return 0, 0, Mismatch
			}
			return value, i + 2, Match
		default:
			return 0, 0, Mismatch
		}
	}
	return 0, 0, NeedMore
}

func validRedisCommandName(command []byte) bool {
	if len(command) == 0 {
		return false
	}
	for _, b := range command {
		if b <= ' ' || b == 0x7f {
			return false
		}
	}
	return true
}

// ProxyProtocolV1 returns a classifier for HAProxy PROXY protocol v1.
//
// It matches the ASCII prefix "PROXY " at stream offset zero. This is a
// routing heuristic, not a full PROXY v1 header parser. It does not validate
// the source address, destination address, ports, or line ending.
func ProxyProtocolV1() Classifier {
	return Prefix([]byte(proxyProtocolV1Prefix))
}

// ProxyProtocolV1Factory returns a factory for PROXY protocol v1 classifiers.
func ProxyProtocolV1Factory() Factory {
	return PrefixFactory([]byte(proxyProtocolV1Prefix))
}

// ProxyProtocolV2 returns a classifier for HAProxy PROXY protocol v2.
//
// It validates the binary signature and fixed 16-byte header. For PROXY
// commands with a known address family, it also checks that the declared
// payload length can contain the required source and destination addresses.
// It does not inspect address values or TLVs.
func ProxyProtocolV2() Classifier {
	return &proxyProtocolV2Classifier{
		buf:   make([]byte, 0, proxyProtocolV2HeaderBytes),
		state: NeedMore,
	}
}

type proxyProtocolV2Classifier struct {
	buf   []byte
	state State
}

func (c *proxyProtocolV2Classifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == proxyProtocolV2HeaderBytes {
			break
		}

		offset := len(c.buf)
		c.buf = append(c.buf, b)
		if offset < len(proxyProtocolV2Signature) &&
			b != proxyProtocolV2Signature[offset] {
			c.state = Mismatch
			return c.state
		}

		if len(c.buf) == proxyProtocolV2HeaderBytes {
			if validProxyProtocolV2Header(c.buf) {
				c.state = Match
			} else {
				c.state = Mismatch
			}
			return c.state
		}
	}

	return NeedMore
}

func (c *proxyProtocolV2Classifier) MinSniffBufferSize() int {
	return proxyProtocolV2HeaderBytes
}

// ProxyProtocolV2Factory returns a factory for PROXY protocol v2 classifiers.
func ProxyProtocolV2Factory() Factory {
	return FactoryWithMinSniffBufferSize(
		proxyProtocolV2HeaderBytes,
		FactoryFunc(ProxyProtocolV2),
	)
}

// ProxyProtocol returns a classifier for HAProxy PROXY protocol v1 or v2.
func ProxyProtocol() Classifier {
	return Or(ProxyProtocolV1(), ProxyProtocolV2())
}

// ProxyProtocolFactory returns a factory for PROXY protocol classifiers.
func ProxyProtocolFactory() Factory {
	return OrFactory(ProxyProtocolV1Factory(), ProxyProtocolV2Factory())
}

func validProxyProtocolV2Header(header []byte) bool {
	if len(header) != proxyProtocolV2HeaderBytes ||
		string(header[:len(proxyProtocolV2Signature)]) !=
			proxyProtocolV2Signature {
		return false
	}

	versionCommand := header[12]
	if versionCommand>>4 != 2 {
		return false
	}
	command := versionCommand & 0x0f
	if command != 0 && command != 1 {
		return false
	}

	familyProtocol := header[13]
	family := familyProtocol >> 4
	protocol := familyProtocol & 0x0f
	if !validProxyProtocolV2FamilyProtocol(family, protocol) {
		return false
	}

	if command == 0 {
		return true
	}

	payloadLen := int(binary.BigEndian.Uint16(header[14:16]))
	return payloadLen >= proxyProtocolV2AddressBytes(family)
}

func validProxyProtocolV2FamilyProtocol(family byte, protocol byte) bool {
	switch family {
	case 0:
		return protocol == 0
	case 1, 2, 3:
		return protocol == 1 || protocol == 2
	default:
		return false
	}
}

func proxyProtocolV2AddressBytes(family byte) int {
	switch family {
	case 1:
		return 12
	case 2:
		return 36
	case 3:
		return 216
	default:
		return 0
	}
}

// SOCKS4 returns a classifier for SOCKS4 and SOCKS4a requests.
//
// It validates the fixed request header: version 4, CONNECT or BIND command,
// non-zero destination port, and non-zero destination address marker. It
// matches before reading the user ID or the optional SOCKS4a hostname.
func SOCKS4() Classifier {
	return &socks4Classifier{
		buf:   make([]byte, 0, socks4HeaderBytes),
		state: NeedMore,
	}
}

type socks4Classifier struct {
	buf   []byte
	state State
}

func (c *socks4Classifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == socks4HeaderBytes {
			break
		}

		offset := len(c.buf)
		c.buf = append(c.buf, b)
		switch offset {
		case 0:
			if b != 4 {
				c.state = Mismatch
				return c.state
			}
		case 1:
			if b != 1 && b != 2 {
				c.state = Mismatch
				return c.state
			}
		}

		if len(c.buf) == socks4HeaderBytes {
			if validSOCKS4Header(c.buf) {
				c.state = Match
			} else {
				c.state = Mismatch
			}
			return c.state
		}
	}

	return NeedMore
}

func (c *socks4Classifier) MinSniffBufferSize() int {
	return socks4HeaderBytes
}

// SOCKS4Factory returns a factory for SOCKS4 classifiers.
func SOCKS4Factory() Factory {
	return FactoryWithMinSniffBufferSize(
		socks4HeaderBytes,
		FactoryFunc(SOCKS4),
	)
}

func validSOCKS4Header(header []byte) bool {
	if len(header) != socks4HeaderBytes ||
		header[0] != 4 ||
		(header[1] != 1 && header[1] != 2) {
		return false
	}
	if binary.BigEndian.Uint16(header[2:4]) == 0 {
		return false
	}
	for _, b := range header[4:8] {
		if b != 0 {
			return true
		}
	}
	return false
}

// SOCKS5 returns a classifier for SOCKS5 client greetings.
//
// It validates the version byte, waits for the declared method list, and
// rejects empty method lists.
func SOCKS5() Classifier {
	return &socks5Classifier{
		buf:       make([]byte, 0, socks5GreetingMinBytes),
		needBytes: socks5GreetingMinBytes,
		state:     NeedMore,
	}
}

type socks5Classifier struct {
	buf       []byte
	needBytes int
	state     State
}

func (c *socks5Classifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	for _, b := range p {
		if len(c.buf) == c.needBytes {
			break
		}

		offset := len(c.buf)
		c.buf = append(c.buf, b)
		switch offset {
		case 0:
			if b != 5 {
				c.state = Mismatch
				return c.state
			}
		case 1:
			if b == 0 {
				c.state = Mismatch
				return c.state
			}
			c.needBytes = socks5GreetingMinBytes + int(b)
		}

		if len(c.buf) == c.needBytes {
			c.state = Match
			return c.state
		}
	}

	return NeedMore
}

func (c *socks5Classifier) MinSniffBufferSize() int {
	return socks5GreetingMaxBytes
}

// SOCKS5Factory returns a factory for SOCKS5 classifiers.
func SOCKS5Factory() Factory {
	return FactoryWithMinSniffBufferSize(
		socks5GreetingMaxBytes,
		FactoryFunc(SOCKS5),
	)
}

// SOCKS returns a classifier for SOCKS4, SOCKS4a, or SOCKS5 client streams.
func SOCKS() Classifier {
	return Or(SOCKS4(), SOCKS5())
}

// SOCKSFactory returns a factory for SOCKS classifiers.
func SOCKSFactory() Factory {
	return OrFactory(SOCKS4Factory(), SOCKS5Factory())
}

// DNSOverTCPConfig configures a DNS-over-TCP classifier.
//
// MaxMessageBytes bounds the DNS message bytes after the two-byte TCP length
// prefix. Zero uses DefaultDNSOverTCPMessageMaxBytes. A negative value, or a
// value above the 65535-byte DNS TCP length field, is a programming error and
// causes a panic.
type DNSOverTCPConfig struct {
	MaxMessageBytes int
}

// DNSOverTCP returns a classifier that matches a DNS-over-TCP query.
//
// The classifier reads the two-byte TCP length prefix, then validates a DNS
// message header and question section. It requires a client query, not a
// response, and at least one question.
func DNSOverTCP() Classifier {
	return DNSOverTCPWithConfig(DNSOverTCPConfig{})
}

// DNSOverTCPWithConfig returns a DNS-over-TCP classifier that uses config.
func DNSOverTCPWithConfig(config DNSOverTCPConfig) Classifier {
	return newDNSOverTCPClassifier(normalizeDNSOverTCPConfig(config))
}

// DNSOverTCPFactory returns a factory for DNSOverTCP classifiers.
func DNSOverTCPFactory() Factory {
	return DNSOverTCPFactoryWithConfig(DNSOverTCPConfig{})
}

// DNSOverTCPFactoryWithConfig returns a factory for DNS-over-TCP classifiers
// that use config.
func DNSOverTCPFactoryWithConfig(config DNSOverTCPConfig) Factory {
	normalized := normalizeDNSOverTCPConfig(config)
	return FactoryWithMinSniffBufferSize(
		normalized.minSniffBufferSize(),
		FactoryFunc(func() Classifier {
			return newDNSOverTCPClassifier(normalized)
		}),
	)
}

type normalizedDNSOverTCPConfig struct {
	maxMessageBytes int
}

func (c normalizedDNSOverTCPConfig) minSniffBufferSize() int {
	return dnsOverTCPLengthBytes + c.maxMessageBytes
}

func normalizeDNSOverTCPConfig(
	config DNSOverTCPConfig,
) normalizedDNSOverTCPConfig {
	if config.MaxMessageBytes < 0 {
		panic("sniffer: negative DNS-over-TCP message byte limit")
	}
	if config.MaxMessageBytes > dnsOverTCPMaxMessageBytes {
		panic("sniffer: DNS-over-TCP message byte limit is too large")
	}

	maxMessageBytes := config.MaxMessageBytes
	if maxMessageBytes == 0 {
		maxMessageBytes = DefaultDNSOverTCPMessageMaxBytes
	}
	return normalizedDNSOverTCPConfig{maxMessageBytes: maxMessageBytes}
}

func newDNSOverTCPClassifier(
	config normalizedDNSOverTCPConfig,
) Classifier {
	return &dnsOverTCPClassifier{
		config:    config,
		buf:       make([]byte, 0, dnsOverTCPLengthBytes),
		needBytes: dnsOverTCPLengthBytes,
		state:     NeedMore,
	}
}

type dnsOverTCPClassifier struct {
	config    normalizedDNSOverTCPConfig
	buf       []byte
	needBytes int
	state     State
}

func (c *dnsOverTCPClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	if len(p) != 0 {
		limit := c.config.minSniffBufferSize()
		remaining := limit - len(c.buf)
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

	if len(c.buf) < dnsOverTCPLengthBytes {
		return NeedMore
	}

	messageLen := int(binary.BigEndian.Uint16(c.buf[:dnsOverTCPLengthBytes]))
	if messageLen < dnsHeaderBytes ||
		messageLen > c.config.maxMessageBytes {
		c.state = Mismatch
		return c.state
	}

	c.needBytes = dnsOverTCPLengthBytes + messageLen
	if len(c.buf) < c.needBytes {
		return NeedMore
	}

	if validDNSOverTCPQuery(c.buf[dnsOverTCPLengthBytes:c.needBytes]) {
		c.state = Match
	} else {
		c.state = Mismatch
	}
	return c.state
}

func (c *dnsOverTCPClassifier) MinSniffBufferSize() int {
	return c.config.minSniffBufferSize()
}

func validDNSOverTCPQuery(message []byte) bool {
	if len(message) < dnsHeaderBytes {
		return false
	}

	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 != 0 {
		return false
	}
	opcode := (flags >> 11) & 0x0f
	if opcode > 5 {
		return false
	}

	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	if questionCount == 0 {
		return false
	}

	offset := dnsHeaderBytes
	for range questionCount {
		var ok bool
		offset, ok = skipDNSName(message, offset)
		if !ok || !protocolHasBytes(message, offset, 4) {
			return false
		}
		qtype := binary.BigEndian.Uint16(message[offset:])
		qclass := binary.BigEndian.Uint16(message[offset+2:])
		if qtype == 0 || qclass == 0 {
			return false
		}
		offset += 4
	}
	return offset <= len(message)
}

func skipDNSName(message []byte, offset int) (int, bool) {
	nameBytes := 0
	for {
		if !protocolHasBytes(message, offset, 1) {
			return 0, false
		}

		length := int(message[offset])
		switch length & 0xc0 {
		case 0:
			offset++
			nameBytes++
			if nameBytes > 255 {
				return 0, false
			}
			if length == 0 {
				return offset, true
			}
			if !protocolHasBytes(message, offset, length) {
				return 0, false
			}
			offset += length
			nameBytes += length
			if nameBytes > 255 {
				return 0, false
			}
		case 0xc0:
			if !protocolHasBytes(message, offset, 2) {
				return 0, false
			}
			pointer := int(binary.BigEndian.Uint16(message[offset:]) & 0x3fff)
			if pointer >= len(message) {
				return 0, false
			}
			return offset + 2, true
		default:
			return 0, false
		}
	}
}

func protocolHasBytes(data []byte, offset int, count int) bool {
	return count >= 0 &&
		offset >= 0 &&
		offset <= len(data) &&
		count <= len(data)-offset
}
