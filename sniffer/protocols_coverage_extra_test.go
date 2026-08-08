//nolint:testpackage // These tests exercise unexported parser branches.
package sniffer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestCoverageProtocolFactoryClassifiers(t *testing.T) {
	tests := []struct {
		name    string
		factory Factory
		input   []byte
	}{
		{
			name:    "RTSP",
			factory: RTSPFactory(),
			input:   []byte("OPTIONS rtsp://example.test/live RTSP/1.0\r\n"),
		},
		{
			name:    "SIP",
			factory: SIPFactory(),
			input:   []byte("ACK sip:bob@example.test SIP/2.0\r\n"),
		},
		{
			name:    "STUN",
			factory: STUNFactory(),
			input:   coverageSTUNHeader(0x0001, 0),
		},
		{
			name:    "RDP",
			factory: RDPFactory(),
			input:   coverageRDPHeader(),
		},
		{
			name:    "SMB",
			factory: SMBFactory(),
			input:   coverageSMB1Header(),
		},
		{
			name:    "LDAP",
			factory: LDAPFactory(),
			input:   []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x60},
		},
		{
			name:    "Cassandra",
			factory: CassandraFactory(),
			input:   coverageCassandraHeader(4, 0, 0x01, 2),
		},
		{
			name:    "memcached binary",
			factory: MemcachedBinaryFactory(),
			input:   coverageMemcachedBinaryHeader(0x00, 1, 0, 1),
		},
		{
			name:    "memcached ASCII",
			factory: MemcachedASCIIFactory(),
			input:   []byte("version\r\n"),
		},
		{
			name:    "DNS over TCP",
			factory: DNSOverTCPFactory(),
			input:   coverageDNSOverTCPQuery("example.test"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.factory.NewClassifier().
				Feed(test.input); got != Match {
				t.Fatalf("state = %v, want Match", got)
			}
		})
	}
}

func TestCoverageProtocolFeedLimitBranches(t *testing.T) {
	t.Run("MQTT already full", func(t *testing.T) {
		classifier := &mqttClassifier{
			buf:   bytes.Repeat([]byte{0}, mqttConnectMaxPrefixBytes),
			state: NeedMore,
		}
		if got := classifier.Feed([]byte{0}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("MQTT full after empty feed", func(t *testing.T) {
		classifier := &mqttClassifier{
			buf:   bytes.Repeat([]byte{0}, mqttConnectMaxPrefixBytes),
			state: NeedMore,
		}
		if got := classifier.Feed(nil); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("Redis already full", func(t *testing.T) {
		classifier := &redisRESPClassifier{
			buf:   bytes.Repeat([]byte{0}, redisRESPRequestMaxPrefixBytes),
			state: NeedMore,
		}
		if got := classifier.Feed([]byte{0}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("Redis full after empty feed", func(t *testing.T) {
		classifier := &redisRESPClassifier{
			buf:   bytes.Repeat([]byte{0}, redisRESPRequestMaxPrefixBytes),
			state: NeedMore,
		}
		if got := classifier.Feed(nil); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("protocol prefix already full", func(t *testing.T) {
		classifier := &protocolPrefixClassifier{
			buf:      []byte{'x'},
			maxBytes: 1,
			match:    func([]byte) State { return NeedMore },
			state:    NeedMore,
		}
		if got := classifier.Feed([]byte{'y'}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("protocol prefix full after feed", func(t *testing.T) {
		classifier := newProtocolPrefixClassifier(
			1,
			func([]byte) State { return NeedMore },
		)
		if got := classifier.Feed([]byte{'x'}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("bounded line already full", func(t *testing.T) {
		classifier := &boundedCRLFLineClassifier{
			line:     []byte{'x'},
			maxBytes: 1,
			valid:    func([]byte) bool { return true },
			state:    NeedMore,
		}
		if got := classifier.Feed([]byte{'y'}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("bounded line bad carriage return", func(t *testing.T) {
		classifier := newBoundedCRLFLineClassifier(
			4,
			func([]byte) bool { return true },
		)
		if got := classifier.Feed([]byte{'\r', 'x'}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run("bounded line full after feed", func(t *testing.T) {
		classifier := newBoundedCRLFLineClassifier(
			1,
			func([]byte) bool { return true },
		)
		if got := classifier.Feed([]byte{'x'}); got != Mismatch {
			t.Fatalf("state = %v, want Mismatch", got)
		}
	})

	t.Run(
		"fixed header classifiers ignore extra data when directly full",
		func(t *testing.T) {
			tests := []struct {
				name       string
				classifier Classifier
			}{
				{
					name: "PostgreSQL",
					classifier: &postgresqlClassifier{
						buf:   bytes.Repeat([]byte{0}, postgresqlHeaderBytes),
						state: NeedMore,
					},
				},
				{
					name: "MongoDB",
					classifier: &mongoDBClassifier{
						buf:   bytes.Repeat([]byte{0}, mongoDBHeaderBytes),
						state: NeedMore,
					},
				},
				{
					name: "PROXY v2",
					classifier: &proxyProtocolV2Classifier{
						buf: bytes.Repeat(
							[]byte{0},
							proxyProtocolV2HeaderBytes,
						),
						state: NeedMore,
					},
				},
				{
					name: "SOCKS4",
					classifier: &socks4Classifier{
						buf:   bytes.Repeat([]byte{0}, socks4HeaderBytes),
						state: NeedMore,
					},
				},
				{
					name: "SOCKS5",
					classifier: &socks5Classifier{
						buf: bytes.Repeat(
							[]byte{0},
							socks5GreetingMinBytes,
						),
						needBytes: socks5GreetingMinBytes,
						state:     NeedMore,
					},
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					if got := test.classifier.Feed([]byte{0}); got != NeedMore {
						t.Fatalf("state = %v, want NeedMore", got)
					}
				})
			}
		},
	)

	t.Run("terminal states", func(t *testing.T) {
		proxy := ProxyProtocolV2()
		if got := proxy.Feed(
			coverageProxyProtocolV2Header(0x21, 0x11, 12),
		); got != Match {
			t.Fatalf("PROXY v2 match = %v, want Match", got)
		}
		if got := proxy.Feed([]byte("ignored")); got != Match {
			t.Fatalf("terminal PROXY v2 = %v, want Match", got)
		}

		socks5 := SOCKS5()
		if got := socks5.Feed([]byte{5, 1, 0}); got != Match {
			t.Fatalf("SOCKS5 match = %v, want Match", got)
		}
		if got := socks5.Feed([]byte("ignored")); got != Match {
			t.Fatalf("terminal SOCKS5 = %v, want Match", got)
		}
	})
}

func TestCoverageProtocolPrivateHelpers(t *testing.T) {
	if got := matchMQTTConnectPrefix(nil); got != NeedMore {
		t.Fatalf("empty MQTT prefix = %v, want NeedMore", got)
	}
	shortMQTTHeader := []byte{
		0x10, 10,
		0, 6,
		'M', 'Q', 'I', 's', 'd', 'p',
	}
	if got := matchMQTTConnectPrefix(shortMQTTHeader); got != Mismatch {
		t.Fatalf("short MQTT header = %v, want Mismatch", got)
	}

	if validPostgreSQLStartupHeader(nil) {
		t.Fatal("short PostgreSQL header was valid")
	}
	if got := PostgreSQL().MinSniffBufferSize(); got != postgresqlHeaderBytes {
		t.Fatalf("PostgreSQL size = %d, want %d", got, postgresqlHeaderBytes)
	}

	if validMongoDBHeader(nil) {
		t.Fatal("short MongoDB header was valid")
	}
	if got := MongoDB().MinSniffBufferSize(); got != mongoDBHeaderBytes {
		t.Fatalf("MongoDB size = %d, want %d", got, mongoDBHeaderBytes)
	}

	if got := matchRedisRESPRequestPrefix(nil); got != NeedMore {
		t.Fatalf("empty Redis prefix = %v, want NeedMore", got)
	}
	if _, _, got := parsePositiveDecimalCRLF(
		[]byte("\r\n"),
		0,
		10,
	); got != Mismatch {
		t.Fatalf("empty Redis decimal = %v, want Mismatch", got)
	}
	if validRedisCommandName(nil) {
		t.Fatal("empty Redis command was valid")
	}

	badSignature := append([]byte("bad signature"), 0, 0, 0)
	if validProxyProtocolV2Header(badSignature[:proxyProtocolV2HeaderBytes]) {
		t.Fatal("bad PROXY v2 signature was valid")
	}
	if !validProxyProtocolV2Header(
		coverageProxyProtocolV2Header(0x20, 0x00, 0),
	) {
		t.Fatal("PROXY v2 LOCAL header was invalid")
	}
	if !validProxyProtocolV2FamilyProtocol(2, 2) {
		t.Fatal("PROXY v2 IPv6 stream protocol was invalid")
	}
	if validProxyProtocolV2FamilyProtocol(0, 1) {
		t.Fatal("PROXY v2 unspecified stream protocol was valid")
	}
	if got := proxyProtocolV2AddressBytes(2); got != 36 {
		t.Fatalf("IPv6 bytes = %d, want 36", got)
	}
	if got := proxyProtocolV2AddressBytes(3); got != 216 {
		t.Fatalf("Unix bytes = %d, want 216", got)
	}
	if got := proxyProtocolV2AddressBytes(0); got != 0 {
		t.Fatalf("unspecified bytes = %d, want 0", got)
	}

	if got := SOCKS4().Feed([]byte{4, 3}); got != Mismatch {
		t.Fatalf("bad SOCKS4 command = %v, want Mismatch", got)
	}
	if validSOCKS4Header(nil) {
		t.Fatal("short SOCKS4 header was valid")
	}
	zeroAddress := []byte{4, 1, 0, 80, 0, 0, 0, 0}
	if validSOCKS4Header(zeroAddress) {
		t.Fatal("SOCKS4 zero address was valid")
	}
}

func TestCoverageDNSOverTCPBranches(t *testing.T) {
	query := coverageDNSOverTCPQuery("example.test")
	classifier := DNSOverTCPWithConfig(DNSOverTCPConfig{
		MaxMessageBytes: len(query) - dnsOverTCPLengthBytes,
	})
	if got := classifier.Feed(append(query, 0xff)); got != Match {
		t.Fatalf("oversized read chunk = %v, want Match", got)
	}

	noRoom := &dnsOverTCPClassifier{
		config: normalizedDNSOverTCPConfig{maxMessageBytes: 0},
		buf:    bytes.Repeat([]byte{0}, dnsOverTCPLengthBytes),
		state:  NeedMore,
	}
	if got := noRoom.Feed([]byte{0}); got != Mismatch {
		t.Fatalf("no room state = %v, want Mismatch", got)
	}

	if validDNSOverTCPQuery(nil) {
		t.Fatal("short DNS message was valid")
	}

	message := coverageDNSQueryMessage("example.test")
	withOpcode := append([]byte(nil), message...)
	withOpcode[2] = 0x30
	if validDNSOverTCPQuery(withOpcode) {
		t.Fatal("DNS message with reserved opcode was valid")
	}

	noQuestions := append([]byte(nil), message...)
	binary.BigEndian.PutUint16(noQuestions[4:6], 0)
	if validDNSOverTCPQuery(noQuestions) {
		t.Fatal("DNS message without questions was valid")
	}

	zeroQType := append([]byte(nil), message...)
	questionOffset := len(zeroQType) - 4
	binary.BigEndian.PutUint16(zeroQType[questionOffset:], 0)
	if validDNSOverTCPQuery(zeroQType) {
		t.Fatal("DNS message with zero qtype was valid")
	}

	zeroQClass := append([]byte(nil), message...)
	binary.BigEndian.PutUint16(zeroQClass[questionOffset+2:], 0)
	if validDNSOverTCPQuery(zeroQClass) {
		t.Fatal("DNS message with zero qclass was valid")
	}

	if _, ok := skipDNSName(nil, 0); ok {
		t.Fatal("missing DNS name byte was valid")
	}
	if _, ok := skipDNSName([]byte{3, 'a'}, 0); ok {
		t.Fatal("truncated DNS label was valid")
	}
	if _, ok := skipDNSName(coverageDNSNameBytesBeforeLabelLimit(), 0); ok {
		t.Fatal("oversize DNS name before label was valid")
	}
	if _, ok := skipDNSName(coverageDNSNameBytesAfterLabelLimit(), 0); ok {
		t.Fatal("oversize DNS name after label was valid")
	}
	if _, ok := skipDNSName([]byte{0xc0}, 0); ok {
		t.Fatal("truncated DNS pointer was valid")
	}
	offset, ok := skipDNSName([]byte{0xc0, 0}, 0)
	if !ok || offset != 2 {
		t.Fatalf("DNS pointer = (%d, %v), want (2, true)", offset, ok)
	}
	if _, ok := skipDNSName([]byte{0x40}, 0); ok {
		t.Fatal("reserved DNS label form was valid")
	}
}

func TestCoverageWellKnownConstructorsAndHelpers(t *testing.T) {
	requireCoveragePanic(t, func() {
		_ = newProtocolPrefixClassifier(-1, func([]byte) State {
			return NeedMore
		})
	})
	requireCoveragePanic(t, func() {
		_ = newProtocolPrefixClassifier(1, nil)
	})
	requireCoveragePanic(t, func() {
		_ = newBoundedCRLFLineClassifier(-1, func([]byte) bool {
			return true
		})
	})
	requireCoveragePanic(t, func() {
		_ = newBoundedCRLFLineClassifier(1, nil)
	})

	if validTextRequestTarget(nil) {
		t.Fatal("empty text request target was valid")
	}
	if validTextRequestTarget([]byte("bad\x7f")) {
		t.Fatal("control text request target was valid")
	}

	if got := matchSTUNHeaderPrefix(nil); got != NeedMore {
		t.Fatalf("empty STUN prefix = %v, want NeedMore", got)
	}
	if validSTUNMessageType(0xc001) {
		t.Fatal("STUN message type with top bits was valid")
	}

	if got := matchRDPConnectionRequestPrefix(nil); got != NeedMore {
		t.Fatalf("empty RDP prefix = %v, want NeedMore", got)
	}
	if got := matchRDPConnectionRequestPrefix([]byte{3, 1}); got != Mismatch {
		t.Fatalf("bad RDP reserved byte = %v, want Mismatch", got)
	}
	if got := matchRDPConnectionRequestPrefix(
		[]byte{3, 0, 0, 11, 5},
	); got != Mismatch {
		t.Fatalf("short RDP COTP header = %v, want Mismatch", got)
	}
	badRDPType := coverageRDPHeader()
	badRDPType[5] = 0xd0
	if validRDPConnectionRequestHeader(badRDPType) {
		t.Fatal("RDP header with bad type was valid")
	}
	badRDPSize := coverageRDPHeader()
	badRDPSize[4] = 5
	if validRDPConnectionRequestHeader(badRDPSize) {
		t.Fatal("RDP header with short COTP size was valid")
	}

	if got := matchSMBOverTCPRequestPrefix(nil); got != NeedMore {
		t.Fatalf("empty SMB prefix = %v, want NeedMore", got)
	}
	if got := matchSMBOverTCPRequestPrefix([]byte{0, 2}); got != Mismatch {
		t.Fatalf("bad SMB length byte = %v, want Mismatch", got)
	}
	if validSMBOverTCPRequestHeader(nil) {
		t.Fatal("short SMB header was valid")
	}
	badSMBProtocol := bytes.Repeat([]byte{0}, smbOverTCPRequestMinBytes)
	if validSMBOverTCPRequestHeader(badSMBProtocol) {
		t.Fatal("SMB header with bad protocol was valid")
	}
}

func TestCoverageLDAPAndCassandraHelpers(t *testing.T) {
	if got := matchLDAPMessagePrefix(nil); got != NeedMore {
		t.Fatalf("empty LDAP prefix = %v, want NeedMore", got)
	}
	ldapInputs := []struct {
		name string
		in   []byte
	}{
		{name: "short message length", in: []byte{0x30, 0x04}},
		{name: "bad message id tag", in: []byte{0x30, 0x05, 0x03}},
		{name: "zero message id length", in: []byte{0x30, 0x05, 0x02, 0}},
		{name: "message id outside message", in: []byte{0x30, 0x05, 0x02, 4}},
		{
			name: "missing protocol op",
			in:   []byte{0x30, 0x05, 0x02, 3, 0, 0, 1},
		},
	}
	for _, input := range ldapInputs {
		t.Run(input.name, func(t *testing.T) {
			if got := matchLDAPMessagePrefix(input.in); got != Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if _, _, got := parseBERDefiniteLength(
		[]byte{0x82, 1, 0},
		0,
		1,
	); got != Mismatch {
		t.Fatalf("too many BER length octets = %v, want Mismatch", got)
	}
	if _, _, got := parseBERDefiniteLength(
		[]byte{0x81, 0},
		0,
		1,
	); got != Mismatch {
		t.Fatalf("leading-zero BER length = %v, want Mismatch", got)
	}

	if got := matchCassandraRequestHeaderPrefix(nil); got != NeedMore {
		t.Fatalf("empty Cassandra prefix = %v, want NeedMore", got)
	}
	if validCassandraRequestHeader(nil) {
		t.Fatal("short Cassandra header was valid")
	}
	hugeBody := coverageCassandraHeader(4, 0, 0x01, 1<<31)
	if validCassandraRequestHeader(hugeBody) {
		t.Fatal("Cassandra header with huge body was valid")
	}
	badOpcode := coverageCassandraHeader(4, 0, 0x02, 0)
	if validCassandraRequestHeader(badOpcode) {
		t.Fatal("Cassandra header with bad opcode was valid")
	}
}

func TestCoverageMemcachedHelpers(t *testing.T) {
	if got := matchMemcachedBinaryHeaderPrefix(nil); got != NeedMore {
		t.Fatalf("empty memcached binary prefix = %v, want NeedMore", got)
	}
	if validMemcachedBinaryHeader(nil) {
		t.Fatal("short memcached binary header was valid")
	}
	badDataType := coverageMemcachedBinaryHeader(0x00, 1, 0, 1)
	badDataType[5] = 1
	if validMemcachedBinaryHeader(badDataType) {
		t.Fatal("memcached binary header with bad data type was valid")
	}

	opcodeInputs := []byte{0x05, 0x1c, 0x1b}
	for _, opcode := range opcodeInputs {
		if _, _, _, ok := memcachedBinaryRequestOpcodeRules(opcode); !ok {
			t.Fatalf("opcode %x was unknown", opcode)
		}
	}
	requireCoveragePanic(t, func() {
		_ = memcachedBinaryKeyLengthOK(memcachedBinaryKeyMode(99), 0)
	})

	asciiMatches := [][]byte{
		[]byte("verbosity 2 noreply\r\n"),
		[]byte("flush_all\r\n"),
		[]byte("flush_all noreply\r\n"),
		[]byte("flush_all 1\r\n"),
	}
	for _, input := range asciiMatches {
		t.Run(
			string(bytes.TrimSuffix(input, []byte("\r\n"))),
			func(t *testing.T) {
				if got := MemcachedASCII().Feed(input); got != Match {
					t.Fatalf("state = %v, want Match", got)
				}
			},
		)
	}

	asciiMismatches := [][]byte{
		[]byte("set a 0 1\r\n"),
		[]byte("set " + strings.Repeat("a", 251) + " 0 1 1\r\n"),
		[]byte("flush_all 1 noreply extra\r\n"),
		[]byte("get " + strings.Repeat("a", 251) + "\r\n"),
	}
	for _, input := range asciiMismatches {
		t.Run(
			string(bytes.TrimSuffix(input, []byte("\r\n"))),
			func(t *testing.T) {
				if got := MemcachedASCII().Feed(input); got != Mismatch {
					t.Fatalf("state = %v, want Mismatch", got)
				}
			},
		)
	}

	if validMemcachedKeys(nil) {
		t.Fatal("empty memcached key list was valid")
	}
	if validMemcachedTokens([][]byte{[]byte("ok"), nil}) {
		t.Fatal("memcached token list with empty token was valid")
	}
	if validMemcachedToken(nil) {
		t.Fatal("empty memcached token was valid")
	}
	if validMemcachedToken([]byte("bad token")) {
		t.Fatal("memcached token with space was valid")
	}
	if validMemcachedDecimal(nil) {
		t.Fatal("empty memcached decimal was valid")
	}
	if validMemcachedDecimal([]byte(strings.Repeat("1", 21))) {
		t.Fatal("long memcached decimal was valid")
	}
}

func requireCoveragePanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("function did not panic")
		}
	}()
	f()
}

func coverageProxyProtocolV2Header(
	versionCommand byte,
	familyProtocol byte,
	payloadLen uint16,
) []byte {
	header := []byte(proxyProtocolV2Signature)
	header = append(header, versionCommand, familyProtocol, 0, 0)
	binary.BigEndian.PutUint16(header[14:16], payloadLen)
	return header
}

func coverageSTUNHeader(messageType uint16, length uint16) []byte {
	header := make([]byte, stunHeaderBytes)
	binary.BigEndian.PutUint16(header[:2], messageType)
	binary.BigEndian.PutUint16(header[2:4], length)
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	return header
}

func coverageRDPHeader() []byte {
	return []byte{3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0}
}

func coverageSMB1Header() []byte {
	header := make([]byte, smbOverTCPRequestMinBytes)
	binary.BigEndian.PutUint16(header[2:4], 32)
	copy(header[4:8], []byte{0xff, 'S', 'M', 'B'})
	header[8] = 0x72
	return header
}

func coverageCassandraHeader(
	version byte,
	flags byte,
	opcode byte,
	bodyLen uint32,
) []byte {
	header := make([]byte, cassandraRequestHeaderBytes)
	header[0] = version
	header[1] = flags
	header[4] = opcode
	binary.BigEndian.PutUint32(header[5:9], bodyLen)
	return header
}

func coverageMemcachedBinaryHeader(
	opcode byte,
	keyLen uint16,
	extrasLen byte,
	bodyLen uint32,
) []byte {
	header := make([]byte, memcachedBinaryHeaderBytes)
	header[0] = 0x80
	header[1] = opcode
	binary.BigEndian.PutUint16(header[2:4], keyLen)
	header[4] = extrasLen
	binary.BigEndian.PutUint32(header[8:12], bodyLen)
	return header
}

func coverageDNSOverTCPQuery(name string) []byte {
	message := coverageDNSQueryMessage(name)
	query := make(
		[]byte,
		dnsOverTCPLengthBytes,
		len(message)+dnsOverTCPLengthBytes,
	)
	binary.BigEndian.PutUint16(query, coverageUint16Len(len(message)))
	return append(query, message...)
}

func coverageUint16Len(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("length %d exceeds uint16", n))
	}
	return uint16(n)
}

func coverageDNSQueryMessage(name string) []byte {
	message := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint16(message, 1)
	return message
}

func coverageDNSNameBytesBeforeLabelLimit() []byte {
	name := make([]byte, 0, 256)
	for range 85 {
		name = append(name, 2, 'a', 'b')
	}
	return append(name, 1)
}

func coverageDNSNameBytesAfterLabelLimit() []byte {
	name := make([]byte, 0, 256)
	for range 128 {
		name = append(name, 1, 'a')
	}
	return name
}
