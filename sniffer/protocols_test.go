package sniffer_test

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"github.com/asciimoth/gonnect/sniffer"
)

func TestHTTP2Classifier(t *testing.T) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	classifier := sniffer.HTTP2()
	if got := classifier.Feed([]byte(preface[:10])); got != sniffer.NeedMore {
		t.Fatalf("partial state = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte(preface[10:])); got != sniffer.Match {
		t.Fatalf("final state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	classifier = sniffer.HTTP2()
	if got := classifier.Feed(
		[]byte("PRI * HTTP/1.1\r\n"),
	); got != sniffer.Mismatch {
		t.Fatalf("mismatch state = %v, want Mismatch", got)
	}

	if got := sniffer.HTTP2Factory().MinSniffBufferSize(); got != len(preface) {
		t.Fatalf("factory size = %d, want %d", got, len(preface))
	}
}

func TestProxyProtocolClassifiers(t *testing.T) {
	v1 := []byte("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n")
	classifier := sniffer.ProxyProtocolV1()
	if got := classifier.Feed(v1[:3]); got != sniffer.NeedMore {
		t.Fatalf("v1 partial state = %v, want NeedMore", got)
	}
	if got := classifier.Feed(v1[3:]); got != sniffer.Match {
		t.Fatalf("v1 final state = %v, want Match", got)
	}

	v2 := validProxyProtocolV2Header()
	for split := range 17 {
		t.Run(fmt.Sprintf("v2-split-%d", split), func(t *testing.T) {
			classifier := sniffer.ProxyProtocolV2()
			state := classifier.Feed(v2[:split])
			if split < 16 {
				if state != sniffer.NeedMore {
					t.Fatalf("first state = %v, want NeedMore", state)
				}
				state = classifier.Feed(v2[split:16])
			}
			if state != sniffer.Match {
				t.Fatalf("final state = %v, want Match", state)
			}
		})
	}
	if got := sniffer.ProxyProtocolV2().Feed(v2); got != sniffer.Match {
		t.Fatalf("v2 with payload state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{
			name: "bad signature",
			in:   []byte("\r\n\r\n\x00\r\nFAIL\n!\x11\x00\x0c"),
		},
		{
			name: "bad version",
			in: proxyProtocolV2HeaderWith(
				0x11,
				0x11,
				12,
			),
		},
		{
			name: "bad command",
			in: proxyProtocolV2HeaderWith(
				0x22,
				0x11,
				12,
			),
		},
		{
			name: "bad family",
			in: proxyProtocolV2HeaderWith(
				0x21,
				0x41,
				12,
			),
		},
		{
			name: "short IPv4 address payload",
			in: proxyProtocolV2HeaderWith(
				0x21,
				0x11,
				11,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.ProxyProtocolV2().
				Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.ProxyProtocol().Feed(v1); got != sniffer.Match {
		t.Fatalf("combined v1 state = %v, want Match", got)
	}
	if got := sniffer.ProxyProtocol().Feed(v2); got != sniffer.Match {
		t.Fatalf("combined v2 state = %v, want Match", got)
	}
	if got := sniffer.ProxyProtocolFactory().
		MinSniffBufferSize(); got != 16 {
		t.Fatalf("combined factory size = %d, want 16", got)
	}
}

func TestSOCKSClassifiers(t *testing.T) {
	socks4 := []byte{4, 1, 0, 80, 127, 0, 0, 1, 'u', 0}
	classifier := sniffer.SOCKS4()
	if got := classifier.Feed(socks4[:3]); got != sniffer.NeedMore {
		t.Fatalf("SOCKS4 partial state = %v, want NeedMore", got)
	}
	if got := classifier.Feed(socks4[3:]); got != sniffer.Match {
		t.Fatalf("SOCKS4 final state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("SOCKS4 terminal state = %v, want Match", got)
	}

	badSOCKS4 := []byte{4, 1, 0, 0, 127, 0, 0, 1}
	if got := sniffer.SOCKS4().Feed(badSOCKS4); got != sniffer.Mismatch {
		t.Fatalf("SOCKS4 bad port state = %v, want Mismatch", got)
	}

	socks5 := []byte{5, 2, 0, 2}
	classifier = sniffer.SOCKS5()
	if got := classifier.Feed(socks5[:1]); got != sniffer.NeedMore {
		t.Fatalf("SOCKS5 version state = %v, want NeedMore", got)
	}
	if got := classifier.Feed(socks5[1:3]); got != sniffer.NeedMore {
		t.Fatalf("SOCKS5 partial methods state = %v, want NeedMore", got)
	}
	if got := classifier.Feed(socks5[3:]); got != sniffer.Match {
		t.Fatalf("SOCKS5 final state = %v, want Match", got)
	}

	if got := sniffer.SOCKS5().Feed([]byte{5, 0}); got != sniffer.Mismatch {
		t.Fatalf("SOCKS5 empty methods state = %v, want Mismatch", got)
	}
	if got := sniffer.SOCKS().Feed(socks4); got != sniffer.Match {
		t.Fatalf("combined SOCKS4 state = %v, want Match", got)
	}
	if got := sniffer.SOCKS().Feed(socks5); got != sniffer.Match {
		t.Fatalf("combined SOCKS5 state = %v, want Match", got)
	}

	if got := sniffer.SOCKS4Factory().MinSniffBufferSize(); got != 8 {
		t.Fatalf("SOCKS4 factory size = %d, want 8", got)
	}
	if got := sniffer.SOCKS5Factory().MinSniffBufferSize(); got != 257 {
		t.Fatalf("SOCKS5 factory size = %d, want 257", got)
	}
	if got := sniffer.SOCKSFactory().MinSniffBufferSize(); got != 257 {
		t.Fatalf("SOCKS factory size = %d, want 257", got)
	}
}

func TestDNSOverTCPClassifier(t *testing.T) {
	query := testDNSOverTCPQuery("example.test")
	for split := range len(query) + 1 {
		t.Run(fmt.Sprintf("split-%d", split), func(t *testing.T) {
			classifier := sniffer.DNSOverTCPWithConfig(
				sniffer.DNSOverTCPConfig{
					MaxMessageBytes: len(query) - 2,
				},
			)
			state := classifier.Feed(query[:split])
			if split < len(query) {
				if state != sniffer.NeedMore {
					t.Fatalf("first state = %v, want NeedMore", state)
				}
				state = classifier.Feed(query[split:])
			}
			if state != sniffer.Match {
				t.Fatalf("final state = %v, want Match", state)
			}
		})
	}

	classifier := sniffer.DNSOverTCP()
	if got := classifier.Feed(query); got != sniffer.Match {
		t.Fatalf("default config state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	response := append([]byte(nil), query...)
	response[4] |= 0x80
	if got := sniffer.DNSOverTCP().Feed(response); got != sniffer.Mismatch {
		t.Fatalf("response state = %v, want Mismatch", got)
	}

	oversize := sniffer.DNSOverTCPWithConfig(sniffer.DNSOverTCPConfig{
		MaxMessageBytes: len(query) - 3,
	})
	if got := oversize.Feed(query[:2]); got != sniffer.Mismatch {
		t.Fatalf("oversize state = %v, want Mismatch", got)
	}

	badName := testDNSOverTCPQuery("example.test")
	badName[14] = 0xc0
	badName[15] = 0xff
	if got := sniffer.DNSOverTCP().Feed(badName); got != sniffer.Mismatch {
		t.Fatalf("bad name state = %v, want Mismatch", got)
	}

	compressedName := testDNSOverTCPQueryWithCompressedSecondQuestion()
	if got := sniffer.DNSOverTCP().Feed(compressedName); got != sniffer.Match {
		t.Fatalf("compressed name state = %v, want Match", got)
	}

	badNameTarget := testDNSOverTCPQuery("example.test")
	badNameTarget[14] = 0xc0
	badNameTarget[15] = 0x00
	badTargetClassifier := sniffer.DNSOverTCP()
	if got := badTargetClassifier.Feed(badNameTarget); got != sniffer.Mismatch {
		t.Fatalf("bad name target state = %v, want Mismatch", got)
	}

	loopName := testDNSOverTCPQuery("example.test")
	loopName[14] = 0xc0
	loopName[15] = 0x0c
	if got := sniffer.DNSOverTCP().Feed(loopName); got != sniffer.Mismatch {
		t.Fatalf("loop name state = %v, want Mismatch", got)
	}

	factory := sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
		MaxMessageBytes: 64,
	})
	if got := factory.MinSniffBufferSize(); got != 66 {
		t.Fatalf("DNS factory size = %d, want 66", got)
	}
	if got := factory.NewClassifier().Feed(query); got != sniffer.Match {
		t.Fatalf("DNS factory classifier = %v, want Match", got)
	}
}

func TestDNSOverTCPConfigPanics(t *testing.T) {
	tests := []struct {
		name   string
		config sniffer.DNSOverTCPConfig
	}{
		{
			name: "negative limit",
			config: sniffer.DNSOverTCPConfig{
				MaxMessageBytes: -1,
			},
		},
		{
			name: "too large limit",
			config: sniffer.DNSOverTCPConfig{
				MaxMessageBytes: 1 << 16,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("DNSOverTCPWithConfig did not panic")
				}
			}()
			_ = sniffer.DNSOverTCPWithConfig(test.config)
		})
	}
}

func TestAMQPClassifier(t *testing.T) {
	headers := []struct {
		name string
		in   []byte
	}{
		{name: "0-9-1", in: []byte("AMQP\x00\x00\x09\x01")},
		{name: "1-0", in: []byte("AMQP\x00\x01\x00\x00")},
		{name: "1-0 SASL", in: []byte("AMQP\x03\x01\x00\x00")},
	}
	for _, header := range headers {
		t.Run(header.name, func(t *testing.T) {
			requireProtocolMatchEverySplit(t, sniffer.AMQP, header.in)
		})
	}

	classifier := sniffer.AMQP()
	if got := classifier.Feed(
		[]byte("AMQP\x00\x01\x00"),
	); got != sniffer.NeedMore {
		t.Fatalf("partial state = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("\x00ignored")); got != sniffer.Match {
		t.Fatalf("final state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	if got := sniffer.AMQP().
		Feed([]byte("AMQP\x01\x01\x00\x00")); got != sniffer.Mismatch {
		t.Fatalf("bad header state = %v, want Mismatch", got)
	}
	if got := sniffer.AMQPFactory().MinSniffBufferSize(); got != 8 {
		t.Fatalf("factory size = %d, want 8", got)
	}
}

func TestMQTTClassifier(t *testing.T) {
	prefixes := []struct {
		name string
		in   []byte
	}{
		{
			name: "3-1",
			in:   testMQTTConnectPrefix("MQIsdp", 3, 14),
		},
		{
			name: "3-1-1",
			in:   testMQTTConnectPrefix("MQTT", 4, 12),
		},
		{
			name: "5",
			in:   testMQTTConnectPrefix("MQTT", 5, 13),
		},
		{
			name: "four-byte remaining length",
			in:   testMQTTConnectPrefix("MQTT", 4, 1<<21),
		},
	}
	for _, prefix := range prefixes {
		t.Run(prefix.name, func(t *testing.T) {
			requireProtocolMatchEverySplit(t, sniffer.MQTT, prefix.in)
		})
	}

	classifier := sniffer.MQTT()
	if got := classifier.Feed(prefixes[1].in); got != sniffer.Match {
		t.Fatalf("valid state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "bad packet type", in: []byte{0x20, 0}},
		{
			name: "bad remaining length",
			in:   []byte{0x10, 0x80, 0x80, 0x80, 0x80},
		},
		{
			name: "short remaining length",
			in:   testMQTTConnectPrefix("MQTT", 4, 10),
		},
		{
			name: "bad protocol name length",
			in: []byte{
				0x10, 13,
				0, 5,
				'M', 'Q', 'T', 'T', 'X',
				4, 2, 0, 60,
			},
		},
		{
			name: "bad protocol level",
			in:   testMQTTConnectPrefix("MQTT", 6, 12),
		},
		{
			name: "reserved flag bit",
			in: []byte{
				0x10, 12,
				0, 4,
				'M', 'Q', 'T', 'T',
				4, 1, 0, 60,
			},
		},
		{
			name: "will qos without will flag",
			in: []byte{
				0x10, 12,
				0, 4,
				'M', 'Q', 'T', 'T',
				4, 0x08, 0, 60,
			},
		},
		{
			name: "password without username",
			in: []byte{
				0x10, 12,
				0, 4,
				'M', 'Q', 'T', 'T',
				4, 0x40, 0, 60,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.MQTT().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.MQTTFactory().MinSniffBufferSize(); got != 17 {
		t.Fatalf("factory size = %d, want 17", got)
	}
}

func TestPostgreSQLClassifier(t *testing.T) {
	packets := []struct {
		name string
		in   []byte
	}{
		{name: "startup", in: testPostgreSQLStartupHeader(9, 196608)},
		{name: "ssl request", in: testPostgreSQLStartupHeader(8, 80877103)},
		{name: "gssenc request", in: testPostgreSQLStartupHeader(8, 80877104)},
		{name: "cancel request", in: testPostgreSQLStartupHeader(16, 80877102)},
	}
	for _, packet := range packets {
		t.Run(packet.name, func(t *testing.T) {
			requireProtocolMatchEverySplit(t, sniffer.PostgreSQL, packet.in)
		})
	}

	classifier := sniffer.PostgreSQL()
	if got := classifier.Feed(packets[0].in); got != sniffer.Match {
		t.Fatalf("startup state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "short packet length", in: []byte{0, 0, 0, 7}},
		{
			name: "startup length too short",
			in:   testPostgreSQLStartupHeader(8, 196608),
		},
		{name: "bad request code", in: testPostgreSQLStartupHeader(8, 1)},
		{name: "bad ssl length", in: testPostgreSQLStartupHeader(9, 80877103)},
		{
			name: "bad cancel length",
			in:   testPostgreSQLStartupHeader(8, 80877102),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.PostgreSQL().
				Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.PostgreSQLFactory().MinSniffBufferSize(); got != 8 {
		t.Fatalf("factory size = %d, want 8", got)
	}
}

func TestMongoDBClassifier(t *testing.T) {
	headers := []struct {
		name   string
		opcode uint32
	}{
		{name: "op query", opcode: 2004},
		{name: "op compressed", opcode: 2012},
		{name: "op msg", opcode: 2013},
	}
	for _, header := range headers {
		t.Run(header.name, func(t *testing.T) {
			requireProtocolMatchEverySplit(
				t,
				sniffer.MongoDB,
				testMongoDBHeader(16, 0, header.opcode),
			)
		})
	}

	classifier := sniffer.MongoDB()
	if got := classifier.Feed(
		testMongoDBHeader(16, 0, 2013),
	); got != sniffer.Match {
		t.Fatalf("OP_MSG state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "short message length", in: testMongoDBHeader(15, 0, 2013)[:4]},
		{name: "response header", in: testMongoDBHeader(16, 1, 2013)},
		{name: "server reply opcode", in: testMongoDBHeader(16, 0, 1)},
		{name: "unknown opcode", in: testMongoDBHeader(16, 0, 99)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.MongoDB().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.MongoDBFactory().MinSniffBufferSize(); got != 16 {
		t.Fatalf("factory size = %d, want 16", got)
	}
}

func TestRedisClassifier(t *testing.T) {
	requests := []struct {
		name string
		in   []byte
	}{
		{name: "get", in: []byte("*2\r\n$3\r\nGET\r\n")},
		{name: "module command", in: []byte("*1\r\n$8\r\nJSON.GET\r\n")},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			requireProtocolMatchEverySplit(t, sniffer.Redis, request.in)
		})
	}

	classifier := sniffer.Redis()
	if got := classifier.Feed(requests[0].in); got != sniffer.Match {
		t.Fatalf("GET state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "inline command", in: []byte("PING\r\n")},
		{name: "empty array", in: []byte("*0\r\n")},
		{name: "first element is not bulk", in: []byte("*1\r\n+PING\r\n")},
		{name: "command contains space", in: []byte("*1\r\n$4\r\nGE T\r\n")},
		{name: "command too large", in: []byte("*1\r\n$129\r\n")},
		{name: "too many array digits", in: []byte("*12345678901\r\n")},
		{name: "bad line ending", in: []byte("*1\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.Redis().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.RedisFactory().MinSniffBufferSize(); got != 156 {
		t.Fatalf("factory size = %d, want 156", got)
	}
}

func requireProtocolMatchEverySplit(
	t *testing.T,
	newClassifier func() sniffer.Classifier,
	input []byte,
) {
	t.Helper()
	for split := range len(input) + 1 {
		t.Run(fmt.Sprintf("split-%d", split), func(t *testing.T) {
			classifier := newClassifier()
			state := classifier.Feed(input[:split])
			if split < len(input) {
				if state != sniffer.NeedMore {
					t.Fatalf("first state = %v, want NeedMore", state)
				}
				state = classifier.Feed(input[split:])
			}
			if state != sniffer.Match {
				t.Fatalf("final state = %v, want Match", state)
			}
		})
	}
}

func validProxyProtocolV2Header() []byte {
	header := proxyProtocolV2HeaderWith(0x21, 0x11, 12)
	header = append(header, []byte{
		192, 0, 2, 1,
		198, 51, 100, 2,
		0x30, 0x39,
		0x01, 0xbb,
	}...)
	return header
}

func proxyProtocolV2HeaderWith(
	versionCommand byte,
	familyProtocol byte,
	payloadLen uint16,
) []byte {
	header := []byte("\r\n\r\n\x00\r\nQUIT\n")
	header = append(header, versionCommand, familyProtocol, 0, 0)
	binary.BigEndian.PutUint16(header[14:16], payloadLen)
	return header
}

func testDNSOverTCPQuery(name string) []byte {
	message := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, label := range splitDNSLabels(name) {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint16(message, 1)

	query := make([]byte, 2, len(message)+2)
	binary.BigEndian.PutUint16(query, testUint16Len(len(message)))
	query = append(query, message...)
	return query
}

func testDNSOverTCPQueryWithCompressedSecondQuestion() []byte {
	const (
		dnsTCPHeaderBytes = 2
		dnsHeaderBytes    = 12
	)

	query := testDNSOverTCPQuery("example.test")
	message := append([]byte(nil), query[dnsTCPHeaderBytes:]...)
	binary.BigEndian.PutUint16(message[4:6], 2)
	message = append(message, 0xc0, dnsHeaderBytes)
	message = binary.BigEndian.AppendUint16(message, 1)
	message = binary.BigEndian.AppendUint16(message, 1)

	compressedQuery := make(
		[]byte,
		dnsTCPHeaderBytes,
		len(message)+dnsTCPHeaderBytes,
	)
	binary.BigEndian.PutUint16(compressedQuery, testUint16Len(len(message)))
	return append(compressedQuery, message...)
}

func splitDNSLabels(name string) []string {
	var labels []string
	start := 0
	for i := range name {
		if name[i] != '.' {
			continue
		}
		labels = append(labels, name[start:i])
		start = i + 1
	}
	return append(labels, name[start:])
}

func testMQTTConnectPrefix(
	protocolName string,
	level byte,
	remainingLength int,
) []byte {
	prefix := []byte{0x10}
	prefix = appendMQTTRemainingLength(prefix, remainingLength)
	prefix = binary.BigEndian.AppendUint16(
		prefix,
		testUint16Len(len(protocolName)),
	)
	prefix = append(prefix, protocolName...)
	prefix = append(prefix, level, 2, 0, 60)
	return prefix
}

func testUint16Len(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("length %d exceeds uint16", n))
	}
	return uint16(n)
}

func appendMQTTRemainingLength(dst []byte, remainingLength int) []byte {
	for {
		encoded := byte(remainingLength % 128)
		remainingLength /= 128
		if remainingLength > 0 {
			encoded |= 0x80
		}
		dst = append(dst, encoded)
		if remainingLength == 0 {
			return dst
		}
	}
}

func testPostgreSQLStartupHeader(length uint32, code uint32) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[:4], length)
	binary.BigEndian.PutUint32(header[4:8], code)
	return header
}

func testMongoDBHeader(
	length uint32,
	responseTo uint32,
	opcode uint32,
) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[:4], length)
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], responseTo)
	binary.LittleEndian.PutUint32(header[12:16], opcode)
	return header
}
