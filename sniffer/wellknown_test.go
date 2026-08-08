package sniffer_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/asciimoth/gonnect/sniffer"
)

func TestRTSPClassifier(t *testing.T) {
	request := []byte("DESCRIBE rtsp://example.test/live RTSP/1.0\r\n")
	requireWellKnownMatchEverySplit(t, sniffer.RTSP, request)

	classifier := sniffer.RTSP()
	if got := classifier.Feed(request); got != sniffer.Match {
		t.Fatalf("RTSP state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("RTSP terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "unknown method", in: []byte("FETCH rtsp://x RTSP/1.0\r\n")},
		{name: "bad version", in: []byte("DESCRIBE rtsp://x HTTP/1.1\r\n")},
		{name: "empty target", in: []byte("DESCRIBE  RTSP/1.0\r\n")},
		{name: "lf without cr", in: []byte("DESCRIBE rtsp://x RTSP/1.0\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.RTSP().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.RTSPFactory().MinSniffBufferSize(); got != 1024 {
		t.Fatalf("RTSP factory size = %d, want 1024", got)
	}
}

func TestSIPClassifier(t *testing.T) {
	request := []byte("INVITE sip:bob@example.test SIP/2.0\r\n")
	requireWellKnownMatchEverySplit(t, sniffer.SIP, request)

	classifier := sniffer.SIP()
	if got := classifier.Feed(request); got != sniffer.Match {
		t.Fatalf("SIP state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("SIP terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "unknown method", in: []byte("DIAL sip:x SIP/2.0\r\n")},
		{name: "bad version", in: []byte("INVITE sip:x RTSP/1.0\r\n")},
		{name: "extra space", in: []byte("INVITE sip:x SIP/2.0 extra\r\n")},
		{name: "control byte", in: []byte("INVITE sip:\x01 SIP/2.0\r\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.SIP().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.SIPFactory().MinSniffBufferSize(); got != 1024 {
		t.Fatalf("SIP factory size = %d, want 1024", got)
	}
}

func TestSTUNClassifier(t *testing.T) {
	header := testSTUNHeader(0x0001, 0)
	requireWellKnownMatchEverySplit(t, sniffer.STUN, header)

	classifier := sniffer.STUN()
	if got := classifier.Feed(header); got != sniffer.Match {
		t.Fatalf("STUN state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("STUN terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "bad top bits", in: testSTUNHeader(0xc001, 0)},
		{name: "unknown method", in: testSTUNHeader(0x0000, 0)},
		{name: "bad length alignment", in: testSTUNHeader(0x0001, 2)},
		{name: "bad cookie", in: testSTUNHeaderWithCookie(0x0001, 0, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.STUN().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.STUNFactory().MinSniffBufferSize(); got != 20 {
		t.Fatalf("STUN factory size = %d, want 20", got)
	}
}

func TestRDPClassifier(t *testing.T) {
	request := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00,
		0x03, 0x00, 0x00, 0x00,
	}
	requireWellKnownMatchEverySplit(t, sniffer.RDP, request[:11])

	classifier := sniffer.RDP()
	if got := classifier.Feed(request); got != sniffer.Match {
		t.Fatalf("RDP state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("RDP terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "bad tpkt version", in: []byte{2}},
		{name: "short packet", in: []byte{3, 0, 0, 10}},
		{
			name: "bad cotp type",
			in:   []byte{3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0},
		},
		{
			name: "non-zero destination reference",
			in:   []byte{3, 0, 0, 11, 6, 0xe0, 0, 1, 0, 0, 0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.RDP().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.RDPFactory().MinSniffBufferSize(); got != 11 {
		t.Fatalf("RDP factory size = %d, want 11", got)
	}
}

func TestSMBClassifier(t *testing.T) {
	requests := []struct {
		name string
		in   []byte
	}{
		{name: "smb1", in: testSMB1NegotiateHeader()},
		{name: "smb2", in: testSMB2NegotiateHeader()},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			requireWellKnownMatchEverySplit(t, sniffer.SMB, request.in)
		})
	}

	classifier := sniffer.SMB()
	if got := classifier.Feed(requests[1].in); got != sniffer.Match {
		t.Fatalf("SMB state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("SMB terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "bad session type", in: []byte{0x81}},
		{name: "bad protocol id", in: []byte{0, 0, 0, 64, 'B', 'A', 'D', '!'}},
		{name: "smb1 reply", in: testSMB1ReplyHeader()},
		{name: "smb2 reply", in: testSMB2ReplyHeader()},
		{name: "short smb2 payload", in: testSMB2HeaderWithPayload(63)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.SMB().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.SMBFactory().MinSniffBufferSize(); got != 24 {
		t.Fatalf("SMB factory size = %d, want 24", got)
	}
}

func TestLDAPClassifier(t *testing.T) {
	requests := []struct {
		name string
		in   []byte
	}{
		{name: "bind", in: []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60}},
		{name: "search", in: []byte{0x30, 0x81, 0x80, 0x02, 0x01, 0x7f, 0x63}},
		{
			name: "extended",
			in:   []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x02, 0x01, 0x00, 0x77},
		},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			requireWellKnownMatchEverySplit(t, sniffer.LDAP, request.in)
		})
	}

	classifier := sniffer.LDAP()
	if got := classifier.Feed(requests[0].in); got != sniffer.Match {
		t.Fatalf("LDAP state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("LDAP terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "bad sequence tag", in: []byte{0x31}},
		{name: "indefinite length", in: []byte{0x30, 0x80}},
		{
			name: "zero message id",
			in:   []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x60},
		},
		{
			name: "negative message id",
			in:   []byte{0x30, 0x05, 0x02, 0x01, 0x80, 0x60},
		},
		{
			name: "response protocol op",
			in:   []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x61},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.LDAP().Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.LDAPFactory().MinSniffBufferSize(); got != 16 {
		t.Fatalf("LDAP factory size = %d, want 16", got)
	}
}

func TestCassandraClassifier(t *testing.T) {
	requests := []struct {
		name string
		in   []byte
	}{
		{name: "startup v4", in: testCassandraHeader(4, 0, 0x01, 22)},
		{name: "options v5", in: testCassandraHeader(5, 0, 0x05, 0)},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			requireWellKnownMatchEverySplit(t, sniffer.Cassandra, request.in)
		})
	}

	classifier := sniffer.Cassandra()
	if got := classifier.Feed(requests[0].in); got != sniffer.Match {
		t.Fatalf("Cassandra state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("Cassandra terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "response version", in: testCassandraHeader(0x84, 0, 0x01, 22)},
		{name: "reserved flag", in: testCassandraHeader(4, 0xf0, 0x01, 22)},
		{name: "bad first opcode", in: testCassandraHeader(4, 0, 0x07, 4)},
		{name: "empty startup body", in: testCassandraHeader(4, 0, 0x01, 0)},
		{name: "options with body", in: testCassandraHeader(4, 0, 0x05, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.Cassandra().
				Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.CassandraFactory().MinSniffBufferSize(); got != 9 {
		t.Fatalf("Cassandra factory size = %d, want 9", got)
	}
}

func TestMemcachedBinaryClassifier(t *testing.T) {
	headers := []struct {
		name string
		in   []byte
	}{
		{name: "get", in: testMemcachedBinaryHeader(0x00, 3, 0, 3)},
		{name: "set", in: testMemcachedBinaryHeader(0x01, 3, 8, 16)},
		{name: "flush", in: testMemcachedBinaryHeader(0x08, 0, 4, 4)},
		{name: "stat", in: testMemcachedBinaryHeader(0x10, 0, 0, 0)},
	}
	for _, header := range headers {
		t.Run(header.name, func(t *testing.T) {
			requireWellKnownMatchEverySplit(
				t,
				sniffer.MemcachedBinary,
				header.in,
			)
		})
	}

	classifier := sniffer.MemcachedBinary()
	if got := classifier.Feed(headers[0].in); got != sniffer.Match {
		t.Fatalf("binary memcached state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("binary memcached terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "response magic", in: testMemcachedHeaderWithMagic(0x81)},
		{name: "unknown opcode", in: testMemcachedBinaryHeader(0xff, 0, 0, 0)},
		{name: "bad data type", in: testMemcachedHeaderWithDataType(1)},
		{
			name: "missing required key",
			in:   testMemcachedBinaryHeader(0x00, 0, 0, 0),
		},
		{name: "forbidden key", in: testMemcachedBinaryHeader(0x0a, 1, 0, 1)},
		{
			name: "bad extras length",
			in:   testMemcachedBinaryHeader(0x01, 3, 4, 7),
		},
		{name: "short body", in: testMemcachedBinaryHeader(0x01, 3, 8, 10)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.MemcachedBinary().
				Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.MemcachedBinaryFactory().
		MinSniffBufferSize(); got != 24 {
		t.Fatalf("binary memcached factory size = %d, want 24", got)
	}
}

func TestMemcachedASCIIClassifier(t *testing.T) {
	requests := []struct {
		name string
		in   []byte
	}{
		{name: "get", in: []byte("get alpha beta\r\n")},
		{name: "set", in: []byte("set alpha 0 60 5 noreply\r\n")},
		{name: "cas", in: []byte("cas alpha 0 60 5 42\r\n")},
		{name: "delete", in: []byte("delete alpha noreply\r\n")},
		{name: "incr", in: []byte("incr counter 1\r\n")},
		{name: "touch", in: []byte("touch alpha 60\r\n")},
		{name: "flush", in: []byte("flush_all 5 noreply\r\n")},
		{name: "stats", in: []byte("stats settings\r\n")},
		{name: "version", in: []byte("version\r\n")},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			requireWellKnownMatchEverySplit(
				t,
				sniffer.MemcachedASCII,
				request.in,
			)
		})
	}

	classifier := sniffer.MemcachedASCII()
	if got := classifier.Feed(requests[0].in); got != sniffer.Match {
		t.Fatalf("ASCII memcached state = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("ignored")); got != sniffer.Match {
		t.Fatalf("ASCII memcached terminal state = %v, want Match", got)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "unknown command", in: []byte("fetch alpha\r\n")},
		{name: "uppercase http-style get", in: []byte("GET / HTTP/1.1\r\n")},
		{name: "empty key", in: []byte("get \r\n")},
		{name: "bad decimal", in: []byte("set a 0 now 1\r\n")},
		{name: "bad noreply position", in: []byte("delete a later\r\n")},
		{name: "control byte", in: []byte("get a\x01\r\n")},
		{name: "lf without cr", in: []byte("version\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sniffer.MemcachedASCII().
				Feed(test.in); got != sniffer.Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	if got := sniffer.MemcachedASCIIFactory().
		MinSniffBufferSize(); got != 512 {
		t.Fatalf("ASCII memcached factory size = %d, want 512", got)
	}
}

func TestMemcachedClassifier(t *testing.T) {
	if got := sniffer.Memcached().
		Feed(testMemcachedBinaryHeader(0x00, 3, 0, 3)); got != sniffer.Match {
		t.Fatalf("combined binary state = %v, want Match", got)
	}
	if got := sniffer.Memcached().
		Feed([]byte("get alpha\r\n")); got != sniffer.Match {
		t.Fatalf("combined ASCII state = %v, want Match", got)
	}
	if got := sniffer.MemcachedFactory().
		MinSniffBufferSize(); got != 512 {
		t.Fatalf("combined memcached factory size = %d, want 512", got)
	}
}

func requireWellKnownMatchEverySplit(
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

func testSTUNHeader(messageType uint16, length uint16) []byte {
	return testSTUNHeaderWithCookie(messageType, length, 0x2112a442)
}

func testSTUNHeaderWithCookie(
	messageType uint16,
	length uint16,
	cookie uint32,
) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], messageType)
	binary.BigEndian.PutUint16(header[2:4], length)
	binary.BigEndian.PutUint32(header[4:8], cookie)
	copy(header[8:20], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	return header
}

func testSMB1NegotiateHeader() []byte {
	header := make([]byte, 24)
	header[0] = 0
	binary.BigEndian.PutUint16(header[2:4], 32)
	copy(header[4:8], []byte{0xff, 'S', 'M', 'B'})
	header[8] = 0x72
	return header
}

func testSMB1ReplyHeader() []byte {
	header := testSMB1NegotiateHeader()
	header[13] = 0x80
	return header
}

func testSMB2NegotiateHeader() []byte {
	return testSMB2HeaderWithPayload(64)
}

func testSMB2ReplyHeader() []byte {
	header := testSMB2NegotiateHeader()
	binary.LittleEndian.PutUint32(header[20:24], 1)
	return header
}

func testSMB2HeaderWithPayload(payloadLen uint16) []byte {
	header := make([]byte, 24)
	header[0] = 0
	binary.BigEndian.PutUint16(header[2:4], payloadLen)
	copy(header[4:8], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[8:10], 64)
	return header
}

func testCassandraHeader(
	version byte,
	flags byte,
	opcode byte,
	bodyLen uint32,
) []byte {
	header := make([]byte, 9)
	header[0] = version
	header[1] = flags
	header[4] = opcode
	binary.BigEndian.PutUint32(header[5:9], bodyLen)
	return header
}

func testMemcachedBinaryHeader(
	opcode byte,
	keyLen uint16,
	extrasLen byte,
	bodyLen uint32,
) []byte {
	header := make([]byte, 24)
	header[0] = 0x80
	header[1] = opcode
	binary.BigEndian.PutUint16(header[2:4], keyLen)
	header[4] = extrasLen
	binary.BigEndian.PutUint32(header[8:12], bodyLen)
	return header
}

func testMemcachedHeaderWithMagic(magic byte) []byte {
	header := testMemcachedBinaryHeader(0x00, 3, 0, 3)
	header[0] = magic
	return header
}

func testMemcachedHeaderWithDataType(dataType byte) []byte {
	header := testMemcachedBinaryHeader(0x00, 3, 0, 3)
	header[5] = dataType
	return header
}
