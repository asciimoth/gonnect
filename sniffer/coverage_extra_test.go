//nolint:testpackage // These tests exercise unexported parser branches.
package sniffer

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestCoverageTerminalAndWrapperBranches(t *testing.T) {
	limit := Limit(1, Prefix([]byte("A")))
	if got := limit.Feed([]byte("A")); got != Match {
		t.Fatalf("Limit match = %v, want Match", got)
	}
	if got := limit.Feed([]byte("ignored")); got != Match {
		t.Fatalf("terminal Limit = %v, want Match", got)
	}

	sized := WithMinSniffBufferSize(3, Prefix([]byte("OK")))
	if got := sized.Feed([]byte("OK")); got != Match {
		t.Fatalf("sized Feed = %v, want Match", got)
	}

	and := And(Prefix([]byte("A")))
	if got := and.Feed([]byte("A")); got != Match {
		t.Fatalf("And match = %v, want Match", got)
	}
	if got := and.Feed([]byte("ignored")); got != Match {
		t.Fatalf("terminal And = %v, want Match", got)
	}

	or := Or(Prefix([]byte("A")))
	if got := or.Feed([]byte("A")); got != Match {
		t.Fatalf("Or match = %v, want Match", got)
	}
	if got := or.Feed([]byte("ignored")); got != Match {
		t.Fatalf("terminal Or = %v, want Match", got)
	}

	not := Not(Prefix([]byte("A")))
	if got := not.Feed([]byte("A")); got != Mismatch {
		t.Fatalf("Not mismatch = %v, want Mismatch", got)
	}
	if got := not.Feed([]byte("ignored")); got != Mismatch {
		t.Fatalf("terminal Not = %v, want Mismatch", got)
	}
}

func TestCoverageSniffWithPoolNegativeSizePanics(t *testing.T) {
	requirePanic(t, func() {
		_, _ = SniffWithPool(-1, nil, nil)
	})
}

func TestCoverageHTTPFactoryAndClassifierSize(t *testing.T) {
	factory := HTTPFactory()
	if got := factory.NewClassifier().
		Feed([]byte("GET / HTTP/1.1\r\n")); got != Match {
		t.Fatalf("HTTPFactory classifier = %v, want Match", got)
	}
	if got := HTTPWithConfig(HTTPConfig{
		MaxRequestLineBytes: 32,
	}).MinSniffBufferSize(); got != 32 {
		t.Fatalf("HTTP MinSniffBufferSize = %d, want 32", got)
	}
}

func TestCoverageHTTPParserBranches(t *testing.T) {
	invalidPhase := &httpClassifier{
		config: normalizeHTTPConfig(HTTPConfig{}),
		phase:  httpParsePhase(99),
		state:  NeedMore,
	}
	requirePanic(t, func() {
		_ = invalidPhase.Feed([]byte("x"))
	})

	atRequestLimit := &httpClassifier{
		config: normalizedHTTPConfig{maxRequestLineBytes: 0},
		state:  NeedMore,
	}
	if got := atRequestLimit.Feed([]byte("G")); got != Mismatch {
		t.Fatalf("request limit state = %v, want Mismatch", got)
	}

	tests := []struct {
		name string
		c    *httpClassifier
		in   byte
	}{
		{
			name: "header limit",
			c: &httpClassifier{
				config: normalizedHTTPConfig{maxHeaderBytes: 0},
				phase:  httpHeaderPhase,
				state:  NeedMore,
			},
			in: 'X',
		},
		{
			name: "bare header carriage return",
			c: &httpClassifier{
				config: normalizedHTTPConfig{maxHeaderBytes: 16},
				phase:  httpHeaderPhase,
				line:   []byte{'\r'},
				state:  NeedMore,
			},
			in: 'X',
		},
		{
			name: "header control byte",
			c: &httpClassifier{
				config: normalizedHTTPConfig{maxHeaderBytes: 16},
				phase:  httpHeaderPhase,
				state:  NeedMore,
			},
			in: 0,
		},
		{
			name: "header DEL byte",
			c: &httpClassifier{
				config: normalizedHTTPConfig{maxHeaderBytes: 16},
				phase:  httpHeaderPhase,
				state:  NeedMore,
			},
			in: 0x7f,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.c.Feed([]byte{test.in}); got != Mismatch {
				t.Fatalf("state = %v, want Mismatch", got)
			}
		})
	}

	headerAtLimitAfterLine := &httpClassifier{
		config: normalizedHTTPConfig{maxHeaderBytes: 3},
		phase:  httpHeaderPhase,
		state:  NeedMore,
	}
	if got := headerAtLimitAfterLine.Feed([]byte("X:\n")); got != Mismatch {
		t.Fatalf("header at limit state = %v, want Mismatch", got)
	}

	badHeaderName := &httpClassifier{
		config: normalizedHTTPConfig{maxHeaderBytes: 32},
		phase:  httpHeaderPhase,
		state:  NeedMore,
	}
	if got := badHeaderName.Feed([]byte("Bad Header: x\n")); got != Mismatch {
		t.Fatalf("bad header name state = %v, want Mismatch", got)
	}
}

func TestCoverageHTTPHelpers(t *testing.T) {
	if validHTTPRequestTarget([]byte("/bad\x7f")) {
		t.Fatal("target with DEL was valid")
	}
	if _, ok := hostnameFromHostHeaderValue([]byte(" \t ")); ok {
		t.Fatal("empty Host header value was valid")
	}

	invalidHosts := []string{
		"",
		"bad host",
		"user@example.test",
		":443",
	}
	for _, host := range invalidHosts {
		if _, ok := normalizeHTTPHostname(host); ok {
			t.Fatalf("host %q was valid", host)
		}
	}

	for _, method := range [][]byte{
		[]byte("1"),
		[]byte("!"),
	} {
		if !validHTTPMethod(method) {
			t.Fatalf("method %q was invalid", method)
		}
	}

	matcher := newHTTPStringMatcher(
		"",
		nil,
		[]string{"", `api\`},
		nil,
	)
	if !matcher.match(`api\`) {
		t.Fatal("trailing escape pattern did not match")
	}
	if !compileHTTPGlob("a*").match("a") {
		t.Fatal("trailing star did not match empty suffix")
	}
	if !compileHTTPGlob("a?c").match("abc") {
		t.Fatal("single-byte wildcard did not match")
	}
	if !(httpGlobToken{kind: httpGlobAny}).matches('x') {
		t.Fatal("glob ? did not match")
	}
	if (httpGlobToken{kind: httpGlobStar}).matches('x') {
		t.Fatal("glob * matched through token.matches")
	}
	requirePanic(t, func() {
		_ = (httpGlobToken{kind: httpGlobTokenKind(99)}).matches('x')
	})
}

func TestCoverageTLSFactoryAndClassifierSize(t *testing.T) {
	factory := TLSFactory()
	if got := factory.NewClassifier().
		Feed(tlsCoverageClientHello()); got != Match {
		t.Fatalf("TLSFactory classifier = %v, want Match", got)
	}
	if got := TLSWithConfig(TLSConfig{
		MaxClientHelloBytes: 64,
	}).MinSniffBufferSize(); got != 64 {
		t.Fatalf("TLS MinSniffBufferSize = %d, want 64", got)
	}
}

func TestCoverageTLSFeedBranches(t *testing.T) {
	noRoom := &tlsClassifier{
		config: normalizedTLSConfig{maxClientHelloBytes: 0},
		state:  NeedMore,
	}
	if got := noRoom.Feed([]byte{tlsContentTypeHandshake}); got != Mismatch {
		t.Fatalf("no room state = %v, want Mismatch", got)
	}

	tooSmall := TLSWithConfig(TLSConfig{MaxClientHelloBytes: 3})
	if got := tooSmall.Feed(
		[]byte{tlsContentTypeHandshake, 3, 3, 0},
	); got != Mismatch {
		t.Fatalf("too small state = %v, want Mismatch", got)
	}

	atNeedLimit := &tlsClassifier{
		config: normalizedTLSConfig{
			maxClientHelloBytes: tlsRecordHeaderBytes,
		},
		buf:       []byte{tlsContentTypeHandshake, 3, 3, 0, 1},
		needBytes: tlsRecordHeaderBytes,
		state:     NeedMore,
	}
	if got := atNeedLimit.Feed(nil); got != Mismatch {
		t.Fatalf("need limit state = %v, want Mismatch", got)
	}

	partial := TLS()
	if got := partial.Feed(
		[]byte{tlsContentTypeHandshake, 3, 3, 0, 1},
	); got != NeedMore {
		t.Fatalf("partial state = %v, want NeedMore", got)
	}
	if got := partial.Feed(
		[]byte{tlsHandshakeTypeClientHello},
	); got != NeedMore {
		t.Fatalf("continued partial state = %v, want NeedMore", got)
	}
}

func TestCoverageTLSParserMalformedRecords(t *testing.T) {
	inputs := [][]byte{
		{tlsContentTypeHandshake, 4, 0, 0, 1, tlsHandshakeTypeClientHello},
		{
			tlsContentTypeHandshake,
			3,
			3,
			0,
			4,
			tlsHandshakeTypeClientHello,
			0,
			0,
			0,
		},
	}
	for _, input := range inputs {
		if _, state, _ := parseTLSClientHello(input); state != Mismatch {
			t.Fatalf("parseTLSClientHello state = %v, want Mismatch", state)
		}
	}
}

func TestCoverageTLSClientHelloBodyMalformed(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "short body", body: bytes.Repeat([]byte{0}, 33)},
		{
			name: "bad legacy version",
			body: tlsCoverageBodyWithPrefix([]byte{4, 0}),
		},
		{
			name: "long session ID",
			body: tlsCoverageBodyMutate(func(body []byte) {
				body[34] = 33
			}),
		},
		{name: "truncated session ID", body: append(
			append([]byte(nil), tlsCoverageBody()[:35]...),
			bytes.Repeat([]byte{0}, 31)...,
		)},
		{name: "missing cipher suites", body: tlsCoverageBody()[:35]},
		{
			name: "empty cipher suites",
			body: tlsCoverageBodyMutate(func(body []byte) {
				binary.BigEndian.PutUint16(body[35:], 0)
			}),
		},
		{
			name: "odd cipher suites",
			body: tlsCoverageBodyMutate(func(body []byte) {
				binary.BigEndian.PutUint16(body[35:], 3)
			}),
		},
		{
			name: "truncated cipher suites",
			body: tlsCoverageBodyMutate(func(body []byte) {
				binary.BigEndian.PutUint16(body[35:], 4)
			}),
		},
		{name: "missing compression length", body: tlsCoverageBody()[:39]},
		{
			name: "empty compression",
			body: tlsCoverageBodyMutate(func(body []byte) {
				body[39] = 0
			}),
		},
		{
			name: "truncated compression",
			body: tlsCoverageBodyMutate(func(body []byte) {
				body[39] = 2
			}),
		},
		{name: "missing extension length", body: append(tlsCoverageBody(), 0)},
		{name: "zero extension length", body: append(tlsCoverageBody(), 0, 0)},
		{
			name: "truncated extension block",
			body: append(tlsCoverageBody(), 0, 2, 0),
		},
		{name: "extra byte after extension block", body: append(
			tlsCoverageBody(),
			0, 1, 0, 0,
		)},
		{name: "bad extension", body: tlsCoverageBody(
			tlsCoverageExtension{
				typ:  tlsExtensionServerName,
				data: []byte{0, 0},
			},
		)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseTLSClientHelloBody(test.body); ok {
				t.Fatal("parseTLSClientHelloBody succeeded")
			}
		})
	}

	if _, ok := parseTLSClientHelloBody(tlsCoverageBody()); !ok {
		t.Fatal("body without extensions failed")
	}
}

func TestCoverageTLSExtensionMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "short header", data: []byte{0}},
		{name: "duplicate extension", data: append(
			tlsCoverageRawExtension(1, nil),
			tlsCoverageRawExtension(1, nil)...,
		)},
		{name: "truncated extension", data: []byte{0, 1, 0, 2, 0}},
		{name: "bad server name", data: tlsCoverageRawExtension(
			tlsExtensionServerName,
			[]byte{0, 0},
		)},
		{name: "bad ALPN", data: tlsCoverageRawExtension(
			tlsExtensionApplicationProtocols,
			[]byte{0, 0},
		)},
		{name: "bad supported versions", data: tlsCoverageRawExtension(
			tlsExtensionSupportedVersions,
			[]byte{0},
		)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if parseTLSClientHelloExtensions(test.data, &TLSClientHelloInfo{}) {
				t.Fatal("parseTLSClientHelloExtensions succeeded")
			}
		})
	}
}

func TestCoverageTLSServerNameExtension(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "short list length", data: []byte{0}},
		{name: "zero list length", data: []byte{0, 0}},
		{name: "list length mismatch", data: []byte{0, 2, 0}},
		{name: "short name header", data: []byte{0, 1, 0}},
		{name: "zero name length", data: []byte{0, 3, 0, 0, 0}},
		{name: "truncated name", data: []byte{0, 4, 0, 0, 2, 'a'}},
		{name: "duplicate hostname", data: tlsCoverageSNIList(
			tlsCoverageSNIName(tlsServerNameTypeHostName, "a.example"),
			tlsCoverageSNIName(tlsServerNameTypeHostName, "b.example"),
		)},
		{name: "invalid hostname", data: tlsCoverageSNIList(
			tlsCoverageSNIName(tlsServerNameTypeHostName, "bad/name"),
		)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseTLSServerNameExtension(test.data); ok {
				t.Fatal("parseTLSServerNameExtension succeeded")
			}
		})
	}

	host, ok := parseTLSServerNameExtension(tlsCoverageSNIList(
		tlsCoverageSNIName(1, "ignored"),
	))
	if !ok || host != "" {
		t.Fatalf("unknown name type = (%q, %v), want empty success", host, ok)
	}
}

func TestCoverageTLSALPNAndVersionsExtensions(t *testing.T) {
	alpnInputs := [][]byte{
		{0},
		{0, 0},
		{0, 2, 1},
		{0, 1, 0},
		{0, 2, 2, 'h'},
	}
	for _, input := range alpnInputs {
		if _, ok := parseTLSALPNExtension(input); ok {
			t.Fatalf("ALPN input %x succeeded", input)
		}
	}

	versionInputs := [][]byte{
		{0},
		{0, 0, 0},
		{1, 3},
		{4, 3, 4},
	}
	for _, input := range versionInputs {
		if _, ok := parseTLSSupportedVersionsExtension(input); ok {
			t.Fatalf("versions input %x succeeded", input)
		}
	}
}

func TestCoverageTLSHostnameAndFlagHelpers(t *testing.T) {
	if got := normalizeTLSHostnamePattern("BAD/HOST"); got != "bad/host" {
		t.Fatalf("invalid pattern normalized to %q", got)
	}
	invalidHosts := []string{
		"",
		"example.test.",
		"bad\x7fhost",
		"bad/host",
	}
	for _, host := range invalidHosts {
		if _, ok := normalizeTLSHostname(host); ok {
			t.Fatalf("host %q was valid", host)
		}
	}

	matcher := newTLSVersionMatcher(0, []uint16{0, 0x0304})
	if len(matcher.versions) != 1 || matcher.versions[0] != 0x0304 {
		t.Fatalf("versions = %x, want [0304]", matcher.versions)
	}
	requirePanic(t, func() {
		_ = TLSFlag(99).match(true)
	})
}

func requirePanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("function did not panic")
		}
	}()
	f()
}

func tlsCoverageUint16Length(length int) uint16 {
	if length > math.MaxUint16 {
		panic("TLS test data length overflows uint16")
	}
	return uint16(length) //nolint:gosec // length is checked above.
}

type tlsCoverageExtension struct {
	typ  uint16
	data []byte
}

func tlsCoverageClientHello() []byte {
	body := tlsCoverageBody()
	handshake := make([]byte, 4, 4+len(body))
	handshake[0] = tlsHandshakeTypeClientHello
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	handshake = append(handshake, body...)

	record := []byte{tlsContentTypeHandshake, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(
		record[3:],
		tlsCoverageUint16Length(len(handshake)),
	)
	return append(record, handshake...)
}

func tlsCoverageBody(extensions ...tlsCoverageExtension) []byte {
	body := make([]byte, 0, 64)
	body = binary.BigEndian.AppendUint16(body, 0x0303)
	body = append(body, bytes.Repeat([]byte{1}, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = append(body, 1, 0)
	if len(extensions) == 0 {
		return body
	}

	var extensionBlock []byte
	for _, extension := range extensions {
		extensionBlock = append(
			extensionBlock,
			tlsCoverageRawExtension(extension.typ, extension.data)...,
		)
	}
	body = binary.BigEndian.AppendUint16(
		body,
		tlsCoverageUint16Length(len(extensionBlock)),
	)
	body = append(body, extensionBlock...)
	return body
}

func tlsCoverageBodyWithPrefix(prefix []byte) []byte {
	body := tlsCoverageBody()
	copy(body, prefix)
	return body
}

func tlsCoverageBodyMutate(mutate func([]byte)) []byte {
	body := tlsCoverageBody()
	mutate(body)
	return body
}

func tlsCoverageRawExtension(typ uint16, data []byte) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, tlsCoverageUint16Length(len(data)))
	out = append(out, data...)
	return out
}

func tlsCoverageSNIList(names ...[]byte) []byte {
	total := 0
	for _, name := range names {
		total += len(name)
	}
	list := make([]byte, 0, total)
	for _, name := range names {
		list = append(list, name...)
	}
	out := binary.BigEndian.AppendUint16(
		nil,
		tlsCoverageUint16Length(len(list)),
	)
	return append(out, list...)
}

func tlsCoverageSNIName(nameType byte, hostname string) []byte {
	out := []byte{nameType}
	out = binary.BigEndian.AppendUint16(
		out,
		tlsCoverageUint16Length(len(hostname)),
	)
	return append(out, hostname...)
}
