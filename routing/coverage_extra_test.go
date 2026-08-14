//nolint:testpackage
package routing

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sniffer"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func TestBytecodeHelperEdgeCoverage(t *testing.T) {
	ev := &bytecodeEval{
		network: "tcp4",
		laddr: newAddrCache(
			addrInput{str: "[2001:db8::1]:80"},
			nil,
			false,
		),
		raddr: newAddrCache(addrInput{str: "example.test:443"}, nil, false),
	}
	if !ev.isNet4() || ev.isNet6() {
		t.Fatal("network suffix did not control family detection")
	}
	ev.network = "other"
	if ev.portNetwork() != "other" {
		t.Fatalf("portNetwork() = %q, want other", ev.portNetwork())
	}

	if got := (*addrCache)(nil).host(); got != "" {
		t.Fatalf("nil host = %q, want empty", got)
	}
	if got := (*addrCache)(nil).ip(); got.IsValid() {
		t.Fatalf("nil ip = %v, want invalid", got)
	}
	if got := (*addrCache)(nil).port("tcp"); got != -1 {
		t.Fatalf("nil port = %d, want -1", got)
	}

	tcpAddr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 443}
	tcpCache := newAddrCache(addrInput{addr: tcpAddr}, nil, false)
	if got := tcpCache.host(); got != "192.0.2.10" {
		t.Fatalf("TCP host = %q, want 192.0.2.10", got)
	}
	if got := tcpCache.ipv4(); got != ip4(192, 0, 2, 10) {
		t.Fatalf("TCP ipv4 = %#x, want 192.0.2.10", got)
	}
	if got := newAddrCache(
		addrInput{str: "example.test:443"},
		nil,
		false,
	).ipv4(); got != 0 {
		t.Fatalf("FQDN ipv4 = %#x, want 0", got)
	}
	if got := tcpCache.port("tcp"); got != 443 {
		t.Fatalf("TCP port = %d, want 443", got)
	}

	udpCache := newAddrCache(
		addrInput{addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 53}},
		nil,
		false,
	)
	if got := udpCache.port("udp"); got != 53 {
		t.Fatalf("UDP port = %d, want 53", got)
	}

	ipCache := newAddrCache(
		addrInput{addr: &net.IPAddr{IP: net.ParseIP("2001:db8::1")}},
		nil,
		false,
	)
	if got := ipCache.host(); got != "2001:db8::1" {
		t.Fatalf("IPAddr host = %q, want 2001:db8::1", got)
	}
	if !ipCache.ip().Is6() {
		t.Fatalf("IPAddr ip = %v, want IPv6", ipCache.ip())
	}

	host, port, ok := splitHostPort("example.test:8443")
	if !ok || host != "example.test" || port != "8443" {
		t.Fatalf("splitHostPort() = %q %q %v, want example.test 8443 true",
			host, port, ok)
	}
	host, port, ok = splitHostPort("127.0.0.1:53")
	if !ok || host != "127.0.0.1" || port != "53" {
		t.Fatalf("splitHostPort(IPv4) = %q %q %v, want 127.0.0.1 53 true",
			host, port, ok)
	}
	if got := dnsPTRLiteralCacheKey(netip.Addr{}); got != "" {
		t.Fatalf("invalid PTR cache key = %q, want empty", got)
	}
	if got := reverseDNSNames(
		nil,
		netip.MustParseAddr("192.0.2.1"),
		time.Now(),
	); got != nil {
		t.Fatalf("reverseDNSNames(nil) = %#v, want nil", got)
	}
	if got := reverseDNSNames(
		gdns.NewMemoryStorage(),
		netip.Addr{},
		time.Now(),
	); got != nil {
		t.Fatalf("reverseDNSNames(invalid addr) = %#v, want nil", got)
	}
	if got := addrFromIP(net.IP{1, 2, 3}); got.IsValid() {
		t.Fatalf("addrFromIP(short) = %v, want invalid", got)
	}
	if _, ok := bytecodeParamIndex(3, 3); ok {
		t.Fatal("bytecodeParamIndex accepted out-of-range param")
	}
	if _, ok := bytecodeParamInt(1, -1); ok {
		t.Fatal("bytecodeParamInt accepted negative limit")
	}
	if _, ok := bytecodeParamInt(2, 1); ok {
		t.Fatal("bytecodeParamInt accepted out-of-range param")
	}
}

func TestDNSBytecodeAdditionalValidationAndExecutionEdges(t *testing.T) {
	validateErrs := []struct {
		name  string
		rules DNSBytecodeRules
		want  string
	}{
		{
			name: "invalid table",
			rules: DNSBytecodeRules{
				IPv6Addrs: []netip.Addr{{}},
			},
			want: "IPv6 address",
		},
		{
			name: "router method",
			rules: DNSBytecodeRules{
				Route: []byte{OP_DIAL, OP_DROP},
			},
			want: "not valid for DNSRoute",
		},
		{
			name: "split only",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_RULE, 0), OP_DROP),
			},
			want: "not valid for DNSRoute",
		},
		{
			name: "sniffer only",
			rules: DNSBytecodeRules{
				Route: []byte{OP_TRUE, OP_INTERCEPT},
			},
			want: "not valid for DNSRoute",
		},
		{
			name: "transport op",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_PORT, 53), OP_DROP),
			},
			want: "not valid for DNSRoute",
		},
		{
			name: "string index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_ADDR_S, 0), OP_DROP),
			},
			want: "string index 0 out of range 0",
		},
		{
			name: "regexp index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_ADDR_RE, 0), OP_DROP),
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "IPv4 address index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_ADDR4, 0), OP_DROP),
			},
			want: "IPv4 address index 0 out of range 0",
		},
		{
			name: "IPv6 address index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_ADDR6, 0), OP_DROP),
			},
			want: "IPv6 address index 0 out of range 0",
		},
		{
			name: "IPv4 subnet index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_SNET4, 0), OP_DROP),
			},
			want: "IPv4 subnet index 0 out of range 0",
		},
		{
			name: "IPv6 subnet index",
			rules: DNSBytecodeRules{
				Route: append(param16(OP_SNET6, 0), OP_DROP),
			},
			want: "IPv6 subnet index 0 out of range 0",
		},
	}
	for _, tt := range validateErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeDNSRouteFunc(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	cfg := &bytecodeDNSRouteFunc{
		backends: []string{"ok"},
		route: []byte{
			OP_FALSE, OP_NOT, OP_DROP,
			OP_TRUE, OP_FALSE, OP_OR, OP_BACKEND, 0, 0,
		},
	}
	if got := cfg.exec(
		dnsQuery("example.test.", gdns.TypeA, gdns.ClassIN),
	); got != "" {
		t.Fatalf("direct drop route = %q, want empty", got)
	}

	cfg.route = []byte{OP_TRUE, OP_BACKEND, 1, 0}
	if got := cfg.exec(
		dnsQuery("example.test.", gdns.TypeA, gdns.ClassIN),
	); got != "" {
		t.Fatalf("invalid backend index route = %q, want empty", got)
	}
	if _, ok := (&dnsBytecodeEval{}).qclass(); ok {
		t.Fatal("qclass without a question reported ok")
	}
	if _, err := NewDNSBytecodeRules("UDP\nBACKEND up\n"); err == nil ||
		!strings.Contains(err.Error(), "not valid for DNSRoute") {
		t.Fatalf("NewDNSBytecodeRules validation error = %v", err)
	}
}

func TestParserAdditionalEdgeCoverage(t *testing.T) {
	p := newBytecodeParser()
	appendErrs := []struct {
		name   string
		op     byte
		arg    string
		hasArg bool
		want   string
	}{
		{
			name:   "argument rejected",
			op:     OP_TRUE,
			arg:    "x",
			hasArg: true,
			want:   "does not accept",
		},
		{
			name:   "bad slot",
			op:     OP_SLOT,
			arg:    "999",
			hasArg: true,
			want:   "invalid SLOT argument",
		},
		{name: "missing string", op: OP_ADDR_S, want: "requires an argument"},
		{
			name:   "bad regexp",
			op:     OP_ADDR_RE,
			arg:    "[",
			hasArg: true,
			want:   "invalid ADDR_RE regexp",
		},
		{
			name:   "bad IPv4",
			op:     OP_ADDR4,
			arg:    "2001:db8::1",
			hasArg: true,
			want:   "invalid ADDR4 IPv4 address",
		},
		{
			name:   "bad IPv6",
			op:     OP_ADDR6,
			arg:    "192.0.2.1",
			hasArg: true,
			want:   "invalid ADDR6 IPv6 address",
		},
		{
			name:   "bad IPv4 subnet",
			op:     OP_SNET4,
			arg:    "2001:db8::/32",
			hasArg: true,
			want:   "invalid SNET4 IPv4 subnet",
		},
		{
			name:   "bad IPv6 subnet",
			op:     OP_SNET6,
			arg:    "192.0.2.0/24",
			hasArg: true,
			want:   "invalid SNET6 IPv6 subnet",
		},
		{
			name:   "bad rule",
			op:     OP_RULE,
			arg:    "typeonly",
			hasArg: true,
			want:   "requires a rule type",
		},
		{
			name:   "bad sniff",
			op:     OP_SNIFF,
			arg:    "missing",
			hasArg: true,
			want:   "unknown sniff classifier",
		},
		{
			name:   "bad route slot",
			op:     OP_ROUTE,
			arg:    "999",
			hasArg: true,
			want:   "invalid ROUTE slot",
		},
		{
			name:   "bad route field",
			op:     OP_ROUTE,
			arg:    "1 BAD",
			hasArg: true,
			want:   "must use KEY:VALUE",
		},
		{
			name:   "empty route field",
			op:     OP_ROUTE,
			arg:    "1 HOST:",
			hasArg: true,
			want:   "empty value",
		},
		{
			name:   "duplicate route field",
			op:     OP_ROUTE,
			arg:    "1 HOST:a HOST:b",
			hasArg: true,
			want:   "duplicate ROUTE field",
		},
		{
			name:   "unknown route field",
			op:     OP_ROUTE,
			arg:    "1 OTHER:x",
			hasArg: true,
			want:   "unknown ROUTE field",
		},
		{name: "unknown opcode", op: 255, want: "unknown opcode"},
	}
	for _, tt := range appendErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.appendOp(nil, tt.op, tt.arg, tt.hasArg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if _, err := requiredTextArg(OP_ADDR_S, "", true); err == nil {
		t.Fatal("requiredTextArg accepted an empty argument")
	}
	if _, err := parseUintArg(OP_SLOT, "", false, 8); err == nil {
		t.Fatal("parseUintArg accepted a missing argument")
	}
	if _, err := nextTableIndex("TEST", 0x10000); err == nil {
		t.Fatal("nextTableIndex accepted too many entries")
	}
	if _, err := checkedUint8("TEST", 256); err == nil {
		t.Fatal("checkedUint8 accepted 256")
	}
	if _, err := checkedUint16("TEST", 65536); err == nil {
		t.Fatal("checkedUint16 accepted 65536")
	}
	if got := bytecodeName(255); got != "opcode 255" {
		t.Fatalf("bytecodeName(255) = %q, want opcode 255", got)
	}
	if got := bytecodeBoolNot(
		bytecodeBoolState(99),
	); got != bytecodeBoolUnknown {
		t.Fatalf("bytecodeBoolNot(99) = %v, want unknown", got)
	}

	overflow := func() *bytecodeParser {
		p := newBytecodeParser()
		p.strings = make([]string, 0x10001)
		p.regexps = make([]*regexp.Regexp, 0x10001)
		p.ipv4Addrs = make([]uint32, 0x10001)
		p.ipv4Subnets = make([]IPv4Subnet, 0x10001)
		p.ipv6Addrs = make([]netip.Addr, 0x10001)
		p.ipv6Subnets = make([]netip.Prefix, 0x10001)
		p.rules = make([]sysnet.Rule, 0x10001)
		p.sniffClassifiers = make([]NamedSniffClassifier, 0x10001)
		p.routeActions = make([]SnifferRouteAction, 0x10001)
		p.backendNames = make([]string, 0x10001)
		return p
	}
	if _, err := overflow().stringParam(OP_ADDR_S, "x", true); err == nil {
		t.Fatal("stringParam accepted an overflowing table")
	}
	if _, err := overflow().regexpParam(OP_ADDR_RE, "x", true); err == nil {
		t.Fatal("regexpParam accepted an overflowing table")
	}
	if _, err := overflow().ipv4Param(OP_ADDR4, "192.0.2.1", true); err == nil {
		t.Fatal("ipv4Param accepted an overflowing table")
	}
	if _, err := overflow().ipv6Param(OP_ADDR6, "2001:db8::1", true); err == nil {
		t.Fatal("ipv6Param accepted an overflowing table")
	}
	if _, err := overflow().ipv4SubnetParam(OP_SNET4, "192.0.2.0/24", true); err == nil {
		t.Fatal("ipv4SubnetParam accepted an overflowing table")
	}
	if _, err := overflow().ipv6SubnetParam(OP_SNET6, "2001:db8::/32", true); err == nil {
		t.Fatal("ipv6SubnetParam accepted an overflowing table")
	}
	if _, err := overflow().ruleParam(OP_RULE, "type text", true); err == nil {
		t.Fatal("ruleParam accepted an overflowing table")
	}
	if _, err := overflow().addSniffClassifier(NamedSniffClassifier{
		Name:    "x",
		Factory: sniffer.HTTPFactory(),
	}); err == nil {
		t.Fatal("addSniffClassifier accepted an overflowing table")
	}
	if _, err := overflow().routeParam(OP_ROUTE, "1 HOST:x", true); err == nil {
		t.Fatal("routeParam accepted an overflowing table")
	}
	if _, err := overflow().backendParam(OP_BACKEND, "up", true); err == nil {
		t.Fatal("backendParam accepted an overflowing table")
	}
	if ruleType, rule, ok := splitRuleParam(
		"",
	); ok || ruleType != "" ||
		rule != "" {
		t.Fatalf("splitRuleParam(empty) = %q %q %v, want empty false",
			ruleType, rule, ok)
	}
	if _, err := p.routeParam(OP_ROUTE, "", true); err == nil {
		t.Fatal("routeParam accepted an empty field list")
	}
	if _, err := p.routeParam(OP_ROUTE, "   ", true); err == nil {
		t.Fatal("routeParam accepted a whitespace-only field list")
	}
	if _, err := p.sniffParam(OP_SNIFF, "bad name", true); err == nil {
		t.Fatal("sniffParam accepted invalid named classifier")
	}
	if _, err := p.sniffParam(OP_SNIFF, "", false); err == nil {
		t.Fatal("sniffParam accepted a missing argument")
	}
	if _, err := p.backendParam(OP_BACKEND, "", false); err == nil {
		t.Fatal("backendParam accepted a missing argument")
	}
	if _, err := NewSnifferBytecodeRules(nil, "BOGUS\nSLOT 1\n"); err == nil {
		t.Fatal("NewSnifferBytecodeRules accepted unknown operation")
	}
	if _, err := NewRemapperBytecodeRules(
		"ADDR_RE [\nREMAP DST ADDR 127.0.0.1\n",
	); err == nil {
		t.Fatal("NewRemapperBytecodeRules accepted invalid regexp")
	}
}

func TestRouterBytecodeAdditionalEdges(t *testing.T) {
	validateErrs := []struct {
		name  string
		rules BytecodeRules
		want  string
	}{
		{
			name: "lookup local op",
			rules: BytecodeRules{
				Lookup: append(param16(OP_LADDR4, 0), OP_DROP),
			},
			want: "local-address opcode",
		},
		{
			name: "IPv4 index",
			rules: BytecodeRules{
				DialTCP: append(param16(OP_ADDR4, 0), OP_DROP),
			},
			want: "IPv4 address index",
		},
		{
			name: "IPv6 index",
			rules: BytecodeRules{
				DialTCP: append(param16(OP_ADDR6, 0), OP_DROP),
			},
			want: "IPv6 address index",
		},
		{
			name: "IPv4 subnet index",
			rules: BytecodeRules{
				DialTCP: append(param16(OP_SNET4, 0), OP_DROP),
			},
			want: "IPv4 subnet index",
		},
		{
			name: "IPv6 subnet index",
			rules: BytecodeRules{
				DialTCP: append(param16(OP_SNET6, 0), OP_DROP),
			},
			want: "IPv6 subnet index",
		},
	}
	for _, tt := range validateErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeRouterCfg(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	cfg := &bytecodeRouterCfg{dialTCP: []byte{OP_TRUE, OP_SLOT, 99}}
	if got := cfg.exec(
		cfg.dialTCP,
		bytecodeMethodDial,
		"tcp",
		addrInput{},
		addrInput{},
		addrStringOps{},
	); got != 0 {
		t.Fatalf("invalid direct slot = %d, want 0", got)
	}
	cfg = &bytecodeRouterCfg{dialTCP: []byte{OP_TRUE, OP_DROP}}
	if got := cfg.exec(
		cfg.dialTCP,
		bytecodeMethodDial,
		"tcp",
		addrInput{},
		addrInput{},
		addrStringOps{},
	); got != 0 {
		t.Fatalf("direct drop = %d, want 0", got)
	}
}

func TestSniffSpecAdditionalCoverage(t *testing.T) {
	p := newBytecodeParser()
	err := p.setSniffClassifierConstructors([]NamedSniffClassifierConstructor{
		{
			Name: "Custom",
			Constructor: func([]SniffClassifierOption) (string, sniffer.Factory, error) {
				return "A:1", sniffer.HTTPFactory(), nil
			},
		},
	})
	if err != nil {
		t.Fatalf("setSniffClassifierConstructors() error = %v", err)
	}
	idx1, err := p.constructSniffClassifier("Custom")
	if err != nil {
		t.Fatalf("constructSniffClassifier(first) error = %v", err)
	}
	idx2, err := p.constructSniffClassifier("Custom")
	if err != nil {
		t.Fatalf("constructSniffClassifier(second) error = %v", err)
	}
	if idx1 != idx2 {
		t.Fatalf("duplicate inline classifier indexes = %d, %d", idx1, idx2)
	}

	if _, err := p.constructSniffClassifier("Missing URL:/"); err == nil ||
		!strings.Contains(err.Error(), "unknown sniff classifier constructor") {
		t.Fatalf("unknown constructor error = %v", err)
	}
	errConstructor := errors.New("constructor failed")
	p.sniffConstructors["Err"] = func([]SniffClassifierOption) (string, sniffer.Factory, error) {
		return "", nil, errConstructor
	}
	if _, err := p.constructSniffClassifier(
		"Err X:1",
	); !errors.Is(
		err,
		errConstructor,
	) {
		t.Fatalf("constructor error = %v, want %v", err, errConstructor)
	}
	p.sniffConstructors["Nil"] = func([]SniffClassifierOption) (string, sniffer.Factory, error) {
		return "", nil, nil
	}
	if _, err := p.constructSniffClassifier("Nil X:1"); err == nil ||
		!strings.Contains(err.Error(), "returned nil factory") {
		t.Fatalf("nil factory constructor error = %v", err)
	}
	if _, _, err := parseSniffClassifierSpec("HTTP BAD"); err == nil {
		t.Fatal("parseSniffClassifierSpec accepted malformed option")
	}
	if _, _, err := parseSniffClassifierSpec(""); err == nil {
		t.Fatal("parseSniffClassifierSpec accepted empty spec")
	}
	if _, _, err := parseSniffClassifierSpec("BAD:NAME X:1"); err == nil {
		t.Fatal("parseSniffClassifierSpec accepted bad constructor name")
	}
	if _, err := normalizeSniffClassifierConstructorName(
		"BAD:NAME",
	); err == nil {
		t.Fatal("normalizeSniffClassifierConstructorName accepted colon")
	}

	httpCanonical, httpFactory, err := buildHTTPSniffClassifier(
		[]SniffClassifierOption{
			{Key: "METHOD", Value: "GET"},
			{Key: "URL", Value: "/"},
			{Key: "URL_PATTERN", Value: `^/v1`},
			{Key: "VERSION", Value: "HTTP/1.1"},
			{Key: "HOST", Value: "example.test"},
			{Key: "HOST_PATTERN", Value: `\.test$`},
			{Key: "MAX_REQUEST_LINE_BYTES", Value: "128"},
			{Key: "MAX_HEADER_BYTES", Value: "256"},
		},
	)
	if err != nil {
		t.Fatalf("buildHTTPSniffClassifier() error = %v", err)
	}
	if httpCanonical == "" || httpFactory == nil {
		t.Fatalf("HTTP canonical/factory = %q/%v, want non-empty/non-nil",
			httpCanonical, httpFactory)
	}
	if _, _, err := buildHTTPSniffClassifier(
		[]SniffClassifierOption{{Key: "METHOD"}},
	); err == nil {
		t.Fatal("buildHTTPSniffClassifier accepted an empty value")
	}
	if _, _, err := buildHTTPSniffClassifier([]SniffClassifierOption{
		{Key: "MAX_HEADER_BYTES", Value: "x"},
	}); err == nil {
		t.Fatal("buildHTTPSniffClassifier accepted a bad integer")
	}
	if _, _, err := buildHTTPSniffClassifier([]SniffClassifierOption{
		{Key: "MAX_REQUEST_LINE_BYTES", Value: "x"},
	}); err == nil {
		t.Fatal("buildHTTPSniffClassifier accepted a bad request-line integer")
	}
	if _, _, err := buildHTTPSniffClassifier([]SniffClassifierOption{
		{Key: "MAX_HEADER_BYTES", Value: "1"},
		{Key: "MAX_HEADER_BYTES", Value: "2"},
	}); err == nil {
		t.Fatal("buildHTTPSniffClassifier accepted a duplicate scalar")
	}

	tlsCanonical, tlsFactory, err := buildTLSSniffClassifier(
		[]SniffClassifierOption{
			{Key: "VERSION", Value: "1.3"},
			{Key: "SNI", Value: "example.test"},
			{Key: "SNI_PATTERN", Value: `\.test$`},
			{Key: "ALPN", Value: "h2"},
			{Key: "ALPN_PATTERN", Value: `^http/`},
			{Key: "SNI_AVAILABLE", Value: "yes"},
			{Key: "SNI_ENCRYPTED", Value: "no"},
			{Key: "MAX_CLIENT_HELLO_BYTES", Value: "512"},
		},
	)
	if err != nil {
		t.Fatalf("buildTLSSniffClassifier() error = %v", err)
	}
	if tlsCanonical == "" || tlsFactory == nil {
		t.Fatalf("TLS canonical/factory = %q/%v, want non-empty/non-nil",
			tlsCanonical, tlsFactory)
	}
	if _, _, err := buildTLSSniffClassifier(
		[]SniffClassifierOption{{Key: "SNI"}},
	); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted an empty value")
	}
	if _, _, err := buildTLSSniffClassifier(
		[]SniffClassifierOption{{Key: "UNKNOWN", Value: "x"}},
	); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted unknown option")
	}
	if _, _, err := buildTLSSniffClassifier(
		[]SniffClassifierOption{{Key: "VERSION", Value: "bad"}},
	); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted bad TLS version")
	}
	if _, _, err := buildTLSSniffClassifier(
		[]SniffClassifierOption{{Key: "SNI_AVAILABLE", Value: "bad"}},
	); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted bad TLS flag")
	}
	if _, _, err := buildTLSSniffClassifier([]SniffClassifierOption{
		{Key: "SNI_AVAILABLE", Value: "yes"},
		{Key: "SNI_AVAILABLE", Value: "no"},
	}); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted duplicate scalar")
	}
	if _, _, err := buildTLSSniffClassifier([]SniffClassifierOption{
		{Key: "SNI_ENCRYPTED", Value: "bad"},
	}); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted bad encrypted flag")
	}
	if _, _, err := buildTLSSniffClassifier([]SniffClassifierOption{
		{Key: "MAX_CLIENT_HELLO_BYTES", Value: "x"},
	}); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted bad client-hello integer")
	}
	if _, _, err := buildTLSSniffClassifier([]SniffClassifierOption{
		{Key: "SNI_ENCRYPTED", Value: "yes"},
		{Key: "SNI_ENCRYPTED", Value: "no"},
	}); err == nil {
		t.Fatal("buildTLSSniffClassifier accepted duplicate encrypted flag")
	}

	for _, value := range []string{"1.0", "TLS1.1", "TLS12", "TLS1.3"} {
		if _, _, err := parseTLSVersionOption(value); err != nil {
			t.Fatalf("parseTLSVersionOption(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{
		"769",
		"770",
		"771",
		"772",
		"4660",
	} {
		if _, _, err := parseTLSVersionOption(value); err != nil {
			t.Fatalf("parseTLSVersionOption(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"ANY", "TRUE", "FORBIDDEN"} {
		if _, _, err := parseTLSFlagOption("FLAG", value); err != nil {
			t.Fatalf("parseTLSFlagOption(%q) error = %v", value, err)
		}
	}
	if got := formatSniffOptions([]SniffClassifierOption{
		{Key: "B", Value: "2"},
		{Key: "A", Value: "2"},
		{Key: "A", Value: "1"},
		{Key: "A", Value: "1"},
	}); got != "A:1 A:2 B:2" {
		t.Fatalf("formatSniffOptions() = %q", got)
	}

	_ = tls.VersionTLS13
}

func TestRemapperAdditionalValidationAndExecutionEdges(t *testing.T) {
	validateErrs := []struct {
		name  string
		rules RemapperBytecodeRules
		want  string
	}{
		{
			name: "invalid table",
			rules: RemapperBytecodeRules{
				IPv6Addrs: []netip.Addr{{}},
			},
			want: "IPv6 address",
		},
		{
			name: "missing addrport",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{Action: RemapAction{
					Endpoint: gonnect.RemapDst,
					Field:    gonnect.RemapAddrPort,
					Addr:     "127.0.0.1",
				}}},
			},
			want: "ADDR_PORT requires",
		},
		{
			name: "missing addr",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{Action: RemapAction{
					Endpoint: gonnect.RemapDst,
					Field:    gonnect.RemapAddr,
				}}},
			},
			want: "ADDR requires",
		},
		{
			name: "not underflow",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{Predicate: []byte{OP_NOT}, Action: validRemapAction()},
				},
			},
			want: "stack underflow",
		},
		{
			name: "and underflow",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: []byte{OP_TRUE, OP_AND},
						Action:    validRemapAction(),
					},
				},
			},
			want: "stack underflow",
		},
		{
			name: "regexp index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: param16(OP_ADDR_RE, 0),
						Action:    validRemapAction(),
					},
				},
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "IPv4 index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: param16(OP_ADDR4, 0),
						Action:    validRemapAction(),
					},
				},
			},
			want: "IPv4 address index 0 out of range 0",
		},
		{
			name: "IPv6 index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: param16(OP_ADDR6, 0),
						Action:    validRemapAction(),
					},
				},
			},
			want: "IPv6 address index 0 out of range 0",
		},
		{
			name: "IPv4 subnet index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: param16(OP_SNET4, 0),
						Action:    validRemapAction(),
					},
				},
			},
			want: "IPv4 subnet index 0 out of range 0",
		},
		{
			name: "IPv6 subnet index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{
					{
						Predicate: param16(OP_SNET6, 0),
						Action:    validRemapAction(),
					},
				},
			},
			want: "IPv6 subnet index 0 out of range 0",
		},
	}
	for _, tt := range validateErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeRemapRules(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if _, _, skip, err := newBytecodeParser().parseRemapRuleSegment(0, nil); err != nil ||
		!skip {
		t.Fatalf("empty remap segment skip=%v err=%v, want true nil", skip, err)
	}
	if _, err := parseRemapAction("", false); err == nil {
		t.Fatal("parseRemapAction accepted missing arg")
	}
	if _, err := parseRemapAction("DST ADDR", true); err == nil {
		t.Fatal("parseRemapAction accepted too few fields")
	}

	cfg := &bytecodeRemapperRules{
		strings: []string{"remote.test", "local.test"},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`remote`),
			regexp.MustCompile(`local`),
		},
		ipv4Addrs: []uint32{ip4(192, 0, 2, 10), ip4(198, 51, 100, 1)},
		ipv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(198, 51, 100, 0), Bits: 24},
		},
		ipv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("2001:db8::1"),
		},
		ipv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
	}
	info := gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "tcp",
		SrcAddr:   "local.test:1234",
		DstAddr:   "remote.test:443",
	}
	if !cfg.exec([]byte{OP_TRUE}, info, addrStringOps{}) {
		t.Fatal("remapper TRUE did not match")
	}
	if cfg.exec([]byte{OP_FALSE}, info, addrStringOps{}) {
		t.Fatal("remapper FALSE matched")
	}
	if !cfg.exec([]byte{OP_FALSE, OP_NOT}, info, addrStringOps{}) {
		t.Fatal("remapper NOT did not invert")
	}
	if !cfg.exec(param16(OP_LADDR_S, 1), info, addrStringOps{}) {
		t.Fatal("remapper local string did not match")
	}
	if !cfg.exec(param16(OP_ADDR_RE, 0), info, addrStringOps{}) {
		t.Fatal("remapper remote regexp did not match")
	}
	if !cfg.exec(param16(OP_LADDR_RE, 1), info, addrStringOps{}) {
		t.Fatal("remapper local regexp did not match")
	}
	if cfg.exec([]byte{OP_LOOKUP}, info, addrStringOps{}) {
		t.Fatal("remapper LOOKUP matched")
	}
	if _, listen := remapOperationClass(
		gonnect.RemapOperation("unknown"),
	); listen {
		t.Fatal("unknown remap op reported listen")
	}
}

func TestRemapperExecCoversPredicateOpcodes(t *testing.T) {
	cfg := &bytecodeRemapperRules{
		strings: []string{"remote.test", "local.test"},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`remote`),
			regexp.MustCompile(`local`),
		},
		ipv4Addrs: []uint32{ip4(192, 0, 2, 10), ip4(198, 51, 100, 1)},
		ipv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(198, 51, 100, 0), Bits: 24},
		},
		ipv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("2001:db8::1"),
		},
		ipv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
	}
	v4Info := gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "tcp4",
		SrcAddr:   "198.51.100.1:1234",
		DstAddr:   "192.0.2.10:443",
	}
	v6Info := gonnect.RemapInfo{
		Operation: gonnect.RemapOpListenUDP,
		Network:   "udp6",
		SrcAddr:   "[2001:db8::1]:5353",
		DstAddr:   "[2001:db8::10]:53",
	}
	nameInfo := gonnect.RemapInfo{
		Operation: gonnect.RemapOpDial,
		Network:   "tcp",
		SrcAddr:   "local.test:1234",
		DstAddr:   "remote.test:443",
	}
	tests := []struct {
		name string
		code []byte
		info gonnect.RemapInfo
	}{
		{name: "or", code: []byte{OP_FALSE, OP_TRUE, OP_OR}, info: nameInfo},
		{name: "net4", code: []byte{OP_NET4}, info: v4Info},
		{name: "net6", code: []byte{OP_NET6}, info: v6Info},
		{name: "udp", code: []byte{OP_UDP}, info: v6Info},
		{name: "fqdn", code: []byte{OP_FQDN}, info: nameInfo},
		{name: "lfqdn", code: []byte{OP_LFQDN}, info: nameInfo},
		{name: "addr4", code: param16(OP_ADDR4, 0), info: v4Info},
		{name: "laddr4", code: param16(OP_LADDR4, 1), info: v4Info},
		{name: "addr6", code: param16(OP_ADDR6, 0), info: v6Info},
		{name: "laddr6", code: param16(OP_LADDR6, 1), info: v6Info},
		{name: "lsnet4", code: param16(OP_LSNET4, 1), info: v4Info},
		{name: "snet6", code: param16(OP_SNET6, 0), info: v6Info},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !cfg.exec(tt.code, tt.info, bytecodeAddrStringOps(tt.code)) {
				t.Fatalf("%s predicate did not match", tt.name)
			}
		})
	}
}

func validRemapAction() RemapAction {
	return RemapAction{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddr,
		Addr:     "127.0.0.1",
	}
}

func TestSnifferAdditionalValidationAndExecutionEdges(t *testing.T) {
	validateErrs := []struct {
		name  string
		rules SnifferBytecodeRules
		want  string
	}{
		{
			name: "nil factory",
			rules: SnifferBytecodeRules{
				Classifiers: []NamedSniffClassifier{{Name: "x"}},
			},
			want: "nil factory",
		},
		{
			name: "duplicate classifier",
			rules: SnifferBytecodeRules{
				Classifiers: []NamedSniffClassifier{
					{Name: "x", Factory: sniffer.HTTPFactory()},
					{Name: "x", Factory: sniffer.HTTPFactory()},
				},
			},
			want: "duplicate sniff classifier",
		},
		{
			name: "nil regexp",
			rules: SnifferBytecodeRules{
				Regexps: []*regexp.Regexp{nil},
			},
			want: "regexp 0 is nil",
		},
		{
			name: "invalid table",
			rules: SnifferBytecodeRules{
				IPv6Addrs: []netip.Addr{{}},
			},
			want: "IPv6 address",
		},
		{
			name: "string index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_ADDR_S, 0), OP_DROP),
			},
			want: "string index 0 out of range 0",
		},
		{
			name: "regexp index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_ADDR_RE, 0), OP_DROP),
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "IPv4 index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_ADDR4, 0), OP_DROP),
			},
			want: "IPv4 address index 0 out of range 0",
		},
		{
			name: "IPv6 index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_ADDR6, 0), OP_DROP),
			},
			want: "IPv6 address index 0 out of range 0",
		},
		{
			name: "IPv4 subnet index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_SNET4, 0), OP_DROP),
			},
			want: "IPv4 subnet index 0 out of range 0",
		},
		{
			name: "IPv6 subnet index",
			rules: SnifferBytecodeRules{
				Control: append(param16(OP_SNET6, 0), OP_DROP),
			},
			want: "IPv6 subnet index 0 out of range 0",
		},
	}
	for _, tt := range validateErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeSnifferControls(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	cfg := &bytecodeSnifferControls{
		classifiers: []NamedSniffClassifier{
			{Name: "x", Factory: sniffer.HTTPFactory()},
		},
		strings: []string{"remote.test", "local.test"},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`remote`),
			regexp.MustCompile(`local`),
		},
		ipv4Addrs: []uint32{ip4(192, 0, 2, 10), ip4(198, 51, 100, 1)},
		ipv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(198, 51, 100, 0), Bits: 24},
		},
		ipv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("2001:db8::1"),
		},
		ipv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
		routeActions: []SnifferRouteAction{{Slot: 7}},
	}
	call := &sniffer.Call{
		Operation: sniffer.OpLookupHost,
		Network:   "ip",
		Src:       "local.test:1234",
		Dst:       "remote.test:443",
		Host:      "lookup.test",
		Service:   "https",
	}
	if got := cfg.exec([]byte{OP_TRUE, OP_INTERCEPT}, call,
		sniffer.SniffResult{}, addrStringOps{}); !got.Intercept {
		t.Fatalf("intercept action = %#v, want intercept", got)
	}
	if got := cfg.exec([]byte{OP_TRUE, OP_SLOT, 255}, call,
		sniffer.SniffResult{}, addrStringOps{}); got.Slot != 255 {
		t.Fatalf("slot action = %#v, want slot 255", got)
	}
	if got := cfg.exec(
		append([]byte{OP_TRUE}, param16(OP_ROUTE, 9)...),
		call,
		sniffer.SniffResult{},
		addrStringOps{},
	); got.Slot != sniffer.RejectSlot {
		t.Fatalf("invalid route action = %#v, want reject", got)
	}
	if got := cfg.exec(
		param16(OP_SNIFF, 0),
		call,
		sniffer.SniffResult{
			Index: 0,
		},
		addrStringOps{},
	); got.Slot != sniffer.RejectSlot {
		t.Fatalf("unterminated sniff action = %#v, want reject", got)
	}
	applySnifferCallMutation(nil, SnifferCallMutation{SetNetwork: true})
	if laddr, raddr := snifferCallAddresses(sniffer.Call{
		Operation: sniffer.OpLookupPort,
		Service:   "https",
	}); raddr != "https" || laddr != "" {
		t.Fatalf(
			"lookup port addresses = %q %q, want empty https",
			laddr,
			raddr,
		)
	}
	if _, raddr := snifferCallAddresses(sniffer.Call{
		Operation: sniffer.OpLookupTXT,
		Host:      "example.test",
	}); raddr != "example.test" {
		t.Fatalf("lookup host address = %q, want example.test", raddr)
	}
	if _, _, lookup := snifferOperationClass(
		sniffer.Operation("unknown"),
	); lookup {
		t.Fatal("unknown sniffer op reported lookup")
	}
	if _, err := NewBytecodeSniffer(
		sniffer.SnifferConfig{},
		SnifferBytecodeRules{
			Regexps: []*regexp.Regexp{nil},
		},
	); err == nil {
		t.Fatal("NewBytecodeSniffer accepted invalid rules")
	}
}

func TestSnifferExecCoversPredicateOpcodes(t *testing.T) {
	cfg := &bytecodeSnifferControls{
		classifiers: []NamedSniffClassifier{
			{Name: "x", Factory: sniffer.HTTPFactory()},
		},
		strings: []string{"remote.test", "local.test"},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`remote`),
			regexp.MustCompile(`local`),
		},
		ipv4Addrs: []uint32{ip4(192, 0, 2, 10), ip4(198, 51, 100, 1)},
		ipv4Subnets: []IPv4Subnet{
			{Addr: ip4(192, 0, 2, 0), Bits: 24},
			{Addr: ip4(198, 51, 100, 0), Bits: 24},
		},
		ipv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("2001:db8::1"),
		},
		ipv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
	}
	v4Call := &sniffer.Call{
		Operation: sniffer.OpDialTCP,
		Network:   "tcp4",
		Src:       "198.51.100.1:1234",
		Dst:       "192.0.2.10:443",
	}
	v6Call := &sniffer.Call{
		Operation: sniffer.OpListenUDP,
		Network:   "udp6",
		Src:       "[2001:db8::1]:5353",
		Dst:       "[2001:db8::10]:53",
	}
	nameCall := &sniffer.Call{
		Operation: sniffer.OpLookupHost,
		Network:   "ip",
		Src:       "local.test:1234",
		Dst:       "remote.test:443",
	}
	tests := []struct {
		name   string
		code   []byte
		call   *sniffer.Call
		result sniffer.SniffResult
	}{
		{name: "not", code: []byte{OP_FALSE, OP_NOT}, call: nameCall},
		{name: "net4", code: []byte{OP_NET4}, call: v4Call},
		{name: "net6", code: []byte{OP_NET6}, call: v6Call},
		{name: "udp", code: []byte{OP_UDP}, call: v6Call},
		{name: "lookup", code: []byte{OP_LOOKUP}, call: nameCall},
		{name: "fqdn", code: []byte{OP_FQDN}, call: nameCall},
		{name: "lfqdn", code: []byte{OP_LFQDN}, call: nameCall},
		{name: "laddr_s", code: param16(OP_LADDR_S, 1), call: nameCall},
		{name: "addr_re", code: param16(OP_ADDR_RE, 0), call: nameCall},
		{name: "laddr_re", code: param16(OP_LADDR_RE, 1), call: nameCall},
		{name: "addr4", code: param16(OP_ADDR4, 0), call: v4Call},
		{name: "laddr4", code: param16(OP_LADDR4, 1), call: v4Call},
		{name: "addr6", code: param16(OP_ADDR6, 0), call: v6Call},
		{name: "laddr6", code: param16(OP_LADDR6, 1), call: v6Call},
		{name: "snet4", code: param16(OP_SNET4, 0), call: v4Call},
		{name: "lsnet4", code: param16(OP_LSNET4, 1), call: v4Call},
		{name: "snet6", code: param16(OP_SNET6, 0), call: v6Call},
		{name: "lsnet6", code: param16(OP_LSNET6, 0), call: v6Call},
		{name: "lport", code: param16(OP_LPORT, 5353), call: v6Call},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := append([]byte(nil), tt.code...)
			code = append(code, OP_SLOT, 9)
			got := cfg.exec(
				code,
				tt.call,
				tt.result,
				bytecodeAddrStringOps(code),
			)
			if got.Slot != 9 {
				t.Fatalf("%s action = %#v, want slot 9", tt.name, got)
			}
		})
	}

	if _, _, lookup := snifferOperationClass(
		sniffer.OpInterfacesByName,
	); lookup {
		t.Fatal("interface operation reported lookup")
	}
}

func TestSplitAdditionalCoverage(t *testing.T) {
	if _, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:  &sysnetdebug.System{},
		Regexps: []*regexp.Regexp{nil},
		Route:   []byte{OP_TRUE, OP_SLOT, 1},
	}); err == nil || !strings.Contains(err.Error(), "regexp 0 is nil") {
		t.Fatalf("nil regexp error = %v", err)
	}
	if _, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:    &sysnetdebug.System{},
		IPv6Addrs: []netip.Addr{{}},
		Route:     []byte{OP_TRUE, OP_SLOT, 1},
	}); err == nil || !strings.Contains(err.Error(), "IPv6 address") {
		t.Fatalf("invalid table error = %v", err)
	}
	if _, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &sysnetdebug.System{
			RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
				return false, nil
			},
		},
		Rules: []sysnet.Rule{{Type: "err", Rule: "build"}},
		Route: append(param16(OP_RULE, 0), OP_SLOT, 1),
	}); err != nil {
		t.Fatalf("debug matcher build should succeed, got %v", err)
	}

	validateErrs := []struct {
		name  string
		rules SplitBytecodeRules
		want  string
	}{
		{
			name: "slot",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  []byte{OP_TRUE, OP_SLOT, 17},
			},
			want: "slot 17 out of range",
		},
		{
			name: "string",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_ADDR_S, 0), OP_DROP),
			},
			want: "string index 0 out of range 0",
		},
		{
			name: "regexp",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_ADDR_RE, 0), OP_DROP),
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "IPv4",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_ADDR4, 0), OP_DROP),
			},
			want: "IPv4 address index 0 out of range 0",
		},
		{
			name: "IPv6",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_ADDR6, 0), OP_DROP),
			},
			want: "IPv6 address index 0 out of range 0",
		},
		{
			name: "IPv4 subnet",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_SNET4, 0), OP_DROP),
			},
			want: "IPv4 subnet index 0 out of range 0",
		},
		{
			name: "IPv6 subnet",
			rules: SplitBytecodeRules{
				System: &sysnetdebug.System{},
				Route:  append(param16(OP_SNET6, 0), OP_DROP),
			},
			want: "IPv6 subnet index 0 out of range 0",
		},
	}
	for _, tt := range validateErrs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeSplitRouter(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if _, ok := parseIPPacket(nil, 0); ok {
		t.Fatal("parseIPPacket accepted nil packet")
	}
	if _, ok := parseIPPacket([]byte{0x10}, 0); ok {
		t.Fatal("parseIPPacket accepted unknown version")
	}
	if _, ok := parseIPv6Packet(make([]byte, 39)); ok {
		t.Fatal("parseIPv6Packet accepted short packet")
	}
	shortPayload := make([]byte, 40)
	shortPayload[0] = 0x60
	shortPayload[5] = 1
	if _, ok := parseIPv6Packet(shortPayload); ok {
		t.Fatal("parseIPv6Packet accepted missing payload")
	}
	if _, _, _, ok := skipIPv6ExtHeaders([]byte{0}, 0, 0); ok {
		t.Fatal("skipIPv6ExtHeaders accepted short extension header")
	}
	if _, _, _, ok := skipIPv6ExtHeaders([]byte{6, 1}, 0, 0); ok {
		t.Fatal("skipIPv6ExtHeaders accepted truncated extension header")
	}
	if _, _, _, ok := skipIPv6ExtHeaders([]byte{6}, 44, 0); ok {
		t.Fatal("skipIPv6ExtHeaders accepted short fragment header")
	}
	if _, _, _, ok := skipIPv6ExtHeaders([]byte{6}, 51, 0); ok {
		t.Fatal("skipIPv6ExtHeaders accepted short auth header")
	}
	if _, _, _, ok := skipIPv6ExtHeaders([]byte{6, 1}, 51, 0); ok {
		t.Fatal("skipIPv6ExtHeaders accepted truncated auth header")
	}

	hopByHop := ipv6WithExtHeader(0, []byte{17, 0, 0, 0, 0, 0, 0, 0},
		udpHeader(1, 2))
	if pkt, ok := parseIPv6Packet(
		hopByHop,
	); !ok || !pkt.hasPorts ||
		pkt.proto != 17 {
		t.Fatalf("hop-by-hop IPv6 parse = %#v %v, want UDP ports", pkt, ok)
	}
	frag := ipv6WithExtHeader(44, []byte{17, 0, 0, 8, 0, 0, 0, 0}, nil)
	if pkt, ok := parseIPv6Packet(frag); !ok || pkt.flowOK {
		t.Fatalf("fragment IPv6 parse = %#v %v, want non-flow packet", pkt, ok)
	}
	auth := ipv6WithExtHeader(51, append([]byte{17, 0, 0, 0, 0, 0, 0, 0},
		udpHeader(1, 2)...), nil)
	if pkt, ok := parseIPv6Packet(
		auth,
	); !ok || !pkt.hasPorts ||
		pkt.proto != 17 {
		t.Fatalf("auth IPv6 parse = %#v %v, want UDP ports", pkt, ok)
	}

	cache := newSplitRuleResultCache(time.Minute, 1)
	cache.entries[splitRuleCacheKey{rule: 1}] = splitRuleCacheEntry{expires: 1}
	cache.set(splitRuleCacheKey{rule: 2}, true, 10)
	if len(cache.entries) > 1 {
		t.Fatalf("rule cache entries = %d, want pruned", len(cache.entries))
	}
	routeCache := newSplitRouteResultCache(time.Minute, 1, 0, 0)
	routeCache.entries[splitRouteCacheKey{proto: 1}] = splitRouteCacheEntry{
		expires: 1,
	}
	routeCache.set(splitRouteCacheKey{proto: 2}, 9, 10)
	if len(routeCache.entries) > 1 {
		t.Fatalf(
			"route cache entries = %d, want pruned",
			len(routeCache.entries),
		)
	}
	cache = newSplitRuleResultCache(time.Minute, 2)
	for i := range 4 {
		rule := uint16(i) //nolint:gosec // i is bounded by the constant range.
		cache.entries[splitRuleCacheKey{rule: rule}] = splitRuleCacheEntry{
			expires: 100,
		}
	}
	cache.pruneLocked(10)
	if len(cache.entries) > 2 {
		t.Fatalf(
			"rule cache half-prune entries = %d, want <=2",
			len(cache.entries),
		)
	}
	routeCache = newSplitRouteResultCache(time.Minute, 2, 0, 0)
	for i := range 4 {
		proto := uint8(i) //nolint:gosec // i is bounded by the constant range.
		routeCache.entries[splitRouteCacheKey{proto: proto}] = splitRouteCacheEntry{
			expires: 100,
		}
	}
	routeCache.pruneLocked(10)
	if len(routeCache.entries) > 2 {
		t.Fatalf(
			"route cache half-prune entries = %d, want <=2",
			len(routeCache.entries),
		)
	}

	if newSplitRuleResultCache(0, -1) != nil {
		t.Fatal("negative max entries did not disable rule cache")
	}
	if newSplitRouteResultCache(0, -1, 0, 0) != nil {
		t.Fatal("negative route max entries did not disable route cache")
	}
	if got := compileSplitIPv4Subnets(
		[]IPv4Subnet{{Bits: 0}},
	); got[0] != (splitIPv4Subnet{}) {
		t.Fatalf("zero subnet compile = %#v, want zero", got[0])
	}
	if _, _, ok := compileSplitRoute([]byte{OP_DROP}); ok {
		t.Fatal("compileSplitRoute accepted drop underflow")
	}
	if _, _, ok := compileSplitRoute([]byte{OP_TRUE, OP_AND, OP_DROP}); ok {
		t.Fatal("compileSplitRoute accepted AND underflow")
	}
	if _, _, ok := compileSplitRoute([]byte{OP_TRUE}); ok {
		t.Fatal("compileSplitRoute accepted unterminated stack")
	}
}

func TestSplitGenericFallbackCoversInstructionOpcodes(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "fallback"}
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			return false, nil
		},
	}
	route := make([]byte, 0, 256)
	for range 65 {
		route = append(route, OP_TRUE)
	}
	addFalseTerminal := func(expr []byte) {
		route = append(route, expr...)
		route = append(route, OP_SLOT, 1)
	}
	addFalseTerminal([]byte{OP_FALSE})
	addFalseTerminal([]byte{OP_TRUE, OP_NOT})
	addFalseTerminal([]byte{OP_TRUE, OP_FALSE, OP_AND})
	addFalseTerminal([]byte{OP_FALSE, OP_FALSE, OP_OR})
	addFalseTerminal([]byte{OP_NET4, OP_NOT})
	addFalseTerminal([]byte{OP_NET6})
	addFalseTerminal([]byte{OP_UDP})
	addFalseTerminal([]byte{OP_TCP, OP_NOT})
	addFalseTerminal([]byte{OP_FQDN})
	addFalseTerminal(append(param16(OP_LADDR_S, 0), OP_NOT))
	addFalseTerminal(append(param16(OP_ADDR_RE, 0), OP_NOT))
	addFalseTerminal(param16(OP_LADDR_RE, 0))
	addFalseTerminal(param16(OP_ADDR4, 1))
	addFalseTerminal(append(param16(OP_LADDR4, 0), OP_NOT))
	addFalseTerminal(param16(OP_ADDR6, 0))
	addFalseTerminal(param16(OP_LADDR6, 0))
	addFalseTerminal(param16(OP_SNET4, 1))
	addFalseTerminal(append(param16(OP_LSNET4, 0), OP_NOT))
	addFalseTerminal(param16(OP_SNET6, 0))
	addFalseTerminal(param16(OP_LSNET6, 0))
	addFalseTerminal(param16(OP_PORT, 80))
	addFalseTerminal(param16(OP_LPORT, 9999))
	addFalseTerminal(param16(OP_RULE, 0))
	route = append(route, OP_SLOT, 8)

	router, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:  system,
		Rules:   []sysnet.Rule{rule},
		Strings: []string{"198.51.100.1"},
		Regexps: []*regexp.Regexp{
			regexp.MustCompile(`192\.0\.2`),
		},
		IPv4Addrs: []uint32{ip4(198, 51, 100, 1), ip4(203, 0, 113, 1)},
		IPv4Subnets: []IPv4Subnet{
			{Addr: ip4(198, 51, 100, 0), Bits: 24},
			{Addr: ip4(203, 0, 113, 0), Bits: 24},
		},
		IPv6Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		IPv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
		},
		RuleCacheTTL:  -1,
		RouteCacheTTL: -1,
		Route:         route,
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}
	cfg, ok := router.(*bytecodeSplitRouter)
	if !ok {
		t.Fatalf("router type = %T, want *bytecodeSplitRouter", router)
	}
	cfg.Lock()
	if cfg.routeCompiled {
		cfg.Unlock()
		t.Fatal("route compiled, want fallback evaluator")
	}
	cfg.Unlock()
	if cfg.routeStackDepth <= 64 {
		t.Fatalf("routeStackDepth = %d, want >64", cfg.routeStackDepth)
	}
	if got := cfg.Route(ipv4TCPPacket(
		[4]byte{198, 51, 100, 1},
		[4]byte{192, 0, 2, 2},
		1234,
		443,
	), 0, true); got != 8 {
		t.Fatalf("Route() = %d, want 8", got)
	}

	dropRouter, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        &sysnetdebug.System{},
		RouteCacheTTL: -1,
		Route:         []byte{OP_TRUE, OP_FALSE, OP_DROP, OP_DROP},
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter(drop) error = %v", err)
	}
	if got := dropRouter.Route(ipv4TCPPacket(
		[4]byte{198, 51, 100, 1},
		[4]byte{192, 0, 2, 2},
		1234,
		443,
	), 0, true); got != 0 {
		t.Fatalf("drop Route() = %d, want 0", got)
	}
	compiledDrop, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &sysnetdebug.System{},
		Route:  []byte{OP_TRUE, OP_DROP},
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter(compiled drop) error = %v", err)
	}
	if got := compiledDrop.Route(ipv4TCPPacket(
		[4]byte{198, 51, 100, 1},
		[4]byte{192, 0, 2, 2},
		1234,
		443,
	), 0, true); got != 0 {
		t.Fatalf("compiled drop Route() = %d, want 0", got)
	}
}

func TestSplitConditionBuilderAndRecursiveEvalEdges(t *testing.T) {
	b := newSplitCondBuilder()
	atomA := b.atom(OP_TCP, 0)
	atomB := b.atom(OP_NET4, 0)
	if got := b.not(b.trueCond); got != b.falseCond {
		t.Fatalf("not(true) = %d, want false cond", got)
	}
	if got := b.not(b.not(atomA)); got != atomA {
		t.Fatalf("double not = %d, want atom", got)
	}
	if got := b.and(b.trueCond, atomA); got != atomA {
		t.Fatalf("true and atom = %d, want atom", got)
	}
	if got := b.or(b.falseCond, atomA); got != atomA {
		t.Fatalf("false or atom = %d, want atom", got)
	}
	left := b.join(splitCondAnd, atomA, atomB)
	right := b.join(splitCondAnd, b.atom(OP_NET4, 0), b.atom(OP_PORT, 443))
	joined := b.join(splitCondAnd, left, right)
	if len(b.conds[joined].children) != 4 {
		t.Fatalf(
			"flattened children = %d, want 4",
			len(b.conds[joined].children),
		)
	}
	complexNot := b.not(b.join(splitCondAnd, atomA, atomB))
	if kind, preds := b.fastPredicates(
		complexNot,
	); kind != splitFastCondNone ||
		preds != nil {
		t.Fatalf(
			"fastPredicates(complex not) = %v %#v, want none nil",
			kind,
			preds,
		)
	}
	if kind, preds := b.fastPredicates(
		b.falseCond,
	); kind != splitFastCondNone ||
		preds != nil {
		t.Fatalf("fastPredicates(false) = %v %#v, want none nil", kind, preds)
	}
	if kind, preds := b.fastPredicates(
		b.not(atomA),
	); kind != splitFastCondAll ||
		len(preds) != 1 ||
		!preds[0].not {
		t.Fatalf("fastPredicates(not atom) = %v %#v", kind, preds)
	}
	mixed := b.join(splitCondAnd, atomA, b.falseCond)
	if kind, preds := b.fastPredicates(mixed); kind != splitFastCondAll ||
		len(preds) != 2 || !preds[1].not {
		t.Fatalf("fastPredicates(const child) = %v %#v", kind, preds)
	}
	nested := b.join(splitCondAnd, atomA, b.join(splitCondOr, atomA, atomB))
	if kind, preds := b.fastPredicates(nested); kind != splitFastCondNone ||
		preds != nil {
		t.Fatalf(
			"fastPredicates(nested mixed) = %v %#v, want none nil",
			kind,
			preds,
		)
	}

	cfg := &bytecodeSplitRouter{
		routeConds: b.conds,
	}
	ev := &splitEval{
		cfg: cfg,
		packet: parsedIPPacket{
			src:      netip.MustParseAddr("192.0.2.1"),
			dst:      netip.MustParseAddr("192.0.2.2"),
			proto:    6,
			dstPort:  443,
			hasPorts: true,
		},
	}
	if !cfg.evalCond(ev, b.trueCond) {
		t.Fatal("evalCond(true) = false")
	}
	if !cfg.evalCond(ev, joined) {
		t.Fatal("evalCond(and) = false")
	}
	orCond := b.join(splitCondOr, b.falseCond, atomA)
	cfg.routeConds = b.conds
	if !cfg.evalCond(ev, orCond) {
		t.Fatal("evalCond(or) = false")
	}
	falseAnd := b.join(splitCondAnd, b.falseCond, atomA)
	cfg.routeConds = b.conds
	if cfg.evalCond(ev, falseAnd) {
		t.Fatal("evalCond(false and atom) = true")
	}
	cfg.routeConds = append(cfg.routeConds, splitCond{kind: splitCondKind(99)})
	if cfg.evalCond(ev, len(cfg.routeConds)-1) {
		t.Fatal("evalCond(unknown kind) = true")
	}
}

func ipv6WithExtHeader(next uint8, ext []byte, payload []byte) []byte {
	pkt := make([]byte, 40+len(ext)+len(payload))
	pkt[0] = 0x60
	pkt[6] = next
	payloadLen := len(ext) + len(payload)
	if payloadLen > 0xffff {
		panic("payload length out of range")
	}
	//nolint:gosec // payloadLen is range checked immediately above.
	binaryLen := uint16(payloadLen)
	pkt[4] = byte(binaryLen >> 8)
	pkt[5] = byte(binaryLen)
	copy(pkt[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(pkt[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	copy(pkt[40:], ext)
	copy(pkt[40+len(ext):], payload)
	return pkt
}

func udpHeader(src, dst uint16) []byte {
	return []byte{
		byte(src >> 8),
		byte(src),
		byte(dst >> 8),
		byte(dst),
		0,
		8,
		0,
		0,
	}
}

func TestSplitBuildMatcherErrorAndManualEvalEdges(t *testing.T) {
	errBuild := errors.New("build failed")
	if _, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &buildMatcherErrorSystem{err: errBuild},
		Rules:  []sysnet.Rule{{Type: "x", Rule: "y"}},
		Route:  append(param16(OP_RULE, 0), OP_SLOT, 1),
	}); !errors.Is(err, errBuild) {
		t.Fatalf("NewBytecodeSplitRouter() error = %v, want build error", err)
	}

	cfg := &bytecodeSplitRouter{
		strings: []string{"192.0.2.2", "10.0.0.1"},
		regexps: []*regexp.Regexp{
			regexp.MustCompile(`192\.0\.2`),
			regexp.MustCompile(`10\.0\.0`),
		},
		ipv4Addrs: []uint32{ip4(192, 0, 2, 2), ip4(10, 0, 0, 1)},
		splitSubnets: []splitIPv4Subnet{
			{addr: ip4(192, 0, 2, 0), mask: 0xffffff00},
			{addr: ip4(10, 0, 0, 0), mask: 0xffffff00},
		},
		ipv6Addrs: []netip.Addr{
			netip.MustParseAddr("2001:db8::2"),
			netip.MustParseAddr("2001:db8::1"),
		},
		ipv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
	}
	pkt, ok := parseIPv4Packet(ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		1234,
		443,
	))
	if !ok {
		t.Fatal("parseIPv4Packet failed")
	}
	ev := &splitEval{cfg: cfg, packet: pkt, cacheable: true}
	preds := []splitPredicate{
		{op: OP_TRUE},
		{op: OP_NET4},
		{op: OP_TCP},
		{op: OP_ADDR_S, param: 0},
		{op: OP_LADDR_S, param: 1},
		{op: OP_ADDR_RE, param: 0},
		{op: OP_LADDR_RE, param: 1},
		{op: OP_ADDR4, param: 0},
		{op: OP_LADDR4, param: 1},
		{op: OP_SNET4, param: 0},
		{op: OP_LSNET4, param: 1},
		{op: OP_PORT, param: 443},
		{op: OP_LPORT, param: 1234},
	}
	if !ev.predicates(splitFastCondAll, preds) {
		t.Fatal("IPv4 all predicates did not match")
	}
	if ev.predicates(splitFastCondAll, []splitPredicate{{op: OP_FALSE}}) {
		t.Fatal("false all predicate matched")
	}
	if !ev.predicates(splitFastCondAny, []splitPredicate{
		{op: OP_FALSE},
		{op: OP_TRUE},
	}) {
		t.Fatal("any predicates did not match true")
	}
	if ev.predicates(
		splitFastCondAny,
		[]splitPredicate{{op: OP_TRUE, not: true}},
	) {
		t.Fatal("negated true any predicate matched")
	}

	ev.packet = parsedIPPacket{
		src:      netip.MustParseAddr("2001:db8::1"),
		dst:      netip.MustParseAddr("2001:db8::2"),
		proto:    17,
		srcPort:  5353,
		dstPort:  53,
		hasPorts: true,
	}
	if !ev.predicates(splitFastCondAll, []splitPredicate{
		{op: OP_NET6},
		{op: OP_UDP},
		{op: OP_ADDR6, param: 0},
		{op: OP_LADDR6, param: 1},
		{op: OP_SNET6, param: 0},
		{op: OP_LSNET6, param: 0},
		{op: OP_PORT, param: 53},
		{op: OP_LPORT, param: 5353},
	}) {
		t.Fatal("IPv6 all predicates did not match")
	}
	ev.packet = pkt
	for _, pred := range []splitPredicate{
		{op: OP_NET4},
		{op: OP_TCP},
		{op: OP_ADDR_S, param: 0},
		{op: OP_LADDR_S, param: 1},
		{op: OP_ADDR_RE, param: 0},
		{op: OP_LADDR_RE, param: 1},
		{op: OP_ADDR4, param: 0},
		{op: OP_LADDR4, param: 1},
		{op: OP_SNET4, param: 0},
		{op: OP_LSNET4, param: 1},
		{op: OP_PORT, param: 443},
		{op: OP_LPORT, param: 1234},
	} {
		if !ev.predicates(splitFastCondAny, []splitPredicate{pred}) {
			t.Fatalf("any predicate op %d did not match", pred.op)
		}
	}
	if ev.atom(255, 0) {
		t.Fatal("unknown atom matched")
	}
	if ev.rule(0) {
		t.Fatal("missing matcher rule matched")
	}
	ev.native = true
	ev.cfg.matchers = []sysnet.Matcher{nil}
	if ev.rule(0) {
		t.Fatal("nil matcher rule matched")
	}

	atomTests := []struct {
		name string
		op   byte
		want bool
	}{
		{name: "true", op: OP_TRUE, want: true},
		{name: "false", op: OP_FALSE},
		{name: "fqdn", op: OP_FQDN},
		{name: "net4", op: OP_NET4, want: true},
		{name: "tcp", op: OP_TCP, want: true},
		{name: "laddr_s", op: OP_LADDR_S, want: true},
		{name: "laddr_re", op: OP_LADDR_RE, want: true},
		{name: "addr4", op: OP_ADDR4, want: true},
		{name: "laddr4", op: OP_LADDR4, want: true},
		{name: "snet4", op: OP_SNET4, want: true},
		{name: "lsnet4", op: OP_LSNET4, want: true},
		{name: "lport", op: OP_LPORT, want: true},
	}
	ev.packet = pkt
	for _, tt := range atomTests {
		t.Run(tt.name, func(t *testing.T) {
			param := uint16(0)
			if tt.op == OP_LADDR_S || tt.op == OP_LADDR_RE ||
				tt.op == OP_LADDR4 || tt.op == OP_LSNET4 {
				param = 1
			}
			if tt.op == OP_LPORT {
				param = 1234
			}
			if got := ev.atom(tt.op, param); got != tt.want {
				t.Fatalf("atom(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
	ev.packet = parsedIPPacket{
		src:      netip.MustParseAddr("2001:db8::1"),
		dst:      netip.MustParseAddr("2001:db8::2"),
		proto:    17,
		srcPort:  5353,
		dstPort:  53,
		hasPorts: true,
	}
	for _, tt := range []struct {
		name  string
		op    byte
		param uint16
	}{
		{name: "net6", op: OP_NET6},
		{name: "udp", op: OP_UDP},
		{name: "addr6", op: OP_ADDR6, param: 0},
		{name: "laddr6", op: OP_LADDR6, param: 1},
		{name: "snet6", op: OP_SNET6, param: 0},
		{name: "lsnet6", op: OP_LSNET6, param: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !ev.atom(tt.op, tt.param) {
				t.Fatalf("atom(%s) = false, want true", tt.name)
			}
		})
	}
}

type buildMatcherErrorSystem struct {
	sysnetdebug.System
	err error
}

func (s *buildMatcherErrorSystem) BuildMatcher(
	sysnet.Rule,
) (sysnet.Matcher, error) {
	return nil, s.err
}
