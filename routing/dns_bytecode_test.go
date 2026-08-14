// nolint
//
//nolint:testpackage
package routing

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	gdns "github.com/asciimoth/gonnect/dns"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func TestBytecodeDNSRouteFuncRoutesByBytecode(t *testing.T) {
	addr6 := netip.MustParseAddr("2001:db8::53")
	route := append(param16(OP_QTYPE, gdns.TypeAAAA), param16(OP_BACKEND, 1)...)
	route = append(route, param16(OP_ADDR_S, 0)...)
	route = append(route, param16(OP_BACKEND, 0)...)
	route = append(route, param16(OP_ADDR_RE, 0)...)
	route = append(route, param16(OP_BACKEND, 2)...)
	route = append(route, param16(OP_ADDR4, 0)...)
	route = append(route, param16(OP_BACKEND, 3)...)
	route = append(route, param16(OP_ADDR6, 0)...)
	route = append(route, param16(OP_BACKEND, 4)...)
	route = append(route, param16(OP_OPCODE, uint16(gdns.OpcodeQuery))...)
	route = append(route, param16(OP_BACKEND, 5)...)

	fn, err := NewBytecodeDNSRouteFunc(DNSBytecodeRules{
		Backends: []string{
			"corp",
			"v6",
			"regex",
			"literal4",
			"literal6",
			"fallback",
		},
		Strings:   []string{"internal.test."},
		Regexps:   []*regexp.Regexp{regexp.MustCompile(`\.mesh\.$`)},
		IPv4Addrs: []uint32{ip4(192, 0, 2, 53)},
		IPv6Addrs: []netip.Addr{addr6},
		Route:     route,
	})
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}

	tests := []struct {
		name string
		msg  *gdns.Message
		want string
	}{
		{
			name: "AAAA type",
			msg:  dnsQuery("example.test.", gdns.TypeAAAA, gdns.ClassIN),
			want: "v6",
		},
		{
			name: "case-insensitive name",
			msg:  dnsQuery("Internal.TEST.", gdns.TypeA, gdns.ClassIN),
			want: "corp",
		},
		{
			name: "regexp name",
			msg:  dnsQuery("node.mesh.", gdns.TypeA, gdns.ClassIN),
			want: "regex",
		},
		{
			name: "IPv4 literal",
			msg:  dnsQuery("192.0.2.53", gdns.TypeA, gdns.ClassIN),
			want: "literal4",
		},
		{
			name: "IPv6 literal",
			msg:  dnsQuery("2001:db8::53", gdns.TypeA, gdns.ClassIN),
			want: "literal6",
		},
		{
			name: "opcode fallback",
			msg:  dnsQuery("public.test.", gdns.TypeA, gdns.ClassIN),
			want: "fallback",
		},
		{
			name: "no question still can match opcode",
			msg:  &gdns.Message{Opcode: gdns.OpcodeQuery},
			want: "fallback",
		},
		{
			name: "nil message",
			msg:  nil,
			want: "",
		},
	}
	for _, tt := range tests {
		if got := fn(tt.msg); got != tt.want {
			t.Fatalf("%s route = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestBytecodeDNSRouteFuncSupportsDropAndDefaultReject(t *testing.T) {
	route := append(param16(OP_ADDR_S, 0), OP_DROP)
	route = append(route, param16(OP_QCLASS, gdns.ClassIN)...)
	route = append(route, param16(OP_BACKEND, 0)...)
	fn, err := NewBytecodeDNSRouteFunc(DNSBytecodeRules{
		Backends: []string{"default"},
		Strings:  []string{"blocked.test."},
		Route:    route,
	})
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}

	if got := fn(
		dnsQuery("blocked.test.", gdns.TypeA, gdns.ClassIN),
	); got != "" {
		t.Fatalf("blocked route = %q, want empty backend", got)
	}
	if got := fn(
		dnsQuery("allowed.test.", gdns.TypeA, gdns.ClassIN),
	); got != "default" {
		t.Fatalf("allowed route = %q, want default", got)
	}
	if got := fn(dnsQuery("allowed.test.", gdns.TypeA, 255)); got != "" {
		t.Fatalf("non-IN route = %q, want empty backend", got)
	}
}

func TestNewDNSBytecodeRulesParsesRouteText(t *testing.T) {
	rules, err := NewDNSBytecodeRules(`
ADDR_S internal.test.
QTYPE A
AND
BACKEND corp

ADDR_RE \.mesh\.$
QTYPE AAAA
OR
BACKEND mesh
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}

	if got, want := rules.Backends, []string{
		"corp",
		"mesh",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("Backends = %#v, want %#v", got, want)
	}
	if got, want := rules.Strings, []string{
		"internal.test.",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("Strings = %#v, want %#v", got, want)
	}
	if got, want := len(rules.Regexps), 1; got != want {
		t.Fatalf("Regexps len = %d, want %d", got, want)
	}
	fn, err := NewBytecodeDNSRouteFunc(rules)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	if got := fn(
		dnsQuery("internal.test.", gdns.TypeA, gdns.ClassIN),
	); got != "corp" {
		t.Fatalf("internal A route = %q, want corp", got)
	}
	if got := fn(
		dnsQuery("host.mesh.", gdns.TypeA, gdns.ClassIN),
	); got != "mesh" {
		t.Fatalf("mesh A route = %q, want mesh", got)
	}
	if got := fn(
		dnsQuery("example.test.", gdns.TypeAAAA, gdns.ClassIN),
	); got != "mesh" {
		t.Fatalf("AAAA route = %q, want mesh", got)
	}
}

func TestNewDNSBytecodeRulesParsesNumericArgsAndDeduplicatesBackends(
	t *testing.T,
) {
	rules, err := NewDNSBytecodeRules(`
QTYPE 28
QCLASS 1
AND
BACKEND default

OPCODE 0
BACKEND default
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}
	if got, want := rules.Backends, []string{"default"}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("Backends = %#v, want %#v", got, want)
	}

	fn, err := NewBytecodeDNSRouteFunc(rules)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	if got := fn(
		dnsQuery("example.test.", gdns.TypeAAAA, gdns.ClassIN),
	); got != "default" {
		t.Fatalf("AAAA IN route = %q, want default", got)
	}
	if got := fn(
		dnsQuery("example.test.", gdns.TypeA, gdns.ClassIN),
	); got != "default" {
		t.Fatalf("opcode fallback route = %q, want default", got)
	}
}

func TestBytecodeDNSRouteFuncRoutesSubnetsAndFirstQuestion(t *testing.T) {
	rules, err := NewDNSBytecodeRules(`
SNET4 192.0.2.0/24
BACKEND subnet4

SNET6 2001:db8::/32
BACKEND subnet6

NET4
BACKEND a

NET6
BACKEND aaaa

TRUE
BACKEND fallback
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}
	fn, err := NewBytecodeDNSRouteFunc(rules)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}

	tests := []struct {
		name string
		msg  *gdns.Message
		want string
	}{
		{
			name: "IPv4 subnet",
			msg:  dnsQuery("192.0.2.44", gdns.TypeTXT, gdns.ClassIN),
			want: "subnet4",
		},
		{
			name: "bracketed IPv6 subnet",
			msg:  dnsQuery("[2001:db8::44]", gdns.TypeTXT, gdns.ClassIN),
			want: "subnet6",
		},
		{
			name: "A question maps to NET4",
			msg:  dnsQuery("example.test.", gdns.TypeA, gdns.ClassIN),
			want: "a",
		},
		{
			name: "AAAA question maps to NET6",
			msg:  dnsQuery("example.test.", gdns.TypeAAAA, gdns.ClassIN),
			want: "aaaa",
		},
		{
			name: "second question is ignored",
			msg: &gdns.Message{
				Opcode: gdns.OpcodeQuery,
				Questions: []gdns.Question{
					{
						Name:  "first.test.",
						Type:  gdns.TypeTXT,
						Class: gdns.ClassIN,
					},
					{
						Name:  "192.0.2.44",
						Type:  gdns.TypeTXT,
						Class: gdns.ClassIN,
					},
				},
			},
			want: "fallback",
		},
	}
	for _, tt := range tests {
		if got := fn(tt.msg); got != tt.want {
			t.Fatalf("%s route = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestBytecodeDNSRouteFuncHandlesFQDNAndLiteralEdges(t *testing.T) {
	rules, err := NewDNSBytecodeRules(`
FQDN
BACKEND names

ADDR4 198.51.100.10
BACKEND v4

ADDR6 2001:db8::10
BACKEND v6

TRUE
BACKEND fallback
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}
	fn, err := NewBytecodeDNSRouteFunc(rules)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}

	tests := []struct {
		name string
		msg  *gdns.Message
		want string
	}{
		{
			name: "name",
			msg:  dnsQuery("example.test.", gdns.TypeA, gdns.ClassIN),
			want: "names",
		},
		{
			name: "empty question name",
			msg:  dnsQuery("", gdns.TypeA, gdns.ClassIN),
			want: "fallback",
		},
		{
			name: "IPv4 literal is not FQDN",
			msg:  dnsQuery("198.51.100.10", gdns.TypeA, gdns.ClassIN),
			want: "v4",
		},
		{
			name: "bracketed IPv6 literal is not FQDN",
			msg:  dnsQuery("[2001:db8::10]", gdns.TypeAAAA, gdns.ClassIN),
			want: "v6",
		},
	}
	for _, tt := range tests {
		if got := fn(tt.msg); got != tt.want {
			t.Fatalf("%s route = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestBytecodeDNSRouteFuncCopiesSourceRules(t *testing.T) {
	route := append(param16(OP_ADDR_S, 0), param16(OP_BACKEND, 0)...)
	source := DNSBytecodeRules{
		Backends: []string{"up"},
		Strings:  []string{"service.test."},
		Route:    route,
	}
	fn, err := NewBytecodeDNSRouteFunc(source)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	source.Backends[0] = "changed"
	source.Strings[0] = "changed.test."
	source.Route[0] = OP_FALSE

	if got := fn(
		dnsQuery("service.test.", gdns.TypeA, gdns.ClassIN),
	); got != "up" {
		t.Fatalf("route after source mutation = %q, want up", got)
	}
}

func TestBytecodeDNSRouteFuncCopiesAddressTables(t *testing.T) {
	addr6 := netip.MustParseAddr("2001:db8::44")
	route := append(param16(OP_ADDR_RE, 0), param16(OP_BACKEND, 0)...)
	route = append(route, param16(OP_ADDR4, 0)...)
	route = append(route, param16(OP_BACKEND, 1)...)
	route = append(route, param16(OP_SNET4, 0)...)
	route = append(route, param16(OP_BACKEND, 2)...)
	route = append(route, param16(OP_ADDR6, 0)...)
	route = append(route, param16(OP_BACKEND, 3)...)
	route = append(route, param16(OP_SNET6, 0)...)
	route = append(route, param16(OP_BACKEND, 4)...)
	source := DNSBytecodeRules{
		Backends: []string{
			"regex",
			"addr4",
			"subnet4",
			"addr6",
			"subnet6",
		},
		Regexps:     []*regexp.Regexp{regexp.MustCompile(`\.copy\.$`)},
		IPv4Addrs:   []uint32{ip4(192, 0, 2, 44)},
		IPv4Subnets: []IPv4Subnet{{Addr: ip4(198, 51, 100, 0), Bits: 24}},
		IPv6Addrs:   []netip.Addr{addr6},
		IPv6Subnets: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")},
		Route:       route,
	}
	fn, err := NewBytecodeDNSRouteFunc(source)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	source.Regexps[0] = regexp.MustCompile(`\.changed\.$`)
	source.IPv4Addrs[0] = ip4(203, 0, 113, 44)
	source.IPv4Subnets[0] = IPv4Subnet{Addr: ip4(203, 0, 113, 0), Bits: 24}
	source.IPv6Addrs[0] = netip.MustParseAddr("2001:db8:2::44")
	source.IPv6Subnets[0] = netip.MustParsePrefix("2001:db8:3::/48")

	tests := []struct {
		name string
		msg  *gdns.Message
		want string
	}{
		{
			name: "regexp table",
			msg:  dnsQuery("host.copy.", gdns.TypeA, gdns.ClassIN),
			want: "regex",
		},
		{
			name: "IPv4 address table",
			msg:  dnsQuery("192.0.2.44", gdns.TypeA, gdns.ClassIN),
			want: "addr4",
		},
		{
			name: "IPv4 subnet table",
			msg:  dnsQuery("198.51.100.44", gdns.TypeA, gdns.ClassIN),
			want: "subnet4",
		},
		{
			name: "IPv6 address table",
			msg:  dnsQuery("2001:db8::44", gdns.TypeAAAA, gdns.ClassIN),
			want: "addr6",
		},
		{
			name: "IPv6 subnet table",
			msg:  dnsQuery("2001:db8:1::44", gdns.TypeAAAA, gdns.ClassIN),
			want: "subnet6",
		},
	}
	for _, tt := range tests {
		if got := fn(tt.msg); got != tt.want {
			t.Fatalf("%s route = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestBytecodeDNSRouteFuncValidation(t *testing.T) {
	tests := []struct {
		name  string
		rules DNSBytecodeRules
		want  string
	}{
		{
			name:  "empty backend",
			rules: DNSBytecodeRules{Backends: []string{""}},
			want:  "backend 0 has empty name",
		},
		{
			name:  "nil regexp",
			rules: DNSBytecodeRules{Regexps: []*regexp.Regexp{nil}},
			want:  "regexp 0 is nil",
		},
		{
			name: "backend index",
			rules: DNSBytecodeRules{
				Route: append([]byte{OP_TRUE}, param16(OP_BACKEND, 0)...),
			},
			want: "backend index 0 out of range 0",
		},
		{
			name:  "local address invalid",
			rules: DNSBytecodeRules{Route: param16(OP_LADDR_S, 0)},
			want:  "not valid for DNSRoute",
		},
		{
			name:  "slot invalid",
			rules: DNSBytecodeRules{Route: []byte{OP_TRUE, OP_SLOT, 1}},
			want:  "not valid for DNSRoute",
		},
		{
			name: "stack underflow",
			rules: DNSBytecodeRules{
				Route:    param16(OP_BACKEND, 0),
				Backends: []string{"up"},
			},
			want: "stack underflow",
		},
	}
	for _, tt := range tests {
		_, err := NewBytecodeDNSRouteFunc(tt.rules)
		if err == nil || !stringsContains(err.Error(), tt.want) {
			t.Fatalf(
				"%s error = %v, want containing %q",
				tt.name,
				err,
				tt.want,
			)
		}
	}
}

func TestNewDNSBytecodeRulesParsesNamedArgsCaseInsensitive(t *testing.T) {
	rules, err := NewDNSBytecodeRules(`
qtype txt
qclass in
AND
opcode query
AND
backend MixedCase
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}
	if got, want := rules.Backends, []string{"MixedCase"}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("Backends = %#v, want %#v", got, want)
	}
	fn, err := NewBytecodeDNSRouteFunc(rules)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	if got := fn(
		dnsQuery("example.test.", gdns.TypeTXT, gdns.ClassIN),
	); got != "MixedCase" {
		t.Fatalf("TXT IN route = %q, want MixedCase", got)
	}
}

func TestNewDNSBytecodeRulesRejectsInvalidDNSArgs(t *testing.T) {
	tests := []struct {
		name    string
		program string
		want    string
	}{
		{
			name: "missing qtype",
			program: `
QTYPE
BACKEND up
`,
			want: "operation QTYPE requires an argument",
		},
		{
			name: "unknown qtype",
			program: `
QTYPE APL
BACKEND up
`,
			want: "invalid QTYPE argument",
		},
		{
			name: "qclass overflow",
			program: `
QCLASS 65536
BACKEND up
`,
			want: "invalid QCLASS argument",
		},
		{
			name:    "empty backend",
			program: "TRUE\nBACKEND \t\n",
			want:    "operation BACKEND requires a backend name",
		},
	}
	for _, tt := range tests {
		_, err := NewDNSBytecodeRules(tt.program)
		if err == nil || !stringsContains(err.Error(), tt.want) {
			t.Fatalf(
				"%s error = %v, want containing %q",
				tt.name,
				err,
				tt.want,
			)
		}
	}
}

func TestDNSOnlyOpsRejectedByOtherConstructors(t *testing.T) {
	if _, err := NewBytecodeRouterCfg(BytecodeRules{
		Lookup: append([]byte{OP_TRUE}, param16(OP_BACKEND, 0)...),
	}); err == nil || !stringsContains(err.Error(), "not valid for RouterCfg") {
		t.Fatalf(
			"NewBytecodeRouterCfg() error = %v, want DNS-only rejection",
			err,
		)
	}
	if _, err := NewSplitBytecodeRules(
		&sysnetdebug.System{},
		"QTYPE A\nDROP\n",
	); err == nil ||
		!stringsContains(err.Error(), "not valid for SplitRouter") {
		t.Fatalf(
			"NewSplitBytecodeRules() error = %v, want DNS-only rejection",
			err,
		)
	}
	if _, err := NewSnifferBytecodeRules(nil, "QTYPE A\nDROP\n"); err == nil ||
		!stringsContains(err.Error(), "not valid for Sniffer") {
		t.Fatalf(
			"NewSnifferBytecodeRules() error = %v, want DNS-only rejection",
			err,
		)
	}
	if _, err := NewRemapRules(
		"QTYPE A\nREMAP DST ADDR 127.0.0.1\n",
	); err == nil ||
		!stringsContains(err.Error(), "not valid for Remapper") {
		t.Fatalf("NewRemapRules() error = %v, want DNS-only rejection", err)
	}
}

func TestDNSRouteFuncWorksWithDNSRouter(t *testing.T) {
	fn, err := NewDNSBytecodeRules(`
ADDR_S corp.test.
BACKEND corp

TRUE
BACKEND public
`)
	if err != nil {
		t.Fatalf("NewDNSBytecodeRules() error = %v", err)
	}
	route, err := NewBytecodeDNSRouteFunc(fn)
	if err != nil {
		t.Fatalf("NewBytecodeDNSRouteFunc() error = %v", err)
	}
	router := gdns.NewRouter(nil)
	corp := newRouteTestDNS("corp")
	public := newRouteTestDNS("public")
	defer router.Close()
	defer corp.Close()
	defer public.Close()
	if err := router.Attach("corp", corp); err != nil {
		t.Fatalf("Attach corp error = %v", err)
	}
	if err := router.Attach("public", public); err != nil {
		t.Fatalf("Attach public error = %v", err)
	}
	if err := router.AttachRouter(route); err != nil {
		t.Fatalf("AttachRouter() error = %v", err)
	}

	assertDNSRouterBackend(t, router, "corp.test.", "corp")
	assertDNSRouterBackend(t, router, "example.test.", "public")
	if err := router.Detach("public"); err != nil {
		t.Fatalf("Detach public error = %v", err)
	}
	_, err = queryDNSWithTimeout(router, "example.test.")
	if !errors.Is(err, gdns.ErrNoUpstream) {
		t.Fatalf("query detached public error = %v, want ErrNoUpstream", err)
	}
}

func dnsQuery(name string, qtype, qclass uint16) *gdns.Message {
	return &gdns.Message{
		Opcode: gdns.OpcodeQuery,
		Questions: []gdns.Question{{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		}},
	}
}

type routeTestDNS struct {
	name string
	reqs chan gdns.Request
	done chan struct{}
}

func newRouteTestDNS(name string) *routeTestDNS {
	d := &routeTestDNS{
		name: name,
		reqs: make(chan gdns.Request),
		done: make(chan struct{}),
	}
	go func() {
		for {
			select {
			case req := <-d.reqs:
				d.handle(req)
			case <-d.done:
				return
			}
		}
	}()
	return d
}

func (d *routeTestDNS) handle(req gdns.Request) {
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		req.Reply <- gdns.Response{Err: ctx.Err()}
	default:
		resp := req.Message.Copy()
		if resp == nil {
			resp = &gdns.Message{}
		}
		resp.Response = true
		resp.Answers = []gdns.Resource{{
			Name:  firstDNSQuestionName(req.Message),
			Type:  gdns.TypeTXT,
			Class: gdns.ClassIN,
			TTL:   1,
			Data:  []byte(d.name),
		}}
		req.Reply <- gdns.Response{Message: resp}
	}
}

func (d *routeTestDNS) Requests() chan<- gdns.Request { return d.reqs }

func (d *routeTestDNS) Close() error {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
	return nil
}

func assertDNSRouterBackend(
	t *testing.T,
	router gdns.Interface,
	name, backend string,
) {
	t.Helper()
	resp, err := queryDNSWithTimeout(router, name)
	if err != nil {
		t.Fatalf("query %q error = %v", name, err)
	}
	if resp == nil || len(resp.Answers) != 1 {
		t.Fatalf("query %q response = %#v, want one answer", name, resp)
	}
	if got := string(resp.Answers[0].Data); got != backend {
		t.Fatalf("query %q backend = %q, want %q", name, got, backend)
	}
}

func queryDNSWithTimeout(
	router gdns.Interface,
	name string,
) (*gdns.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return gdns.Query(ctx, router, dnsQuery(name, gdns.TypeA, gdns.ClassIN))
}

func firstDNSQuestionName(msg *gdns.Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return ""
	}
	return msg.Questions[0].Name
}

func stringsContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
