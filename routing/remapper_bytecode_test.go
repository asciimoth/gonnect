//nolint:testpackage
package routing

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
)

func TestNewRemapperBytecodeRulesParsesRemapSegments(t *testing.T) {
	rules, err := NewRemapperBytecodeRules(`
ADDR_S service.test
REMAP DST ADDR 127.0.0.1

LADDR_RE ^127\.
REMAP SRC PORT 5353

TRUE
REMAP DST ADDR_PORT [::1]:9443

TRUE
REMAP DST ADDR [2001:db8::1]
`)
	if err != nil {
		t.Fatalf("NewRemapperBytecodeRules() error = %v", err)
	}

	if got, want := rules.Strings, []string{
		"service.test",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Strings = %#v, want %#v", got, want)
	}
	if len(rules.Regexps) != 1 || rules.Regexps[0].String() != `^127\.` {
		t.Fatalf("Regexps = %#v, want one ^127\\. regexp", rules.Regexps)
	}
	if got, want := len(rules.Rules), 4; got != want {
		t.Fatalf("Rules len = %d, want %d", got, want)
	}
	if got, want := rules.Rules[0].Predicate, param16(
		OP_ADDR_S,
		0,
	); !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("first predicate = %#v, want %#v", got, want)
	}
	if got, want := rules.Rules[0].Action, (RemapAction{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddr,
		Addr:     "127.0.0.1",
	}); got != want {
		t.Fatalf("first action = %#v, want %#v", got, want)
	}
	if got, want := rules.Rules[2].Action, (RemapAction{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddrPort,
		Addr:     "::1",
		Port:     "9443",
	}); got != want {
		t.Fatalf("third action = %#v, want %#v", got, want)
	}
	if got, want := rules.Rules[3].Action, (RemapAction{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddr,
		Addr:     "2001:db8::1",
	}); got != want {
		t.Fatalf("fourth action = %#v, want %#v", got, want)
	}
}

func TestNewRemapperBytecodeRulesParsesActionAliases(t *testing.T) {
	rules, err := NewRemapperBytecodeRules(`
# comment-only segments are ignored.

TRUE
REMAP SOURCE ADDRESS_PORT 127.0.0.1:5353

TRUE
REMAP REMOTE ADDRESS 203.0.113.10
`)
	if err != nil {
		t.Fatalf("NewRemapperBytecodeRules() error = %v", err)
	}
	if got, want := len(rules.Rules), 2; got != want {
		t.Fatalf("Rules len = %d, want %d", got, want)
	}
	if got, want := rules.Rules[0].Action, (RemapAction{
		Endpoint: gonnect.RemapSrc,
		Field:    gonnect.RemapAddrPort,
		Addr:     "127.0.0.1",
		Port:     "5353",
	}); got != want {
		t.Fatalf("first action = %#v, want %#v", got, want)
	}
	if got, want := rules.Rules[1].Action, (RemapAction{
		Endpoint: gonnect.RemapDst,
		Field:    gonnect.RemapAddr,
		Addr:     "203.0.113.10",
	}); got != want {
		t.Fatalf("second action = %#v, want %#v", got, want)
	}
}

func TestBytecodeRemapRulesWorkWithRemapper(t *testing.T) {
	rules, err := NewRemapRules(`
DIAL
TCP
AND
ADDR_S service.test
AND
REMAP DST ADDR 127.0.0.1

DIAL
PORT 80
AND
REMAP DST PORT 8080

LISTEN
UDP
AND
REMAP SRC ADDR_PORT 127.0.0.1:5353
`)
	if err != nil {
		t.Fatalf("NewRemapRules() error = %v", err)
	}

	ctx := context.Background()
	wrapped := newRemapCaptureNetwork()
	remapper := gonnect.NewRemapper(wrapped, rules)

	if _, err := remapper.DialTCP(
		ctx,
		"tcp6",
		"",
		"service.test:80",
	); !errors.Is(
		err,
		errRemapCapture,
	) {
		t.Fatalf("DialTCP() error = %v, want capture error", err)
	}
	if got, want := wrapped.args("DialTCP"), []string{
		"tcp4",
		"",
		"127.0.0.1:8080",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DialTCP args = %#v, want %#v", got, want)
	}

	if _, err := remapper.ListenUDP(ctx, "udp6", "[::1]:0"); !errors.Is(
		err,
		errRemapCapture,
	) {
		t.Fatalf("ListenUDP() error = %v, want capture error", err)
	}
	if got, want := wrapped.args("ListenUDP"), []string{
		"udp4",
		"127.0.0.1:5353",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ListenUDP args = %#v, want %#v", got, want)
	}
}

func TestBytecodeRemapRulesEvaluateLocalAndMethodPredicates(t *testing.T) {
	rules, err := NewRemapRules(`
DIAL
LADDR_S local.test
AND
REMAP DST PORT 8443
`)
	if err != nil {
		t.Fatalf("NewRemapRules() error = %v", err)
	}
	if got, want := len(rules), 1; got != want {
		t.Fatalf("rules len = %d, want %d", got, want)
	}
	filter := rules[0].Filter
	if filter == nil {
		t.Fatal("compiled rule has nil filter")
	}

	if !filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "tcp",
		Endpoint:  gonnect.RemapDst,
		Address:   "remote.test:443",
		SrcAddr:   "local.test:0",
		DstAddr:   "remote.test:443",
	}) {
		t.Fatal("filter did not match dial with matching local address")
	}
	if filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpListenTCP,
		Network:   "tcp",
		Endpoint:  gonnect.RemapDst,
		Address:   "remote.test:443",
		SrcAddr:   "local.test:0",
		DstAddr:   "remote.test:443",
	}) {
		t.Fatal("filter matched listen even though DIAL is required")
	}
}

func TestBytecodeRemapRulesAllowEmptyPredicate(t *testing.T) {
	rules, err := NewRemapRules(`
REMAP DST PORT 443
`)
	if err != nil {
		t.Fatalf("NewRemapRules() error = %v", err)
	}
	if got, want := len(rules), 1; got != want {
		t.Fatalf("rules len = %d, want %d", got, want)
	}
	if rules[0].Filter != nil {
		t.Fatal("empty predicate produced non-nil filter")
	}

	wrapped := newRemapCaptureNetwork()
	remapper := gonnect.NewRemapper(wrapped, rules)
	if _, err := remapper.DialTCP(
		context.Background(),
		"tcp",
		"",
		"service.test:80",
	); !errors.Is(
		err,
		errRemapCapture,
	) {
		t.Fatalf("DialTCP() error = %v, want capture error", err)
	}
	if got, want := wrapped.args("DialTCP"), []string{
		"tcp",
		"",
		"service.test:443",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DialTCP args = %#v, want %#v", got, want)
	}
}

func TestBytecodeRemapRulesNormalizeBracketedIPv6Addr(t *testing.T) {
	rules, err := NewRemapRules(`
TRUE
REMAP DST ADDR [::1]
`)
	if err != nil {
		t.Fatalf("NewRemapRules() error = %v", err)
	}

	wrapped := newRemapCaptureNetwork()
	remapper := gonnect.NewRemapper(wrapped, rules)
	if _, err := remapper.DialTCP(
		context.Background(),
		"tcp4",
		"",
		"service.test:80",
	); !errors.Is(
		err,
		errRemapCapture,
	) {
		t.Fatalf("DialTCP() error = %v, want capture error", err)
	}
	if got, want := wrapped.args("DialTCP"), []string{
		"tcp6",
		"",
		"[::1]:80",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DialTCP args = %#v, want %#v", got, want)
	}
}

func TestBytecodeRemapRulesUseReverseDNSCache(t *testing.T) {
	storage := &staticDNSStorage{
		msg: &gdns.Message{
			Response: true,
			RCode:    gdns.RCodeSuccess,
			Answers: []gdns.Resource{{
				Type:  gdns.TypePTR,
				Class: gdns.ClassIN,
				TTL:   60,
				Data:  []byte("service.test"),
			}},
		},
		ok: true,
	}
	rules, err := NewBytecodeRemapRules(RemapperBytecodeRules{
		Strings:         []string{"service.test"},
		DNSCacheStorage: storage,
		Rules: []RemapperBytecodeRule{{
			Predicate: param16(OP_ADDR_S, 0),
			Action: RemapAction{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapPort,
				Port:     "8443",
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewBytecodeRemapRules() error = %v", err)
	}
	if !rules[0].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "tcp",
		Endpoint:  gonnect.RemapDst,
		Address:   "203.0.113.10:443",
		DstAddr:   "203.0.113.10:443",
	}) {
		t.Fatal("filter did not match reverse DNS name")
	}
	if got, want := storage.key, "203.0.113.10.|12|1"; got != want {
		t.Fatalf("reverse DNS cache key = %q, want %q", got, want)
	}
}

func TestBytecodeRemapRulesEvaluateSubnetsAndServicePorts(t *testing.T) {
	remote := append(param16(OP_SNET4, 0), param16(OP_PORT, 80)...)
	remote = append(remote, OP_AND)
	local := make([]byte, 0, 10)
	local = append(local, OP_LISTEN, OP_UDP, OP_AND)
	local = append(local, param16(OP_LSNET6, 0)...)
	local = append(local, OP_AND)
	local = append(local, param16(OP_LPORT, 5353)...)
	local = append(local, OP_AND)
	rules, err := NewBytecodeRemapRules(RemapperBytecodeRules{
		IPv4Subnets: []IPv4Subnet{{
			Addr: ip4(203, 0, 113, 0),
			Bits: 24,
		}},
		IPv6Subnets: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/32"),
		},
		Rules: []RemapperBytecodeRule{
			{
				Predicate: remote,
				Action: RemapAction{
					Endpoint: gonnect.RemapDst,
					Field:    gonnect.RemapPort,
					Port:     "8080",
				},
			},
			{
				Predicate: local,
				Action: RemapAction{
					Endpoint: gonnect.RemapSrc,
					Field:    gonnect.RemapAddr,
					Addr:     "::1",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewBytecodeRemapRules() error = %v", err)
	}

	if !rules[0].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "TCP",
		Endpoint:  gonnect.RemapDst,
		Address:   "203.0.113.44:http",
		DstAddr:   "203.0.113.44:http",
	}) {
		t.Fatal("remote filter did not match IPv4 subnet and service port")
	}
	if rules[0].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "TCP",
		Endpoint:  gonnect.RemapDst,
		Address:   "203.0.114.44:http",
		DstAddr:   "203.0.114.44:http",
	}) {
		t.Fatal("remote filter matched address outside subnet")
	}
	if !rules[1].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpListenUDP,
		Network:   "UDP6",
		Endpoint:  gonnect.RemapSrc,
		Address:   "[2001:db8::44]:5353",
		SrcAddr:   "[2001:db8::44]:5353",
	}) {
		t.Fatal("local filter did not match IPv6 subnet and UDP port")
	}
	if rules[1].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialUDP,
		Network:   "UDP6",
		Endpoint:  gonnect.RemapSrc,
		Address:   "[2001:db8::44]:5353",
		SrcAddr:   "[2001:db8::44]:5353",
	}) {
		t.Fatal("local filter matched dial even though LISTEN is required")
	}
}

func TestBytecodeRemapRulesValidateInput(t *testing.T) {
	tests := []struct {
		name    string
		program string
		wantErr string
	}{
		{
			name: "missing remap",
			program: `
TRUE
`,
			wantErr: "segment must end with REMAP",
		},
		{
			name: "predicate stack depth",
			program: `
TRUE
TRUE
REMAP DST ADDR 127.0.0.1
`,
			wantErr: "predicate leaves stack depth 2",
		},
		{
			name: "sniffer predicate",
			program: `
SNIFF_NONE
REMAP DST ADDR 127.0.0.1
`,
			wantErr: "not valid for Remapper",
		},
		{
			name: "bad action",
			program: `
TRUE
REMAP DST ADDR_PORT 127.0.0.1
`,
			wantErr: "must be host:port",
		},
		{
			name: "unknown endpoint",
			program: `
TRUE
REMAP PEER ADDR 127.0.0.1
`,
			wantErr: "unknown REMAP endpoint",
		},
		{
			name: "unknown field",
			program: `
TRUE
REMAP DST HOST 127.0.0.1
`,
			wantErr: "unknown REMAP field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRemapRules(tt.program)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf(
					"NewRemapRules() error = %v, want containing %q",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestBytecodeRemapRulesValidateDirectInput(t *testing.T) {
	tests := []struct {
		name  string
		rules RemapperBytecodeRules
		want  string
	}{
		{
			name: "nil regexp",
			rules: RemapperBytecodeRules{
				Regexps: []*regexp.Regexp{nil},
			},
			want: "regexp 0 is nil",
		},
		{
			name: "string index",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{
					Predicate: param16(OP_ADDR_S, 0),
					Action: RemapAction{
						Endpoint: gonnect.RemapDst,
						Field:    gonnect.RemapAddr,
						Addr:     "127.0.0.1",
					},
				}},
			},
			want: "string index 0 out of range 0",
		},
		{
			name: "invalid action endpoint",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{
					Action: RemapAction{
						Endpoint: gonnect.RemapEndpoint(99),
						Field:    gonnect.RemapAddr,
						Addr:     "127.0.0.1",
					},
				}},
			},
			want: "invalid endpoint",
		},
		{
			name: "invalid action field",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{
					Action: RemapAction{
						Endpoint: gonnect.RemapDst,
						Field:    gonnect.RemapField(99),
						Addr:     "127.0.0.1",
					},
				}},
			},
			want: "invalid field",
		},
		{
			name: "missing action port",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{
					Action: RemapAction{
						Endpoint: gonnect.RemapDst,
						Field:    gonnect.RemapPort,
					},
				}},
			},
			want: "PORT requires non-empty Port",
		},
		{
			name: "dns opcode",
			rules: RemapperBytecodeRules{
				Rules: []RemapperBytecodeRule{{
					Predicate: param16(OP_QTYPE, gdns.TypeA),
					Action: RemapAction{
						Endpoint: gonnect.RemapDst,
						Field:    gonnect.RemapAddr,
						Addr:     "127.0.0.1",
					},
				}},
			},
			want: "not valid for Remapper",
		},
	}
	for _, tt := range tests {
		_, err := NewBytecodeRemapRules(tt.rules)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf(
				"%s error = %v, want containing %q",
				tt.name,
				err,
				tt.want,
			)
		}
	}
}

func TestBytecodeRemapRulesCopySourceRules(t *testing.T) {
	code := param16(OP_ADDR_S, 0)
	source := RemapperBytecodeRules{
		Strings: []string{"service.test"},
		Rules: []RemapperBytecodeRule{{
			Predicate: code,
			Action: RemapAction{
				Endpoint: gonnect.RemapDst,
				Field:    gonnect.RemapAddr,
				Addr:     "127.0.0.1",
			},
		}},
	}
	rules, err := NewBytecodeRemapRules(source)
	if err != nil {
		t.Fatalf("NewBytecodeRemapRules() error = %v", err)
	}
	source.Strings[0] = "changed.test"
	code[0] = OP_FALSE

	if !rules[0].Filter(gonnect.RemapInfo{
		Operation: gonnect.RemapOpDialTCP,
		Network:   "tcp",
		Endpoint:  gonnect.RemapDst,
		Address:   "service.test:80",
		DstAddr:   "service.test:80",
	}) {
		t.Fatal("filter changed after source rules were mutated")
	}
}

var errRemapCapture = errors.New("remap capture")

type remapCaptureNetwork struct {
	*gonnect.RejectNetwork

	mu    sync.Mutex
	calls map[string][]string
}

func newRemapCaptureNetwork() *remapCaptureNetwork {
	return &remapCaptureNetwork{
		RejectNetwork: &gonnect.RejectNetwork{},
		calls:         make(map[string][]string),
	}
}

func (n *remapCaptureNetwork) record(name string, args ...string) {
	n.mu.Lock()
	n.calls[name] = append([]string(nil), args...)
	n.mu.Unlock()
}

func (n *remapCaptureNetwork) args(name string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls[name]...)
}

func (n *remapCaptureNetwork) DialTCP(
	ctx context.Context,
	network,
	laddr,
	raddr string,
) (gonnect.TCPConn, error) {
	_ = ctx
	n.record("DialTCP", network, laddr, raddr)
	return nil, errRemapCapture
}

func (n *remapCaptureNetwork) ListenUDP(
	ctx context.Context,
	network,
	laddr string,
) (gonnect.UDPConn, error) {
	_ = ctx
	n.record("ListenUDP", network, laddr)
	return nil, errRemapCapture
}
