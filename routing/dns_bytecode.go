package routing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	gdns "github.com/asciimoth/gonnect/dns"
)

// DNSBytecodeRules contains immutable tables and one bytecode program used to
// build a gonnect/dns.RouteFunc.
//
// The route program evaluates the first DNS question in the message. Remote
// address predicates such as OP_FQDN, OP_ADDR_S, and OP_ADDR_RE test the first
// question name. DNS-specific predicates test request metadata:
//   - OP_QTYPE tests the first question type.
//   - OP_QCLASS tests the first question class.
//   - OP_OPCODE tests the message opcode.
//
// OP_BACKEND is the DNS route action. It pops a condition and returns the
// backend name at its table index when the condition is true. OP_DROP also pops
// a condition and returns an empty backend name when the condition is true.
// Empty backend names, unmatched rules, and names without attached backends
// make gonnect/dns.Router reject the request with dns.ErrNoUpstream.
//
// NewBytecodeDNSRouteFunc validates and copies all slices, so later changes to
// DNSBytecodeRules do not affect routing.
type DNSBytecodeRules struct {
	// Backends is the backend-name table used by OP_BACKEND.
	Backends []string

	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	Route []byte
}

// NewBytecodeDNSRouteFunc validates rules and returns a dns.RouteFunc for
// gonnect/dns.Router.
func NewBytecodeDNSRouteFunc(rules DNSBytecodeRules) (gdns.RouteFunc, error) {
	cfg := &bytecodeDNSRouteFunc{
		backends:    append([]string(nil), rules.Backends...),
		strings:     append([]string(nil), rules.Strings...),
		regexps:     append([]*regexp.Regexp(nil), rules.Regexps...),
		ipv4Addrs:   append([]uint32(nil), rules.IPv4Addrs...),
		ipv4Subnets: append([]IPv4Subnet(nil), rules.IPv4Subnets...),
		ipv6Addrs:   append([]netip.Addr(nil), rules.IPv6Addrs...),
		ipv6Subnets: append([]netip.Prefix(nil), rules.IPv6Subnets...),
		route:       append([]byte(nil), rules.Route...),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg.routeFunc(), nil
}

type bytecodeDNSRouteFunc struct {
	backends []string

	strings     []string
	regexps     []*regexp.Regexp
	ipv4Addrs   []uint32
	ipv4Subnets []IPv4Subnet
	ipv6Addrs   []netip.Addr
	ipv6Subnets []netip.Prefix

	route []byte
}

func (cfg *bytecodeDNSRouteFunc) validate() error {
	for i, name := range cfg.backends {
		if name == "" {
			return fmt.Errorf("backend %d has empty name", i)
		}
	}
	for i, re := range cfg.regexps {
		if re == nil {
			return fmt.Errorf("regexp %d is nil", i)
		}
	}
	if err := validateTables(
		cfg.ipv4Subnets,
		cfg.ipv6Addrs,
		cfg.ipv6Subnets,
	); err != nil {
		return err
	}
	return validateBytecode("DNSRoute", cfg.route, cfg.validateOp)
}

func (cfg *bytecodeDNSRouteFunc) validateOp(
	pc int,
	op byte,
	param uint64,
	kind bytecodeParamKind,
) error {
	if isLAddrOp(op) || op == OP_LPORT {
		return fmt.Errorf(
			"DNSRoute bytecode offset %d: opcode %d is not valid for DNSRoute",
			pc,
			op,
		)
	}
	if isRouterMethodOp(op) || isSplitOnlyOp(op) || isSnifferOnlyOp(op) {
		return fmt.Errorf(
			"DNSRoute bytecode offset %d: opcode %d is not valid for DNSRoute",
			pc,
			op,
		)
	}
	switch op {
	case OP_UDP, OP_TCP, OP_PORT, OP_SLOT:
		return fmt.Errorf(
			"DNSRoute bytecode offset %d: opcode %d is not valid for DNSRoute",
			pc,
			op,
		)
	}
	if kind == bytecodeParamNone {
		return nil
	}
	fail := func(table string, n int) error {
		return fmt.Errorf(
			"DNSRoute bytecode offset %d: %s index %d out of range %d",
			pc,
			table,
			param,
			n,
		)
	}
	switch op {
	case OP_BACKEND:
		if _, ok := bytecodeParamIndex(param, len(cfg.backends)); !ok {
			return fail("backend", len(cfg.backends))
		}
	case OP_ADDR_S:
		if _, ok := bytecodeParamIndex(param, len(cfg.strings)); !ok {
			return fail("string", len(cfg.strings))
		}
	case OP_ADDR_RE:
		if _, ok := bytecodeParamIndex(param, len(cfg.regexps)); !ok {
			return fail("regexp", len(cfg.regexps))
		}
	case OP_ADDR4:
		if _, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs)); !ok {
			return fail("IPv4 address", len(cfg.ipv4Addrs))
		}
	case OP_ADDR6:
		if _, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs)); !ok {
			return fail("IPv6 address", len(cfg.ipv6Addrs))
		}
	case OP_SNET4:
		if _, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets)); !ok {
			return fail("IPv4 subnet", len(cfg.ipv4Subnets))
		}
	case OP_SNET6:
		if _, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets)); !ok {
			return fail("IPv6 subnet", len(cfg.ipv6Subnets))
		}
	}
	return nil
}

func (cfg *bytecodeDNSRouteFunc) routeFunc() gdns.RouteFunc {
	return func(msg *gdns.Message) string {
		return cfg.exec(msg)
	}
}

func (cfg *bytecodeDNSRouteFunc) exec(msg *gdns.Message) string {
	ev := newDNSBytecodeEval(msg)
	stack := make([]bool, 0, 8)
	for pc := 0; pc < len(cfg.route); {
		op := cfg.route[pc]
		pc++
		param, next := readBytecodeParamUnchecked(cfg.route, pc, op)
		pc = next
		switch op {
		case OP_DROP:
			if popBool(&stack) {
				return ""
			}
		case OP_BACKEND:
			if popBool(&stack) {
				idx, ok := bytecodeParamIndex(param, len(cfg.backends))
				if !ok {
					return ""
				}
				return cfg.backends[idx]
			}
		case OP_TRUE:
			stack = append(stack, true)
		case OP_FALSE:
			stack = append(stack, false)
		case OP_NOT:
			stack[len(stack)-1] = !stack[len(stack)-1]
		case OP_AND:
			b := popBool(&stack)
			a := popBool(&stack)
			stack = append(stack, a && b)
		case OP_OR:
			b := popBool(&stack)
			a := popBool(&stack)
			stack = append(stack, a || b)
		case OP_NET4:
			qtype, ok := ev.qtype()
			stack = append(stack, ok && qtype == gdns.TypeA)
		case OP_NET6:
			qtype, ok := ev.qtype()
			stack = append(stack, ok && qtype == gdns.TypeAAAA)
		case OP_FQDN:
			stack = append(stack, ev.isFQDN())
		case OP_ADDR_S:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ok && ev.matchString(cfg.strings[idx]))
		case OP_ADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(
				stack,
				ok && cfg.regexps[idx].MatchString(ev.qname()),
			)
		case OP_ADDR4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs))
			stack = append(stack, ok && ev.matchIPv4(cfg.ipv4Addrs[idx]))
		case OP_ADDR6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs))
			stack = append(stack, ok && ev.ipv6() == cfg.ipv6Addrs[idx])
		case OP_SNET4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets))
			stack = append(stack, ok && ev.inIPv4Subnet(cfg.ipv4Subnets[idx]))
		case OP_SNET6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets))
			stack = append(
				stack,
				ok && cfg.ipv6Subnets[idx].Contains(ev.ipv6()),
			)
		case OP_QTYPE:
			_, ok := bytecodeParamInt(param, 0xffff)
			qtype, hasQuestion := ev.qtype()
			stack = append(stack, ok && hasQuestion && uint64(qtype) == param)
		case OP_QCLASS:
			_, ok := bytecodeParamInt(param, 0xffff)
			qclass, hasQuestion := ev.qclass()
			stack = append(stack, ok && hasQuestion && uint64(qclass) == param)
		case OP_OPCODE:
			_, ok := bytecodeParamInt(param, 0xffff)
			opcode, hasMessage := ev.opcode()
			stack = append(
				stack,
				ok && hasMessage && uint64(opcode) == param,
			)
		}
	}
	return ""
}

type dnsBytecodeEval struct {
	msg *gdns.Message

	questionDone bool
	question     gdns.Question
	hasQuestion  bool

	ipDone bool
	ipVal  netip.Addr
}

func newDNSBytecodeEval(msg *gdns.Message) dnsBytecodeEval {
	return dnsBytecodeEval{msg: msg}
}

func (ev *dnsBytecodeEval) firstQuestion() (gdns.Question, bool) {
	if ev.questionDone {
		return ev.question, ev.hasQuestion
	}
	ev.questionDone = true
	if ev.msg == nil || len(ev.msg.Questions) == 0 {
		return gdns.Question{}, false
	}
	ev.question = ev.msg.Questions[0]
	ev.hasQuestion = true
	return ev.question, true
}

func (ev *dnsBytecodeEval) qname() string {
	q, ok := ev.firstQuestion()
	if !ok {
		return ""
	}
	return q.Name
}

func (ev *dnsBytecodeEval) qtype() (uint16, bool) {
	q, ok := ev.firstQuestion()
	if !ok {
		return 0, false
	}
	return q.Type, true
}

func (ev *dnsBytecodeEval) qclass() (uint16, bool) {
	q, ok := ev.firstQuestion()
	if !ok {
		return 0, false
	}
	return q.Class, true
}

func (ev *dnsBytecodeEval) opcode() (uint8, bool) {
	if ev.msg == nil {
		return 0, false
	}
	return ev.msg.Opcode, true
}

func (ev *dnsBytecodeEval) isFQDN() bool {
	name := ev.qname()
	return name != "" && !ev.ip().IsValid()
}

func (ev *dnsBytecodeEval) ip() netip.Addr {
	if ev.ipDone {
		return ev.ipVal
	}
	ev.ipDone = true
	ev.ipVal = parseHostIP(strings.Trim(ev.qname(), "[]"))
	return ev.ipVal
}

func (ev *dnsBytecodeEval) matchString(want string) bool {
	return strings.EqualFold(ev.qname(), want)
}

func (ev *dnsBytecodeEval) matchIPv4(want uint32) bool {
	ip := ev.ip()
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return uint32(
		b[0],
	)<<24|uint32(
		b[1],
	)<<16|uint32(
		b[2],
	)<<8|uint32(
		b[3],
	) == want
}

func (ev *dnsBytecodeEval) inIPv4Subnet(subnet IPv4Subnet) bool {
	ip := ev.ip()
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	addr := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return subnet.contains(addr)
}

func (ev *dnsBytecodeEval) ipv6() netip.Addr {
	ip := ev.ip()
	if !ip.Is6() {
		return netip.Addr{}
	}
	return ip
}
