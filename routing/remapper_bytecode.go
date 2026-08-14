package routing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
)

// RemapAction describes the fixed rewrite done by one REMAP rule.
//
// Endpoint selects source or destination. Field selects which part of that
// endpoint changes. Addr and Port have the same meaning as gonnect.RemapRule.
type RemapAction struct {
	Endpoint gonnect.RemapEndpoint
	Field    gonnect.RemapField
	Addr     string
	Port     string
}

// RemapperBytecodeRule is one bytecode predicate plus one remap action.
//
// Predicate is stack bytecode that must leave exactly one boolean value. An
// empty predicate matches all calls that expose Action.Endpoint.
type RemapperBytecodeRule struct {
	Predicate []byte
	Action    RemapAction
}

// RemapperBytecodeRules contains immutable tables and bytecode used to build
// gonnect.RemapRule values.
//
// REMAP rules evaluate in order. Each matching rule applies, and later rules
// see the network and addresses left by earlier rules. This matches
// gonnect.Remapper.
type RemapperBytecodeRules struct {
	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	// DNSCacheStorage enables cached reverse-DNS matches for ADDR_S,
	// LADDR_S, ADDR_RE, and LADDR_RE when addresses are IP literals. The
	// filter never performs live DNS lookups.
	DNSCacheStorage gdns.CacheStorage

	Rules []RemapperBytecodeRule
}

// NewRemapperBytecodeRules parses one rule text into RemapperBytecodeRules.
//
// Each segment contains normal bytecode predicates and ends with REMAP:
//
//	REMAP <endpoint> <field> <value>
//
// Endpoint is SRC or DST. Field is ADDR_PORT, ADDR, or PORT. ADDR_PORT value
// must be a host:port endpoint, for example "127.0.0.1:8080" or "[::1]:443".
// ADDR and PORT values are used as written and are not resolved.
func NewRemapperBytecodeRules(program string) (RemapperBytecodeRules, error) {
	p := newBytecodeParser()
	segments := splitBytecodeRuleSegments(program)
	var rules RemapperBytecodeRules
	for i, segment := range segments {
		predicateLines, action, skip, err := p.parseRemapRuleSegment(
			i,
			segment,
		)
		if err != nil {
			return RemapperBytecodeRules{}, err
		}
		if skip {
			continue
		}
		code, err := p.parseProgramLines("Remapper", predicateLines)
		if err != nil {
			return RemapperBytecodeRules{}, err
		}
		rules.Rules = append(rules.Rules, RemapperBytecodeRule{
			Predicate: code,
			Action:    action,
		})
	}
	p.applyRemapper(&rules)
	if _, err := NewBytecodeRemapRules(rules); err != nil {
		return RemapperBytecodeRules{}, err
	}
	return rules, nil
}

// NewBytecodeRemapRules validates rules and returns gonnect.RemapRule values
// that can be passed to gonnect.NewRemapper.
func NewBytecodeRemapRules(
	rules RemapperBytecodeRules,
) ([]gonnect.RemapRule, error) {
	cfg := &bytecodeRemapperRules{
		strings:     append([]string(nil), rules.Strings...),
		regexps:     append([]*regexp.Regexp(nil), rules.Regexps...),
		ipv4Addrs:   append([]uint32(nil), rules.IPv4Addrs...),
		ipv4Subnets: append([]IPv4Subnet(nil), rules.IPv4Subnets...),
		ipv6Addrs:   append([]netip.Addr(nil), rules.IPv6Addrs...),
		ipv6Subnets: append([]netip.Prefix(nil), rules.IPv6Subnets...),
		dnsStorage:  rules.DNSCacheStorage,
		rules:       copyRemapperBytecodeRules(rules.Rules),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg.remapRules(), nil
}

// NewRemapRules parses rule text and returns gonnect.RemapRule values.
func NewRemapRules(program string) ([]gonnect.RemapRule, error) {
	rules, err := NewRemapperBytecodeRules(program)
	if err != nil {
		return nil, err
	}
	return NewBytecodeRemapRules(rules)
}

type bytecodeRemapperRules struct {
	strings     []string
	regexps     []*regexp.Regexp
	ipv4Addrs   []uint32
	ipv4Subnets []IPv4Subnet
	ipv6Addrs   []netip.Addr
	ipv6Subnets []netip.Prefix
	dnsStorage  gdns.CacheStorage
	rules       []RemapperBytecodeRule
}

func copyRemapperBytecodeRules(
	rules []RemapperBytecodeRule,
) []RemapperBytecodeRule {
	out := make([]RemapperBytecodeRule, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].Predicate = append([]byte(nil), rule.Predicate...)
	}
	return out
}

func (cfg *bytecodeRemapperRules) validate() error {
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
	for i, rule := range cfg.rules {
		if err := validateRemapAction(i, rule.Action); err != nil {
			return err
		}
		if len(rule.Predicate) == 0 {
			continue
		}
		name := fmt.Sprintf("Remapper rule %d", i)
		if err := cfg.validatePredicate(name, rule.Predicate); err != nil {
			return err
		}
	}
	return nil
}

func validateRemapAction(i int, action RemapAction) error {
	switch action.Endpoint {
	case gonnect.RemapSrc, gonnect.RemapDst:
	default:
		return fmt.Errorf(
			"remap rule %d has invalid endpoint %d",
			i,
			action.Endpoint,
		)
	}
	switch action.Field {
	case gonnect.RemapAddrPort:
		if action.Addr == "" || action.Port == "" {
			return fmt.Errorf(
				"remap rule %d ADDR_PORT requires non-empty Addr and Port",
				i,
			)
		}
	case gonnect.RemapAddr:
		if action.Addr == "" {
			return fmt.Errorf("remap rule %d ADDR requires non-empty Addr", i)
		}
	case gonnect.RemapPort:
		if action.Port == "" {
			return fmt.Errorf("remap rule %d PORT requires non-empty Port", i)
		}
	default:
		return fmt.Errorf("remap rule %d has invalid field %d", i, action.Field)
	}
	return nil
}

func (cfg *bytecodeRemapperRules) validatePredicate(
	name string,
	code []byte,
) error {
	depth := 0
	for pc := 0; pc < len(code); {
		opPC := pc
		op := code[pc]
		pc++
		param, kind, err := readBytecodeParam(name, code, &pc, op)
		if err != nil {
			return err
		}
		if err := cfg.validatePredicateOp(
			name,
			opPC,
			op,
			param,
			kind,
		); err != nil {
			return err
		}
		switch op {
		case OP_NOT:
			if depth < 1 {
				return fmt.Errorf(
					"%s bytecode offset %d: stack underflow",
					name,
					opPC,
				)
			}
		case OP_AND, OP_OR:
			if depth < 2 {
				return fmt.Errorf(
					"%s bytecode offset %d: stack underflow",
					name,
					opPC,
				)
			}
			depth--
		default:
			depth++
		}
	}
	if depth != 1 {
		return fmt.Errorf(
			"%s predicate leaves stack depth %d, want 1",
			name,
			depth,
		)
	}
	return nil
}

func (cfg *bytecodeRemapperRules) validatePredicateOp(
	name string,
	pc int,
	op byte,
	param uint64,
	kind bytecodeParamKind,
) error {
	switch op {
	case OP_DROP, OP_SLOT, OP_RULE, OP_INTERCEPT, OP_SNIFF, OP_SNIFF_NONE,
		OP_ROUTE, OP_BACKEND, OP_QTYPE, OP_QCLASS, OP_OPCODE:
		return fmt.Errorf(
			"%s bytecode offset %d: opcode %d is not valid for Remapper",
			name,
			pc,
			op,
		)
	}
	return cfg.validateOpIndex(name, pc, op, param, kind)
}

func (cfg *bytecodeRemapperRules) validateOpIndex(
	name string,
	pc int,
	op byte,
	param uint64,
	kind bytecodeParamKind,
) error {
	if kind == bytecodeParamNone {
		return nil
	}
	fail := func(table string, n int) error {
		return fmt.Errorf(
			"%s bytecode offset %d: %s index %d out of range %d",
			name,
			pc,
			table,
			param,
			n,
		)
	}
	switch op {
	case OP_ADDR_S, OP_LADDR_S:
		if param >= uint64(len(cfg.strings)) {
			return fail("string", len(cfg.strings))
		}
	case OP_ADDR_RE, OP_LADDR_RE:
		if param >= uint64(len(cfg.regexps)) {
			return fail("regexp", len(cfg.regexps))
		}
	case OP_ADDR4, OP_LADDR4:
		if param >= uint64(len(cfg.ipv4Addrs)) {
			return fail("IPv4 address", len(cfg.ipv4Addrs))
		}
	case OP_ADDR6, OP_LADDR6:
		if param >= uint64(len(cfg.ipv6Addrs)) {
			return fail("IPv6 address", len(cfg.ipv6Addrs))
		}
	case OP_SNET4, OP_LSNET4:
		if param >= uint64(len(cfg.ipv4Subnets)) {
			return fail("IPv4 subnet", len(cfg.ipv4Subnets))
		}
	case OP_SNET6, OP_LSNET6:
		if param >= uint64(len(cfg.ipv6Subnets)) {
			return fail("IPv6 subnet", len(cfg.ipv6Subnets))
		}
	}
	return nil
}

func (cfg *bytecodeRemapperRules) remapRules() []gonnect.RemapRule {
	out := make([]gonnect.RemapRule, 0, len(cfg.rules))
	for _, rule := range cfg.rules {
		code := append([]byte(nil), rule.Predicate...)
		action := rule.Action
		remap := gonnect.RemapRule{
			Endpoint: action.Endpoint,
			Field:    action.Field,
			Addr:     action.Addr,
			Port:     action.Port,
		}
		if len(code) > 0 {
			stringOps := bytecodeAddrStringOps(code)
			remap.Filter = func(info gonnect.RemapInfo) bool {
				return cfg.exec(code, info, stringOps)
			}
		}
		out = append(out, remap)
	}
	return out
}

func (cfg *bytecodeRemapperRules) exec(
	code []byte,
	info gonnect.RemapInfo,
	stringOps addrStringOps,
) bool {
	dial, listen := remapOperationClass(info.Operation)
	ev := bytecodeEval{
		network: strings.ToLower(info.Network),
		laddr: newAddrCache(
			addrInput{str: info.SrcAddr},
			cfg.dnsStorage,
			stringOps.local,
		),
		raddr: newAddrCache(
			addrInput{str: info.DstAddr},
			cfg.dnsStorage,
			stringOps.remote,
		),
		isDial:   dial,
		isListen: listen,
	}
	stack := make([]bool, 0, 8)
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		param, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		switch op {
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
			stack = append(stack, ev.isNet4())
		case OP_NET6:
			stack = append(stack, ev.isNet6())
		case OP_UDP:
			stack = append(stack, isUDPNet(ev.network))
		case OP_TCP:
			stack = append(stack, isTCPNet(ev.network))
		case OP_DIAL:
			stack = append(stack, ev.isDial)
		case OP_LISTEN:
			stack = append(stack, ev.isListen)
		case OP_LOOKUP:
			stack = append(stack, false)
		case OP_FQDN:
			stack = append(stack, ev.raddr.isFQDN())
		case OP_LFQDN:
			stack = append(stack, ev.laddr.isFQDN())
		case OP_ADDR_S:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ok && ev.raddr.matchString(cfg.strings[idx]))
		case OP_LADDR_S:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ok && ev.laddr.matchString(cfg.strings[idx]))
		case OP_ADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(stack, ok && ev.raddr.matchRegexp(cfg.regexps[idx]))
		case OP_LADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(stack, ok && ev.laddr.matchRegexp(cfg.regexps[idx]))
		case OP_ADDR4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs))
			stack = append(stack, ok && ev.raddr.matchIPv4(cfg.ipv4Addrs[idx]))
		case OP_LADDR4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs))
			stack = append(stack, ok && ev.laddr.matchIPv4(cfg.ipv4Addrs[idx]))
		case OP_ADDR6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs))
			stack = append(stack, ok && ev.raddr.ipv6() == cfg.ipv6Addrs[idx])
		case OP_LADDR6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs))
			stack = append(stack, ok && ev.laddr.ipv6() == cfg.ipv6Addrs[idx])
		case OP_SNET4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets))
			stack = append(
				stack,
				ok && ev.raddr.inIPv4Subnet(cfg.ipv4Subnets[idx]),
			)
		case OP_LSNET4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets))
			stack = append(
				stack,
				ok && ev.laddr.inIPv4Subnet(cfg.ipv4Subnets[idx]),
			)
		case OP_SNET6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets))
			stack = append(
				stack,
				ok && cfg.ipv6Subnets[idx].Contains(ev.raddr.ipv6()),
			)
		case OP_LSNET6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets))
			stack = append(
				stack,
				ok && cfg.ipv6Subnets[idx].Contains(ev.laddr.ipv6()),
			)
		case OP_PORT:
			port, ok := bytecodeParamInt(param, 0xffff)
			stack = append(stack, ok && ev.raddr.port(ev.portNetwork()) == port)
		case OP_LPORT:
			port, ok := bytecodeParamInt(param, 0xffff)
			stack = append(stack, ok && ev.laddr.port(ev.portNetwork()) == port)
		}
	}
	return len(stack) == 1 && stack[0]
}

func remapOperationClass(op gonnect.RemapOperation) (dial, listen bool) {
	switch op {
	case gonnect.RemapOpDial,
		gonnect.RemapOpPacketDial,
		gonnect.RemapOpDialTCP,
		gonnect.RemapOpDialUDP:
		return true, false
	case gonnect.RemapOpListen,
		gonnect.RemapOpListenPacket,
		gonnect.RemapOpListenTCP,
		gonnect.RemapOpListenUDP,
		gonnect.RemapOpListenPacketConfig,
		gonnect.RemapOpListenUDPConfig,
		gonnect.RemapOpListenMulticastUDP:
		return false, true
	}
	return false, false
}

func (p *bytecodeParser) parseRemapRuleSegment(
	index int,
	segment []bytecodeRuleLine,
) ([]bytecodeRuleLine, RemapAction, bool, error) {
	if segmentHasOnlyComments(segment) {
		return nil, RemapAction{}, true, nil
	}
	for i := len(segment) - 1; i >= 0; i-- {
		line := segment[i].text
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		opName, arg, hasArg := splitRuleLine(line)
		if strings.ToUpper(opName) != "REMAP" {
			return nil, RemapAction{}, false, fmt.Errorf(
				"remapper segment %d line %d: segment must end with REMAP",
				index,
				segment[i].no,
			)
		}
		action, err := parseRemapAction(arg, hasArg)
		if err != nil {
			return nil, RemapAction{}, false, fmt.Errorf(
				"remapper line %d: %w",
				segment[i].no,
				err,
			)
		}
		return segment[:i], action, false, nil
	}
	return nil, RemapAction{}, true, nil
}

func segmentHasOnlyComments(segment []bytecodeRuleLine) bool {
	for _, line := range segment {
		trimmed := strings.TrimSpace(line.text)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return false
		}
	}
	return true
}

func parseRemapAction(arg string, hasArg bool) (RemapAction, error) {
	if !hasArg || strings.TrimSpace(arg) == "" {
		return RemapAction{}, fmt.Errorf(
			"REMAP requires endpoint, field, and value",
		)
	}
	fields := strings.Fields(arg)
	if len(fields) != 3 {
		return RemapAction{}, fmt.Errorf(
			"REMAP requires endpoint, field, and value",
		)
	}
	endpoint, err := parseRemapEndpoint(fields[0])
	if err != nil {
		return RemapAction{}, err
	}
	field, err := parseRemapField(fields[1])
	if err != nil {
		return RemapAction{}, err
	}
	action := RemapAction{Endpoint: endpoint, Field: field}
	switch field {
	case gonnect.RemapAddrPort:
		host, port, ok := splitHostPort(fields[2])
		if !ok {
			return RemapAction{}, fmt.Errorf(
				"REMAP ADDR_PORT value %q must be host:port",
				fields[2],
			)
		}
		action.Addr = strings.Trim(host, "[]")
		action.Port = port
	case gonnect.RemapAddr:
		action.Addr = strings.Trim(fields[2], "[]")
	case gonnect.RemapPort:
		action.Port = fields[2]
	}
	return action, nil
}

func parseRemapEndpoint(s string) (gonnect.RemapEndpoint, error) {
	switch strings.ToUpper(s) {
	case "SRC", "SOURCE", "LADDR", "LOCAL":
		return gonnect.RemapSrc, nil
	case "DST", "DEST", "RADDR", "REMOTE":
		return gonnect.RemapDst, nil
	default:
		return 0, fmt.Errorf("unknown REMAP endpoint %q", s)
	}
}

func parseRemapField(s string) (gonnect.RemapField, error) {
	switch strings.ToUpper(s) {
	case "ADDR_PORT", "ADDRPORT", "ADDRESS_PORT":
		return gonnect.RemapAddrPort, nil
	case "ADDR", "ADDRESS":
		return gonnect.RemapAddr, nil
	case "PORT":
		return gonnect.RemapPort, nil
	default:
		return 0, fmt.Errorf("unknown REMAP field %q", s)
	}
}
