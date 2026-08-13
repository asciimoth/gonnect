package routing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect/sysnet"
)

// NewBytecodeRules parses the simple routing rules language into BytecodeRules.
func NewBytecodeRules(
	dialTCP, listenTCP, dialUDP, routeUDP, lookup string,
) (BytecodeRules, error) {
	p := newBytecodeParser()
	var rules BytecodeRules
	programs := []struct {
		name string
		src  string
		dst  *[]byte
	}{
		{name: "DialTCP", src: dialTCP, dst: &rules.DialTCP},
		{name: "ListenTCP", src: listenTCP, dst: &rules.ListenTCP},
		{name: "DialUDP", src: dialUDP, dst: &rules.DialUDP},
		{name: "RouteUDP", src: routeUDP, dst: &rules.RouteUDP},
		{name: "Lookup", src: lookup, dst: &rules.Lookup},
	}
	for _, program := range programs {
		code, err := p.parseProgram(program.name, program.src)
		if err != nil {
			return BytecodeRules{}, err
		}
		*program.dst = code
	}
	p.apply(&rules)
	if _, err := NewBytecodeRouterCfg(rules); err != nil {
		return BytecodeRules{}, err
	}
	return rules, nil
}

// NewBytecodeRulesProgram parses one routing rules program and derives the five
// RouterCfg method programs from it.
//
// The input is split into independent segments. A segment ends at a DROP or
// SLOT operation, matched case-insensitively, or at the end of the string. Each
// derived method program receives only the segments that can still affect that
// method:
//   - segments without DIAL, LISTEN, or LOOKUP are copied to every method;
//   - segments with method operations are omitted only when their terminal DROP
//     or SLOT condition is provably false for that method.
//
// The proof is intentionally conservative. Method operations are evaluated as
// constants for the target method, TRUE/FALSE/NOT/AND/OR are evaluated exactly,
// and every runtime-dependent predicate is treated as unknown. Unknown, invalid,
// or unterminated segments are kept and then validated normally by
// NewBytecodeRouterCfg.
func NewBytecodeRulesProgram(program string) (BytecodeRules, error) {
	p := newBytecodeParser()
	var rules BytecodeRules
	segments := splitBytecodeRuleSegments(program)
	programs := []struct {
		name   string
		method bytecodeMethod
		dst    *[]byte
	}{
		{name: "DialTCP", method: bytecodeMethodDial, dst: &rules.DialTCP},
		{
			name:   "ListenTCP",
			method: bytecodeMethodListen,
			dst:    &rules.ListenTCP,
		},
		{name: "DialUDP", method: bytecodeMethodDial, dst: &rules.DialUDP},
		{name: "RouteUDP", method: bytecodeMethodDial, dst: &rules.RouteUDP},
		{name: "Lookup", method: bytecodeMethodLookup, dst: &rules.Lookup},
	}
	for _, segment := range segments {
		for _, target := range programs {
			if !bytecodeSegmentCanTrigger(segment, target.method) {
				continue
			}
			code, err := p.parseProgramLines(target.name, segment)
			if err != nil {
				return BytecodeRules{}, err
			}
			*target.dst = append(*target.dst, code...)
		}
	}
	p.apply(&rules)
	if _, err := NewBytecodeRouterCfg(rules); err != nil {
		return BytecodeRules{}, err
	}
	return rules, nil
}

// NewSplitBytecodeRules parses the simple routing rules language into
// SplitBytecodeRules. RULE takes a sysnet rule type followed by the rule text:
//
//	RULE app org.example.App
//
// The first field after RULE becomes sysnet.Rule.Type. Everything after the
// separating space or tab becomes sysnet.Rule.Rule verbatim, so rule text may
// contain spaces and tabs.
func NewSplitBytecodeRules(
	system sysnet.System,
	route string,
) (SplitBytecodeRules, error) {
	p := newBytecodeParser()
	code, err := p.parseProgram("SplitRoute", route)
	if err != nil {
		return SplitBytecodeRules{}, err
	}
	rules := SplitBytecodeRules{System: system, Route: code}
	p.applySplit(&rules)
	if _, err := NewBytecodeSplitRouter(rules); err != nil {
		return SplitBytecodeRules{}, err
	}
	return rules, nil
}

// NewSnifferBytecodeRules parses one rules program and derives the Sniffer
// control and sniff-control programs from it.
//
// INTERCEPT segments are copied only to Control. SNIFF and SNIFF_NONE segments
// are copied only to SniffControl. Segments that use neither Sniffer-only
// operation are copied to both programs. A segment that uses SNIFF and ends in
// INTERCEPT is rejected because it has no meaningful execution phase.
//
// SNIFF can refer to a named classifier from classifiers, or to an inline
// classifier specification built by DefaultSniffClassifierConstructors.
func NewSnifferBytecodeRules(
	classifiers []NamedSniffClassifier,
	program string,
) (SnifferBytecodeRules, error) {
	return NewSnifferBytecodeRulesWithConstructors(
		classifiers,
		DefaultSniffClassifierConstructors(),
		program,
	)
}

// NewSnifferBytecodeRulesWithConstructors parses one rules program like
// NewSnifferBytecodeRules, but uses constructors as the inline SNIFF
// classifier collection.
//
// A SNIFF argument that matches a named classifier still refers to that
// classifier. Other arguments can use this form:
//
//	SNIFF <constructor> [<option>:<value> ...]
//
// Constructor names are case-sensitive. Option names are normalized by each
// constructor. Repeated equivalent inline specifications share one generated
// classifier entry. Generated classifiers are appended after the named
// classifiers, in first-use order.
func NewSnifferBytecodeRulesWithConstructors(
	classifiers []NamedSniffClassifier,
	constructors []NamedSniffClassifierConstructor,
	program string,
) (SnifferBytecodeRules, error) {
	p := newBytecodeParser()
	if err := p.setSniffClassifiers(classifiers); err != nil {
		return SnifferBytecodeRules{}, err
	}
	if err := p.setSniffClassifierConstructors(constructors); err != nil {
		return SnifferBytecodeRules{}, err
	}
	var rules SnifferBytecodeRules
	for _, segment := range splitBytecodeRuleSegments(program) {
		targets, err := bytecodeSnifferSegmentTargets(segment)
		if err != nil {
			return SnifferBytecodeRules{}, err
		}
		if targets.control {
			code, err := p.parseProgramLines("SnifferControl", segment)
			if err != nil {
				return SnifferBytecodeRules{}, err
			}
			rules.Control = append(rules.Control, code...)
		}
		if targets.sniff {
			code, err := p.parseProgramLines("SnifferSniffControl", segment)
			if err != nil {
				return SnifferBytecodeRules{}, err
			}
			rules.SniffControl = append(rules.SniffControl, code...)
		}
	}
	p.applySniffer(&rules)
	if _, err := NewBytecodeSnifferControls(rules); err != nil {
		return SnifferBytecodeRules{}, err
	}
	return rules, nil
}

type bytecodeParser struct {
	strings      []string
	stringIndex  map[string]uint16
	regexps      []*regexp.Regexp
	regexpIndex  map[string]uint16
	ipv4Addrs    []uint32
	ipv4Index    map[uint32]uint16
	ipv4Subnets  []IPv4Subnet
	ipv4NetIndex map[IPv4Subnet]uint16
	ipv6Addrs    []netip.Addr
	ipv6Index    map[netip.Addr]uint16
	ipv6Subnets  []netip.Prefix
	ipv6NetIndex map[netip.Prefix]uint16
	rules        []sysnet.Rule
	ruleIndex    map[sysnet.Rule]uint16

	sniffClassifiers  []NamedSniffClassifier
	sniffIndex        map[string]uint16
	sniffConstructors map[string]SniffClassifierConstructor
	sniffSpecIndex    map[string]uint16

	routeActions     []SnifferRouteAction
	routeActionIndex map[SnifferRouteAction]uint16
}

func newBytecodeParser() *bytecodeParser {
	return &bytecodeParser{
		stringIndex:  make(map[string]uint16),
		regexpIndex:  make(map[string]uint16),
		ipv4Index:    make(map[uint32]uint16),
		ipv4NetIndex: make(map[IPv4Subnet]uint16),
		ipv6Index:    make(map[netip.Addr]uint16),
		ipv6NetIndex: make(map[netip.Prefix]uint16),
		ruleIndex:    make(map[sysnet.Rule]uint16),

		sniffIndex:        make(map[string]uint16),
		sniffConstructors: make(map[string]SniffClassifierConstructor),
		sniffSpecIndex:    make(map[string]uint16),
		routeActionIndex:  make(map[SnifferRouteAction]uint16),
	}
}

func (p *bytecodeParser) setSniffClassifiers(
	classifiers []NamedSniffClassifier,
) error {
	for i, classifier := range classifiers {
		if _, err := p.addSniffClassifier(classifier); err != nil {
			return fmt.Errorf("sniff classifier %d: %w", i, err)
		}
	}
	return nil
}

func (p *bytecodeParser) setSniffClassifierConstructors(
	constructors []NamedSniffClassifierConstructor,
) error {
	for i, constructor := range constructors {
		name, err := normalizeSniffClassifierConstructorName(constructor.Name)
		if err != nil {
			return fmt.Errorf("sniff classifier constructor %d: %w", i, err)
		}
		if constructor.Constructor == nil {
			return fmt.Errorf(
				"sniff classifier constructor %q has nil constructor",
				name,
			)
		}
		if _, ok := p.sniffConstructors[name]; ok {
			return fmt.Errorf("duplicate sniff classifier constructor %q", name)
		}
		p.sniffConstructors[name] = constructor.Constructor
	}
	return nil
}

func (p *bytecodeParser) addSniffClassifier(
	classifier NamedSniffClassifier,
) (uint16, error) {
	name, err := normalizeSniffClassifierName(classifier.Name)
	if err != nil {
		return 0, err
	}
	if classifier.Factory == nil {
		return 0, fmt.Errorf("sniff classifier %q has nil factory", name)
	}
	if _, ok := p.sniffIndex[name]; ok {
		return 0, fmt.Errorf("duplicate sniff classifier %q", name)
	}
	idx, err := nextTableIndex("SNIFF", len(p.sniffClassifiers))
	if err != nil {
		return 0, err
	}
	classifier.Name = name
	p.sniffIndex[name] = idx
	p.sniffClassifiers = append(p.sniffClassifiers, classifier)
	return idx, nil
}

func (p *bytecodeParser) apply(rules *BytecodeRules) {
	rules.Strings = append([]string(nil), p.strings...)
	rules.Regexps = append([]*regexp.Regexp(nil), p.regexps...)
	rules.IPv4Addrs = append([]uint32(nil), p.ipv4Addrs...)
	rules.IPv4Subnets = append([]IPv4Subnet(nil), p.ipv4Subnets...)
	rules.IPv6Addrs = append([]netip.Addr(nil), p.ipv6Addrs...)
	rules.IPv6Subnets = append([]netip.Prefix(nil), p.ipv6Subnets...)
}

func (p *bytecodeParser) applySplit(rules *SplitBytecodeRules) {
	rules.Strings = append([]string(nil), p.strings...)
	rules.Regexps = append([]*regexp.Regexp(nil), p.regexps...)
	rules.IPv4Addrs = append([]uint32(nil), p.ipv4Addrs...)
	rules.IPv4Subnets = append([]IPv4Subnet(nil), p.ipv4Subnets...)
	rules.IPv6Addrs = append([]netip.Addr(nil), p.ipv6Addrs...)
	rules.IPv6Subnets = append([]netip.Prefix(nil), p.ipv6Subnets...)
	rules.Rules = append([]sysnet.Rule(nil), p.rules...)
}

func (p *bytecodeParser) applySniffer(rules *SnifferBytecodeRules) {
	rules.Classifiers = append(
		[]NamedSniffClassifier(nil),
		p.sniffClassifiers...)
	rules.Strings = append([]string(nil), p.strings...)
	rules.Regexps = append([]*regexp.Regexp(nil), p.regexps...)
	rules.IPv4Addrs = append([]uint32(nil), p.ipv4Addrs...)
	rules.IPv4Subnets = append([]IPv4Subnet(nil), p.ipv4Subnets...)
	rules.IPv6Addrs = append([]netip.Addr(nil), p.ipv6Addrs...)
	rules.IPv6Subnets = append([]netip.Prefix(nil), p.ipv6Subnets...)
	rules.RouteActions = append([]SnifferRouteAction(nil), p.routeActions...)
}

func (p *bytecodeParser) parseProgram(name, src string) ([]byte, error) {
	return p.parseProgramLines(name, splitBytecodeRuleLines(src))
}

type bytecodeRuleLine struct {
	no   int
	text string
}

func splitBytecodeRuleLines(src string) []bytecodeRuleLine {
	lines := strings.Split(src, "\n")
	out := make([]bytecodeRuleLine, 0, len(lines))
	for i, line := range lines {
		out = append(out, bytecodeRuleLine{
			no:   i + 1,
			text: strings.TrimRight(line, "\r"),
		})
	}
	return out
}

func (p *bytecodeParser) parseProgramLines(
	name string,
	lines []bytecodeRuleLine,
) ([]byte, error) {
	var code []byte
	for _, srcLine := range lines {
		line := srcLine.text
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		opName, arg, hasArg := splitRuleLine(line)
		op, ok := bytecodeOpByName[strings.ToUpper(opName)]
		if !ok {
			return nil, fmt.Errorf(
				"%s line %d: unknown operation %q",
				name,
				srcLine.no,
				opName,
			)
		}
		next, err := p.appendOp(code, op, arg, hasArg)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, srcLine.no, err)
		}
		code = next
	}
	return code, nil
}

func splitBytecodeRuleSegments(src string) [][]bytecodeRuleLine {
	lines := splitBytecodeRuleLines(src)
	segments := make([][]bytecodeRuleLine, 0, len(lines))
	segment := make([]bytecodeRuleLine, 0, len(lines))
	for _, line := range lines {
		segment = append(segment, line)
		if bytecodeRuleLineEndsSegment(line.text) {
			segments = append(segments, segment)
			segment = make([]bytecodeRuleLine, 0, len(lines))
		}
	}
	if len(segment) > 0 {
		segments = append(segments, segment)
	}
	return segments
}

func bytecodeRuleLineEndsSegment(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	opName, _, _ := splitRuleLine(line)
	switch strings.ToUpper(opName) {
	case "DROP", "SLOT", "INTERCEPT", "ROUTE":
		return true
	default:
		return false
	}
}

type bytecodeSnifferTargets struct {
	control bool
	sniff   bool
}

func bytecodeSnifferSegmentTargets(
	segment []bytecodeRuleLine,
) (bytecodeSnifferTargets, error) {
	var targets bytecodeSnifferTargets
	hasSniffPredicate := false
	hasIntercept := false
	for _, srcLine := range segment {
		line := srcLine.text
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		opName, _, _ := splitRuleLine(line)
		op, ok := bytecodeOpByName[strings.ToUpper(opName)]
		if !ok {
			targets.control = true
			targets.sniff = true
			return targets, nil
		}
		switch op {
		case OP_SNIFF, OP_SNIFF_NONE:
			hasSniffPredicate = true
		case OP_INTERCEPT:
			hasIntercept = true
		}
	}
	if hasSniffPredicate && hasIntercept {
		return bytecodeSnifferTargets{}, fmt.Errorf(
			"sniffer segment cannot combine SNIFF and INTERCEPT",
		)
	}
	targets.control = !hasSniffPredicate
	targets.sniff = !hasIntercept
	return targets, nil
}

type bytecodeBoolState uint8

const (
	bytecodeBoolFalse bytecodeBoolState = iota
	bytecodeBoolTrue
	bytecodeBoolUnknown
)

func bytecodeSegmentCanTrigger(
	segment []bytecodeRuleLine,
	method bytecodeMethod,
) bool {
	var stack []bytecodeBoolState
	hasMethodOp := false
	for _, srcLine := range segment {
		line := srcLine.text
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		opName, _, _ := splitRuleLine(line)
		op, ok := bytecodeOpByName[strings.ToUpper(opName)]
		if !ok {
			return true
		}
		switch op {
		case OP_DROP, OP_SLOT:
			if len(stack) < 1 {
				return true
			}
			condition := stack[len(stack)-1]
			return !hasMethodOp || condition != bytecodeBoolFalse
		case OP_TRUE:
			stack = append(stack, bytecodeBoolTrue)
		case OP_FALSE:
			stack = append(stack, bytecodeBoolFalse)
		case OP_NOT:
			if len(stack) < 1 {
				return true
			}
			stack[len(stack)-1] = bytecodeBoolNot(stack[len(stack)-1])
		case OP_AND:
			if len(stack) < 2 {
				return true
			}
			b := stack[len(stack)-1]
			a := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, bytecodeBoolAnd(a, b))
		case OP_OR:
			if len(stack) < 2 {
				return true
			}
			b := stack[len(stack)-1]
			a := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, bytecodeBoolOr(a, b))
		case OP_DIAL:
			hasMethodOp = true
			stack = append(
				stack,
				bytecodeBoolFromBool(method == bytecodeMethodDial),
			)
		case OP_LISTEN:
			hasMethodOp = true
			stack = append(
				stack,
				bytecodeBoolFromBool(method == bytecodeMethodListen),
			)
		case OP_LOOKUP:
			hasMethodOp = true
			stack = append(
				stack,
				bytecodeBoolFromBool(method == bytecodeMethodLookup),
			)
		default:
			stack = append(stack, bytecodeBoolUnknown)
		}
	}
	return true
}

func bytecodeBoolFromBool(v bool) bytecodeBoolState {
	if v {
		return bytecodeBoolTrue
	}
	return bytecodeBoolFalse
}

func bytecodeBoolNot(v bytecodeBoolState) bytecodeBoolState {
	switch v {
	case bytecodeBoolFalse:
		return bytecodeBoolTrue
	case bytecodeBoolTrue:
		return bytecodeBoolFalse
	case bytecodeBoolUnknown:
		return bytecodeBoolUnknown
	}
	return bytecodeBoolUnknown
}

func bytecodeBoolAnd(a, b bytecodeBoolState) bytecodeBoolState {
	if a == bytecodeBoolFalse || b == bytecodeBoolFalse {
		return bytecodeBoolFalse
	}
	if a == bytecodeBoolTrue && b == bytecodeBoolTrue {
		return bytecodeBoolTrue
	}
	return bytecodeBoolUnknown
}

func bytecodeBoolOr(a, b bytecodeBoolState) bytecodeBoolState {
	if a == bytecodeBoolTrue || b == bytecodeBoolTrue {
		return bytecodeBoolTrue
	}
	if a == bytecodeBoolFalse && b == bytecodeBoolFalse {
		return bytecodeBoolFalse
	}
	return bytecodeBoolUnknown
}

func splitRuleLine(line string) (op, arg string, hasArg bool) {
	line = strings.TrimLeft(line, " \t")
	for i, r := range line {
		if r == ' ' || r == '\t' {
			return line[:i], line[i+1:], true
		}
	}
	return line, "", false
}

func (p *bytecodeParser) appendOp(
	code []byte,
	op byte,
	arg string,
	hasArg bool,
) ([]byte, error) {
	switch op {
	case OP_DROP, OP_TRUE, OP_FALSE, OP_NOT, OP_AND, OP_OR,
		OP_NET4, OP_NET6, OP_UDP, OP_TCP, OP_FQDN, OP_LFQDN,
		OP_DIAL, OP_LISTEN, OP_LOOKUP, OP_INTERCEPT, OP_SNIFF_NONE:
		if hasArg && strings.TrimSpace(arg) != "" {
			return nil, fmt.Errorf(
				"operation %s does not accept an argument",
				bytecodeName(op),
			)
		}
		return append(code, op), nil
	case OP_SLOT:
		v, err := parseUintArg(op, arg, hasArg, 8)
		if err != nil {
			return nil, err
		}
		return append(code, op, byte(v)), nil
	case OP_ADDR_S, OP_LADDR_S:
		idx, err := p.stringParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_ADDR_RE, OP_LADDR_RE:
		idx, err := p.regexpParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_ADDR4, OP_LADDR4:
		idx, err := p.ipv4Param(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_ADDR6, OP_LADDR6:
		idx, err := p.ipv6Param(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_SNET4, OP_LSNET4:
		idx, err := p.ipv4SubnetParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_SNET6, OP_LSNET6:
		idx, err := p.ipv6SubnetParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_PORT, OP_LPORT:
		v, err := parseUintArg(op, arg, hasArg, 16)
		if err != nil {
			return nil, err
		}
		param, err := checkedUint16(bytecodeName(op), v)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, param), nil
	case OP_RULE:
		idx, err := p.ruleParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_SNIFF:
		idx, err := p.sniffParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_ROUTE:
		idx, err := p.routeParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	default:
		return nil, fmt.Errorf("unknown opcode %d", op)
	}
}

func (p *bytecodeParser) stringParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	arg, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	if idx, ok := p.stringIndex[arg]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.strings))
	if err != nil {
		return 0, err
	}
	p.strings = append(p.strings, arg)
	p.stringIndex[arg] = idx
	return idx, nil
}

func (p *bytecodeParser) regexpParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	arg, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	if idx, ok := p.regexpIndex[arg]; ok {
		return idx, nil
	}
	re, err := regexp.Compile(arg)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid %s regexp %q: %w",
			bytecodeName(op),
			arg,
			err,
		)
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.regexps))
	if err != nil {
		return 0, err
	}
	p.regexps = append(p.regexps, re)
	p.regexpIndex[arg] = idx
	return idx, nil
}

func (p *bytecodeParser) ipv4Param(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	text, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf(
			"invalid %s IPv4 address %q",
			bytecodeName(op),
			arg,
		)
	}
	v := binary.BigEndian.Uint32(addr.AsSlice())
	if idx, ok := p.ipv4Index[v]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.ipv4Addrs))
	if err != nil {
		return 0, err
	}
	p.ipv4Addrs = append(p.ipv4Addrs, v)
	p.ipv4Index[v] = idx
	return idx, nil
}

func (p *bytecodeParser) ipv6Param(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	text, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is6() {
		return 0, fmt.Errorf(
			"invalid %s IPv6 address %q",
			bytecodeName(op),
			arg,
		)
	}
	if idx, ok := p.ipv6Index[addr]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.ipv6Addrs))
	if err != nil {
		return 0, err
	}
	p.ipv6Addrs = append(p.ipv6Addrs, addr)
	p.ipv6Index[addr] = idx
	return idx, nil
}

func (p *bytecodeParser) ipv4SubnetParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	text, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
	if err != nil || !prefix.Addr().Is4() {
		return 0, fmt.Errorf("invalid %s IPv4 subnet %q", bytecodeName(op), arg)
	}
	addr := prefix.Masked().Addr()
	bits, err := checkedUint8(bytecodeName(op), prefix.Bits())
	if err != nil {
		return 0, err
	}
	subnet := IPv4Subnet{
		Addr: binary.BigEndian.Uint32(addr.AsSlice()),
		Bits: bits,
	}
	if idx, ok := p.ipv4NetIndex[subnet]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.ipv4Subnets))
	if err != nil {
		return 0, err
	}
	p.ipv4Subnets = append(p.ipv4Subnets, subnet)
	p.ipv4NetIndex[subnet] = idx
	return idx, nil
}

func (p *bytecodeParser) ipv6SubnetParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	text, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
	if err != nil || !prefix.Addr().Is6() {
		return 0, fmt.Errorf("invalid %s IPv6 subnet %q", bytecodeName(op), arg)
	}
	prefix = prefix.Masked()
	if idx, ok := p.ipv6NetIndex[prefix]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.ipv6Subnets))
	if err != nil {
		return 0, err
	}
	p.ipv6Subnets = append(p.ipv6Subnets, prefix)
	p.ipv6NetIndex[prefix] = idx
	return idx, nil
}

func (p *bytecodeParser) ruleParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	arg, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	ruleType, rule, ok := splitRuleParam(arg)
	if !ok {
		return 0, fmt.Errorf(
			"operation %s requires a rule type and rule text",
			bytecodeName(op),
		)
	}
	entry := sysnet.Rule{Type: ruleType, Rule: rule}
	if idx, ok := p.ruleIndex[entry]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.rules))
	if err != nil {
		return 0, err
	}
	p.rules = append(p.rules, entry)
	p.ruleIndex[entry] = idx
	return idx, nil
}

func splitRuleParam(arg string) (ruleType, rule string, ok bool) {
	arg = strings.TrimLeft(arg, " \t")
	if arg == "" {
		return "", "", false
	}
	for i, r := range arg {
		if r == ' ' || r == '\t' {
			ruleType = arg[:i]
			rule = arg[i+1:]
			return ruleType, rule, ruleType != ""
		}
	}
	return "", "", false
}

func (p *bytecodeParser) sniffParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	arg, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	name, err := normalizeSniffClassifierName(arg)
	if err == nil {
		if idx, ok := p.sniffIndex[name]; ok {
			return idx, nil
		}
	}
	idx, specErr := p.constructSniffClassifier(arg)
	if specErr == nil {
		return idx, nil
	}
	return 0, specErr
}

func (p *bytecodeParser) routeParam(
	op byte,
	arg string,
	hasArg bool,
) (uint16, error) {
	arg, err := requiredTextArg(op, arg, hasArg)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return 0, fmt.Errorf(
			"operation %s requires an argument",
			bytecodeName(op),
		)
	}
	slot, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid ROUTE slot %q: %w", fields[0], err)
	}

	action := SnifferRouteAction{Slot: uint8(slot)}
	seen := make(map[string]struct{}, len(fields)-1)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, ":")
		key = strings.ToUpper(key)
		if !ok || key == "" {
			return 0, fmt.Errorf("ROUTE field %q must use KEY:VALUE", field)
		}
		if strings.ContainsAny(key, " \t\r\n:") {
			return 0, fmt.Errorf("ROUTE field key %q is invalid", key)
		}
		if value == "" {
			return 0, fmt.Errorf("ROUTE field %q has empty value", key)
		}
		if _, ok := seen[key]; ok {
			return 0, fmt.Errorf("duplicate ROUTE field %q", key)
		}
		seen[key] = struct{}{}
		if err := setSnifferRouteField(
			&action.Mutation,
			key,
			value,
		); err != nil {
			return 0, err
		}
	}

	if idx, ok := p.routeActionIndex[action]; ok {
		return idx, nil
	}
	idx, err := nextTableIndex(bytecodeName(op), len(p.routeActions))
	if err != nil {
		return 0, err
	}
	p.routeActions = append(p.routeActions, action)
	p.routeActionIndex[action] = idx
	return idx, nil
}

func setSnifferRouteField(
	mutation *SnifferCallMutation,
	key, value string,
) error {
	switch key {
	case "NETWORK":
		mutation.SetNetwork = true
		mutation.Network = value
	case "SRC":
		mutation.SetSrc = true
		mutation.Src = value
	case "DST":
		mutation.SetDst = true
		mutation.Dst = value
	case "SRC_ADDR":
		mutation.SetSrcAddr = true
		mutation.SrcAddr = value
	case "SRC_PORT":
		mutation.SetSrcPort = true
		mutation.SrcPort = value
	case "DST_ADDR":
		mutation.SetDstAddr = true
		mutation.DstAddr = value
	case "DST_PORT":
		mutation.SetDstPort = true
		mutation.DstPort = value
	case "HOST":
		mutation.SetHost = true
		mutation.Host = value
	case "SERVICE":
		mutation.SetService = true
		mutation.Service = value
	case "PROTO":
		mutation.SetProto = true
		mutation.Proto = value
	default:
		return fmt.Errorf("unknown ROUTE field %q", key)
	}
	return nil
}

func normalizeSniffClassifierName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty sniff classifier name")
	}
	if strings.ContainsAny(name, " \t\r\n") {
		return "", fmt.Errorf(
			"sniff classifier name %q contains whitespace",
			name,
		)
	}
	return name, nil
}

func requiredTextArg(op byte, arg string, hasArg bool) (string, error) {
	if !hasArg || arg == "" {
		return "", fmt.Errorf(
			"operation %s requires an argument",
			bytecodeName(op),
		)
	}
	return arg, nil
}

func parseUintArg(op byte, arg string, hasArg bool, bits int) (uint64, error) {
	if !hasArg || strings.TrimSpace(arg) == "" {
		return 0, fmt.Errorf(
			"operation %s requires an argument",
			bytecodeName(op),
		)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(arg), 10, bits)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid %s argument %q: %w",
			bytecodeName(op),
			arg,
			err,
		)
	}
	return v, nil
}

func nextTableIndex(name string, n int) (uint16, error) {
	if n > 0xffff {
		return 0, fmt.Errorf("%s resource table has too many entries", name)
	}
	return uint16(n), nil //nolint:gosec // Range checked immediately above.
}

func checkedUint8(name string, v int) (uint8, error) {
	if v < 0 || v > 0xff {
		return 0, fmt.Errorf("%s value %d out of range 0..255", name, v)
	}
	return uint8(v), nil //nolint:gosec // Range checked immediately above.
}

func checkedUint16(name string, v uint64) (uint16, error) {
	if v > 0xffff {
		return 0, fmt.Errorf("%s value %d out of range 0..65535", name, v)
	}
	return uint16(v), nil //nolint:gosec // Range checked immediately above.
}

func appendParam16(code []byte, op byte, param uint16) []byte {
	code = append(code, op, 0, 0)
	binary.LittleEndian.PutUint16(code[len(code)-2:], param)
	return code
}

func bytecodeName(op byte) string {
	for name, candidate := range bytecodeOpByName {
		if candidate == op {
			return name
		}
	}
	return fmt.Sprintf("opcode %d", op)
}

var bytecodeOpByName = map[string]byte{
	"DROP":       OP_DROP,
	"SLOT":       OP_SLOT,
	"TRUE":       OP_TRUE,
	"FALSE":      OP_FALSE,
	"NOT":        OP_NOT,
	"AND":        OP_AND,
	"OR":         OP_OR,
	"NET4":       OP_NET4,
	"NET6":       OP_NET6,
	"UDP":        OP_UDP,
	"TCP":        OP_TCP,
	"FQDN":       OP_FQDN,
	"LFQDN":      OP_LFQDN,
	"ADDR_S":     OP_ADDR_S,
	"LADDR_S":    OP_LADDR_S,
	"ADDR_RE":    OP_ADDR_RE,
	"LADDR_RE":   OP_LADDR_RE,
	"ADDR4":      OP_ADDR4,
	"LADDR4":     OP_LADDR4,
	"ADDR6":      OP_ADDR6,
	"LADDR6":     OP_LADDR6,
	"SNET4":      OP_SNET4,
	"LSNET4":     OP_LSNET4,
	"SNET6":      OP_SNET6,
	"LSNET6":     OP_LSNET6,
	"PORT":       OP_PORT,
	"LPORT":      OP_LPORT,
	"RULE":       OP_RULE,
	"DIAL":       OP_DIAL,
	"LISTEN":     OP_LISTEN,
	"LOOKUP":     OP_LOOKUP,
	"INTERCEPT":  OP_INTERCEPT,
	"SNIFF":      OP_SNIFF,
	"SNIFF_NONE": OP_SNIFF_NONE,
	"ROUTE":      OP_ROUTE,
}
