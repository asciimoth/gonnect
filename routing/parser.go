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

// NewSplitBytecodeRules parses the simple routing rules language into SplitBytecodeRules.
func NewSplitBytecodeRules(
	matcher sysnet.IPMatcher,
	route string,
) (SplitBytecodeRules, error) {
	p := newBytecodeParser()
	code, err := p.parseProgram("SplitRoute", route)
	if err != nil {
		return SplitBytecodeRules{}, err
	}
	rules := SplitBytecodeRules{Matcher: matcher, Route: code}
	p.applySplit(&rules)
	if _, err := NewBytecodeSplitRouter(rules); err != nil {
		return SplitBytecodeRules{}, err
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
}

func newBytecodeParser() *bytecodeParser {
	return &bytecodeParser{
		stringIndex:  make(map[string]uint16),
		regexpIndex:  make(map[string]uint16),
		ipv4Index:    make(map[uint32]uint16),
		ipv4NetIndex: make(map[IPv4Subnet]uint16),
		ipv6Index:    make(map[netip.Addr]uint16),
		ipv6NetIndex: make(map[netip.Prefix]uint16),
	}
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
}

func (p *bytecodeParser) parseProgram(name, src string) ([]byte, error) {
	var code []byte
	for lineNo, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
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
				lineNo+1,
				opName,
			)
		}
		next, err := p.appendOp(code, op, arg, hasArg)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", name, lineNo+1, err)
		}
		code = next
	}
	return code, nil
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
		OP_NET4, OP_NET6, OP_UDP, OP_TCP, OP_FQDN, OP_LFQDN:
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
	case OP_ADDR_S, OP_LADDR_S, OP_UNAME:
		idx, err := p.stringParam(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam16(code, op, idx), nil
	case OP_ADDR_RE, OP_LADDR_RE, OP_UEXP:
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
	case OP_MARK:
		v, err := parseMarkArg(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam32(code, op, v), nil
	case OP_PID:
		v, err := parseInt32Arg(op, arg, hasArg)
		if err != nil {
			return nil, err
		}
		return appendParam32(code, op, v), nil
	case OP_RULE, OP_CGRP, OP_UID, OP_GID:
		v, err := parseUintArg(op, arg, hasArg, 64)
		if err != nil {
			return nil, err
		}
		return appendParam64(code, op, v), nil
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

func parseInt32Arg(op byte, arg string, hasArg bool) (uint32, error) {
	if !hasArg || strings.TrimSpace(arg) == "" {
		return 0, fmt.Errorf(
			"operation %s requires an argument",
			bytecodeName(op),
		)
	}
	text := strings.TrimSpace(arg)
	if strings.HasPrefix(text, "-") {
		v, err := strconv.ParseInt(text, 10, 32)
		if err != nil {
			return 0, fmt.Errorf(
				"invalid %s argument %q: %w",
				bytecodeName(op),
				arg,
				err,
			)
		}
		//nolint:gosec // ParseInt with bitSize 32 guarantees int32 range; conversion preserves bytecode representation.
		return uint32(v), nil
	}
	v, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid %s argument %q: %w",
			bytecodeName(op),
			arg,
			err,
		)
	}
	return uint32(v), nil
}

func parseMarkArg(op byte, arg string, hasArg bool) (uint32, error) {
	if !hasArg || strings.TrimSpace(arg) == "" {
		return 0, fmt.Errorf(
			"operation %s requires an argument",
			bytecodeName(op),
		)
	}
	text := strings.TrimSpace(arg)
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		v, err := strconv.ParseUint(text, 0, 32)
		if err != nil {
			return 0, fmt.Errorf(
				"invalid %s argument %q: %w",
				bytecodeName(op),
				arg,
				err,
			)
		}
		return uint32(v), nil
	}
	return parseInt32Arg(op, arg, hasArg)
}

func appendParam16(code []byte, op byte, param uint16) []byte {
	code = append(code, op, 0, 0)
	binary.LittleEndian.PutUint16(code[len(code)-2:], param)
	return code
}

func appendParam32(code []byte, op byte, param uint32) []byte {
	code = append(code, op, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], param)
	return code
}

func appendParam64(code []byte, op byte, param uint64) []byte {
	code = append(code, op, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(code[len(code)-8:], param)
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
	"DROP":     OP_DROP,
	"SLOT":     OP_SLOT,
	"TRUE":     OP_TRUE,
	"FALSE":    OP_FALSE,
	"NOT":      OP_NOT,
	"AND":      OP_AND,
	"OR":       OP_OR,
	"NET4":     OP_NET4,
	"NET6":     OP_NET6,
	"UDP":      OP_UDP,
	"TCP":      OP_TCP,
	"FQDN":     OP_FQDN,
	"LFQDN":    OP_LFQDN,
	"ADDR_S":   OP_ADDR_S,
	"LADDR_S":  OP_LADDR_S,
	"ADDR_RE":  OP_ADDR_RE,
	"LADDR_RE": OP_LADDR_RE,
	"ADDR4":    OP_ADDR4,
	"LADDR4":   OP_LADDR4,
	"ADDR6":    OP_ADDR6,
	"LADDR6":   OP_LADDR6,
	"SNET4":    OP_SNET4,
	"LSNET4":   OP_LSNET4,
	"SNET6":    OP_SNET6,
	"LSNET6":   OP_LSNET6,
	"PORT":     OP_PORT,
	"LPORT":    OP_LPORT,
	"RULE":     OP_RULE,
	"CGRP":     OP_CGRP,
	"UID":      OP_UID,
	"GID":      OP_GID,
	"UNAME":    OP_UNAME,
	"UEXP":     OP_UEXP,
	"MARK":     OP_MARK,
	"PID":      OP_PID,
}
