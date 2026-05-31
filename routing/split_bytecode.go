package routing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

// SplitBytecodeRules contains the immutable tables and bytecode program used
// to build a tun.SplitRouter.
//
// The packet router supports the common bytecode opcodes plus OP_RULE,
// OP_CGRP, OP_UID, OP_GID, OP_UNAME, OP_UEXP, OP_MARK, and OP_PID. The
// constructor validates and copies all slices before returning the router.
type SplitBytecodeRules struct {
	Matcher sysnet.IPMatcher

	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	Route []byte
}

// NewBytecodeSplitRouter validates rules and returns a tun.SplitRouter that
// evaluates stack-based bytecode against IP packets.
func NewBytecodeSplitRouter(rules SplitBytecodeRules) (tun.SplitRouter, error) {
	cfg := &bytecodeSplitRouter{
		matcher:     rules.Matcher,
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
	return cfg, nil
}

type bytecodeSplitRouter struct {
	matcher sysnet.IPMatcher

	strings     []string
	regexps     []*regexp.Regexp
	ipv4Addrs   []uint32
	ipv4Subnets []IPv4Subnet
	ipv6Addrs   []netip.Addr
	ipv6Subnets []netip.Prefix

	route []byte
}

var _ tun.SplitRouter = (*bytecodeSplitRouter)(nil)

func (cfg *bytecodeSplitRouter) Lock() {
	cfg.matcher.Lock()
}

func (cfg *bytecodeSplitRouter) Unlock() {
	cfg.matcher.Unlock()
}

func (cfg *bytecodeSplitRouter) Route(
	buf []byte,
	offset int,
	isNative bool,
) int {
	pkt, ok := parseIPPacket(buf, offset)
	if !ok {
		return 0
	}
	ev := splitEval{
		cfg:        cfg,
		native:     isNative,
		packet:     pkt,
		packetData: buf[offset : offset+pkt.total],
		ruleCache:  make(map[uint64]bool),
	}
	stack := make([]bool, 0, 8)
	for pc := 0; pc < len(cfg.route); {
		op := cfg.route[pc]
		pc++
		param, next := readBytecodeParamUnchecked(cfg.route, pc, op)
		pc = next
		switch op {
		case OP_DROP:
			if popBool(&stack) {
				return 0
			}
		case OP_SLOT:
			if popBool(&stack) {
				slot, ok := bytecodeParamInt(param, 16)
				if !ok {
					return 0
				}
				return slot
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
			stack = append(stack, pkt.src.Is4())
		case OP_NET6:
			stack = append(stack, pkt.src.Is6())
		case OP_UDP:
			stack = append(stack, pkt.proto == 17)
		case OP_TCP:
			stack = append(stack, pkt.proto == 6)
		case OP_FQDN, OP_LFQDN:
			stack = append(stack, false)
		case OP_ADDR_S:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ok && pkt.dst.String() == cfg.strings[idx])
		case OP_LADDR_S:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ok && pkt.src.String() == cfg.strings[idx])
		case OP_ADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(
				stack,
				ok && cfg.regexps[idx].MatchString(pkt.dst.String()),
			)
		case OP_LADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(
				stack,
				ok && cfg.regexps[idx].MatchString(pkt.src.String()),
			)
		case OP_ADDR4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs))
			stack = append(
				stack,
				ok && pkt.dst4 == cfg.ipv4Addrs[idx] && pkt.dst.Is4(),
			)
		case OP_LADDR4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Addrs))
			stack = append(
				stack,
				ok && pkt.src4 == cfg.ipv4Addrs[idx] && pkt.src.Is4(),
			)
		case OP_ADDR6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs))
			stack = append(stack, ok && pkt.dst == cfg.ipv6Addrs[idx])
		case OP_LADDR6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Addrs))
			stack = append(stack, ok && pkt.src == cfg.ipv6Addrs[idx])
		case OP_SNET4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets))
			stack = append(
				stack,
				ok && pkt.dst.Is4() && cfg.ipv4Subnets[idx].contains(pkt.dst4),
			)
		case OP_LSNET4:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv4Subnets))
			stack = append(
				stack,
				ok && pkt.src.Is4() && cfg.ipv4Subnets[idx].contains(pkt.src4),
			)
		case OP_SNET6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets))
			stack = append(stack, ok && cfg.ipv6Subnets[idx].Contains(pkt.dst))
		case OP_LSNET6:
			idx, ok := bytecodeParamIndex(param, len(cfg.ipv6Subnets))
			stack = append(stack, ok && cfg.ipv6Subnets[idx].Contains(pkt.src))
		case OP_PORT:
			port, ok := bytecodeParamInt(param, 0xffff)
			stack = append(stack, ok && pkt.hasPorts && port == pkt.dstPort)
		case OP_LPORT:
			port, ok := bytecodeParamInt(param, 0xffff)
			stack = append(stack, ok && pkt.hasPorts && port == pkt.srcPort)
		case OP_RULE:
			stack = append(stack, ev.rule(param))
		case OP_CGRP:
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return info.Cgroup == param
			}))
		case OP_UID:
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return info.UID == param
			}))
		case OP_GID:
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return info.GID == param
			}))
		case OP_UNAME:
			idx, ok := bytecodeParamIndex(param, len(cfg.strings))
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return ok && info.User == cfg.strings[idx]
			}))
		case OP_UEXP:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return ok && cfg.regexps[idx].MatchString(info.User)
			}))
		case OP_MARK:
			want, ok := bytecodeParamSigned32(param)
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return ok && info.RouteMark == want
			}))
		case OP_PID:
			want, ok := bytecodeParamSigned32(param)
			stack = append(stack, ev.infoField(func(info *sysnet.NetInfo) bool {
				return ok && info.PID == want
			}))
		}
	}
	return 0
}

func (cfg *bytecodeSplitRouter) validate() error {
	if cfg.matcher == nil {
		return fmt.Errorf("split bytecode matcher is nil")
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
	return validateBytecode("SplitRoute", cfg.route, cfg.validateOp)
}

func (cfg *bytecodeSplitRouter) validateOp(
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
			"SplitRoute bytecode offset %d: %s index %d out of range %d",
			pc,
			table,
			param,
			n,
		)
	}
	switch op {
	case OP_SLOT:
		if param > 16 {
			return fmt.Errorf(
				"SplitRoute bytecode offset %d: slot %d out of range 0..16",
				pc,
				param,
			)
		}
	case OP_ADDR_S, OP_LADDR_S, OP_UNAME:
		if int(param) >= len(cfg.strings) {
			return fail("string", len(cfg.strings))
		}
	case OP_ADDR_RE, OP_LADDR_RE, OP_UEXP:
		if int(param) >= len(cfg.regexps) {
			return fail("regexp", len(cfg.regexps))
		}
	case OP_ADDR4, OP_LADDR4:
		if int(param) >= len(cfg.ipv4Addrs) {
			return fail("IPv4 address", len(cfg.ipv4Addrs))
		}
	case OP_ADDR6, OP_LADDR6:
		if int(param) >= len(cfg.ipv6Addrs) {
			return fail("IPv6 address", len(cfg.ipv6Addrs))
		}
	case OP_SNET4, OP_LSNET4:
		if int(param) >= len(cfg.ipv4Subnets) {
			return fail("IPv4 subnet", len(cfg.ipv4Subnets))
		}
	case OP_SNET6, OP_LSNET6:
		if int(param) >= len(cfg.ipv6Subnets) {
			return fail("IPv6 subnet", len(cfg.ipv6Subnets))
		}
	}
	return nil
}

type splitEval struct {
	cfg        *bytecodeSplitRouter
	native     bool
	packet     parsedIPPacket
	packetData []byte
	ruleCache  map[uint64]bool
	infoDone   bool
	info       *sysnet.NetInfo
}

func (ev *splitEval) rule(rule uint64) bool {
	if !ev.native {
		return false
	}
	if got, ok := ev.ruleCache[rule]; ok {
		return got
	}
	got := ev.cfg.matcher.Match(ev.packetData, rule)
	ev.ruleCache[rule] = got
	return got
}

func (ev *splitEval) packetInfo() *sysnet.NetInfo {
	if !ev.native {
		return nil
	}
	if !ev.infoDone {
		ev.infoDone = true
		ev.info = ev.cfg.matcher.PktInfo(ev.packetData)
	}
	return ev.info
}

func (ev *splitEval) infoField(match func(*sysnet.NetInfo) bool) bool {
	info := ev.packetInfo()
	return info != nil && match(info)
}

type parsedIPPacket struct {
	src, dst       netip.Addr
	src4, dst4     uint32
	proto          uint8
	total          int
	srcPort        int
	dstPort        int
	hasPorts       bool
	transportStart int
}

func parseIPPacket(buf []byte, offset int) (parsedIPPacket, bool) {
	if offset < 0 || offset >= len(buf) {
		return parsedIPPacket{}, false
	}
	pkt := buf[offset:]
	if len(pkt) == 0 {
		return parsedIPPacket{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4Packet(pkt)
	case 6:
		return parseIPv6Packet(pkt)
	default:
		return parsedIPPacket{}, false
	}
}

func parseIPv4Packet(pkt []byte) (parsedIPPacket, bool) {
	if len(pkt) < 20 {
		return parsedIPPacket{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return parsedIPPacket{}, false
	}
	src4 := binary.BigEndian.Uint32(pkt[12:16])
	dst4 := binary.BigEndian.Uint32(pkt[16:20])
	out := parsedIPPacket{
		src: netip.AddrFrom4(
			[4]byte{pkt[12], pkt[13], pkt[14], pkt[15]},
		),
		dst: netip.AddrFrom4(
			[4]byte{pkt[16], pkt[17], pkt[18], pkt[19]},
		),
		src4:           src4,
		dst4:           dst4,
		proto:          pkt[9],
		total:          total,
		transportStart: ihl,
	}
	flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
	if flagsFrag&0x1fff == 0 {
		out.parsePorts(pkt[:total])
	}
	return out, true
}

func parseIPv6Packet(pkt []byte) (parsedIPPacket, bool) {
	if len(pkt) < 40 {
		return parsedIPPacket{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	total := 40 + payloadLen
	if total > len(pkt) {
		return parsedIPPacket{}, false
	}
	var src, dst [16]byte
	copy(src[:], pkt[8:24])
	copy(dst[:], pkt[24:40])
	out := parsedIPPacket{
		src:            netip.AddrFrom16(src),
		dst:            netip.AddrFrom16(dst),
		proto:          pkt[6],
		total:          total,
		transportStart: 40,
	}
	proto, start, ok := skipIPv6ExtHeaders(
		pkt[:total],
		out.proto,
		out.transportStart,
	)
	if !ok {
		return parsedIPPacket{}, false
	}
	out.proto = proto
	out.transportStart = start
	out.parsePorts(pkt[:total])
	return out, true
}

func skipIPv6ExtHeaders(pkt []byte, proto uint8, start int) (uint8, int, bool) {
	for {
		switch proto {
		case 0, 43, 60:
			if start+2 > len(pkt) {
				return 0, 0, false
			}
			next := pkt[start]
			hdrLen := (int(pkt[start+1]) + 1) * 8
			if start+hdrLen > len(pkt) {
				return 0, 0, false
			}
			proto = next
			start += hdrLen
		case 44:
			if start+8 > len(pkt) {
				return 0, 0, false
			}
			next := pkt[start]
			frag := binary.BigEndian.Uint16(pkt[start+2 : start+4])
			start += 8
			proto = next
			if frag&0xfff8 != 0 {
				return proto, start, true
			}
		case 51:
			if start+2 > len(pkt) {
				return 0, 0, false
			}
			next := pkt[start]
			hdrLen := (int(pkt[start+1]) + 2) * 4
			if start+hdrLen > len(pkt) {
				return 0, 0, false
			}
			proto = next
			start += hdrLen
		default:
			return proto, start, true
		}
	}
}

func (p *parsedIPPacket) parsePorts(pkt []byte) {
	if p.proto != 6 && p.proto != 17 {
		return
	}
	if p.transportStart+4 > len(pkt) {
		return
	}
	p.srcPort = int(binary.BigEndian.Uint16(pkt[p.transportStart:]))
	p.dstPort = int(binary.BigEndian.Uint16(pkt[p.transportStart+2:]))
	p.hasPorts = true
}
