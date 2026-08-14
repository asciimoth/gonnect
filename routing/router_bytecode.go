package routing

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
)

// BytecodeRules contains the immutable tables and bytecode programs used to
// build a gonnect.RouterCfg.
//
// Each program is encoded as one-byte opcodes followed by the opcode parameter
// when it has one. OP_SLOT uses one uint8 parameter. String, regexp, address,
// subnet, and port operations use one little-endian uint16 parameter. A program
// routes to slot 0 when it finishes without a matching OP_DROP or OP_SLOT.
// OP_DIAL, OP_LISTEN, and OP_LOOKUP push the current RouterCfg method class:
// DialTCP, DialUDP, and RouteUDP are dial operations; ListenTCP is a listen
// operation; Lookup is a lookup operation.
//
// Every bytecode slice is validated by NewBytecodeRouterCfg. The constructor
// copies all slices, so later changes to BytecodeRules do not affect routing.
// When DNSCacheStorage is set, cached reverse DNS names are matched exactly as
// stored; names produced by github.com/asciimoth/gonnect/dns.Cache are usually
// absolute names with a trailing dot, such as "example.test.".
type BytecodeRules struct {
	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	DNSCacheStorage gdns.CacheStorage

	DialTCP   []byte
	ListenTCP []byte
	DialUDP   []byte
	RouteUDP  []byte
	Lookup    []byte
}

type RouterCfg interface {
	gonnect.RouterCfg
	SlotReporter
}

// NewBytecodeRouterCfg validates rules and returns a gonnect.RouterCfg that
// evaluates stack-based bytecode for each Router operation.
func NewBytecodeRouterCfg(rules BytecodeRules) (RouterCfg, error) {
	cfg := &bytecodeRouterCfg{
		strings:     append([]string(nil), rules.Strings...),
		regexps:     append([]*regexp.Regexp(nil), rules.Regexps...),
		ipv4Addrs:   append([]uint32(nil), rules.IPv4Addrs...),
		ipv4Subnets: append([]IPv4Subnet(nil), rules.IPv4Subnets...),
		ipv6Addrs:   append([]netip.Addr(nil), rules.IPv6Addrs...),
		ipv6Subnets: append([]netip.Prefix(nil), rules.IPv6Subnets...),
		dialTCP:     append([]byte(nil), rules.DialTCP...),
		listenTCP:   append([]byte(nil), rules.ListenTCP...),
		dialUDP:     append([]byte(nil), rules.DialUDP...),
		routeUDP:    append([]byte(nil), rules.RouteUDP...),
		lookup:      append([]byte(nil), rules.Lookup...),
		dnsStorage:  rules.DNSCacheStorage,
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.dialTCPStringOps = bytecodeAddrStringOps(cfg.dialTCP)
	cfg.listenTCPStringOps = bytecodeAddrStringOps(cfg.listenTCP)
	cfg.dialUDPStringOps = bytecodeAddrStringOps(cfg.dialUDP)
	cfg.routeUDPStringOps = bytecodeAddrStringOps(cfg.routeUDP)
	cfg.lookupStringOps = bytecodeAddrStringOps(cfg.lookup)
	cfg.mentionedSlots = mentionedBytecodeSlots(
		gonnect.RouterSlots,
		cfg.dialTCP,
		cfg.listenTCP,
		cfg.dialUDP,
		cfg.routeUDP,
		cfg.lookup,
	)
	return cfg, nil
}

type bytecodeRouterCfg struct {
	strings     []string
	regexps     []*regexp.Regexp
	ipv4Addrs   []uint32
	ipv4Subnets []IPv4Subnet
	ipv6Addrs   []netip.Addr
	ipv6Subnets []netip.Prefix

	dialTCP   []byte
	listenTCP []byte
	dialUDP   []byte
	routeUDP  []byte
	lookup    []byte

	dnsStorage gdns.CacheStorage

	dialTCPStringOps   addrStringOps
	listenTCPStringOps addrStringOps
	dialUDPStringOps   addrStringOps
	routeUDPStringOps  addrStringOps
	lookupStringOps    addrStringOps

	mentionedSlots []int
}

type bytecodeMethod uint8

const (
	bytecodeMethodDial bytecodeMethod = iota
	bytecodeMethodListen
	bytecodeMethodLookup
)

var _ gonnect.RouterCfg = (*bytecodeRouterCfg)(nil)
var _ SlotReporter = (*bytecodeRouterCfg)(nil)

func (cfg *bytecodeRouterCfg) MentionedSlots() []int {
	return append([]int(nil), cfg.mentionedSlots...)
}

func (cfg *bytecodeRouterCfg) DialTCP(network, laddr, raddr string) int {
	return cfg.exec(
		cfg.dialTCP,
		bytecodeMethodDial,
		network,
		addrInput{str: laddr},
		addrInput{str: raddr},
		cfg.dialTCPStringOps,
	)
}

func (cfg *bytecodeRouterCfg) ListenTCP(network, laddr string) int {
	return cfg.exec(
		cfg.listenTCP,
		bytecodeMethodListen,
		network,
		addrInput{str: laddr},
		addrInput{},
		cfg.listenTCPStringOps,
	)
}

func (cfg *bytecodeRouterCfg) DialUDP(network, laddr, raddr string) int {
	return cfg.exec(
		cfg.dialUDP,
		bytecodeMethodDial,
		network,
		addrInput{str: laddr},
		addrInput{str: raddr},
		cfg.dialUDPStringOps,
	)
}

func (cfg *bytecodeRouterCfg) RouteUDP(
	network string,
	laddr, raddr net.Addr,
) int {
	return cfg.exec(
		cfg.routeUDP,
		bytecodeMethodDial,
		network,
		addrInput{addr: laddr},
		addrInput{addr: raddr},
		cfg.routeUDPStringOps,
	)
}

func (cfg *bytecodeRouterCfg) Lookup(network, address string) int {
	return cfg.exec(
		cfg.lookup,
		bytecodeMethodLookup,
		network,
		addrInput{},
		addrInput{str: address},
		cfg.lookupStringOps,
	)
}

func (cfg *bytecodeRouterCfg) validate() error {
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
	checks := []struct {
		name   string
		code   []byte
		laddr  bool
		lookup bool
	}{
		{name: "DialTCP", code: cfg.dialTCP, laddr: true},
		{name: "ListenTCP", code: cfg.listenTCP, laddr: true},
		{name: "DialUDP", code: cfg.dialUDP, laddr: true},
		{name: "RouteUDP", code: cfg.routeUDP, laddr: true},
		{name: "Lookup", code: cfg.lookup, lookup: true},
	}
	for _, check := range checks {
		if err := cfg.validateCode(
			check.name,
			check.code,
			check.laddr,
			check.lookup,
		); err != nil {
			return err
		}
	}
	return nil
}

func (cfg *bytecodeRouterCfg) validateCode(
	name string,
	code []byte,
	hasLAddr, lookup bool,
) error {
	return validateBytecode(
		name,
		code,
		func(pc int, op byte, param uint64, kind bytecodeParamKind) error {
			if !hasLAddr && isLAddrOp(op) {
				return fmt.Errorf(
					"%s bytecode offset %d: local-address opcode is not valid",
					name,
					pc,
				)
			}
			if lookup && isLAddrOp(op) {
				return fmt.Errorf(
					"%s bytecode offset %d: local-address opcode is not valid for Lookup",
					name,
					pc,
				)
			}
			if isSplitOnlyOp(op) {
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for RouterCfg",
					name,
					pc,
					op,
				)
			}
			if isSnifferOnlyOp(op) {
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for RouterCfg",
					name,
					pc,
					op,
				)
			}
			if isDNSOnlyOp(op) {
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for RouterCfg",
					name,
					pc,
					op,
				)
			}
			return cfg.validateOpIndex(name, pc, op, param, kind)
		},
	)
}

func (cfg *bytecodeRouterCfg) validateOpIndex(
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
	case OP_SLOT:
		if param > gonnect.RouterSlots {
			return fmt.Errorf(
				"%s bytecode offset %d: slot %d out of range 0..%d",
				name,
				pc,
				param,
				gonnect.RouterSlots,
			)
		}
	case OP_ADDR_S, OP_LADDR_S:
		if int(param) >= len(cfg.strings) {
			return fail("string", len(cfg.strings))
		}
	case OP_ADDR_RE, OP_LADDR_RE:
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

func (cfg *bytecodeRouterCfg) exec(
	code []byte,
	method bytecodeMethod,
	network string,
	laddr, raddr addrInput,
	stringOps addrStringOps,
) int {
	ev := bytecodeEval{
		network:  strings.ToLower(network),
		laddr:    newAddrCache(laddr, cfg.dnsStorage, stringOps.local),
		raddr:    newAddrCache(raddr, cfg.dnsStorage, stringOps.remote),
		isDial:   method == bytecodeMethodDial,
		isListen: method == bytecodeMethodListen,
		isLookup: method == bytecodeMethodLookup,
	}
	stack := make([]bool, 0, 8)
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		param, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		switch op {
		case OP_DROP:
			if popBool(&stack) {
				return 0
			}
		case OP_SLOT:
			if popBool(&stack) {
				slot, ok := bytecodeParamInt(param, gonnect.RouterSlots)
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
			stack = append(stack, ev.isLookup)
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
			stack = append(
				stack,
				ok && ev.raddr.matchRegexp(cfg.regexps[idx]),
			)
		case OP_LADDR_RE:
			idx, ok := bytecodeParamIndex(param, len(cfg.regexps))
			stack = append(
				stack,
				ok && ev.laddr.matchRegexp(cfg.regexps[idx]),
			)
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
	return 0
}
