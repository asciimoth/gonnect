package routing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sniffer"
)

const maxSnifferBytecodeSlot = 0xff

// NamedSniffClassifier binds a rule-language name to a Sniffer classifier
// factory.
//
// Name must be non-empty and must not contain white space. Factory can be any
// implementation of sniffer.Factory. Built-in HTTP and TLS factories can carry
// URL, host, SNI, or ALPN filters; custom factories can carry any equivalent
// policy before bytecode tests the winning name with SNIFF.
type NamedSniffClassifier struct {
	Name    string
	Factory sniffer.Factory
}

// SnifferBytecodeRules contains the immutable tables and bytecode programs
// used to build gonnect/sniffer control callbacks.
//
// Control runs before sniffing. It can route directly with OP_SLOT/OP_DROP or
// request TCP interception with OP_INTERCEPT. SniffControl runs after Sniffer
// restores inspected bytes. It can route with OP_SLOT/OP_DROP and can test the
// matched classifier with OP_SNIFF or OP_SNIFF_NONE.
//
// NewSnifferBytecodeRules derives Control and SniffControl from one rule text.
// Sniffer-only segments are copied only to the phase where they make sense;
// normal address, network, method, and slot segments are copied to both.
type SnifferBytecodeRules struct {
	Classifiers []NamedSniffClassifier

	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	DNSCacheStorage gdns.CacheStorage

	Control      []byte
	SniffControl []byte
}

// SnifferControls is the bytecode-backed control pair for sniffer.Sniffer.
type SnifferControls interface {
	SlotReporter

	Control(call *sniffer.Call) sniffer.Action
	SniffControl(call *sniffer.SniffedCall) sniffer.Action
	Classifiers() []sniffer.Factory
}

// NewBytecodeSniffer validates rules and returns callbacks that can be used by
// sniffer.NewSniffer. Existing Control, SniffControl, and Classifiers fields in
// config are replaced with the bytecode-backed values.
func NewBytecodeSniffer(
	config sniffer.SnifferConfig,
	rules SnifferBytecodeRules,
) (*sniffer.Sniffer, error) {
	controls, err := NewBytecodeSnifferControls(rules)
	if err != nil {
		return nil, err
	}
	config.Control = controls.Control
	config.SniffControl = controls.SniffControl
	config.Classifiers = controls.Classifiers()
	return sniffer.NewSniffer(config)
}

// NewBytecodeSnifferControls validates rules and returns a reusable Sniffer
// control pair. Sniff errors always reject, independent of SniffControl
// bytecode.
func NewBytecodeSnifferControls(
	rules SnifferBytecodeRules,
) (SnifferControls, error) {
	cfg := &bytecodeSnifferControls{
		classifiers:  append([]NamedSniffClassifier(nil), rules.Classifiers...),
		strings:      append([]string(nil), rules.Strings...),
		regexps:      append([]*regexp.Regexp(nil), rules.Regexps...),
		ipv4Addrs:    append([]uint32(nil), rules.IPv4Addrs...),
		ipv4Subnets:  append([]IPv4Subnet(nil), rules.IPv4Subnets...),
		ipv6Addrs:    append([]netip.Addr(nil), rules.IPv6Addrs...),
		ipv6Subnets:  append([]netip.Prefix(nil), rules.IPv6Subnets...),
		control:      append([]byte(nil), rules.Control...),
		sniffControl: append([]byte(nil), rules.SniffControl...),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.controlStringOps = bytecodeAddrStringOps(cfg.control)
	cfg.sniffStringOps = bytecodeAddrStringOps(cfg.sniffControl)
	if cfg.controlStringOps.remote ||
		cfg.controlStringOps.local ||
		cfg.sniffStringOps.remote ||
		cfg.sniffStringOps.local {
		cfg.dnsStorage = rules.DNSCacheStorage
	}
	cfg.mentionedSlots = mentionedBytecodeSlots(
		maxSnifferBytecodeSlot,
		cfg.control,
		cfg.sniffControl,
	)
	return cfg, nil
}

type bytecodeSnifferControls struct {
	classifiers []NamedSniffClassifier

	strings     []string
	regexps     []*regexp.Regexp
	ipv4Addrs   []uint32
	ipv4Subnets []IPv4Subnet
	ipv6Addrs   []netip.Addr
	ipv6Subnets []netip.Prefix

	control      []byte
	sniffControl []byte

	dnsStorage       gdns.CacheStorage
	controlStringOps addrStringOps
	sniffStringOps   addrStringOps

	mentionedSlots []int
}

var _ SnifferControls = (*bytecodeSnifferControls)(nil)

func (cfg *bytecodeSnifferControls) MentionedSlots() []int {
	return append([]int(nil), cfg.mentionedSlots...)
}

func (cfg *bytecodeSnifferControls) Classifiers() []sniffer.Factory {
	out := make([]sniffer.Factory, len(cfg.classifiers))
	for i, classifier := range cfg.classifiers {
		out[i] = classifier.Factory
	}
	return out
}

func (cfg *bytecodeSnifferControls) Control(
	call *sniffer.Call,
) sniffer.Action {
	if call == nil {
		return sniffer.Action{Slot: sniffer.RejectSlot}
	}
	return cfg.exec(
		cfg.control,
		*call,
		sniffer.SniffResult{Index: sniffer.NoMatch},
		cfg.controlStringOps,
	)
}

func (cfg *bytecodeSnifferControls) SniffControl(
	call *sniffer.SniffedCall,
) sniffer.Action {
	if call == nil || call.Result.Err != nil {
		return sniffer.Action{Slot: sniffer.RejectSlot}
	}
	return cfg.exec(
		cfg.sniffControl,
		call.Call,
		call.Result,
		cfg.sniffStringOps,
	)
}

type snifferBytecodeProgram uint8

const (
	snifferBytecodeControl snifferBytecodeProgram = iota
	snifferBytecodeSniffControl
)

func (cfg *bytecodeSnifferControls) validate() error {
	names := make(map[string]struct{}, len(cfg.classifiers))
	for i, classifier := range cfg.classifiers {
		name, err := normalizeSniffClassifierName(classifier.Name)
		if err != nil {
			return fmt.Errorf("sniff classifier %d: %w", i, err)
		}
		if classifier.Factory == nil {
			return fmt.Errorf("sniff classifier %q has nil factory", name)
		}
		if _, ok := names[name]; ok {
			return fmt.Errorf("duplicate sniff classifier %q", name)
		}
		names[name] = struct{}{}
		cfg.classifiers[i].Name = name
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
	if err := cfg.validateCode(
		"SnifferControl",
		cfg.control,
		snifferBytecodeControl,
	); err != nil {
		return err
	}
	return cfg.validateCode(
		"SnifferSniffControl",
		cfg.sniffControl,
		snifferBytecodeSniffControl,
	)
}

func (cfg *bytecodeSnifferControls) validateCode(
	name string,
	code []byte,
	program snifferBytecodeProgram,
) error {
	return validateBytecode(
		name,
		code,
		func(pc int, op byte, param uint64, kind bytecodeParamKind) error {
			switch {
			case op == OP_RULE:
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for Sniffer",
					name,
					pc,
					op,
				)
			case program == snifferBytecodeControl &&
				(op == OP_SNIFF || op == OP_SNIFF_NONE):
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for Sniffer control",
					name,
					pc,
					op,
				)
			case program == snifferBytecodeSniffControl &&
				op == OP_INTERCEPT:
				return fmt.Errorf(
					"%s bytecode offset %d: opcode %d is not valid for Sniffer sniff control",
					name,
					pc,
					op,
				)
			}
			return cfg.validateOpIndex(name, pc, op, param, kind)
		},
	)
}

func (cfg *bytecodeSnifferControls) validateOpIndex(
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
		if param > maxSnifferBytecodeSlot {
			return fmt.Errorf(
				"%s bytecode offset %d: slot %d out of range 0..%d",
				name,
				pc,
				param,
				maxSnifferBytecodeSlot,
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
	case OP_SNIFF:
		if int(param) >= len(cfg.classifiers) {
			return fail("sniff classifier", len(cfg.classifiers))
		}
	}
	return nil
}

func (cfg *bytecodeSnifferControls) exec(
	code []byte,
	call sniffer.Call,
	result sniffer.SniffResult,
	stringOps addrStringOps,
) sniffer.Action {
	ev := newSnifferBytecodeEval(call, cfg.dnsStorage, stringOps)
	stack := make([]bool, 0, 8)
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		param, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		switch op {
		case OP_DROP:
			if popBool(&stack) {
				return sniffer.Action{Slot: sniffer.RejectSlot}
			}
		case OP_SLOT:
			if popBool(&stack) {
				slot, ok := bytecodeParamInt(param, maxSnifferBytecodeSlot)
				if !ok {
					return sniffer.Action{Slot: sniffer.RejectSlot}
				}
				return sniffer.Action{Slot: slot}
			}
		case OP_INTERCEPT:
			if popBool(&stack) {
				return sniffer.Action{
					Slot:      sniffer.RejectSlot,
					Intercept: true,
				}
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
		case OP_SNIFF:
			idx, ok := bytecodeParamInt(param, len(cfg.classifiers)-1)
			stack = append(stack, ok && result.Index == idx)
		case OP_SNIFF_NONE:
			stack = append(stack, result.Index == sniffer.NoMatch)
		}
	}
	return sniffer.Action{Slot: sniffer.RejectSlot}
}

func newSnifferBytecodeEval(
	call sniffer.Call,
	storage gdns.CacheStorage,
	stringOps addrStringOps,
) bytecodeEval {
	dial, listen, lookup := snifferOperationClass(call.Operation)
	laddr, raddr := snifferCallAddresses(call)
	return bytecodeEval{
		network: strings.ToLower(call.Network),
		laddr:   newAddrCache(addrInput{str: laddr}, storage, stringOps.local),
		raddr: newAddrCache(
			addrInput{str: raddr},
			storage,
			stringOps.remote,
		),
		isDial:   dial,
		isListen: listen,
		isLookup: lookup,
	}
}

func snifferCallAddresses(call sniffer.Call) (laddr, raddr string) {
	laddr = call.Src
	raddr = call.Dst
	if raddr != "" {
		return laddr, raddr
	}
	switch call.Operation {
	case sniffer.OpDial,
		sniffer.OpListen,
		sniffer.OpPacketDial,
		sniffer.OpListenPacket,
		sniffer.OpDialTCP,
		sniffer.OpListenTCP,
		sniffer.OpDialUDP,
		sniffer.OpListenUDP,
		sniffer.OpListenPacketConfig,
		sniffer.OpListenUDPConfig,
		sniffer.OpListenMulticastUDP,
		sniffer.OpInterfaces,
		sniffer.OpInterfaceAddrs,
		sniffer.OpInterfaceMcast,
		sniffer.OpInterfacesByIndex,
		sniffer.OpInterfacesByName:
		return laddr, raddr
	case sniffer.OpLookupPort:
		return laddr, call.Service
	case sniffer.OpLookupIP,
		sniffer.OpLookupIPAddr,
		sniffer.OpLookupNetIP,
		sniffer.OpLookupHost,
		sniffer.OpLookupAddr,
		sniffer.OpLookupCNAME,
		sniffer.OpLookupNS,
		sniffer.OpLookupMX,
		sniffer.OpLookupSRV,
		sniffer.OpLookupTXT:
		return laddr, call.Host
	}
	return laddr, raddr
}

func snifferOperationClass(
	op sniffer.Operation,
) (dial, listen, lookup bool) {
	switch op {
	case sniffer.OpDial,
		sniffer.OpPacketDial,
		sniffer.OpDialTCP,
		sniffer.OpDialUDP:
		return true, false, false
	case sniffer.OpListen,
		sniffer.OpListenPacket,
		sniffer.OpListenTCP,
		sniffer.OpListenUDP,
		sniffer.OpListenPacketConfig,
		sniffer.OpListenUDPConfig,
		sniffer.OpListenMulticastUDP:
		return false, true, false
	case sniffer.OpLookupIP,
		sniffer.OpLookupIPAddr,
		sniffer.OpLookupNetIP,
		sniffer.OpLookupHost,
		sniffer.OpLookupAddr,
		sniffer.OpLookupCNAME,
		sniffer.OpLookupPort,
		sniffer.OpLookupNS,
		sniffer.OpLookupMX,
		sniffer.OpLookupSRV,
		sniffer.OpLookupTXT:
		return false, false, true
	case sniffer.OpInterfaces,
		sniffer.OpInterfaceAddrs,
		sniffer.OpInterfaceMcast,
		sniffer.OpInterfacesByIndex,
		sniffer.OpInterfacesByName:
		return false, false, false
	}
	return false, false, false
}
