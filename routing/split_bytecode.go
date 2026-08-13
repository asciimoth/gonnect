package routing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/gonnect/tun"
)

// SplitBytecodeRules contains the immutable tables and bytecode program used
// to build a tun.SplitRouter.
//
// The packet router supports the common bytecode opcodes plus OP_RULE. OP_RULE
// indexes Rules and is evaluated by a sysnet.Matcher built from System. The
// RouterCfg method opcodes OP_DIAL, OP_LISTEN, and OP_LOOKUP are not valid for
// packet routing. The constructor validates and copies all slices before
// returning the router. When DNSCacheStorage is set, cached reverse DNS names
// are matched exactly as stored; names produced by
// github.com/asciimoth/gonnect/dns.Cache are usually absolute names with a
// trailing dot, such as "example.test.".
type SplitBytecodeRules struct {
	System sysnet.System
	Rules  []sysnet.Rule

	// RuleCacheTTL controls how long OP_RULE matcher results are cached by
	// flow. A zero value uses the default TTL; a negative value disables the
	// cross-packet rule cache.
	RuleCacheTTL time.Duration
	// RuleCacheMaxEntries bounds the cross-packet OP_RULE cache. A zero value
	// uses the default size; a negative value disables the cache.
	RuleCacheMaxEntries int
	// RouteCacheTTL controls how long whole bytecode route results are cached
	// by packet flow. When RouteCacheTTL and RouteCacheMaxEntries are both
	// zero, the route cache inherits the OP_RULE cache settings; this means
	// disabling the rule cache also disables the default route cache. A negative
	// value disables the route cache.
	RouteCacheTTL time.Duration
	// RouteCacheMaxEntries bounds the whole bytecode route-result cache. A zero
	// value uses the inherited or default size; a negative value disables the
	// route cache.
	RouteCacheMaxEntries int

	Strings     []string
	Regexps     []*regexp.Regexp
	IPv4Addrs   []uint32
	IPv4Subnets []IPv4Subnet
	IPv6Addrs   []netip.Addr
	IPv6Subnets []netip.Prefix

	DNSCacheStorage gdns.CacheStorage

	Route []byte
}

type SplitRouter interface {
	tun.SplitRouter
	SlotReporter
	Close() error
}

const (
	defaultSplitRuleCacheTTL        = time.Second
	defaultSplitRuleCacheMaxEntries = 4096
)

// NewBytecodeSplitRouter validates rules and returns a SplitRouter that
// evaluates stack-based bytecode against IP packets. The returned router owns
// matchers built from rules.System; call Close when the router is no longer
// used.
func NewBytecodeSplitRouter(rules SplitBytecodeRules) (SplitRouter, error) {
	cfg := &bytecodeSplitRouter{
		system:      rules.System,
		rules:       append([]sysnet.Rule(nil), rules.Rules...),
		strings:     append([]string(nil), rules.Strings...),
		regexps:     append([]*regexp.Regexp(nil), rules.Regexps...),
		ipv4Addrs:   append([]uint32(nil), rules.IPv4Addrs...),
		ipv4Subnets: append([]IPv4Subnet(nil), rules.IPv4Subnets...),
		ipv6Addrs:   append([]netip.Addr(nil), rules.IPv6Addrs...),
		ipv6Subnets: append([]netip.Prefix(nil), rules.IPv6Subnets...),
		route:       append([]byte(nil), rules.Route...),
		ruleCache: newSplitRuleResultCache(
			rules.RuleCacheTTL,
			rules.RuleCacheMaxEntries,
		),
		routeCache: newSplitRouteResultCache(
			rules.RouteCacheTTL,
			rules.RouteCacheMaxEntries,
			rules.RuleCacheTTL,
			rules.RuleCacheMaxEntries,
		),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.routeStringOps = bytecodeAddrStringOps(cfg.route)
	if cfg.routeStringOps.remote || cfg.routeStringOps.local {
		cfg.dnsStorage = rules.DNSCacheStorage
	}
	cfg.splitSubnets = compileSplitIPv4Subnets(cfg.ipv4Subnets)
	cfg.routeProgram, cfg.routeStackDepth = compileSplitBytecode(cfg.route)
	cfg.routeConds, cfg.routeSegments, cfg.routeCompiled = compileSplitRoute(
		cfg.route,
	)
	if err := cfg.buildMatchers(); err != nil {
		return nil, err
	}
	cfg.mentionedSlots = mentionedBytecodeSlots(gonnect.RouterSlots, cfg.route)
	return cfg, nil
}

type bytecodeSplitRouter struct {
	system   sysnet.System
	rules    []sysnet.Rule
	matchers []sysnet.Matcher

	strings      []string
	regexps      []*regexp.Regexp
	ipv4Addrs    []uint32
	ipv4Subnets  []IPv4Subnet
	splitSubnets []splitIPv4Subnet
	ipv6Addrs    []netip.Addr
	ipv6Subnets  []netip.Prefix

	// route is kept as the immutable bytecode source for diagnostics and slot
	// reporting. routeProgram is the same program predecoded into fixed-width
	// instructions for the generic stack evaluator fallback.
	route           []byte
	routeProgram    []splitInstr
	routeStackDepth int
	// routeConds and routeSegments are the optimized, segment-oriented form of
	// route. routeCompiled is false only when the optimizer sees a bytecode shape
	// it cannot prove is a sequence of terminal condition/action segments.
	routeConds     []splitCond
	routeSegments  []splitRouteSegment
	routeCompiled  bool
	routeStringOps addrStringOps
	dnsStorage     gdns.CacheStorage
	// ruleCache memoizes expensive OP_RULE matcher results by flow; routeCache
	// memoizes the final slot for the whole bytecode program by the same packet
	// fields plus parser/native-state flags that affect routing semantics.
	ruleCache  *splitRuleResultCache
	routeCache *splitRouteResultCache

	mentionedSlots []int
}

var _ tun.SplitRouter = (*bytecodeSplitRouter)(nil)
var _ SlotReporter = (*bytecodeSplitRouter)(nil)

func (cfg *bytecodeSplitRouter) MentionedSlots() []int {
	return append([]int(nil), cfg.mentionedSlots...)
}

func (cfg *bytecodeSplitRouter) Lock() {}

func (cfg *bytecodeSplitRouter) Unlock() {}

func (cfg *bytecodeSplitRouter) Close() error {
	var err error
	for _, matcher := range cfg.matchers {
		if matcher != nil {
			err = errors.Join(err, matcher.Close())
		}
	}
	cfg.matchers = nil
	if cfg.ruleCache != nil {
		cfg.ruleCache.clear()
	}
	if cfg.routeCache != nil {
		cfg.routeCache.clear()
	}
	return err
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
	var routeKey splitRouteCacheKey
	if cfg.routeCache != nil {
		// The whole-route cache still requires packet parsing so the key can
		// include protocol, endpoint, port, native, and parser-state bits. This
		// prevents portless, flow-ineligible, or non-native packets from reusing
		// a native flow's result even when addresses and ports happen to match.
		routeKey = splitRouteCacheKeyFromPacket(pkt, isNative)
		now := time.Now().UnixNano()
		if got, ok := cfg.routeCache.get(routeKey, now); ok {
			return got
		}
	}
	ev := splitEval{
		cfg:        cfg,
		native:     isNative,
		packet:     pkt,
		packetData: buf[offset : offset+pkt.total],
		cacheable:  true,
	}
	slot := 0
	if cfg.routeCompiled {
		slot = cfg.routeBySegments(&ev)
	} else {
		// The fallback evaluator executes the original stack bytecode but avoids
		// per-packet opcode decoding and the old append/pop stack allocations.
		// Validation has already guaranteed stack safety and table bounds.
		var stackSmall [64]bool
		stack := stackSmall[:]
		if cfg.routeStackDepth > len(stackSmall) {
			stack = make([]bool, cfg.routeStackDepth)
		}
		sp := 0
		for _, inst := range cfg.routeProgram {
			switch inst.op {
			case OP_DROP:
				sp--
				if stack[sp] {
					slot = 0
					goto done
				}
			case OP_SLOT:
				sp--
				if stack[sp] {
					slot = int(inst.param)
					goto done
				}
			case OP_TRUE:
				stack[sp] = true
				sp++
			case OP_FALSE:
				stack[sp] = false
				sp++
			case OP_NOT:
				stack[sp-1] = !stack[sp-1]
			case OP_AND:
				sp--
				stack[sp-1] = stack[sp-1] && stack[sp]
			case OP_OR:
				sp--
				stack[sp-1] = stack[sp-1] || stack[sp]
			case OP_NET4:
				stack[sp] = pkt.src.Is4()
				sp++
			case OP_NET6:
				stack[sp] = pkt.src.Is6()
				sp++
			case OP_UDP:
				stack[sp] = pkt.proto == 17
				sp++
			case OP_TCP:
				stack[sp] = pkt.proto == 6
				sp++
			case OP_FQDN, OP_LFQDN:
				stack[sp] = false
				sp++
			case OP_ADDR_S:
				stack[sp] = ev.matchDstString(cfg.strings[inst.param])
				sp++
			case OP_LADDR_S:
				stack[sp] = ev.matchSrcString(cfg.strings[inst.param])
				sp++
			case OP_ADDR_RE:
				stack[sp] = ev.matchDstRegexp(cfg.regexps[inst.param])
				sp++
			case OP_LADDR_RE:
				stack[sp] = ev.matchSrcRegexp(cfg.regexps[inst.param])
				sp++
			case OP_ADDR4:
				stack[sp] = pkt.dst4 == cfg.ipv4Addrs[inst.param] &&
					pkt.dst.Is4()
				sp++
			case OP_LADDR4:
				stack[sp] = pkt.src4 == cfg.ipv4Addrs[inst.param] &&
					pkt.src.Is4()
				sp++
			case OP_ADDR6:
				stack[sp] = pkt.dst == cfg.ipv6Addrs[inst.param]
				sp++
			case OP_LADDR6:
				stack[sp] = pkt.src == cfg.ipv6Addrs[inst.param]
				sp++
			case OP_SNET4:
				stack[sp] = pkt.dst.Is4() &&
					cfg.splitSubnets[inst.param].contains(pkt.dst4)
				sp++
			case OP_LSNET4:
				stack[sp] = pkt.src.Is4() &&
					cfg.splitSubnets[inst.param].contains(pkt.src4)
				sp++
			case OP_SNET6:
				stack[sp] = cfg.ipv6Subnets[inst.param].Contains(pkt.dst)
				sp++
			case OP_LSNET6:
				stack[sp] = cfg.ipv6Subnets[inst.param].Contains(pkt.src)
				sp++
			case OP_PORT:
				stack[sp] = pkt.hasPorts && inst.param == pkt.dstPort
				sp++
			case OP_LPORT:
				stack[sp] = pkt.hasPorts && inst.param == pkt.srcPort
				sp++
			case OP_RULE:
				stack[sp] = ev.rule(inst.param)
				sp++
			}
		}
	}
done:
	if cfg.routeCache != nil && ev.cacheable {
		// Matcher and flow-construction errors mark the evaluation non-cacheable:
		// callers should get a fresh attempt on the next packet instead of
		// replaying an error-forced false result from the route cache.
		cfg.routeCache.set(routeKey, slot, time.Now().UnixNano())
	}
	return slot
}

func (cfg *bytecodeSplitRouter) validate() error {
	if cfg.system == nil {
		return fmt.Errorf("split bytecode system is nil")
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

// splitInstr is one validated bytecode instruction with its parameter already
// decoded. SplitRoute parameters are encoded as uint8 or uint16, so keeping
// them as uint16 lets the hot evaluator skip bounds/width decoding work.
type splitInstr struct {
	op    byte
	param uint16
}

// splitCondKind describes the boolean expression tree built from stack
// bytecode. Constants are folded during construction; AND/OR nodes may carry
// more than two children because simple chains are flattened.
type splitCondKind uint8

const (
	splitCondConst splitCondKind = iota
	splitCondAtom
	splitCondNot
	splitCondAnd
	splitCondOr
)

// splitCond is a node in the compiled condition arena. Nodes refer to other
// nodes by integer index instead of pointers so route segments can cheaply hold
// stable references into one compact slice.
type splitCond struct {
	kind     splitCondKind
	op       byte
	param    uint16
	value    bool
	child    int
	children []int
}

// splitRouteSegment is one terminal rule in SplitRoute bytecode: evaluate cond,
// then either drop or return slot. Segments preserve bytecode order, which is
// important because the first matching terminal instruction wins.
type splitRouteSegment struct {
	cond      int
	slot      int
	drop      bool
	fastKind  splitFastCondKind
	fastPreds []splitPredicate
}

// splitFastCondKind identifies condition shapes that can be evaluated as a
// flat predicate loop. This avoids recursive condition evaluation for the
// parser's common "A B AND C AND SLOT" output.
type splitFastCondKind uint8

const (
	splitFastCondNone splitFastCondKind = iota
	splitFastCondAll
	splitFastCondAny
)

// splitPredicate is an atom that can participate in a flat all/any loop. The
// not bit is limited to direct atom negation; more complex negated expressions
// stay on the recursive evaluator path.
type splitPredicate struct {
	op    byte
	param uint16
	not   bool
}

// splitIPv4Subnet stores the mask and masked network address for an IPv4 CIDR
// entry so per-packet subnet checks do not rebuild the mask.
type splitIPv4Subnet struct {
	addr uint32
	mask uint32
}

// compileSplitIPv4Subnets precomputes IPv4 subnet masks in the same order as
// the public IPv4Subnets table, preserving bytecode indexes.
func compileSplitIPv4Subnets(subnets []IPv4Subnet) []splitIPv4Subnet {
	out := make([]splitIPv4Subnet, len(subnets))
	for i, subnet := range subnets {
		if subnet.Bits == 0 {
			continue
		}
		mask := ^uint32(0) << (32 - subnet.Bits)
		out[i] = splitIPv4Subnet{
			addr: subnet.Addr & mask,
			mask: mask,
		}
	}
	return out
}

func (n splitIPv4Subnet) contains(addr uint32) bool {
	return addr&n.mask == n.addr
}

// compileSplitBytecode decodes bytecode once and computes the maximum stack
// depth needed by the fallback evaluator. validateBytecode has already checked
// structural correctness, so this intentionally uses unchecked parameter reads.
func compileSplitBytecode(code []byte) ([]splitInstr, int) {
	program := make([]splitInstr, 0, len(code))
	depth := 0
	maxDepth := 0
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		param, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		program = append(program, splitInstr{
			op: op,
			// Validation limits params to uint16.
			param: uint16(param), //nolint:gosec
		})
		switch op {
		case OP_DROP, OP_SLOT:
			if depth > 0 {
				depth--
			}
		case OP_NOT:
		case OP_AND, OP_OR:
			if depth > 0 {
				depth--
			}
		default:
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}
	return program, maxDepth
}

// compileSplitRoute converts validated stack bytecode into ordered route
// segments. A segment is produced only when a terminal OP_SLOT/OP_DROP consumes
// the whole boolean stack; otherwise the caller falls back to the generic stack
// evaluator. The compiler folds SplitRouter-only constants such as FQDN/LFQDN,
// flattens simple AND/OR chains, and stops after an unconditional terminal
// segment because later bytecode is unreachable.
func compileSplitRoute(code []byte) ([]splitCond, []splitRouteSegment, bool) {
	b := newSplitCondBuilder()
	stack := make([]int, 0, 8)
	segments := make([]splitRouteSegment, 0, 4)
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		param, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		switch op {
		case OP_DROP, OP_SLOT:
			if len(stack) < 1 {
				return nil, nil, false
			}
			cond := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) != 0 {
				return nil, nil, false
			}
			value, isConst := b.constValue(cond)
			if isConst && !value {
				continue
			}
			slot := 0
			if op == OP_SLOT {
				slot, _ = bytecodeParamInt(param, gonnect.RouterSlots)
			}
			fastKind, fastPreds := b.fastPredicates(cond)
			segments = append(segments, splitRouteSegment{
				cond:      cond,
				slot:      slot,
				drop:      op == OP_DROP,
				fastKind:  fastKind,
				fastPreds: fastPreds,
			})
			if isConst {
				return b.conds, segments, true
			}
		case OP_TRUE:
			stack = append(stack, b.trueCond)
		case OP_FALSE, OP_FQDN, OP_LFQDN:
			stack = append(stack, b.falseCond)
		case OP_NOT:
			if len(stack) < 1 {
				return nil, nil, false
			}
			stack[len(stack)-1] = b.not(stack[len(stack)-1])
		case OP_AND, OP_OR:
			if len(stack) < 2 {
				return nil, nil, false
			}
			right := stack[len(stack)-1]
			left := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			if op == OP_AND {
				stack = append(stack, b.and(left, right))
			} else {
				stack = append(stack, b.or(left, right))
			}
		default:
			stack = append(
				stack,
				b.atom(
					op,
					// Validation limits params to uint16.
					uint16(param), //nolint:gosec
				),
			)
		}
	}
	if len(stack) != 0 {
		return nil, nil, false
	}
	return b.conds, segments, true
}

// splitCondBuilder owns the condition arena and applies local rewrites while
// preserving bytecode evaluation order for non-constant operands.
type splitCondBuilder struct {
	conds     []splitCond
	falseCond int
	trueCond  int
}

func newSplitCondBuilder() *splitCondBuilder {
	b := &splitCondBuilder{}
	b.falseCond = b.add(splitCond{kind: splitCondConst})
	b.trueCond = b.add(splitCond{kind: splitCondConst, value: true})
	return b
}

func (b *splitCondBuilder) add(cond splitCond) int {
	idx := len(b.conds)
	b.conds = append(b.conds, cond)
	return idx
}

func (b *splitCondBuilder) atom(op byte, param uint16) int {
	return b.add(splitCond{
		kind:  splitCondAtom,
		op:    op,
		param: param,
	})
}

// not folds constants and removes double negation. Anything else remains an
// explicit NOT node so short-circuit order stays tied to the original tree.
func (b *splitCondBuilder) not(child int) int {
	if value, ok := b.constValue(child); ok {
		if value {
			return b.falseCond
		}
		return b.trueCond
	}
	if b.conds[child].kind == splitCondNot {
		return b.conds[child].child
	}
	return b.add(splitCond{
		kind:  splitCondNot,
		child: child,
	})
}

// and folds identity/annihilator constants and otherwise joins with flattening.
// It does not reorder operands: OP_RULE and regexp atoms can be expensive, and
// the left-to-right short-circuit semantics are observable through matcher
// errors and cache population.
func (b *splitCondBuilder) and(left, right int) int {
	if value, ok := b.constValue(left); ok {
		if !value {
			return b.falseCond
		}
		return right
	}
	if value, ok := b.constValue(right); ok && value {
		return left
	}
	return b.join(splitCondAnd, left, right)
}

// or is the OR counterpart of and: it folds constants while preserving operand
// order for short-circuit behavior.
func (b *splitCondBuilder) or(left, right int) int {
	if value, ok := b.constValue(left); ok {
		if value {
			return b.trueCond
		}
		return right
	}
	if value, ok := b.constValue(right); ok && !value {
		return left
	}
	return b.join(splitCondOr, left, right)
}

// join flattens adjacent nodes of the same kind into one ordered child list.
// That gives the fast predicate compiler a simple linear shape without changing
// evaluation order.
func (b *splitCondBuilder) join(kind splitCondKind, left, right int) int {
	children := make([]int, 0, 2)
	if b.conds[left].kind == kind {
		children = append(children, b.conds[left].children...)
	} else {
		children = append(children, left)
	}
	if b.conds[right].kind == kind {
		children = append(children, b.conds[right].children...)
	} else {
		children = append(children, right)
	}
	return b.add(splitCond{
		kind:     kind,
		children: children,
	})
}

func (b *splitCondBuilder) constValue(idx int) (bool, bool) {
	cond := b.conds[idx]
	if cond.kind != splitCondConst {
		return false, false
	}
	return cond.value, true
}

// fastPredicates recognizes condition nodes that can be evaluated by a straight
// all/any loop. Mixed or nested shapes are deliberately rejected so the fallback
// recursive evaluator remains the single source of truth for uncommon forms.
func (b *splitCondBuilder) fastPredicates(
	idx int,
) (splitFastCondKind, []splitPredicate) {
	cond := b.conds[idx]
	switch cond.kind {
	case splitCondConst:
		if cond.value {
			return splitFastCondAll, nil
		}
		return splitFastCondNone, nil
	case splitCondAtom:
		return splitFastCondAll, []splitPredicate{{
			op:    cond.op,
			param: cond.param,
		}}
	case splitCondNot:
		child := b.conds[cond.child]
		if child.kind != splitCondAtom {
			return splitFastCondNone, nil
		}
		return splitFastCondAll, []splitPredicate{{
			op:    child.op,
			param: child.param,
			not:   true,
		}}
	case splitCondAnd, splitCondOr:
		preds := make([]splitPredicate, 0, len(cond.children))
		for _, childIdx := range cond.children {
			child := b.conds[childIdx]
			switch child.kind {
			case splitCondAtom:
				preds = append(preds, splitPredicate{
					op:    child.op,
					param: child.param,
				})
			case splitCondNot:
				grandchild := b.conds[child.child]
				if grandchild.kind != splitCondAtom {
					return splitFastCondNone, nil
				}
				preds = append(preds, splitPredicate{
					op:    grandchild.op,
					param: grandchild.param,
					not:   true,
				})
			case splitCondConst:
				preds = append(preds, splitPredicate{
					op:  OP_TRUE,
					not: !child.value,
				})
			case splitCondAnd, splitCondOr:
				return splitFastCondNone, nil
			}
		}
		if cond.kind == splitCondAnd {
			return splitFastCondAll, preds
		}
		return splitFastCondAny, preds
	}
	return splitFastCondNone, nil
}

func (cfg *bytecodeSplitRouter) buildMatchers() error {
	cfg.matchers = make([]sysnet.Matcher, len(cfg.rules))
	for i, rule := range cfg.rules {
		matcher, err := cfg.system.BuildMatcher(rule)
		if err != nil {
			_ = cfg.Close()
			return fmt.Errorf("build matcher %d: %w", i, err)
		}
		cfg.matchers[i] = matcher
	}
	return nil
}

// routeBySegments evaluates compiled terminal segments in bytecode order. The
// common fast predicate paths avoid recursion, and the single OP_RULE case goes
// straight to ev.rule so it does not pay the generic predicate-loop overhead.
func (cfg *bytecodeSplitRouter) routeBySegments(ev *splitEval) int {
	for _, segment := range cfg.routeSegments {
		matched := false
		switch segment.fastKind {
		case splitFastCondAll, splitFastCondAny:
			if len(segment.fastPreds) == 1 &&
				!segment.fastPreds[0].not &&
				segment.fastPreds[0].op == OP_RULE {
				matched = ev.rule(segment.fastPreds[0].param)
			} else {
				matched = ev.predicates(segment.fastKind, segment.fastPreds)
			}
		case splitFastCondNone:
			matched = cfg.evalCond(ev, segment.cond)
		}
		if !matched {
			continue
		}
		if segment.drop {
			return 0
		}
		return segment.slot
	}
	return 0
}

// evalCond evaluates the condition arena recursively with left-to-right
// short-circuiting for flattened AND/OR nodes. That order matches the stack
// bytecode shape produced by the parser and controls whether later OP_RULE
// matchers are called.
func (cfg *bytecodeSplitRouter) evalCond(ev *splitEval, idx int) bool {
	cond := cfg.routeConds[idx]
	switch cond.kind {
	case splitCondConst:
		return cond.value
	case splitCondAtom:
		return ev.atom(cond.op, cond.param)
	case splitCondNot:
		return !cfg.evalCond(ev, cond.child)
	case splitCondAnd:
		for _, child := range cond.children {
			if !cfg.evalCond(ev, child) {
				return false
			}
		}
		return true
	case splitCondOr:
		for _, child := range cond.children {
			if cfg.evalCond(ev, child) {
				return true
			}
		}
	}
	return false
}

func (cfg *bytecodeSplitRouter) validateOp(
	pc int,
	op byte,
	param uint64,
	kind bytecodeParamKind,
) error {
	if isRouterMethodOp(op) {
		return fmt.Errorf(
			"SplitRoute bytecode offset %d: opcode %d is not valid for SplitRouter",
			pc,
			op,
		)
	}
	if isSnifferOnlyOp(op) {
		return fmt.Errorf(
			"SplitRoute bytecode offset %d: opcode %d is not valid for SplitRouter",
			pc,
			op,
		)
	}
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
	case OP_RULE:
		if int(param) >= len(cfg.rules) {
			return fail("rule", len(cfg.rules))
		}
	}
	return nil
}

// splitEval is the per-packet execution state shared by the generic stack
// evaluator, compiled segment evaluator, and OP_RULE matcher path. It caches
// only work that is valid within one packet unless explicitly stored in
// cfg.ruleCache or cfg.routeCache.
type splitEval struct {
	cfg        *bytecodeSplitRouter
	native     bool
	packet     parsedIPPacket
	packetData []byte
	// ruleSeenMask/ruleValueMask dedupe repeated OP_RULE evaluations for rule
	// indexes 0..63 without allocating. Larger indexes spill into ruleCache only
	// if they are actually observed.
	ruleSeenMask  uint64
	ruleValueMask uint64
	ruleCache     map[uint16]splitLocalRuleResult
	// flowDone ensures FlowTupleFromOutgoingIPPacket is attempted at most once
	// per packet. flowOK is separate from packet.flowOK because flow
	// construction can still fail after header parsing accepted the packet.
	flowDone bool
	flow     sockowner.FlowTuple
	flowOK   bool
	// String bytecode ops can ask for the same address repeatedly. These fields
	// keep netip.Addr.String out of the hot path after the first conversion.
	srcStringVal    string
	dstStringVal    string
	srcStringSet    bool
	dstStringSet    bool
	srcReverseDone  bool
	dstReverseDone  bool
	srcReverseNames []string
	dstReverseNames []string
	// cacheNow makes all OP_RULE cache lookups within one packet use one time
	// sample. cacheable is cleared when a matcher or flow-construction error
	// should prevent writing the final route result.
	cacheNow  int64
	cacheable bool
}

// rule evaluates one OP_RULE with the exact SplitRouter semantics: non-native
// packets never call matchers, missing matchers are false, and repeated checks
// within the same packet reuse the first result.
func (ev *splitEval) rule(rule uint16) bool {
	if !ev.native {
		return false
	}
	idx := int(rule)
	if idx >= len(ev.cfg.matchers) {
		return false
	}
	if idx < 64 {
		bit := uint64(1) << idx
		if ev.ruleSeenMask&bit != 0 {
			return ev.ruleValueMask&bit != 0
		}
		got := ev.matchRule(idx, rule)
		ev.ruleSeenMask |= bit
		if got {
			ev.ruleValueMask |= bit
		}
		return got
	}
	if ev.ruleCache != nil {
		if cached, ok := ev.ruleCache[rule]; ok {
			return cached.value
		}
	}
	got := ev.matchRule(idx, rule)
	if ev.ruleCache == nil {
		ev.ruleCache = make(map[uint16]splitLocalRuleResult, 1)
	}
	ev.ruleCache[rule] = splitLocalRuleResult{value: got}
	return got
}

type splitLocalRuleResult struct {
	value bool
}

// predicates evaluates a flattened AND/OR condition. It intentionally mirrors
// atom instead of calling it for every predicate so the fast path stays as small
// as possible in the common parser output shape.
func (ev *splitEval) predicates(
	kind splitFastCondKind,
	preds []splitPredicate,
) bool {
	cfg := ev.cfg
	pkt := ev.packet
	if kind == splitFastCondAll {
		for _, pred := range preds {
			got := false
			switch pred.op {
			case OP_TRUE:
				got = true
			case OP_FALSE, OP_FQDN, OP_LFQDN:
			case OP_NET4:
				got = pkt.src.Is4()
			case OP_NET6:
				got = pkt.src.Is6()
			case OP_UDP:
				got = pkt.proto == 17
			case OP_TCP:
				got = pkt.proto == 6
			case OP_ADDR_S:
				got = ev.matchDstString(cfg.strings[pred.param])
			case OP_LADDR_S:
				got = ev.matchSrcString(cfg.strings[pred.param])
			case OP_ADDR_RE:
				got = ev.matchDstRegexp(cfg.regexps[pred.param])
			case OP_LADDR_RE:
				got = ev.matchSrcRegexp(cfg.regexps[pred.param])
			case OP_ADDR4:
				got = pkt.dst4 == cfg.ipv4Addrs[pred.param] && pkt.dst.Is4()
			case OP_LADDR4:
				got = pkt.src4 == cfg.ipv4Addrs[pred.param] && pkt.src.Is4()
			case OP_ADDR6:
				got = pkt.dst == cfg.ipv6Addrs[pred.param]
			case OP_LADDR6:
				got = pkt.src == cfg.ipv6Addrs[pred.param]
			case OP_SNET4:
				got = pkt.dst.Is4() &&
					cfg.splitSubnets[pred.param].contains(pkt.dst4)
			case OP_LSNET4:
				got = pkt.src.Is4() &&
					cfg.splitSubnets[pred.param].contains(pkt.src4)
			case OP_SNET6:
				got = cfg.ipv6Subnets[pred.param].Contains(pkt.dst)
			case OP_LSNET6:
				got = cfg.ipv6Subnets[pred.param].Contains(pkt.src)
			case OP_PORT:
				got = pkt.hasPorts && pred.param == pkt.dstPort
			case OP_LPORT:
				got = pkt.hasPorts && pred.param == pkt.srcPort
			case OP_RULE:
				got = ev.rule(pred.param)
			}
			if pred.not {
				got = !got
			}
			if !got {
				return false
			}
		}
		return true
	}
	for _, pred := range preds {
		got := false
		switch pred.op {
		case OP_TRUE:
			got = true
		case OP_FALSE, OP_FQDN, OP_LFQDN:
		case OP_NET4:
			got = pkt.src.Is4()
		case OP_NET6:
			got = pkt.src.Is6()
		case OP_UDP:
			got = pkt.proto == 17
		case OP_TCP:
			got = pkt.proto == 6
		case OP_ADDR_S:
			got = ev.matchDstString(cfg.strings[pred.param])
		case OP_LADDR_S:
			got = ev.matchSrcString(cfg.strings[pred.param])
		case OP_ADDR_RE:
			got = ev.matchDstRegexp(cfg.regexps[pred.param])
		case OP_LADDR_RE:
			got = ev.matchSrcRegexp(cfg.regexps[pred.param])
		case OP_ADDR4:
			got = pkt.dst4 == cfg.ipv4Addrs[pred.param] && pkt.dst.Is4()
		case OP_LADDR4:
			got = pkt.src4 == cfg.ipv4Addrs[pred.param] && pkt.src.Is4()
		case OP_ADDR6:
			got = pkt.dst == cfg.ipv6Addrs[pred.param]
		case OP_LADDR6:
			got = pkt.src == cfg.ipv6Addrs[pred.param]
		case OP_SNET4:
			got = pkt.dst.Is4() &&
				cfg.splitSubnets[pred.param].contains(pkt.dst4)
		case OP_LSNET4:
			got = pkt.src.Is4() &&
				cfg.splitSubnets[pred.param].contains(pkt.src4)
		case OP_SNET6:
			got = cfg.ipv6Subnets[pred.param].Contains(pkt.dst)
		case OP_LSNET6:
			got = cfg.ipv6Subnets[pred.param].Contains(pkt.src)
		case OP_PORT:
			got = pkt.hasPorts && pred.param == pkt.dstPort
		case OP_LPORT:
			got = pkt.hasPorts && pred.param == pkt.srcPort
		case OP_RULE:
			got = ev.rule(pred.param)
		}
		if pred.not {
			got = !got
		}
		if got {
			return true
		}
	}
	return false
}

// atom evaluates a single bytecode predicate against the parsed packet. It is
// used by the recursive condition evaluator for uncommon condition shapes.
func (ev *splitEval) atom(op byte, param uint16) bool {
	cfg := ev.cfg
	pkt := ev.packet
	switch op {
	case OP_TRUE:
		return true
	case OP_FALSE, OP_FQDN, OP_LFQDN:
		return false
	case OP_NET4:
		return pkt.src.Is4()
	case OP_NET6:
		return pkt.src.Is6()
	case OP_UDP:
		return pkt.proto == 17
	case OP_TCP:
		return pkt.proto == 6
	case OP_ADDR_S:
		return ev.matchDstString(cfg.strings[param])
	case OP_LADDR_S:
		return ev.matchSrcString(cfg.strings[param])
	case OP_ADDR_RE:
		return ev.matchDstRegexp(cfg.regexps[param])
	case OP_LADDR_RE:
		return ev.matchSrcRegexp(cfg.regexps[param])
	case OP_ADDR4:
		return pkt.dst4 == cfg.ipv4Addrs[param] && pkt.dst.Is4()
	case OP_LADDR4:
		return pkt.src4 == cfg.ipv4Addrs[param] && pkt.src.Is4()
	case OP_ADDR6:
		return pkt.dst == cfg.ipv6Addrs[param]
	case OP_LADDR6:
		return pkt.src == cfg.ipv6Addrs[param]
	case OP_SNET4:
		return pkt.dst.Is4() && cfg.splitSubnets[param].contains(pkt.dst4)
	case OP_LSNET4:
		return pkt.src.Is4() && cfg.splitSubnets[param].contains(pkt.src4)
	case OP_SNET6:
		return cfg.ipv6Subnets[param].Contains(pkt.dst)
	case OP_LSNET6:
		return cfg.ipv6Subnets[param].Contains(pkt.src)
	case OP_PORT:
		return pkt.hasPorts && param == pkt.dstPort
	case OP_LPORT:
		return pkt.hasPorts && param == pkt.srcPort
	case OP_RULE:
		return ev.rule(param)
	}
	return false
}

// matchRule handles the expensive OP_RULE path after per-packet deduping. The
// cross-packet cache stores successful matcher calls, including false results;
// matcher errors are treated as false for this packet but are not cached.
func (ev *splitEval) matchRule(idx int, rule uint16) bool {
	if !ev.packet.hasPorts || ev.cfg.matchers[idx] == nil {
		return false
	}
	if !ev.packet.flowOK {
		return false
	}
	if ev.cfg.ruleCache != nil {
		key := ev.ruleCacheKey(rule)
		now := ev.now()
		if got, ok := ev.cfg.ruleCache.get(key, now); ok {
			return got
		}
		flow, ok := ev.packetFlow()
		if !ok {
			return false
		}
		got, err := ev.cfg.matchers[idx].Match(flow)
		if err != nil {
			ev.cacheable = false
			return false
		}
		ev.cfg.ruleCache.set(key, got, time.Now().UnixNano())
		return got
	}
	flow, ok := ev.packetFlow()
	if !ok {
		return false
	}
	got, err := ev.cfg.matchers[idx].Match(flow)
	if err != nil {
		ev.cacheable = false
		return false
	}
	return got
}

// packetFlow builds the sockowner flow tuple lazily because many bytecode
// routes never reach OP_RULE after cheap guards. A construction error makes the
// packet's whole-route result non-cacheable for the same reason matcher errors
// are not cached.
func (ev *splitEval) packetFlow() (sockowner.FlowTuple, bool) {
	if !ev.flowDone {
		ev.flowDone = true
		if !ev.packet.flowOK {
			return ev.flow, false
		}
		flow, err := sockowner.FlowTupleFromOutgoingIPPacket(ev.packetData)
		if err == nil {
			ev.flow = flow
			ev.flowOK = true
		} else {
			ev.cacheable = false
		}
	}
	return ev.flow, ev.flowOK
}

func (ev *splitEval) srcString() string {
	if !ev.srcStringSet {
		ev.srcStringVal = ev.packet.src.String()
		ev.srcStringSet = true
	}
	return ev.srcStringVal
}

func (ev *splitEval) dstString() string {
	if !ev.dstStringSet {
		ev.dstStringVal = ev.packet.dst.String()
		ev.dstStringSet = true
	}
	return ev.dstStringVal
}

func (ev *splitEval) matchSrcString(want string) bool {
	if ev.srcString() == want {
		return true
	}
	for _, name := range ev.srcReverseDNSNames() {
		if name == want {
			return true
		}
	}
	return false
}

func (ev *splitEval) matchDstString(want string) bool {
	if ev.dstString() == want {
		return true
	}
	for _, name := range ev.dstReverseDNSNames() {
		if name == want {
			return true
		}
	}
	return false
}

func (ev *splitEval) matchSrcRegexp(re *regexp.Regexp) bool {
	if re.MatchString(ev.srcString()) {
		return true
	}
	for _, name := range ev.srcReverseDNSNames() {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (ev *splitEval) matchDstRegexp(re *regexp.Regexp) bool {
	if re.MatchString(ev.dstString()) {
		return true
	}
	for _, name := range ev.dstReverseDNSNames() {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (ev *splitEval) srcReverseDNSNames() []string {
	if ev.srcReverseDone {
		return ev.srcReverseNames
	}
	if ev.cfg.dnsStorage == nil || !ev.cfg.routeStringOps.local {
		return nil
	}
	ev.srcReverseDone = true
	ev.cacheable = false
	ev.srcReverseNames = reverseDNSNames(
		ev.cfg.dnsStorage,
		ev.packet.src,
		time.Unix(0, ev.now()),
	)
	return ev.srcReverseNames
}

func (ev *splitEval) dstReverseDNSNames() []string {
	if ev.dstReverseDone {
		return ev.dstReverseNames
	}
	if ev.cfg.dnsStorage == nil || !ev.cfg.routeStringOps.remote {
		return nil
	}
	ev.dstReverseDone = true
	ev.cacheable = false
	ev.dstReverseNames = reverseDNSNames(
		ev.cfg.dnsStorage,
		ev.packet.dst,
		time.Unix(0, ev.now()),
	)
	return ev.dstReverseNames
}

// now returns a stable timestamp for all OP_RULE cache reads in one packet. Set
// operations use a fresh timestamp after matcher execution so slow matchers do
// not consume part of the configured TTL before the value is stored.
func (ev *splitEval) now() int64 {
	if ev.cacheNow == 0 {
		ev.cacheNow = time.Now().UnixNano()
	}
	return ev.cacheNow
}

// ruleCacheKey is the flow identity visible to OP_RULE matchers. It must stay
// aligned with the matcher inputs; adding matcher-observable packet fields would
// require extending this key.
func (ev *splitEval) ruleCacheKey(rule uint16) splitRuleCacheKey {
	return splitRuleCacheKey{
		rule:    rule,
		proto:   ev.packet.proto,
		src:     ev.packet.src,
		dst:     ev.packet.dst,
		srcPort: ev.packet.srcPort,
		dstPort: ev.packet.dstPort,
	}
}

type splitRuleCacheKey struct {
	rule    uint16
	proto   uint8
	src     netip.Addr
	dst     netip.Addr
	srcPort uint16
	dstPort uint16
}

// splitRouteCache flags record packet/router state that affects the final route
// but is not represented by the endpoint tuple alone.
const (
	splitRouteCacheFlagNative uint8 = 1 << iota
	splitRouteCacheFlagHasPorts
	splitRouteCacheFlagFlowOK
)

// splitRouteCacheKeyFromPacket builds the whole-route cache key from every
// field current SplitRoute bytecode can observe. OP_RULE results are also keyed
// by this flow identity, so a cached route result is valid only while future
// opcodes remain limited to these packet fields.
func splitRouteCacheKeyFromPacket(
	pkt parsedIPPacket,
	native bool,
) splitRouteCacheKey {
	var flags uint8
	if native {
		flags |= splitRouteCacheFlagNative
	}
	if pkt.hasPorts {
		flags |= splitRouteCacheFlagHasPorts
	}
	if pkt.flowOK {
		flags |= splitRouteCacheFlagFlowOK
	}
	return splitRouteCacheKey{
		proto:   pkt.proto,
		flags:   flags,
		src:     pkt.src,
		dst:     pkt.dst,
		srcPort: pkt.srcPort,
		dstPort: pkt.dstPort,
	}
}

// splitRouteCacheKey is intentionally wider than splitRuleCacheKey: native
// state, readable-port state, and flow-construction eligibility all influence
// whether OP_RULE may run and therefore can change the selected slot.
type splitRouteCacheKey struct {
	proto   uint8
	flags   uint8
	src     netip.Addr
	dst     netip.Addr
	srcPort uint16
	dstPort uint16
}

type splitRuleCacheEntry struct {
	value   bool
	expires int64
}

type splitRouteCacheEntry struct {
	slot    int
	expires int64
}

// splitRuleResultCache is the cross-packet OP_RULE result cache. The map holds
// general flow reuse under mu; last is a lock-free single-entry fast path for
// repeated packets from the same flow and is bounded by the same expiry time.
type splitRuleResultCache struct {
	mu         sync.Mutex
	ttl        int64
	maxEntries int
	entries    map[splitRuleCacheKey]splitRuleCacheEntry
	last       atomic.Pointer[splitRuleCacheLastEntry]
}

// splitRouteResultCache is the whole-bytecode route cache. It uses the same
// map-plus-last-entry shape as the OP_RULE cache because packet batches often
// route several consecutive packets from one flow.
type splitRouteResultCache struct {
	mu         sync.Mutex
	ttl        int64
	maxEntries int
	entries    map[splitRouteCacheKey]splitRouteCacheEntry
	last       atomic.Pointer[splitRouteCacheLastEntry]
}

type splitRuleCacheLastEntry struct {
	key   splitRuleCacheKey
	entry splitRuleCacheEntry
}

type splitRouteCacheLastEntry struct {
	key   splitRouteCacheKey
	entry splitRouteCacheEntry
}

// newSplitRuleResultCache normalizes public cache configuration. Negative
// values disable caching, zero values select defaults, and non-positive
// normalized values produce nil so callers can skip cache branches cheaply.
func newSplitRuleResultCache(
	ttl time.Duration,
	maxEntries int,
) *splitRuleResultCache {
	if ttl < 0 || maxEntries < 0 {
		return nil
	}
	if ttl == 0 {
		ttl = defaultSplitRuleCacheTTL
	}
	if maxEntries == 0 {
		maxEntries = defaultSplitRuleCacheMaxEntries
	}
	if ttl <= 0 || maxEntries <= 0 {
		return nil
	}
	return &splitRuleResultCache{
		ttl:        int64(ttl),
		maxEntries: maxEntries,
		entries:    make(map[splitRuleCacheKey]splitRuleCacheEntry),
	}
}

// newSplitRouteResultCache applies route-cache inheritance. Leaving both route
// cache fields at zero intentionally follows OP_RULE cache settings so existing
// callers can disable all cross-packet caching with the rule-cache knobs.
func newSplitRouteResultCache(
	routeTTL time.Duration,
	routeMaxEntries int,
	ruleTTL time.Duration,
	ruleMaxEntries int,
) *splitRouteResultCache {
	if routeTTL == 0 && routeMaxEntries == 0 {
		routeTTL = ruleTTL
		routeMaxEntries = ruleMaxEntries
	}
	if routeTTL < 0 || routeMaxEntries < 0 {
		return nil
	}
	if routeTTL == 0 {
		routeTTL = defaultSplitRuleCacheTTL
	}
	if routeMaxEntries == 0 {
		routeMaxEntries = defaultSplitRuleCacheMaxEntries
	}
	if routeTTL <= 0 || routeMaxEntries <= 0 {
		return nil
	}
	return &splitRouteResultCache{
		ttl:        int64(routeTTL),
		maxEntries: routeMaxEntries,
		entries:    make(map[splitRouteCacheKey]splitRouteCacheEntry),
	}
}

// get returns a live OP_RULE cache entry. Expired entries are removed from the
// map, and an expired matching last entry is cleared so future lookups cannot
// keep observing it without taking the lock.
func (c *splitRuleResultCache) get(
	key splitRuleCacheKey,
	now int64,
) (bool, bool) {
	if last := c.last.Load(); last != nil && last.key == key {
		if now < last.entry.expires {
			return last.entry.value, true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return false, false
	}
	if now >= entry.expires {
		delete(c.entries, key)
		if last := c.last.Load(); last != nil && last.key == key {
			c.last.Store(nil)
		}
		return false, false
	}
	return entry.value, true
}

// get returns a live whole-route cache entry using the same expiry semantics as
// the OP_RULE cache.
func (c *splitRouteResultCache) get(
	key splitRouteCacheKey,
	now int64,
) (int, bool) {
	if last := c.last.Load(); last != nil && last.key == key {
		if now < last.entry.expires {
			return last.entry.slot, true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return 0, false
	}
	if now >= entry.expires {
		delete(c.entries, key)
		if last := c.last.Load(); last != nil && last.key == key {
			c.last.Store(nil)
		}
		return 0, false
	}
	return entry.slot, true
}

// set stores an OP_RULE result with expiry measured after matcher execution.
// The map is updated under the mutex before publishing last, so readers cannot
// observe a partially initialized fast-path entry. Later pruning may remove the
// map copy independently; the last entry is still constrained by its expiry.
func (c *splitRuleResultCache) set(
	key splitRuleCacheKey,
	value bool,
	now int64,
) {
	entry := splitRuleCacheEntry{
		value:   value,
		expires: now + c.ttl,
	}
	c.mu.Lock()
	c.entries[key] = entry
	if len(c.entries) > c.maxEntries {
		c.pruneLocked(now)
	}
	c.mu.Unlock()
	c.last.Store(&splitRuleCacheLastEntry{key: key, entry: entry})
}

// set stores a whole-route result. Route results are written only by callers
// that know the packet did not hit matcher/flow errors.
func (c *splitRouteResultCache) set(
	key splitRouteCacheKey,
	slot int,
	now int64,
) {
	entry := splitRouteCacheEntry{
		slot:    slot,
		expires: now + c.ttl,
	}
	c.mu.Lock()
	c.entries[key] = entry
	if len(c.entries) > c.maxEntries {
		c.pruneLocked(now)
	}
	c.mu.Unlock()
	c.last.Store(&splitRouteCacheLastEntry{key: key, entry: entry})
}

// clear releases cached results when the router closes. It is safe to call on a
// live cache, but callers must still coordinate normal router lifetime.
func (c *splitRuleResultCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.last.Store(nil)
}

// clear releases cached route results when the router closes.
func (c *splitRouteResultCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.last.Store(nil)
}

// pruneLocked first removes expired OP_RULE entries, then sheds arbitrary map
// entries toward half capacity. It trades perfect LRU behavior for tiny write
// overhead on the hot route path.
func (c *splitRuleResultCache) pruneLocked(now int64) {
	for key, entry := range c.entries {
		if now >= entry.expires {
			delete(c.entries, key)
		}
	}
	if len(c.entries) <= c.maxEntries {
		return
	}
	target := c.maxEntries / 2
	if target < 1 {
		target = c.maxEntries
	}
	for key := range c.entries {
		delete(c.entries, key)
		if len(c.entries) <= target {
			return
		}
	}
}

// pruneLocked applies the same expired-first, half-capacity fallback strategy
// to whole-route results.
func (c *splitRouteResultCache) pruneLocked(now int64) {
	for key, entry := range c.entries {
		if now >= entry.expires {
			delete(c.entries, key)
		}
	}
	if len(c.entries) <= c.maxEntries {
		return
	}
	target := c.maxEntries / 2
	if target < 1 {
		target = c.maxEntries
	}
	for key := range c.entries {
		delete(c.entries, key)
		if len(c.entries) <= target {
			return
		}
	}
}

// parsedIPPacket is the normalized header state SplitRoute bytecode can observe.
// src4/dst4 duplicate IPv4 addresses as uint32 for cheap IPv4 table lookups;
// flowOK means the packet is well formed enough to build a sockowner FlowTuple.
type parsedIPPacket struct {
	src, dst       netip.Addr
	src4, dst4     uint32
	proto          uint8
	total          int
	srcPort        uint16
	dstPort        uint16
	hasPorts       bool
	flowOK         bool
	transportStart int
}

// parseIPPacket validates the outer IP packet at offset and returns only the
// packet bytes covered by the IP total/payload length. Later cache and matcher
// paths use that total to avoid reading trailing bytes from a larger buffer.
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

// parseIPv4Packet accepts complete IPv4 packets and parses TCP/UDP ports only
// when the fragment offset is zero. Later fragments cannot identify a flow
// safely enough for OP_RULE.
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

// parseIPv6Packet accepts IPv6 packets after walking extension headers that can
// precede TCP/UDP. Fragmented non-first packets remain routeable by address and
// protocol, but are marked ineligible for flow-based OP_RULE matching.
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
	proto, start, flowCandidate, ok := skipIPv6ExtHeaders(
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
	if !flowCandidate {
		out.flowOK = false
	}
	return out, true
}

// skipIPv6ExtHeaders advances to the transport header through extension headers
// this router understands. The third return value reports whether the packet is
// a candidate for sockowner flow construction; the fourth reports parse success.
func skipIPv6ExtHeaders(
	pkt []byte,
	proto uint8,
	start int,
) (uint8, int, bool, bool) {
	for {
		switch proto {
		case 0, 43, 60:
			if start+2 > len(pkt) {
				return 0, 0, false, false
			}
			next := pkt[start]
			hdrLen := (int(pkt[start+1]) + 1) * 8
			if start+hdrLen > len(pkt) {
				return 0, 0, false, false
			}
			proto = next
			start += hdrLen
		case 44:
			if start+8 > len(pkt) {
				return 0, 0, false, false
			}
			next := pkt[start]
			frag := binary.BigEndian.Uint16(pkt[start+2 : start+4])
			start += 8
			proto = next
			if frag&0xfff8 != 0 {
				return proto, start, false, true
			}
		case 51:
			if start+2 > len(pkt) {
				return 0, 0, false, false
			}
			next := pkt[start]
			hdrLen := (int(pkt[start+1]) + 2) * 4
			if start+hdrLen > len(pkt) {
				return 0, 0, false, false
			}
			proto = next
			start += hdrLen
		default:
			return proto, start, true, true
		}
	}
}

// parsePorts records TCP/UDP ports and marks flowOK only after the transport
// header is complete enough for sockowner.FlowTupleFromOutgoingIPPacket.
func (p *parsedIPPacket) parsePorts(pkt []byte) {
	if p.proto != 6 && p.proto != 17 {
		return
	}
	if p.transportStart+4 > len(pkt) {
		return
	}
	p.srcPort = binary.BigEndian.Uint16(pkt[p.transportStart:])
	p.dstPort = binary.BigEndian.Uint16(pkt[p.transportStart+2:])
	p.hasPorts = true
	switch p.proto {
	case 6:
		if p.transportStart+20 > len(pkt) {
			return
		}
		headerLen := int(pkt[p.transportStart+12]>>4) * 4
		if headerLen < 20 || p.transportStart+headerLen > len(pkt) {
			return
		}
		p.flowOK = true
	case 17:
		if p.transportStart+8 <= len(pkt) {
			p.flowOK = true
		}
	}
}
