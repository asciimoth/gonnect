package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/gonnect"
	gdns "github.com/asciimoth/gonnect/dns"
)

const (
	// OP_DROP pops a boolean value and routes to slot 0 when it is true.
	OP_DROP byte = iota
	// OP_SLOT pops a boolean value and routes to the following uint8 slot when it is true.
	OP_SLOT
	// OP_TRUE pushes true onto the boolean stack.
	OP_TRUE
	// OP_FALSE pushes false onto the boolean stack.
	OP_FALSE
	// OP_NOT inverts the boolean value on top of the stack.
	OP_NOT
	// OP_AND replaces the two top stack values with their logical conjunction.
	OP_AND
	// OP_OR replaces the two top stack values with their logical disjunction.
	OP_OR
	// OP_NET4 pushes whether the operation is for IPv4 or has an IPv4 address.
	OP_NET4
	// OP_NET6 pushes whether the operation is for IPv6 or has an IPv6 address.
	OP_NET6
	// OP_UDP pushes whether the operation uses a UDP network.
	OP_UDP
	// OP_TCP pushes whether the operation uses a TCP network.
	OP_TCP
	// OP_FQDN pushes whether the remote address is a hostname rather than an IP.
	OP_FQDN
	// OP_LFQDN pushes whether the local address is a hostname rather than an IP.
	OP_LFQDN
	// OP_ADDR_S pushes whether the remote address host equals a string table value.
	OP_ADDR_S
	// OP_LADDR_S pushes whether the local address host equals a string table value.
	OP_LADDR_S
	// OP_ADDR_RE pushes whether the remote address host matches a regexp table value.
	OP_ADDR_RE
	// OP_LADDR_RE pushes whether the local address host matches a regexp table value.
	OP_LADDR_RE
	// OP_ADDR4 pushes whether the remote address equals an IPv4 table value.
	OP_ADDR4
	// OP_LADDR4 pushes whether the local address equals an IPv4 table value.
	OP_LADDR4
	// OP_ADDR6 pushes whether the remote address equals an IPv6 table value.
	OP_ADDR6
	// OP_LADDR6 pushes whether the local address equals an IPv6 table value.
	OP_LADDR6
	// OP_SNET4 pushes whether the remote IPv4 address is in an IPv4 subnet table value.
	OP_SNET4
	// OP_LSNET4 pushes whether the local IPv4 address is in an IPv4 subnet table value.
	OP_LSNET4
	// OP_SNET6 pushes whether the remote IPv6 address is in an IPv6 subnet table value.
	OP_SNET6
	// OP_LSNET6 pushes whether the local IPv6 address is in an IPv6 subnet table value.
	OP_LSNET6
	// OP_PORT pushes whether the remote address port equals the following uint16 port.
	OP_PORT
	// OP_LPORT pushes whether the local address port equals the following uint16 port.
	OP_LPORT
	// OP_RULE pushes whether the packet flow matches a sysnet rule.
	OP_RULE
	// OP_DIAL pushes whether the RouterCfg method is DialTCP, DialUDP, or RouteUDP.
	OP_DIAL
	// OP_LISTEN pushes whether the RouterCfg method is ListenTCP.
	OP_LISTEN
	// OP_LOOKUP pushes whether the RouterCfg method is Lookup.
	OP_LOOKUP
	// OP_INTERCEPT pops a boolean value and asks sniffer.Sniffer to sniff the
	// TCP stream when it is true. It is valid only in Sniffer control bytecode.
	OP_INTERCEPT
	// OP_SNIFF pushes whether the sniff result matched the named classifier
	// referenced by the following uint16 classifier table index.
	OP_SNIFF
	// OP_SNIFF_NONE pushes whether sniffing found no matching classifier.
	OP_SNIFF_NONE
	// OP_ROUTE pops a boolean value, mutates a sniffer call, and routes to
	// a route-action slot when it is true.
	OP_ROUTE
	// OP_BACKEND pops a boolean value and routes a DNS request to the following
	// backend-name table index when it is true.
	OP_BACKEND
	// OP_QTYPE pushes whether the first DNS question type equals the following
	// uint16 value.
	OP_QTYPE
	// OP_QCLASS pushes whether the first DNS question class equals the following
	// uint16 value.
	OP_QCLASS
	// OP_OPCODE pushes whether the DNS message opcode equals the following
	// uint16 value.
	OP_OPCODE
)

// IPv4Subnet is an IPv4 CIDR subnet used by bytecode routing rules.
//
// Addr is the canonical big-endian 32-bit IPv4 address. Bits is the CIDR
// prefix length and must be in the range 0..32.
type IPv4Subnet struct {
	Addr uint32
	Bits uint8
}

type bytecodeParamKind uint8

const (
	bytecodeParamNone bytecodeParamKind = iota
	bytecodeParamUint8
	bytecodeParamUint16
)

func validateTables(
	ipv4Subnets []IPv4Subnet,
	ipv6Addrs []netip.Addr,
	ipv6Subnets []netip.Prefix,
) error {
	for i, subnet := range ipv4Subnets {
		if subnet.Bits > 32 {
			return fmt.Errorf(
				"IPv4 subnet %d has prefix length %d",
				i,
				subnet.Bits,
			)
		}
	}
	for i, addr := range ipv6Addrs {
		if !addr.Is6() {
			return fmt.Errorf("IPv6 address %d is %q", i, addr)
		}
	}
	for i, subnet := range ipv6Subnets {
		if !subnet.IsValid() || !subnet.Addr().Is6() {
			return fmt.Errorf("IPv6 subnet %d is %q", i, subnet)
		}
	}
	return nil
}

func validateBytecode(
	name string,
	code []byte,
	validateOp func(pc int, op byte, param uint64, kind bytecodeParamKind) error,
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
		if err := validateOp(opPC, op, param, kind); err != nil {
			return err
		}
		switch op {
		case OP_DROP, OP_SLOT, OP_INTERCEPT, OP_ROUTE, OP_BACKEND:
			if depth < 1 {
				return fmt.Errorf(
					"%s bytecode offset %d: stack underflow",
					name,
					opPC,
				)
			}
			depth--
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
	return nil
}

func readBytecodeParam(
	name string,
	code []byte,
	pc *int,
	op byte,
) (uint64, bytecodeParamKind, error) {
	switch op {
	case OP_DROP, OP_TRUE, OP_FALSE, OP_NOT, OP_AND, OP_OR,
		OP_NET4, OP_NET6, OP_UDP, OP_TCP, OP_FQDN, OP_LFQDN,
		OP_DIAL, OP_LISTEN, OP_LOOKUP, OP_INTERCEPT, OP_SNIFF_NONE:
		return 0, bytecodeParamNone, nil
	case OP_SLOT:
		if *pc >= len(code) {
			return 0, bytecodeParamUint8, fmt.Errorf(
				"%s bytecode offset %d: missing uint8 parameter",
				name,
				*pc-1,
			)
		}
		param := code[*pc]
		*pc++
		return uint64(param), bytecodeParamUint8, nil
	case OP_ADDR_S, OP_LADDR_S, OP_ADDR_RE, OP_LADDR_RE,
		OP_ADDR4, OP_LADDR4, OP_ADDR6, OP_LADDR6,
		OP_SNET4, OP_LSNET4, OP_SNET6, OP_LSNET6,
		OP_PORT, OP_LPORT, OP_RULE, OP_SNIFF, OP_ROUTE, OP_BACKEND,
		OP_QTYPE, OP_QCLASS, OP_OPCODE:
		if *pc+1 >= len(code) {
			return 0, bytecodeParamUint16, fmt.Errorf(
				"%s bytecode offset %d: missing uint16 parameter",
				name,
				*pc-1,
			)
		}
		param := binary.LittleEndian.Uint16(code[*pc:])
		*pc += 2
		return uint64(param), bytecodeParamUint16, nil
	default:
		return 0, bytecodeParamNone, fmt.Errorf(
			"%s bytecode offset %d: unknown opcode %d",
			name,
			*pc-1,
			op,
		)
	}
}

func readBytecodeParamUnchecked(code []byte, pc int, op byte) (uint64, int) {
	switch op {
	case OP_SLOT:
		return uint64(code[pc]), pc + 1
	case OP_ADDR_S, OP_LADDR_S, OP_ADDR_RE, OP_LADDR_RE,
		OP_ADDR4, OP_LADDR4, OP_ADDR6, OP_LADDR6,
		OP_SNET4, OP_LSNET4, OP_SNET6, OP_LSNET6,
		OP_PORT, OP_LPORT, OP_RULE, OP_SNIFF, OP_ROUTE, OP_BACKEND,
		OP_QTYPE, OP_QCLASS, OP_OPCODE:
		return uint64(binary.LittleEndian.Uint16(code[pc:])), pc + 2
	default:
		return 0, pc
	}
}

// SlotReporter is implemented by bytecode-backed routers that can report the
// non-drop slots mentioned by their rules.
type SlotReporter interface {
	MentionedSlots() []int
}

func mentionedBytecodeSlots(maxSlot int, programs ...[]byte) []int {
	return mentionedBytecodeSlotsWithRoutes(maxSlot, nil, programs...)
}

func mentionedBytecodeSlotsWithRoutes(
	maxSlot int,
	routeActions []SnifferRouteAction,
	programs ...[]byte,
) []int {
	seen := make([]bool, maxSlot+1)
	mark := func(param uint64) {
		if param == 0 {
			return
		}
		slot, ok := bytecodeParamInt(param, maxSlot)
		if ok {
			seen[slot] = true
		}
	}
	for _, code := range programs {
		for pc := 0; pc < len(code); {
			op := code[pc]
			pc++
			param, next := readBytecodeParamUnchecked(code, pc, op)
			pc = next
			switch op {
			case OP_SLOT:
				mark(param)
			case OP_ROUTE:
				idx, ok := bytecodeParamIndex(param, len(routeActions))
				if ok {
					mark(uint64(routeActions[idx].Slot))
				}
			}
		}
	}
	slots := make([]int, 0, maxSlot)
	for slot := 1; slot <= maxSlot; slot++ {
		if seen[slot] {
			slots = append(slots, slot)
		}
	}
	return slots
}

func popBool(stack *[]bool) bool {
	old := *stack
	v := old[len(old)-1]
	*stack = old[:len(old)-1]
	return v
}

type bytecodeEval struct {
	network  string
	laddr    *addrCache
	raddr    *addrCache
	isDial   bool
	isListen bool
	isLookup bool
}

func (ev *bytecodeEval) isNet4() bool {
	if isNet4(ev.network) {
		return true
	}
	if isNet6(ev.network) {
		return false
	}
	return ev.laddr.isIPv4() || ev.raddr.isIPv4()
}

func (ev *bytecodeEval) isNet6() bool {
	if isNet6(ev.network) {
		return true
	}
	if isNet4(ev.network) {
		return false
	}
	return ev.laddr.isIPv6() || ev.raddr.isIPv6()
}

func (ev *bytecodeEval) portNetwork() string {
	switch {
	case isTCPNet(ev.network):
		return "tcp"
	case isUDPNet(ev.network):
		return "udp"
	default:
		return ev.network
	}
}

type addrInput struct {
	str  string
	addr net.Addr
}

type addrCache struct {
	input addrInput

	hostDone bool
	hostVal  string

	ipDone bool
	ipVal  netip.Addr

	portDone bool
	portVal  int

	reverseStorage gdns.CacheStorage
	reverseEnabled bool
	reverseDone    bool
	reverseNames   []string
}

func newAddrCache(
	input addrInput,
	storage gdns.CacheStorage,
	reverse bool,
) *addrCache {
	if !reverse {
		storage = nil
	}
	return &addrCache{
		input:          input,
		reverseStorage: storage,
		reverseEnabled: storage != nil,
	}
}

func (a *addrCache) host() string {
	if a == nil {
		return ""
	}
	if a.hostDone {
		return a.hostVal
	}
	a.hostDone = true
	switch addr := a.input.addr.(type) {
	case *net.TCPAddr:
		a.hostVal = addr.IP.String()
	case *net.UDPAddr:
		a.hostVal = addr.IP.String()
	case *net.IPAddr:
		a.hostVal = addr.IP.String()
	case nil:
		a.hostVal = hostFromString(a.input.str)
	default:
		a.hostVal = hostFromString(addr.String())
	}
	return a.hostVal
}

func (a *addrCache) ip() netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if a.ipDone {
		return a.ipVal
	}
	a.ipDone = true
	switch addr := a.input.addr.(type) {
	case *net.TCPAddr:
		a.ipVal = addrFromIP(addr.IP)
	case *net.UDPAddr:
		a.ipVal = addrFromIP(addr.IP)
	case *net.IPAddr:
		a.ipVal = addrFromIP(addr.IP)
	case nil:
		a.ipVal = parseHostIP(a.host())
	default:
		a.ipVal = parseHostIP(a.host())
	}
	return a.ipVal
}

func (a *addrCache) isFQDN() bool {
	host := a.host()
	return host != "" && !a.ip().IsValid()
}

func (a *addrCache) isIPv4() bool {
	return a.ip().Is4()
}

func (a *addrCache) isIPv6() bool {
	return a.ip().Is6()
}

func (a *addrCache) ipv4() uint32 { //nolint:unused
	ip := a.ip()
	if !ip.Is4() {
		return 0
	}
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func (a *addrCache) matchIPv4(want uint32) bool {
	ip := a.ip()
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:]) == want
}

func (a *addrCache) inIPv4Subnet(subnet IPv4Subnet) bool {
	ip := a.ip()
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return subnet.contains(binary.BigEndian.Uint32(b[:]))
}

func (a *addrCache) ipv6() netip.Addr {
	ip := a.ip()
	if !ip.Is6() {
		return netip.Addr{}
	}
	return ip
}

func (a *addrCache) port(network string) int {
	if a == nil {
		return -1
	}
	if a.portDone {
		return a.portVal
	}
	a.portDone = true
	a.portVal = -1
	switch addr := a.input.addr.(type) {
	case *net.TCPAddr:
		a.portVal = addr.Port
		return a.portVal
	case *net.UDPAddr:
		a.portVal = addr.Port
		return a.portVal
	}
	_, port, ok := splitHostPort(a.rawString())
	if !ok {
		port = a.rawString()
	}
	if port == "" {
		return a.portVal
	}
	if p, err := strconv.ParseUint(port, 10, 16); err == nil {
		a.portVal = int(p)
		return a.portVal
	}
	p, err := gonnect.LookupPortOffline(network, port)
	if err == nil && p >= 0 && p <= 65535 {
		a.portVal = p
	}
	return a.portVal
}

func (a *addrCache) rawString() string {
	if a.input.addr != nil {
		return a.input.addr.String()
	}
	return a.input.str
}

func (a *addrCache) matchString(want string) bool {
	if a.host() == want {
		return true
	}
	for _, name := range a.reverseDNSNames() {
		if name == want {
			return true
		}
	}
	return false
}

func (a *addrCache) matchRegexp(re *regexp.Regexp) bool {
	if re.MatchString(a.host()) {
		return true
	}
	for _, name := range a.reverseDNSNames() {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (a *addrCache) reverseDNSNames() []string {
	if a == nil || !a.reverseEnabled || a.reverseStorage == nil {
		return nil
	}
	if a.reverseDone {
		return a.reverseNames
	}
	a.reverseDone = true
	ip := a.ip()
	if !ip.IsValid() {
		return nil
	}
	a.reverseNames = reverseDNSNames(a.reverseStorage, ip, time.Now())
	return a.reverseNames
}

type addrStringOps struct {
	remote bool
	local  bool
}

func bytecodeAddrStringOps(code []byte) addrStringOps {
	var ops addrStringOps
	for pc := 0; pc < len(code); {
		op := code[pc]
		pc++
		_, next := readBytecodeParamUnchecked(code, pc, op)
		pc = next
		switch op {
		case OP_ADDR_S, OP_ADDR_RE:
			ops.remote = true
		case OP_LADDR_S, OP_LADDR_RE:
			ops.local = true
		}
	}
	return ops
}

func dnsPTRLiteralCacheKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return ""
	}
	return addr.String() + ".|12|1"
}

func reverseDNSNames(
	storage gdns.CacheStorage,
	addr netip.Addr,
	now time.Time,
) []string {
	if storage == nil {
		return nil
	}
	key := dnsPTRLiteralCacheKey(addr)
	if key == "" {
		return nil
	}
	msg, ok := storage.Get(key, now)
	if !ok || msg == nil || !msg.Response || msg.RCode != gdns.RCodeSuccess {
		return nil
	}
	var names []string
	for _, rr := range msg.Answers {
		if rr.Type != gdns.TypePTR || rr.Class != gdns.ClassIN ||
			len(rr.Data) == 0 {
			continue
		}
		names = append(names, string(rr.Data))
	}
	return names
}

func hostFromString(s string) string {
	host, _, ok := splitHostPort(s)
	if ok {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(s, "[]")
}

func splitHostPort(s string) (host, port string, ok bool) {
	if s == "" {
		return "", "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		return host, port, true
	}
	return "", "", false
}

func parseHostIP(host string) netip.Addr {
	if host == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func addrFromIP(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func (n IPv4Subnet) contains(addr uint32) bool {
	if n.Bits == 0 {
		return true
	}
	mask := ^uint32(0) << (32 - n.Bits)
	return addr&mask == n.Addr&mask
}

func isLAddrOp(op byte) bool {
	switch op {
	case OP_LFQDN, OP_LADDR_S, OP_LADDR_RE, OP_LADDR4, OP_LADDR6,
		OP_LSNET4, OP_LSNET6, OP_LPORT:
		return true
	default:
		return false
	}
}

func isSplitOnlyOp(op byte) bool {
	switch op {
	case OP_RULE:
		return true
	default:
		return false
	}
}

func isSnifferOnlyOp(op byte) bool {
	switch op {
	case OP_INTERCEPT, OP_SNIFF, OP_SNIFF_NONE, OP_ROUTE:
		return true
	default:
		return false
	}
}

func isDNSOnlyOp(op byte) bool {
	switch op {
	case OP_BACKEND, OP_QTYPE, OP_QCLASS, OP_OPCODE:
		return true
	default:
		return false
	}
}

func isRouterMethodOp(op byte) bool {
	switch op {
	case OP_DIAL, OP_LISTEN, OP_LOOKUP:
		return true
	default:
		return false
	}
}

func isNet4(network string) bool {
	return strings.HasSuffix(network, "4")
}

func isNet6(network string) bool {
	return strings.HasSuffix(network, "6")
}

func isTCPNet(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}

func isUDPNet(network string) bool {
	return network == "udp" || network == "udp4" || network == "udp6"
}

func bytecodeParamIndex(param uint64, n int) (int, bool) {
	if n <= 0 {
		return 0, false
	}
	// n is positive and comes from a slice length.
	maxParam := uint64(n) //nolint:gosec
	if param >= maxParam {
		return 0, false
	}
	//nolint:gosec // Range checked against the slice length immediately above.
	return int(param), true
}

func bytecodeParamInt(param uint64, limit int) (int, bool) {
	if limit < 0 {
		return 0, false
	}
	// limit is non-negative and caller bounded.
	maxParam := uint64(limit) //nolint:gosec
	if param > maxParam {
		return 0, false
	}
	return int(param), true //nolint:gosec // Range checked immediately above.
}
