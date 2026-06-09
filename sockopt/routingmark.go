package sockopt

const (
	routingMarkSignBit = 1 << 31
	minRoutingMarkInt  = -routingMarkSignBit
	maxRoutingMark     = 2*routingMarkSignBit - 1
)

func routingMarkFromSockoptInt(value int) uint32 {
	if value < minRoutingMarkInt {
		return 0
	}
	converted := int64(value)
	if value < 0 {
		converted += maxRoutingMark + 1
	}
	if converted < 0 || converted > maxRoutingMark {
		return 0
	}
	return uint32(converted)
}
