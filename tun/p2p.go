package tun

import "github.com/asciimoth/bufpool"

// Point2Point manages bidirectional forwarding between two TUN devices,
// conventionally named A and B.
// It can be reconfigured dynamically (e.g., swap TUN devices)
// without stopping.
type Point2Point struct {
	a2b, b2a *Forwarder
}

// NewP2P creates a new Point2Point instance using the provided buffer pool.
// Point2Point start with no TUN devices
// and must be configured using SetA and SetB.
func NewP2P(pool bufpool.Pool) *Point2Point {
	return &Point2Point{
		a2b: NewForwarder(pool),
		b2a: NewForwarder(pool),
	}
}

// Stop gracefully shuts down both internal forwarders, releasing all resources
// and waiting for goroutines to finish.
func (p *Point2Point) Stop() {
	p.a2b.Stop()
	p.b2a.Stop()
}

// SetA configures the given TUN device as endpoint A.
// Endpoint A will be used for reading packets to send to B, and will also receive
// packets coming from B (i.e., writes from B to A are written to this TUN).
func (p *Point2Point) SetA(tun Tun) {
	p.a2b.SetReadTun(tun)
	p.b2a.SetWriteTun(tun)
}

// SetB configures the given TUN device as endpoint B.
// Endpoint B will be used for reading packets to send to A, and will also receive
// packets coming from A (i.e., writes from A to B are written to this TUN).
func (p *Point2Point) SetB(tun Tun) {
	p.b2a.SetReadTun(tun)
	p.a2b.SetWriteTun(tun)
}
