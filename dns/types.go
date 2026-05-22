package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33

	ClassIN uint16 = 1

	OpcodeQuery uint8 = 0

	RCodeSuccess        uint8 = 0
	RCodeFormatError    uint8 = 1
	RCodeServerFailure  uint8 = 2
	RCodeNameError      uint8 = 3
	RCodeNotImplemented uint8 = 4
)

var globalID atomic.Uint32

// NextID returns the next value of a process-wide cycling DNS message ID
// counter. The counter is safe for concurrent use. It is intended for
// correlation, not for cryptographic randomness.
func NextID() uint16 {
	// #nosec G115 -- DNS message IDs are defined as wrapping 16-bit values.
	return uint16(globalID.Add(1))
}

// Message is the package-level representation of a DNS message.
//
// It intentionally models the message header and the four standard sections
// without tying callers to a concrete wire codec. Name values are regular DNS
// names; callers may use either absolute names with a trailing dot or relative
// presentation names.
type Message struct {
	ID       uint16
	Response bool

	Opcode uint8
	RCode  uint8

	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticatedData  bool
	CheckingDisabled   bool

	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

// Question identifies one DNS question.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Resource identifies one DNS resource record. Data stores record-specific
// payload in DNS wire format without the owner name, type, class, or TTL.
type Resource struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Copy returns a deep copy of m. Nil receivers return nil.
func (m *Message) Copy() *Message {
	if m == nil {
		return nil
	}
	cp := *m
	cp.Questions = append([]Question(nil), m.Questions...)
	cp.Answers = copyResources(m.Answers)
	cp.Authorities = copyResources(m.Authorities)
	cp.Additionals = copyResources(m.Additionals)
	return &cp
}

func copyResources(in []Resource) []Resource {
	out := make([]Resource, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Data = append([]byte(nil), in[i].Data...)
	}
	return out
}

// Response is delivered on a request's response channel.
type Response struct {
	Message *Message
	Err     error
}

// RequestContext is the subset of context.Context carried by a Request.
type RequestContext interface {
	context.Context
}

// Request is the channel envelope used by DNS implementations. Context cancels
// only this request. Reply receives exactly one Response unless the provider
// has already been closed before it can accept the request.
type Request struct {
	Context RequestContext
	Message *Message
	Reply   chan<- Response
}

// Interface is a concurrent, channel based DNS message transport.
//
// Implementations accept request messages through Requests and respond through
// the per-request Reply channel. Close terminates the implementation and
// cancels in-flight work owned by that implementation. Callers may share one
// Interface between multiple goroutines.
type Interface interface {
	Requests() chan<- Request
	Close() error
}

// Query sends req through d and waits for one response or cancellation.
func Query(ctx context.Context, d Interface, req *Message) (*Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reply := make(chan Response, 1)
	select {
	case d.Requests() <- Request{Context: ctx, Message: req, Reply: reply}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r := <-reply:
		return r.Message, r.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var (
	// ErrNoUpstream is returned when middleware has no wrapped DNS interface.
	ErrNoUpstream = errors.New("dns: no upstream attached")
	// ErrClosed is returned by providers and middleware after Close.
	ErrClosed = net.ErrClosed
)

func closeAll(closers []io.Closer) error {
	var err error
	for _, c := range closers {
		err = errors.Join(err, c.Close())
	}
	return err
}
