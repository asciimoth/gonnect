package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

const (
	// FallbackSlots is the number of upstream slots in a Fallback.
	FallbackSlots = 16

	defaultFallbackAttemptTimeout = 5 * time.Second
)

var (
	// ErrInvalidFallbackSlot is returned when a slot is outside the range from
	// 1 through FallbackSlots.
	ErrInvalidFallbackSlot = errors.New("dns: fallback slot out of range")
)

var _ Interface = (*Fallback)(nil)

// FallbackOptions controls how a Fallback sends requests to its upstreams.
type FallbackOptions struct {
	// AttemptTimeout limits one request to one upstream. The Fallback tries the
	// next attached slot after this time. A value less than 1 uses the default
	// timeout of five seconds.
	AttemptTimeout time.Duration
}

// Fallback is a DNS middleware that tries attached upstreams in slot order.
//
// Slots are numbered from 1 through FallbackSlots. Empty slots are skipped. A
// request starts with the attached upstream that has the smallest slot number.
// The Fallback tries the next attached slot when an upstream returns a Go
// error, a DNS error response, or no reply before AttemptTimeout. It returns
// the first NOERROR DNS response that has no Go error. If all attached
// upstreams fail, it returns the response and error from the last attempted
// upstream.
//
// Upstreams can be attached, detached, or replaced while the Fallback is in
// use. A slot change cancels requests that are using the old value of that
// slot. Those requests can continue with later attached slots. Close cancels
// in-flight requests but does not close attached upstreams.
type Fallback struct {
	p       *provider
	timeout time.Duration

	mu      sync.Mutex
	slots   [FallbackSlots]Interface
	changed [FallbackSlots]chan struct{}
	closed  bool
}

// NewFallback creates an empty Fallback with a five-second timeout for each
// upstream attempt.
func NewFallback(spawner gonnect.Spawner) *Fallback {
	return NewFallbackWithOptions(FallbackOptions{}, spawner)
}

// NewFallbackWithOptions creates an empty Fallback with the specified options.
func NewFallbackWithOptions(
	opts FallbackOptions,
	spawner gonnect.Spawner,
) *Fallback {
	if opts.AttemptTimeout < 1 {
		opts.AttemptTimeout = defaultFallbackAttemptTimeout
	}
	f := &Fallback{timeout: opts.AttemptTimeout}
	for i := range f.changed {
		f.changed[i] = make(chan struct{})
	}
	f.p = newProvider(f.handle, spawner)
	return f
}

// Requests returns the channel that accepts DNS requests.
func (f *Fallback) Requests() chan<- Request { return f.p.Requests() }

// Close stops the Fallback and cancels its in-flight requests. It does not
// close attached upstreams.
func (f *Fallback) Close() error {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		for i := range f.changed {
			close(f.changed[i])
		}
	}
	f.mu.Unlock()
	return f.p.Close()
}

// Attach installs upstream in slot. Slots are numbered from 1 through
// FallbackSlots. Passing nil is equivalent to Detach. Replacing an upstream
// cancels requests that are currently using the old upstream.
func (f *Fallback) Attach(slot int, upstream Interface) error {
	if !validFallbackSlot(slot) {
		return fallbackSlotError(slot)
	}
	if upstream == nil {
		return f.Detach(slot)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	idx := slot - 1
	close(f.changed[idx])
	f.slots[idx] = upstream
	f.changed[idx] = make(chan struct{})
	return nil
}

// Detach removes the upstream in slot. It cancels requests that are currently
// using that upstream. Detach does not close the upstream.
func (f *Fallback) Detach(slot int) error {
	if !validFallbackSlot(slot) {
		return fallbackSlotError(slot)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	idx := slot - 1
	close(f.changed[idx])
	f.slots[idx] = nil
	f.changed[idx] = make(chan struct{})
	return nil
}

func (f *Fallback) handle(root context.Context, req Request) {
	requestCtx := req.Context
	if requestCtx == nil {
		requestCtx = context.Background()
	}

	var last Response
	attempted := false
	for slot := 1; slot <= FallbackSlots; slot++ {
		upstream, changed, closed := f.current(slot)
		if closed {
			sendResponse(req, nil, net.ErrClosed)
			return
		}
		if upstream == nil {
			continue
		}

		attempted = true
		ctx, cancel := fallbackAttemptContext(
			requestCtx,
			root,
			changed,
			f.timeout,
		)
		last.Message, last.Err = Query(ctx, upstream, req.Message)
		cancel()
		if last.Err == nil &&
			last.Message != nil &&
			last.Message.RCode == RCodeSuccess {
			sendResponse(req, last.Message, nil)
			return
		}
		if err := requestCtx.Err(); err != nil {
			sendResponse(req, last.Message, err)
			return
		}
		if err := root.Err(); err != nil {
			sendResponse(req, last.Message, err)
			return
		}
	}

	if !attempted {
		sendResponse(req, nil, ErrNoUpstream)
		return
	}
	sendResponse(req, last.Message, last.Err)
}

func (f *Fallback) current(
	slot int,
) (Interface, <-chan struct{}, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := slot - 1
	return f.slots[idx], f.changed[idx], f.closed
}

func fallbackAttemptContext(
	requestCtx context.Context,
	root context.Context,
	changed <-chan struct{},
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	baseCtx, cancelBase := context.WithCancel(requestCtx)
	ctx := baseCtx
	cancelTimeout := func() {}
	if timeout > 0 {
		ctx, cancelTimeout = context.WithTimeout(baseCtx, timeout)
	}
	go func() {
		select {
		case <-root.Done():
			cancelBase()
		case <-changed:
			cancelBase()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		cancelTimeout()
		cancelBase()
	}
}

func validFallbackSlot(slot int) bool {
	return slot >= 1 && slot <= FallbackSlots
}

func fallbackSlotError(slot int) error {
	return fmt.Errorf("%w: %d", ErrInvalidFallbackSlot, slot)
}
