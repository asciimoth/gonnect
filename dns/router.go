package dns

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/asciimoth/gonnect"
)

var _ Interface = (*Router)(nil)

// RouteFunc selects the backend name for a DNS request.
//
// Returning an empty string or a name without an attached backend rejects the
// request with ErrNoUpstream.
type RouteFunc func(*Message) string

// ErrInvalidBackendName is returned when a backend mutation uses an empty name.
var ErrInvalidBackendName = errors.New("dns: invalid backend name")

// Router is a DNS Interface that routes requests to named backend interfaces.
//
// Backends and the route function can be attached, detached, or replaced while
// the Router is serving requests. Mutations cancel in-flight requests that were
// routed through an older backend set or route function. Closing the Router
// cancels in-flight work owned by the Router but does not close attached
// backends.
type Router struct {
	p *provider

	mu       sync.Mutex
	backends map[string]Interface
	route    RouteFunc
	done     chan struct{}
	closed   bool
}

// NewRouter creates an empty DNS Router.
func NewRouter(spawner gonnect.Spawner) *Router {
	r := &Router{
		backends: make(map[string]Interface),
		done:     make(chan struct{}),
	}
	r.p = newProvider(r.handle, spawner)
	return r
}

func (r *Router) Requests() chan<- Request { return r.p.Requests() }

func (r *Router) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.done)
	}
	r.mu.Unlock()
	return r.p.Close()
}

// Attach installs backend under name. Passing nil is equivalent to Detach.
func (r *Router) Attach(name string, backend Interface) error {
	if name == "" {
		return ErrInvalidBackendName
	}
	if backend == nil {
		return r.Detach(name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	r.cancelLocked()
	r.backends[name] = backend
	return nil
}

// Detach removes the backend named name.
func (r *Router) Detach(name string) error {
	if name == "" {
		return ErrInvalidBackendName
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	r.cancelLocked()
	delete(r.backends, name)
	return nil
}

// AttachRouter installs or replaces the route function. Passing nil is
// equivalent to DetachRouter.
func (r *Router) AttachRouter(route RouteFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	r.cancelLocked()
	r.route = route
	return nil
}

// SetRouter installs or replaces the route function. Passing nil removes it.
func (r *Router) SetRouter(route RouteFunc) error {
	return r.AttachRouter(route)
}

// DetachRouter removes the route function.
func (r *Router) DetachRouter() error {
	return r.AttachRouter(nil)
}

func (r *Router) handle(root context.Context, req Request) {
	backend, done, err := r.current(req.Message)
	if err != nil {
		sendResponse(req, nil, err)
		return
	}
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-root.Done():
			cancel()
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	resp, err := Query(ctx, backend, req.Message)
	sendResponse(req, resp, err)
}

func (r *Router) current(msg *Message) (Interface, <-chan struct{}, error) {
	r.mu.Lock()
	if r.closed || r.route == nil {
		done := r.done
		r.mu.Unlock()
		return nil, done, ErrNoUpstream
	}
	route := r.route
	done := r.done
	r.mu.Unlock()

	name := route(msg)

	r.mu.Lock()
	defer r.mu.Unlock()
	if done != r.done {
		return nil, done, context.Canceled
	}
	if name == "" {
		return nil, done, ErrNoUpstream
	}
	backend := r.backends[name]
	if backend == nil {
		return nil, done, ErrNoUpstream
	}
	return backend, done, nil
}

func (r *Router) cancelLocked() {
	close(r.done)
	r.done = make(chan struct{})
}
