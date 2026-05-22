package dns

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type provider struct {
	ch     chan Request
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func newProvider(fn func(context.Context, Request)) *provider {
	ctx, cancel := context.WithCancel(context.Background())
	p := &provider{
		ch:     make(chan Request),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(p.done)
		for {
			select {
			case req := <-p.ch:
				p.wg.Add(1)
				go func() {
					defer p.wg.Done()
					fn(ctx, req)
				}()
			case <-ctx.Done():
				return
			}
		}
	}()
	return p
}

func (p *provider) Requests() chan<- Request { return p.ch }

func (p *provider) Close() error {
	p.once.Do(p.cancel)
	<-p.done
	p.wg.Wait()
	return nil
}

func sendResponse(req Request, msg *Message, err error) {
	if req.Reply == nil {
		return
	}
	select {
	case req.Reply <- Response{Message: msg, Err: err}:
	default:
	}
}

// Detached is an independently closable wrapper around another DNS Interface.
//
// Closing the detached wrapper cancels requests that are currently passing
// through it but does not close the wrapped interface. Other users of the
// wrapped interface continue to operate normally.
type Detached struct {
	upstream Interface
	p        *provider
}

// Detach wraps upstream with independent close and cancellation state.
func Detach(upstream Interface) *Detached {
	d := &Detached{upstream: upstream}
	d.p = newProvider(d.handle)
	return d
}

func (d *Detached) Requests() chan<- Request { return d.p.Requests() }
func (d *Detached) Close() error             { return d.p.Close() }

func (d *Detached) handle(root context.Context, req Request) {
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
		case <-ctx.Done():
		}
	}()
	msg, err := Query(ctx, d.upstream, req.Message)
	sendResponse(req, msg, err)
}

// CacheStorage stores DNS messages by cache key. Implementations must be safe
// for concurrent callers when shared by multiple Cache values.
type CacheStorage interface {
	Get(key string, now time.Time) (*Message, bool)
	Set(key string, msg *Message, now time.Time)
	Delete(key string)
}

type cacheEntry struct {
	msg    *Message
	expire time.Time
}

// MemoryStorage is a simple map-backed CacheStorage implementation.
type MemoryStorage struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

// NewMemoryStorage returns an empty in-memory cache storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{m: make(map[string]cacheEntry)}
}

func (s *MemoryStorage) Get(key string, now time.Time) (*Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ent, ok := s.m[key]
	if !ok {
		return nil, false
	}
	if !ent.expire.IsZero() && !now.Before(ent.expire) {
		delete(s.m, key)
		return nil, false
	}
	return ent.msg.Copy(), true
}

func (s *MemoryStorage) Set(key string, msg *Message, now time.Time) {
	if msg == nil || !msg.Response || msg.RCode != RCodeSuccess {
		return
	}
	if key == "" {
		key = cacheKey(msg)
	}
	ttl := minTTL(msg)
	if ttl == 0 {
		return
	}
	cp := msg.Copy()
	exp := now.Add(time.Duration(ttl) * time.Second)
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[string]cacheEntry)
	}
	s.m[key] = cacheEntry{msg: cp, expire: exp}
	s.mu.Unlock()
}

func (s *MemoryStorage) Delete(key string) {
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

func minTTL(msg *Message) uint32 {
	var ttl uint32
	for _, rr := range msg.Answers {
		if ttl == 0 || rr.TTL < ttl {
			ttl = rr.TTL
		}
	}
	return ttl
}

// Cache is a DNS middleware that caches successful responses and forwards
// misses to an attachable upstream. Detach cancels requests that are currently
// waiting on the old upstream. Cached responses remain available across
// attach, detach, and reattach operations.
type Cache struct {
	storage CacheStorage
	p       *provider

	mu       sync.Mutex
	upstream Interface
	gen      uint64
	done     chan struct{}
}

// NewCache creates a cache using storage. If storage is nil, a new
// MemoryStorage is used.
func NewCache(upstream Interface, storage CacheStorage) *Cache {
	if storage == nil {
		storage = NewMemoryStorage()
	}
	c := &Cache{storage: storage}
	c.Attach(upstream)
	c.p = newProvider(c.handle)
	return c
}

func (c *Cache) Requests() chan<- Request { return c.p.Requests() }

func (c *Cache) Close() error {
	c.Detach()
	return c.p.Close()
}

// Attach replaces the upstream DNS interface. Existing requests going through
// a previous upstream are canceled before the new upstream is installed.
func (c *Cache) Attach(upstream Interface) {
	c.mu.Lock()
	if c.done != nil {
		close(c.done)
	}
	c.upstream = upstream
	c.done = make(chan struct{})
	c.gen++
	c.mu.Unlock()
}

// Detach removes the upstream and cancels in-flight miss lookups. Cached hits
// continue to be served.
func (c *Cache) Detach() {
	c.Attach(nil)
}

func (c *Cache) handle(root context.Context, req Request) {
	key := cacheKey(req.Message)
	if msg, ok := c.storage.Get(key, time.Now()); ok {
		resp := msg.Copy()
		resp.ID = req.Message.ID
		sendResponse(req, resp, nil)
		return
	}
	up, gen, cancelCh := c.current()
	if up == nil {
		sendResponse(req, nil, ErrNoUpstream)
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
		case <-cancelCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	resp, err := Query(ctx, up, req.Message)
	if err == nil && resp != nil {
		c.mu.Lock()
		stillCurrent := gen == c.gen
		c.mu.Unlock()
		if stillCurrent {
			c.storage.Set(key, resp, time.Now())
		}
	}
	sendResponse(req, resp, err)
}

func (c *Cache) current() (Interface, uint64, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upstream, c.gen, c.done
}

func cacheKey(msg *Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return ""
	}
	q := msg.Questions[0]
	return fmt.Sprintf("%s|%d|%d", absName(q.Name), q.Type, q.Class)
}
