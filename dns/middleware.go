package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

type provider struct {
	ch      chan Request
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	spawner gonnect.Spawner
}

func newProvider(
	fn func(context.Context, Request),
	spawner gonnect.Spawner,
) *provider {
	ctx, cancel := context.WithCancel(context.Background())
	p := &provider{
		ch:      make(chan Request),
		cancel:  cancel,
		done:    make(chan struct{}),
		spawner: spawner,
	}
	if err := spawn(spawner, func() {
		defer close(p.done)
		for {
			select {
			case req := <-p.ch:
				err := spawnWg(spawner, func() {
					fn(ctx, req)
				}, &p.wg, "dns.provider.request")
				if err != nil {
					sendResponse(req, nil, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}, "dns.provider.loop"); err != nil {
		cancel()
		close(p.done)
	}
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
func Detach(upstream Interface, spawner gonnect.Spawner) *Detached {
	d := &Detached{upstream: upstream}
	d.p = newProvider(d.handle, spawner)
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

// ReverseDNSNames returns cached PTR names for addr. It does not make a DNS
// request. This method lets MemoryStorage be used directly as a
// gonnect.FirewallDNSCache.
func (s *MemoryStorage) ReverseDNSNames(
	addr netip.Addr,
	now time.Time,
) []string {
	if s == nil {
		return nil
	}
	return CachedReverseDNSNames(s, addr, now)
}

// ReverseDNSCache adapts any CacheStorage for cached firewall hostname
// matching. It does not make live DNS requests.
type ReverseDNSCache struct {
	storage CacheStorage
}

// NewReverseDNSCache returns a cached reverse-DNS adapter for storage. A nil
// storage produces an adapter that always returns no names.
func NewReverseDNSCache(storage CacheStorage) *ReverseDNSCache {
	return &ReverseDNSCache{storage: storage}
}

// ReverseDNSNames returns cached PTR names for addr.
func (c *ReverseDNSCache) ReverseDNSNames(
	addr netip.Addr,
	now time.Time,
) []string {
	if c == nil {
		return nil
	}
	return CachedReverseDNSNames(c.storage, addr, now)
}

// CachedReverseDNSNames returns the synthetic literal PTR names for addr from
// storage. It returns no names for a miss, an expired entry, or an invalid DNS
// response. It does not make a live DNS request.
func CachedReverseDNSNames(
	storage CacheStorage,
	addr netip.Addr,
	now time.Time,
) []string {
	if storage == nil {
		return nil
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil
	}
	msg, ok := storage.Get(addr.String()+".|12|1", now)
	if !ok || msg == nil || !msg.Response || msg.RCode != RCodeSuccess {
		return nil
	}
	var names []string
	for _, rr := range msg.Answers {
		if rr.Type != TypePTR || rr.Class != ClassIN || len(rr.Data) == 0 {
			continue
		}
		names = append(names, string(rr.Data))
	}
	return names
}

var (
	_ gonnect.FirewallDNSCache = (*MemoryStorage)(nil)
	_ gonnect.FirewallDNSCache = (*ReverseDNSCache)(nil)
)

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
//
// By default, Cache both reads from and writes to CacheStorage. Enable
// storageWriteOnly when this Cache should only populate the shared storage and
// must not serve answers already present there.
//
// When reverse lookups are enabled, successful A and AAAA responses also
// populate synthetic PTR cache entries for the returned addresses. This can
// leak forward lookup history between consumers that share the same cache:
// a consumer can probe reverse lookups to infer whether another consumer
// recently resolved a hostname. Leave it disabled unless that information
// sharing is acceptable for every cache user.
type Cache struct {
	storage              CacheStorage
	enableReverseLookups bool
	storageWriteOnly     bool
	p                    *provider

	mu       sync.Mutex
	upstream Interface
	gen      uint64
	done     chan struct{}
}

// NewCache creates a cache using storage. If storage is nil, a new
// MemoryStorage is used. Set enableReverseLookups to true only when consumers
// sharing this cache are allowed to observe synthetic PTR answers derived from
// each other's A and AAAA lookups. Set storageWriteOnly to true to keep
// writing successful upstream answers without serving storage hits.
func NewCache(
	upstream Interface,
	storage CacheStorage,
	enableReverseLookups bool,
	storageWriteOnly bool,
	spawner gonnect.Spawner,
) *Cache {
	if storage == nil {
		storage = NewMemoryStorage()
	}
	c := &Cache{
		storage:              storage,
		enableReverseLookups: enableReverseLookups,
		storageWriteOnly:     storageWriteOnly,
	}
	c.Attach(upstream)
	c.p = newProvider(c.handle, spawner)
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
	if !c.storageWriteOnly {
		if msg, ok := c.storage.Get(key, time.Now()); ok {
			resp := msg.Copy()
			resp.ID = req.Message.ID
			sendResponse(req, resp, nil)
			return
		}
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
		now := time.Now()
		c.mu.Lock()
		stillCurrent := gen == c.gen
		c.mu.Unlock()
		if stillCurrent {
			c.storage.Set(key, resp, now)
			if c.enableReverseLookups {
				c.storeReverseLookups(resp, now)
			}
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

func (c *Cache) storeReverseLookups(msg *Message, now time.Time) {
	if msg == nil || !msg.Response || msg.RCode != RCodeSuccess {
		return
	}
	for _, rr := range msg.Answers {
		ip := resourceIP(rr)
		if ip == nil {
			continue
		}
		host := absName(rr.Name)
		if host == "." && len(msg.Questions) > 0 {
			host = absName(msg.Questions[0].Name)
		}
		if host == "." {
			continue
		}
		for _, ptrName := range ptrCacheNames(ip) {
			ptr := &Message{
				Response:           true,
				RCode:              RCodeSuccess,
				RecursionAvailable: true,
				Questions: []Question{{
					Name:  ptrName,
					Type:  TypePTR,
					Class: ClassIN,
				}},
				Answers: []Resource{{
					Name:  ptrName,
					Type:  TypePTR,
					Class: ClassIN,
					TTL:   rr.TTL,
					Data:  []byte(host),
				}},
			}
			c.storage.Set("", ptr, now)
		}
	}
}

func resourceIP(rr Resource) net.IP {
	switch rr.Type {
	case TypeA:
		if rr.Class == ClassIN && len(rr.Data) == net.IPv4len {
			return net.IPv4(rr.Data[0], rr.Data[1], rr.Data[2], rr.Data[3])
		}
	case TypeAAAA:
		if rr.Class == ClassIN && len(rr.Data) == net.IPv6len {
			return net.IP(append([]byte(nil), rr.Data...))
		}
	}
	return nil
}

func ptrCacheNames(ip net.IP) []string {
	var names []string
	if reverse := reverseAddr(ip); reverse != "" {
		names = append(names, reverse)
	}
	if reverse := reverseAddr6(ip); reverse != "" {
		names = append(names, reverse)
	}
	if literal := ip.String(); literal != "" && literal != "<nil>" {
		names = append(names, absName(literal))
	}
	return names
}

func reverseAddr6(ip net.IP) string {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return ""
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.Grow(72)
	for i := len(ip16) - 1; i >= 0; i-- {
		b.WriteByte(hex[ip16[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hex[ip16[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa.")
	return b.String()
}
