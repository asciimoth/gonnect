package tun

import (
	"sync"

	"github.com/asciimoth/bufpool"
)

type frwPkg struct {
	data         []byte
	offset, size int
}

type frwCfg struct {
	tun    Tun
	offset int
	mtu    int
}

// Forwarder manages bidirectional forwarding between two TUN devices.
// It runs two goroutines: one for reading from the read TUN and one
// for writing to the write TUN.
// The forwarder can be reconfigured dynamically (e.g., swap TUN devices)
// without stopping.
//
// For bi-directional forwarding see Point2Point.
type Forwarder struct {
	wg sync.WaitGroup
	mu sync.Mutex

	stopped bool

	pool bufpool.Pool

	tunRead, tunWrite Tun

	chCfgRead, chCfgWrite chan *frwCfg

	sendCh chan frwPkg
}

// NewForwarder creates a new Forwarder with the given buffer pool (can be nil).
// It starts the reader and writer goroutines.
// The forwarder initially has no TUN devices
// and must be configured via SetReadTun and SetWriteTun.
func NewForwarder(pool bufpool.Pool) *Forwarder {
	frw := &Forwarder{
		pool: pool,

		chCfgRead:  make(chan *frwCfg, 2),
		chCfgWrite: make(chan *frwCfg, 2),

		sendCh: make(chan frwPkg),
	}
	frw.wg.Go(func() {
		frwReader(frw.chCfgRead, frw.sendCh, pool)
	})
	frw.wg.Go(func() {
		frwWriter(frw.chCfgWrite, frw.sendCh, pool)
	})
	return frw
}

// Stop gracefully shuts down the forwarder.
// It closes the TUN devices, signals the goroutines to exit, waits for them,
// and releases all pooled buffers.
func (f *Forwarder) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return
	}
	f.stopped = true

	if f.tunRead != nil {
		_ = f.tunRead.Close()
	}
	if f.tunWrite != nil {
		_ = f.tunWrite.Close()
	}

	close(f.chCfgWrite)
	close(f.chCfgRead)

	f.wg.Wait()

	close(f.sendCh)

	// Drain
	for range f.chCfgRead {
	}
	for range f.chCfgWrite {
	}
	for pkg := range f.sendCh {
		bufpool.PutBuffer(f.pool, pkg.data)
	}
}

// SetReadTun dynamically replaces the TUN device used for reading.
// The old read TUN (if any) is closed.
// If the forwarder is stopped, this call does nothing.
func (f *Forwarder) SetReadTun(tun Tun) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return
	}

	if f.tunRead != nil {
		_ = f.tunRead.Close()
	}

	f.tunRead = tun

	offset := 0
	mtu := 0
	if tun != nil {
		offset = tun.MRO()
		m, err := tun.MTU()
		if err == nil {
			mtu = m
		}
	}

	f.chCfgRead <- &frwCfg{
		tun:    tun,
		offset: offset,
		mtu:    mtu,
	}
}

// SetWriteTun dynamically replaces the TUN device used for writing.
// The old write TUN (if any) is closed.
// If the forwarder is stopped, this call does nothing.
func (f *Forwarder) SetWriteTun(tun Tun) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return
	}

	if f.tunWrite != nil {
		_ = f.tunWrite.Close()
	}

	f.tunWrite = tun

	offset := 0
	mtu := 0
	if tun != nil {
		offset = tun.MWO()
		m, err := tun.MTU()
		if err == nil {
			mtu = m
		}
	}

	f.chCfgWrite <- &frwCfg{
		tun:    tun,
		offset: offset,
		mtu:    mtu,
	}
}

func frwWriter(
	cfgCh <-chan *frwCfg,
	recvCh <-chan frwPkg,
	pool bufpool.Pool,
) {
	cfg := &frwCfg{}
	for {
		if cfg.tun == nil { //nolint nestif
			// Passive
			c := <-cfgCh
			if c == nil {
				return
			}
			if cfg.tun != nil {
				_ = cfg.tun.Close()
			}
			cfg = c
		} else {
			// Active
			select {
			case c := <-cfgCh:
				if c == nil {
					return
				}
				if cfg.tun != nil && cfg.tun != c.tun {
					_ = cfg.tun.Close()
				}
				cfg = c
			case pkg := <-recvCh:
				data := pkg.data[pkg.offset : pkg.offset+pkg.size]
				buf := bufpool.GetBuffer(pool, cfg.offset+len(data))
				copy(buf[cfg.offset:], data)
				_, err := cfg.tun.Write([][]byte{buf}, cfg.offset)
				if err != nil {
					_ = cfg.tun.Close()
					cfg.tun = nil
				}
				bufpool.PutBuffer(pool, pkg.data)
				bufpool.PutBuffer(pool, buf)
			}
		}
	}
}

func frwReader(
	cfgCh <-chan *frwCfg,
	sendCh chan frwPkg,
	pool bufpool.Pool,
) {
	cfg := &frwCfg{}
	for {
		if cfg.tun == nil { //nolint nestif
			// Passive
			c := <-cfgCh
			if c == nil {
				return
			}
			if cfg.tun != nil {
				_ = cfg.tun.Close()
			}
			cfg = c
		} else {
			// Active
			bufs := [][]byte{bufpool.GetBuffer(pool, cfg.mtu+cfg.offset)}
			sizes := []int{0}
			n, err := cfg.tun.Read(bufs, sizes, cfg.offset)
			if err != nil {
				_ = cfg.tun.Close()
				cfg.tun = nil
				bufpool.PutBuffer(pool, bufs[0])
			} else {
				if n == 0 {
					bufpool.PutBuffer(pool, bufs[0])
				} else {
					select {
					case sendCh <- frwPkg{
						data:   bufs[0],
						offset: cfg.offset,
						size:   sizes[0],
					}:
					case c := <-cfgCh:
						bufpool.PutBuffer(pool, bufs[0]) // nolint
						if c == nil {
							return
						}
						if cfg.tun != nil {
							_ = cfg.tun.Close()
						}
						cfg = c
					}
				}
			}
		}
	}
}
