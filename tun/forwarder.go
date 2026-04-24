package tun

import (
	"sync"

	"github.com/asciimoth/bufpool"
)

type frwPkg struct {
	bufs   [][]byte
	sizes  []int
	n      int
	offset int
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
		for i := range pkg.n {
			bufpool.PutBuffer(f.pool, pkg.bufs[i])
		}
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
				writeBufs := make([][]byte, pkg.n)
				for i := range pkg.n {
					data := pkg.bufs[i][pkg.offset : pkg.offset+pkg.sizes[i]]
					buf := bufpool.GetBuffer(pool, cfg.offset+len(data))
					copy(buf[cfg.offset:], data)
					writeBufs[i] = buf[:cfg.offset+len(data)]
				}

				err := writePackets(cfg.tun, writeBufs, cfg.offset)
				if err != nil {
					_ = cfg.tun.Close()
					cfg.tun = nil
				}

				for i := range pkg.n {
					bufpool.PutBuffer(pool, pkg.bufs[i])
					bufpool.PutBuffer(pool, writeBufs[i])
				}
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
			readBatch := batchSizeOf(cfg.tun)
			bufs := make([][]byte, readBatch)
			sizes := make([]int, readBatch)
			for i := range bufs {
				bufs[i] = bufpool.GetBuffer(pool, cfg.mtu+cfg.offset)
			}

			n, err := cfg.tun.Read(bufs, sizes, cfg.offset)
			if err != nil {
				for i := range bufs {
					bufpool.PutBuffer(pool, bufs[i])
				}
				if isRetryableReadError(err) {
					continue
				}
				_ = cfg.tun.Close()
				cfg.tun = nil
			} else {
				if n == 0 {
					for i := range bufs {
						bufpool.PutBuffer(pool, bufs[i])
					}
				} else {
					for i := n; i < len(bufs); i++ {
						bufpool.PutBuffer(pool, bufs[i])
					}
					select {
					case sendCh <- frwPkg{
						bufs:   bufs[:n],
						sizes:  append([]int(nil), sizes[:n]...),
						n:      n,
						offset: cfg.offset,
					}:
					case c := <-cfgCh:
						for i := range n {
							bufpool.PutBuffer(pool, bufs[i])
						}
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
