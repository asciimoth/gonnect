package tun

import (
	"bytes"
	"io"

	"github.com/asciimoth/bufpool"
)

// Static type assertion
var _ io.ReadWriteCloser = (*IO)(nil)

// IO is an io.ReadWriteCloser wrapper for a Tun.
// It adapts the batch-oriented Tun interface to the single-buffer
// io.ReadWriteCloser interface, handling one packet at a time.
type IO struct {
	Tun
	wo, ro int
	pool   bufpool.Pool

	pending [][]byte
}

// NewIO creates a new IO wrapper for the given Tun.
func NewIO(tun Tun, pool bufpool.Pool) *IO {
	return &IO{
		Tun:  tun,
		wo:   tun.MWO(),
		ro:   tun.MRO(),
		pool: pool,
	}
}

// Read implements io.Reader. It reads a single packet from the Device.
func (r *IO) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(r.pending) > 0 {
		packet := r.pending[0]
		r.pending[0] = nil
		r.pending = r.pending[1:]
		n := min(len(packet), len(p))
		copy(p, packet[:n])
		return n, nil
	}

	packetSize := len(p)
	if mtu, err := r.MTU(); err == nil && mtu > packetSize {
		packetSize = mtu
	}

	readBatch := batchSizeOf(r.Tun)
	bufs := make([][]byte, readBatch)
	sizes := make([]int, readBatch)
	for i := range bufs {
		bufs[i] = bufpool.GetBuffer(r.pool, r.ro+packetSize)
	}

	n, err := r.Tun.Read(bufs, sizes, r.ro)
	if err != nil {
		for i := range bufs {
			bufpool.PutBuffer(r.pool, bufs[i])
		}
		return 0, err
	}
	if n == 0 {
		for i := range bufs {
			bufpool.PutBuffer(r.pool, bufs[i])
		}
		return 0, io.EOF
	}

	readLen := min(sizes[0], len(p))
	copy(p, bufs[0][r.ro:r.ro+readLen])

	for i := 1; i < n; i++ {
		r.pending = append(r.pending, bytes.Clone(bufs[i][r.ro:r.ro+sizes[i]]))
	}

	for i := range bufs {
		bufpool.PutBuffer(r.pool, bufs[i])
	}

	return readLen, nil
}

// Write implements io.Writer. It writes a single packet to the Device.
func (r *IO) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// If there is a write offset, build a temporary packet with leading space.
	if r.wo > 0 {
		buf := bufpool.GetBuffer(r.pool, r.wo+len(p))
		defer bufpool.PutBuffer(r.pool, buf)

		copy(buf[r.wo:], p)

		if err := writePackets(
			r.Tun,
			[][]byte{buf[:r.wo+len(p)]},
			r.wo,
		); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	if err := writePackets(r.Tun, [][]byte{p}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements io.Closer. It closes the underlying Device.
func (r *IO) Close() error {
	return r.Tun.Close()
}
