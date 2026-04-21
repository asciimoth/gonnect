package tun

import (
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

	// If there is a read offset, read into a temporary buffer that includes it,
	// then copy the packet payload back into p.
	if r.ro > 0 {
		buf := r.pool.Get(r.ro + len(p))
		defer r.pool.Put(buf)

		sizes := []int{1}
		n, err := r.Tun.Read([][]byte{buf}, sizes, r.ro)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}

		n = min(sizes[0], len(p))
		copy(p, buf[r.ro:r.ro+n])
		return n, nil
	}

	sizes := []int{1}
	n, err := r.Tun.Read([][]byte{p}, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return sizes[0], nil
}

// Write implements io.Writer. It writes a single packet to the Device.
func (r *IO) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// If there is a write offset, build a temporary packet with leading space.
	if r.wo > 0 {
		buf := r.pool.Get(r.wo + len(p))
		defer r.pool.Put(buf)

		copy(buf[r.wo:], p)

		n, err := r.Tun.Write([][]byte{buf}, r.wo)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}
		return len(p), nil
	}

	n, err := r.Tun.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(p), nil
}

// Close implements io.Closer. It closes the underlying Device.
func (r *IO) Close() error {
	return r.Tun.Close()
}
