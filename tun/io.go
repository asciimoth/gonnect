package tun

import (
	"io"
)

// Static type assertion
var _ io.ReadWriteCloser = (*IO)(nil)

// IO is an io.ReadWriteCloser wrapper for a Tun.
// It adapts the batch-oriented Tun interface to the single-buffer
// io.ReadWriteCloser interface, handling one packet at a time.
type IO struct {
	Tun
	buf []byte
}

// NewIO creates a new IO wrapper for the given Tun.
func NewIO(tun Tun) *IO {
	return &IO{
		Tun: tun,
		buf: make([]byte, 0, tun.BatchSize()),
	}
}

// Read implements io.Reader. It reads a single packet from the Device.
func (r *IO) Read(p []byte) (int, error) {
	sizes := make([]int, 1)
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
