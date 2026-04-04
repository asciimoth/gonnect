package tun

import (
	"errors"
	"os"
	"sync"
)

var ErrReadOnClosedPipe = errors.Join(
	os.ErrClosed,
	errors.New("tun: read on closed Tun"),
)

var ErrWriteOnClosedPipe = errors.Join(
	os.ErrClosed,
	errors.New("tun: write on closed Tun"),
)

// pipeTun implements Tun interface using channels for bidirectional communication
type pipeTun struct {
	mu        sync.Mutex
	tx        chan []byte // transmit channel (packets this Tun sends)
	rx        chan []byte // receive channel (packets this Tun reads)
	closed    bool
	name      string
	mtu       int
	events    chan Event
	batchSize int
}

// Pipe creates two connected Tun implementations that are bound together.
// Packets written to one Tun can be read from the other, similar to net.Pipe.
// The returned Tun instances share a bidirectional channel-based connection.
func Pipe(batch int, mtu int) (Tun, Tun) {
	// Create channels for both directions
	// chan1: tun1 writes (tx), tun2 reads (rx)
	// chan2: tun2 writes (tx), tun1 reads (rx)
	chan1 := make(chan []byte, 100)
	chan2 := make(chan []byte, 100)

	events1 := make(chan Event, 1)
	events2 := make(chan Event, 1)
	events1 <- EventUp
	events2 <- EventUp

	tun1 := &pipeTun{
		tx:        chan1,
		rx:        chan2,
		name:      "pipe-tun-0",
		mtu:       mtu,
		events:    events1,
		batchSize: batch,
	}

	tun2 := &pipeTun{
		tx:        chan2,
		rx:        chan1,
		name:      "pipe-tun-1",
		mtu:       mtu,
		events:    events2,
		batchSize: batch,
	}

	return tun1, tun2
}

func (p *pipeTun) File() *os.File { return nil }

func (p *pipeTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (n int, err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, ErrReadOnClosedPipe
	}
	p.mu.Unlock()

	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}

	if len(sizes) < len(bufs) {
		bufs = bufs[:len(sizes)]
	}

	// Read at least one packet (blocking)
	buf, ok := <-p.rx
	if !ok {
		return 0, ErrReadOnClosedPipe
	}

	// Copy data into the first buffer
	copyLen := len(buf)
	if offset+copyLen > len(bufs[0]) {
		copyLen = max(len(bufs[0])-offset, 0)
	}
	if copyLen > 0 {
		copy(bufs[0][offset:offset+copyLen], buf)
	}
	sizes[0] = copyLen

	return 1, nil
}

func (p *pipeTun) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}

	// Write all buffers to the transmit channel (other end reads from this)
	for i, buf := range bufs {
		if offset >= len(buf) {
			continue
		}

		// Copy the data (to avoid sharing underlying arrays)
		data := make([]byte, len(buf)-offset)
		copy(data, buf[offset:])

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return i, ErrWriteOnClosedPipe
		}
		// Block until we can send
		p.tx <- data
		p.mu.Unlock()
	}

	return len(bufs), nil
}

func (p *pipeTun) MTU() (int, error) {
	return p.mtu, nil
}

func (p *pipeTun) Name() (string, error) {
	return p.name, nil
}

func (p *pipeTun) Events() <-chan Event {
	return p.events
}

func (p *pipeTun) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.events)
	close(p.tx) // Close transmit channel - other end will see this on read

	return nil
}

func (p *pipeTun) BatchSize() int {
	return p.batchSize
}
