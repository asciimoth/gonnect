package tun

import (
	"errors"
	"os"
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
	name                     string
	mtu, mwo, mro, batchSize int
	events                   chan Event

	writer Channel
	reader Channel
}

// Pipe creates two connected Tun implementations that are bound together
// via Channel instances.
// Packets written to one Tun can be read from the other, similar to net.Pipe.
func Pipe(batch int, mtu, mwo, mro int) (Tun, Tun) {
	events1 := make(chan Event, 1)
	events2 := make(chan Event, 1)
	events1 <- EventUp
	events2 <- EventUp

	a2b := NewChan()
	b2a := NewChan()

	tunA := &pipeTun{
		name:      "pipe-tun-0",
		mtu:       mtu,
		batchSize: batch,
		mwo:       mwo,
		mro:       mro,

		events: events1,

		writer: *a2b,
		reader: *b2a,
	}

	tunB := &pipeTun{
		name:      "pipe-tun-1",
		mtu:       mtu,
		batchSize: batch,
		mwo:       mwo,
		mro:       mro,

		events: events2,

		writer: *b2a,
		reader: *a2b,
	}

	return tunA, tunB
}

func (p *pipeTun) MWO() int { return p.mwo }
func (p *pipeTun) MRO() int { return p.mro }

func (p *pipeTun) File() *os.File { return nil }

func (p *pipeTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (n int, err error) {
	if offset < p.mro {
		return 0, errors.New("too small read offset")
	}

	return p.reader.Read(bufs, sizes, offset)
}

func (p *pipeTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < p.mwo {
		return 0, errors.New("too small write offset")
	}

	return p.writer.Write(bufs, offset)
}

func (p *pipeTun) MTU() (int, error) {
	return p.mtu, nil
}

func (p *pipeTun) Name() (string, error) {
	return p.name, nil
}

func (p *pipeTun) BatchSize() int {
	return p.batchSize
}

func (p *pipeTun) Events() <-chan Event {
	return p.events
}

func (p *pipeTun) Close() error {
	_ = p.reader.Close()
	_ = p.writer.Close()
	return nil
}
