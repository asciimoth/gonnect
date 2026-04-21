package tun

import (
	"errors"
	"os"
)

var ErrReadOnClosedChan = errors.Join(
	os.ErrClosed,
	errors.New("tun: read on closed Tun channel"),
)

var ErrWriteOnClosedChan = errors.Join(
	os.ErrClosed,
	errors.New("tun: write on closed Tun channel"),
)

type chanPkg struct {
	bufs   [][]byte
	offset int
}

// Channel is a batched communication channel for byte slices
// that partially implements Tun interface.
// For bi-directional full Tun implementation see Pipe.
type Channel struct {
	closeCh  chan any
	pkgs     chan *chanPkg
	feedback chan int
}

// NewChan builds a new Channel.
func NewChan() *Channel {
	return &Channel{
		closeCh:  make(chan any),
		pkgs:     make(chan *chanPkg),
		feedback: make(chan int),
	}
}

func (p *Channel) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (n int, err error) {
	select {
	case <-p.closeCh:
		err = ErrReadOnClosedChan
		return
	case pkg := <-p.pkgs:
		n = min(len(bufs), len(sizes), len(pkg.bufs))
		for i := range n {
			sizes[i] = copy(bufs[i][offset:], pkg.bufs[i][pkg.offset:])
		}
		p.feedback <- n
	}
	return
}

func (p *Channel) Write(bufs [][]byte, offset int) (written int, err error) {
	for {
		if written >= len(bufs) {
			return
		}
		select {
		case <-p.closeCh:
			err = ErrWriteOnClosedChan
			return
		case p.pkgs <- &chanPkg{
			bufs:   bufs[written:],
			offset: offset,
		}:
			r := <-p.feedback
			written += r
		}
	}
}

func (ch *Channel) Close() (err error) {
	defer func() {
		_ = recover()
	}()
	close(ch.closeCh)
	return nil
}
