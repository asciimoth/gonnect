package tun

import (
	"sync"
)

// Copy copies packets bidirectionally between two Tun implementations.
// It uses the batch nature of the Tun interface for optimal performance.
// Copy blocks until one of the Tuns is closed or encounters an error,
// then closes both Tuns and returns the first error encountered (if any).
func Copy(a, b Tun) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer a.Close() // nolint
		errCh <- copyOneWay(a, b, max(a.MRO(), b.MWO()))
	})
	wg.Go(func() {
		defer b.Close() // nolint
		errCh <- copyOneWay(b, a, max(b.MRO(), a.MWO()))
	})
	wg.Wait()
	close(errCh)
	_ = a.Close()
	_ = b.Close()
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// copyOneWay copies packets from src to dst using batch operations.
// It returns when src is closed or an error occurs.
func copyOneWay(src, dst Tun, offset int) error {
	readBatch := batchSizeOf(src)

	mtu, err := src.MTU()
	if err != nil {
		mtu = 1500
	}
	if dstMTU, err := dst.MTU(); err == nil && dstMTU > mtu {
		mtu = dstMTU
	}

	// Allocate buffers with room for the offset.
	bufs := make([][]byte, readBatch)
	sizes := make([]int, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+offset)
	}

	dataBufs := make([][]byte, readBatch)
	writeBufs := make([][]byte, readBatch)
	for i := range dataBufs {
		dataBufs[i] = make([]byte, mtu+offset)
	}

	for {
		n, err := src.Read(bufs, sizes, offset)
		if err != nil {
			if isRetryableReadError(err) {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}

		for i := range n {
			// Copy from read buffer (at offset) to write buffer (at offset)
			copy(
				dataBufs[i][offset:offset+sizes[i]],
				bufs[i][offset:offset+sizes[i]],
			)
			// Slice to include the offset region so dst.Write can access data at offset
			writeBufs[i] = dataBufs[i][:offset+sizes[i]]
		}

		if err := writePackets(dst, writeBufs[:n], offset); err != nil {
			return err
		}
	}
}
