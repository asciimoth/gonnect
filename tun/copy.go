package tun

import (
	"sync"
)

// CopyOffset copies packets bidirectionally between two Tun implementations
// with an explicit offset.
// It uses the batch nature of the Tun interface for optimal performance.
// CopyOffset blocks until one of the Tuns is closed or encounters an error,
// then closes both Tuns and returns the first error encountered (if any).
// The offset parameter specifies the starting position in the buffers for read/write operations.
func CopyOffset(a, b Tun, offset int) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer a.Close() // nolint
		errCh <- copyOneWay(a, b, offset)
	})
	wg.Go(func() {
		defer b.Close() // nolint
		errCh <- copyOneWay(b, a, offset)
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

// Copy copies packets bidirectionally between two Tun implementations.
// It uses the batch nature of the Tun interface for optimal performance.
// Copy blocks until one of the Tuns is closed or encounters an error,
// then closes both Tuns and returns the first error encountered (if any).
// This is a convenience wrapper around CopyOffset with offset=0.
func Copy(a, b Tun) error {
	return CopyOffset(a, b, 0)
}

// copyOneWay copies packets from src to dst using batch operations.
// It returns when src is closed or an error occurs.
func copyOneWay(src, dst Tun, offset int) error {
	batchSize := src.BatchSize()
	if dstBatch := dst.BatchSize(); dstBatch < batchSize {
		batchSize = dstBatch
	}
	if batchSize <= 0 {
		batchSize = 1
	}

	mtu, err := src.MTU()
	if err != nil {
		mtu = 1500
	}
	if dstMTU, err := dst.MTU(); err == nil && dstMTU > mtu {
		mtu = dstMTU
	}

	// Allocate buffers with room for the offset
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, mtu+offset)
	}

	dataBufs := make([][]byte, batchSize)
	writeBufs := make([][]byte, batchSize)
	for i := range dataBufs {
		dataBufs[i] = make([]byte, mtu+offset)
	}

	for {
		n, err := src.Read(bufs, sizes, offset)
		if err != nil {
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

		for written := 0; written < n; {
			// Pass the full slice (including offset region) to dst.Write
			wn, err := dst.Write(writeBufs[written:n], offset)
			if err != nil {
				return err
			}
			written += wn
		}
	}
}
