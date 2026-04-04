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

	// Copy from a to b
	wg.Go(func() {
		defer a.Close() //nolint errcheck
		defer a.Close() //nolint errcheck
		errCh <- copyOneWay(a, b)
	})

	// Copy from b to a
	wg.Go(func() {
		defer a.Close() //nolint errcheck
		defer a.Close() //nolint errcheck
		errCh <- copyOneWay(b, a)
	})

	// Wait for both directions to complete
	wg.Wait()
	close(errCh)

	// Close both Tuns (doublecheck)
	_ = a.Close()
	_ = b.Close()

	// Return the first non-nil error (if any)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// copyOneWay copies packets from src to dst using batch operations.
// It returns when src is closed or an error occurs.
func copyOneWay(src, dst Tun) error {
	batchSize := src.BatchSize()
	if dstBatch := dst.BatchSize(); dstBatch < batchSize {
		batchSize = dstBatch
	}
	if batchSize <= 0 {
		batchSize = 1
	}

	// Determine buffer size based on MTU
	mtu, err := src.MTU()
	if err != nil {
		mtu = 1500 // default MTU
	}
	if dstMTU, err := dst.MTU(); err == nil && dstMTU > mtu {
		mtu = dstMTU
	}

	// Allocate batch buffers
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, mtu)
	}

	// Pre-allocate write buffers to avoid allocations in the loop
	writeBufs := make([][]byte, batchSize)
	dataBufs := make([][]byte, batchSize)
	for i := range dataBufs {
		dataBufs[i] = make([]byte, mtu)
	}

	for {
		// Read a batch of packets from source
		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			return err
		}

		if n == 0 {
			continue
		}

		// Prepare buffers for writing (only the packets we read)
		for i := range n {
			// Copy data to pre-allocated buffer to avoid race conditions
			copy(dataBufs[i][:sizes[i]], bufs[i][:sizes[i]])
			writeBufs[i] = dataBufs[i][:sizes[i]]
		}

		// Write the batch to destination, handling partial writes
		for written := 0; written < n; {
			wn, err := dst.Write(writeBufs[written:n], 0)
			if err != nil {
				return err
			}
			written += wn
		}
	}
}
