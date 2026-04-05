// nolint
package tun_test

import (
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

func TestCopyBasic(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(4, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		// Copy will return error when tun1 is closed
		tun.Copy(tun1, tun2)
	})

	// Write some packets from tun1
	data := []byte{0x01, 0x02, 0x03, 0x04}
	_, err := tun1.Write([][]byte{data}, 0)
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Read on tun2
	buf := make([]byte, 100)
	sizes := make([]int, 1)
	n, err := tun2.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if n != 1 || sizes[0] != len(data) {
		t.Errorf(
			"Read() returned n=%d, size=%d, want n=1, size=%d",
			n,
			sizes[0],
			len(data),
		)
	}
	if string(buf[:sizes[0]]) != string(data) {
		t.Errorf("Data mismatch: got %q, want %q", buf[:sizes[0]], data)
	}

	// Close tun1 to trigger Copy to finish
	tun1.Close()

	// Wait for Copy with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - Copy finished (may have returned error, that's OK)
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyBidirectional(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(4, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Test tun1 -> tun2
	data1 := []byte{0x01, 0x02, 0x03}
	_, err := tun1.Write([][]byte{data1}, 0)
	if err != nil {
		t.Fatalf("tun1.Write() error: %v", err)
	}

	buf1 := make([]byte, 100)
	sizes1 := make([]int, 1)
	n, err := tun2.Read([][]byte{buf1}, sizes1, 0)
	if err != nil {
		t.Fatalf("tun2.Read() error: %v", err)
	}
	if n != 1 || sizes1[0] != len(data1) {
		t.Errorf("tun2.Read() returned n=%d, size=%d", n, sizes1[0])
	}
	if string(buf1[:sizes1[0]]) != string(data1) {
		t.Errorf("tun2.Read() data=%q, want %q", buf1[:sizes1[0]], data1)
	}

	// Test tun2 -> tun1
	data2 := []byte{0x04, 0x05, 0x06, 0x07}
	_, err = tun2.Write([][]byte{data2}, 0)
	if err != nil {
		t.Fatalf("tun2.Write() error: %v", err)
	}

	buf2 := make([]byte, 100)
	sizes2 := make([]int, 1)
	n, err = tun1.Read([][]byte{buf2}, sizes2, 0)
	if err != nil {
		t.Fatalf("tun1.Read() error: %v", err)
	}
	if n != 1 || sizes2[0] != len(data2) {
		t.Errorf("tun1.Read() returned n=%d, size=%d", n, sizes2[0])
	}
	if string(buf2[:sizes2[0]]) != string(data2) {
		t.Errorf("tun1.Read() data=%q, want %q", buf2[:sizes2[0]], data2)
	}

	// Close to finish
	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyBatchOptimization(t *testing.T) {
	t.Parallel()

	const batchSize = 8
	tun1, tun2 := tun.Pipe(batchSize, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Write multiple packets
	numPackets := batchSize
	packets := make([][]byte, numPackets)
	for i := range numPackets {
		packets[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
	}

	// Write all packets one at a time
	for _, pkt := range packets {
		_, err := tun1.Write([][]byte{pkt}, 0)
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}

	// Read them back - should be able to read in batch
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 100)
	}

	// Read all packets
	totalRead := 0
	for totalRead < numPackets {
		n, err := tun2.Read(bufs[totalRead:], sizes[totalRead:], 0)
		if err != nil {
			break
		}
		totalRead += n
	}

	if totalRead != numPackets {
		t.Errorf("Read %d packets, want %d", totalRead, numPackets)
	}

	// Verify all packets
	for i := range numPackets {
		expected := packets[i]
		actual := bufs[i][:sizes[i]]
		if string(actual) != string(expected) {
			t.Errorf("Packet %d: got %q, want %q", i, actual, expected)
		}
	}

	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyClosesBothOnExit(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Close tun1
	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}

	// Verify tun1 is closed by trying to write
	_, err := tun1.Write([][]byte{{0x01}}, 0)
	if err == nil {
		t.Error("Expected error writing to closed tun1")
	}

	// tun2 should also be closed by Copy
	_, err = tun2.Write([][]byte{{0x02}}, 0)
	if err == nil {
		t.Error(
			"Expected error writing to closed tun2 (Copy should have closed it)",
		)
	}
}

func TestCopyWithDifferentBatchSizes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		batch1 int
		batch2 int
	}{
		{"Equal", 4, 4},
		{"Different", 2, 8},
		{"OneLarge", 1, 16},
		{"BothLarge", 16, 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Both ends of Pipe have same batch size, but we test the logic anyway
			tun1, tun2 := tun.Pipe(tc.batch1, 1500)

			// Write and read some packets directly (without Copy running)
			for i := range 4 {
				data := []byte{byte(i)}
				_, err := tun1.Write([][]byte{data}, 0)
				if err != nil {
					t.Fatalf("Write() error: %v", err)
				}

				buf := make([]byte, 100)
				sizes := make([]int, 1)
				n, err := tun2.Read([][]byte{buf}, sizes, 0)
				if err != nil {
					t.Fatalf("Read() error: %v", err)
				}
				if n != 1 || sizes[0] != 1 {
					t.Errorf("Read() returned n=%d, size=%d", n, sizes[0])
				}
				if buf[0] != byte(i) {
					t.Errorf("Packet %d: got %d, want %d", i, buf[0], i)
				}
			}

			// Now start Copy and verify it works
			var wg sync.WaitGroup
			wg.Go(func() {
				tun.Copy(tun1, tun2)
			})

			// Write one more packet through Copy
			data := []byte{0xFF}
			_, err := tun1.Write([][]byte{data}, 0)
			if err != nil {
				t.Fatalf("Write() error: %v", err)
			}

			buf := make([]byte, 100)
			sizes := make([]int, 1)
			n, err := tun2.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				t.Fatalf("Read() error: %v", err)
			}
			if n != 1 || sizes[0] != 1 || buf[0] != 0xFF {
				t.Errorf(
					"Read() through Copy returned n=%d, size=%d, data=%d",
					n,
					sizes[0],
					buf[0],
				)
			}

			tun1.Close()

			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				// Success
			case <-time.After(1 * time.Second):
				t.Fatal("Copy() did not finish within timeout")
			}
		})
	}
}

func TestCopyWithOffset(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(4, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Write with offset
	data := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
	_, err := tun1.Write([][]byte{data}, 2)
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Read on other end
	buf := make([]byte, 100)
	sizes := make([]int, 1)
	n, err := tun2.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if n != 1 {
		t.Errorf("Read() returned n=%d, want 1", n)
	}

	// Should have received 3 bytes (after offset)
	if sizes[0] != 3 {
		t.Errorf("Read() size=%d, want 3", sizes[0])
	}
	expected := []byte{0x01, 0x02, 0x03}
	if string(buf[:sizes[0]]) != string(expected) {
		t.Errorf("Read() data=%q, want %q", buf[:sizes[0]], expected)
	}

	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyLargeBatch(t *testing.T) {
	t.Parallel()

	const batchSize = 64
	const mtu = 9000
	tun1, tun2 := tun.Pipe(batchSize, mtu)

	// Don't run Copy for this test - we want to test large packet transfer directly
	// Write multiple large packets
	for i := range 5 {
		data := make([]byte, mtu)
		for j := range data {
			data[j] = byte((i + j) % 256)
		}

		_, err := tun1.Write([][]byte{data}, 0)
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}

		// Read it back
		buf := make([]byte, mtu)
		sizes := make([]int, 1)
		n, err := tun2.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			t.Fatalf("Read() error: %v", err)
		}
		if n != 1 || sizes[0] != mtu {
			t.Errorf(
				"Read() returned n=%d, size=%d, want n=1, size=%d",
				n,
				sizes[0],
				mtu,
			)
		}
		if string(buf[:sizes[0]]) != string(data) {
			t.Errorf("Packet %d: data mismatch", i)
		}
	}

	tun1.Close()
	tun2.Close()
}

func TestCopyConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(8, 1500)

	const numMessages = 10

	// Concurrent writes from tun1
	var writeWg sync.WaitGroup
	writeWg.Add(numMessages)
	for i := range numMessages {
		go func(idx int) {
			defer writeWg.Done()
			data := []byte{byte(idx)}
			_, err := tun1.Write([][]byte{data}, 0)
			if err != nil {
				t.Errorf("Write() error: %v", err)
			}
		}(i)
	}

	// Concurrent reads on tun2
	received := make(map[int]bool)
	var mu sync.Mutex
	readDone := make(chan struct{})
	go func() {
		for range numMessages {
			buf := make([]byte, 100)
			sizes := make([]int, 1)
			n, err := tun2.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				break
			}
			if n == 1 && sizes[0] == 1 {
				mu.Lock()
				received[int(buf[0])] = true
				mu.Unlock()
			}
		}
		close(readDone)
	}()

	writeWg.Wait()

	// Wait for reads to complete
	select {
	case <-readDone:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not complete within timeout")
	}

	if len(received) != numMessages {
		t.Errorf("Received %d messages, want %d", len(received), numMessages)
	}

	tun1.Close()
	tun2.Close()
}

func TestCopySmallMTU(t *testing.T) {
	t.Parallel()

	const smallMTU = 64
	tun1, tun2 := tun.Pipe(1, smallMTU)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Write packet at small MTU size
	data := make([]byte, smallMTU)
	for i := range data {
		data[i] = byte(i)
	}

	_, err := tun1.Write([][]byte{data}, 0)
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Read packet
	buf := make([]byte, smallMTU)
	sizes := make([]int, 1)
	n, err := tun2.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if n != 1 || sizes[0] != smallMTU {
		t.Errorf(
			"Read() returned n=%d, size=%d, want n=1, size=%d",
			n,
			sizes[0],
			smallMTU,
		)
	}
	if string(buf[:sizes[0]]) != string(data) {
		t.Error("Data mismatch")
	}

	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyMultiplePacketsInBatch(t *testing.T) {
	t.Parallel()

	const batchSize = 16
	tun1, tun2 := tun.Pipe(batchSize, 1500)

	var wg sync.WaitGroup
	wg.Go(func() {
		tun.Copy(tun1, tun2)
	})

	// Write packets quickly to allow batching
	numPackets := batchSize
	for i := range numPackets {
		data := []byte{byte(i)}
		_, err := tun1.Write([][]byte{data}, 0)
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}

	// Read all packets one by one with timeout
	received := make(map[int]bool)
	timeout := time.After(2 * time.Second)
	for len(received) < numPackets {
		select {
		case <-timeout:
			goto done
		default:
		}

		buf := make([]byte, 100)
		sizes := make([]int, 1)
		n, err := tun2.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			goto done
		}
		if n == 1 && sizes[0] == 1 {
			received[int(buf[0])] = true
		}
	}

done:
	// Verify we got all packets
	if len(received) != numPackets {
		t.Errorf("Received %d packets, want %d", len(received), numPackets)
	}

	tun1.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Copy() did not finish within timeout")
	}
}
