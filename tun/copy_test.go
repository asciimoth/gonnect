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

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(4, 1500, mwo, mro)

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
	}
}

func TestCopyBidirectional(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			_ = mwo
			_ = mro
			tun1, tun2 := tun.Pipe(4, 1500, mwo, mro)

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
				t.Errorf(
					"tun2.Read() data=%q, want %q",
					buf1[:sizes1[0]],
					data1,
				)
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
				t.Errorf(
					"tun1.Read() data=%q, want %q",
					buf2[:sizes2[0]],
					data2,
				)
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
	}
}

func TestCopyBatchOptimization(t *testing.T) {
	t.Parallel()
	for mwo := range 10 {
		for mro := range 10 {
			runTestCopyBatch(t, mwo, mro)
		}
	}
}

func runTestCopyBatch(t *testing.T, mwo, mro int) {
	const batchSize = 8
	tun1, tunA := tun.Pipe(batchSize, 1500, mwo, mro)
	tunB, tun2 := tun.Pipe(batchSize, 1500, mwo, mro)

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = tun.Copy(tunA, tunB)
	})

	numPackets := batchSize
	packets := make([][]byte, numPackets)
	for i := range packets {
		packets[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
		t.Logf("packet %d: %q", i, string(packets[i]))
	}

	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 100)
	}

	errCh := make(chan error, 1)
	go func() {
		totalRead := 0
		for totalRead < numPackets {
			n, err := tun2.Read(bufs[totalRead:], sizes[totalRead:], 0)
			if err != nil {
				errCh <- err
				return
			}
			totalRead += n
			t.Log(totalRead, numPackets)
		}
		t.Log("tun2 read complete")
		errCh <- nil
	}()

	for _, pkt := range packets {
		if _, err := tun1.Write([][]byte{pkt}, 0); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	t.Log("no errors")

	for i := range packets {
		if got := bufs[i][:sizes[i]]; string(got) != string(packets[i]) {
			t.Errorf("Packet %d: got %q, want %q", i, got, packets[i])
		}
	}

	_ = tun1.Close()
	_ = tun2.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second * 10):
		t.Fatal("Copy() did not finish within timeout")
	}
}

func TestCopyWithOffset(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			_ = mwo
			_ = mro
			tun1, tun2 := tun.Pipe(4, 1500, mwo, mro)

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
	}
}

func TestCopyLargeBatch(t *testing.T) {
	t.Parallel()

	const batchSize = 64
	const mtu = 9000
	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(batchSize, mtu, mwo, mro)

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
	}
}

func TestCopyConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(8, 1500, mwo, mro)

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
				t.Errorf(
					"Received %d messages, want %d",
					len(received),
					numMessages,
				)
			}

			tun1.Close()
			tun2.Close()
		}
	}
}

func TestCopySmallMTU(t *testing.T) {
	t.Parallel()

	const smallMTU = 64

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(1, smallMTU, mwo, mro)

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
	}
}

func TestCopyMultiplePacketsInBatch(t *testing.T) {
	t.Parallel()

	const batchSize = 16
	for mwo := range 10 {
		for mro := range 10 {
			_ = mwo
			_ = mro
			tun1, tun2 := tun.Pipe(batchSize, 1500, mwo, mro)

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
	}
}
