// nolint
package tun_test

import (
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/tun"
)

func TestPipeBasic(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			func() {
				tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
				defer tun1.Close()
				defer tun2.Close()

				// Verify both are non-nil
				if tun1 == nil || tun2 == nil {
					t.Fatal("Pipe() returned nil Tun")
				}

				// Verify File() returns nil for virtual implementation
				if tun1.File() != nil || tun2.File() != nil {
					t.Error("File() should return nil for virtual Tun")
				}

				// Verify names are different
				name1, err := tun1.Name()
				if err != nil {
					t.Fatalf("Name() error: %v", err)
				}
				name2, err := tun2.Name()
				if err != nil {
					t.Fatalf("Name() error: %v", err)
				}
				if name1 == name2 {
					t.Errorf(
						"Expected different names, got %q and %q",
						name1,
						name2,
					)
				}

				// Verify MTU
				mtu1, err := tun1.MTU()
				if err != nil {
					t.Fatalf("MTU() error: %v", err)
				}
				if mtu1 <= 0 {
					t.Errorf("Expected positive MTU, got %d", mtu1)
				}

				// Verify BatchSize
				bs1 := tun1.BatchSize()
				if bs1 <= 0 {
					t.Errorf("Expected positive BatchSize, got %d", bs1)
				}
			}()
		}
	}
}

func TestPipeBidirectional(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			func() {
				tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
				defer tun1.Close()
				defer tun2.Close()

				// Test tun1 -> tun2
				data1 := []byte{0x01, 0x02, 0x03, 0x04}
				bufs1 := [][]byte{data1}

				// Write from tun1
				n, err := tun1.Write(bufs1, 0)
				if err != nil {
					t.Fatalf("tun1.Write() error: %v", err)
				}
				if n != 1 {
					t.Errorf("tun1.Write() returned n=%d, want 1", n)
				}

				// Read on tun2
				buf2 := make([]byte, 100)
				bufs2 := [][]byte{buf2}
				sizes2 := make([]int, 1)

				n, err = tun2.Read(bufs2, sizes2, 0)
				if err != nil {
					t.Fatalf("tun2.Read() error: %v", err)
				}
				if n != 1 {
					t.Errorf("tun2.Read() returned n=%d, want 1", n)
				}
				if sizes2[0] != len(data1) {
					t.Errorf(
						"tun2.Read() size=%d, want %d",
						sizes2[0],
						len(data1),
					)
				}
				if string(buf2[:sizes2[0]]) != string(data1) {
					t.Errorf(
						"tun2.Read() data=%q, want %q",
						buf2[:sizes2[0]],
						data1,
					)
				}

				// Test tun2 -> tun1
				data2 := []byte{0x05, 0x06, 0x07}
				bufs3 := [][]byte{data2}

				n, err = tun2.Write(bufs3, 0)
				if err != nil {
					t.Fatalf("tun2.Write() error: %v", err)
				}
				if n != 1 {
					t.Errorf("tun2.Write() returned n=%d, want 1", n)
				}

				// Read on tun1
				buf1 := make([]byte, 100)
				bufs4 := [][]byte{buf1}
				sizes4 := make([]int, 1)

				n, err = tun1.Read(bufs4, sizes4, 0)
				if err != nil {
					t.Fatalf("tun1.Read() error: %v", err)
				}
				if n != 1 {
					t.Errorf("tun1.Read() returned n=%d, want 1", n)
				}
				if sizes4[0] != len(data2) {
					t.Errorf(
						"tun1.Read() size=%d, want %d",
						sizes4[0],
						len(data2),
					)
				}
				if string(buf1[:sizes4[0]]) != string(data2) {
					t.Errorf(
						"tun1.Read() data=%q, want %q",
						buf1[:sizes4[0]],
						data2,
					)
				}
			}()
		}
	}
}

func TestPipeWithOffset(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			func() {
				tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
				defer tun1.Close()
				defer tun2.Close()

				// Write with offset
				data := []byte{0x00, 0x00, 0x01, 0x02, 0x03}
				bufs := [][]byte{data}

				n, err := tun1.Write(bufs, 2) // Skip first 2 bytes
				if err != nil {
					t.Fatalf("Write() error: %v", err)
				}
				if n != 1 {
					t.Errorf("Write() returned n=%d, want 1", n)
				}

				// Read on other end
				buf := make([]byte, 100)
				readBufs := [][]byte{buf}
				sizes := make([]int, 1)

				n, err = tun2.Read(readBufs, sizes, 0)
				if err != nil {
					t.Fatalf("Read() error: %v", err)
				}

				// Should have received 3 bytes (0x01, 0x02, 0x03)
				if sizes[0] != 3 {
					t.Errorf("Read() size=%d, want 3", sizes[0])
				}
				expected := []byte{0x01, 0x02, 0x03}
				if string(buf[:sizes[0]]) != string(expected) {
					t.Errorf(
						"Read() data=%q, want %q",
						buf[:sizes[0]],
						expected,
					)
				}
			}()
		}
	}
}

func TestPipeClose(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)

			// Close tun1
			err := tun1.Close()
			if err != nil {
				t.Fatalf("Close() error: %v", err)
			}

			// Double close should be OK
			err = tun1.Close()
			if err != nil {
				t.Errorf("Double Close() error: %v", err)
			}

			// Write to closed tun should fail
			_, err = tun1.Write([][]byte{{0x01}}, 0)
			if err == nil {
				t.Error("Expected error writing to closed Tun")
			}

			// Close tun2
			tun2.Close()
		}
	}
}

func TestPipeEvents(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()

			// Check that events channel receives EventUp
			select {
			case event := <-tun1.Events():
				if event != tun.EventUp {
					t.Errorf("Expected EventUp, got %v", event)
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("Timeout waiting for EventUp")
			}

			select {
			case event := <-tun2.Events():
				if event != tun.EventUp {
					t.Errorf("Expected EventUp, got %v", event)
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("Timeout waiting for EventUp")
			}
		}
	}
}

func TestPipeConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()

			var wg sync.WaitGroup
			const numMessages = 10

			// Concurrent writes from tun1
			wg.Add(numMessages)
			for i := range numMessages {
				go func(idx int) {
					defer wg.Done()
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
			for range numMessages {
				buf := make([]byte, 100)
				sizes := make([]int, 1)
				n, err := tun2.Read([][]byte{buf}, sizes, 0)
				if err != nil {
					t.Errorf("Read() error: %v", err)
					continue
				}
				if n != 1 || sizes[0] != 1 {
					t.Errorf("Read() returned n=%d, size=%d", n, sizes[0])
					continue
				}
				mu.Lock()
				received[int(buf[0])] = true
				mu.Unlock()
			}

			wg.Wait()

			if len(received) != numMessages {
				t.Errorf(
					"Received %d messages, want %d",
					len(received),
					numMessages,
				)
			}
		}
	}
}

func TestPipeDifferentBatchSizes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		batch int
	}{
		{"BatchSize1", 1},
		{"BatchSize4", 4},
		{"BatchSize8", 8},
		{"BatchSize16", 16},
		{"BatchSize32", 32},
		{"BatchSize64", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for mwo := range 10 {
				for mro := range 10 {
					tun1, tun2 := tun.Pipe(tc.batch, 1500, mwo, mro)
					defer tun1.Close()
					defer tun2.Close()

					// Verify batch size
					bs1 := tun1.BatchSize()
					if bs1 != tc.batch {
						t.Errorf(
							"tun1.BatchSize() = %d, want %d",
							bs1,
							tc.batch,
						)
					}

					bs2 := tun2.BatchSize()
					if bs2 != tc.batch {
						t.Errorf(
							"tun2.BatchSize() = %d, want %d",
							bs2,
							tc.batch,
						)
					}

					// Test writing multiple packets one at a time and reading them back
					numPackets := tc.batch
					for i := range numPackets {
						data := []byte{byte(i), byte(i + 1), byte(i + 2)}

						// Write single packet
						n, err := tun1.Write([][]byte{data}, 0)
						if err != nil {
							t.Fatalf("Write() error: %v", err)
						}
						if n != 1 {
							t.Errorf("Write() returned n=%d, want 1", n)
						}

						// Read single packet
						buf := make([]byte, 100)
						sizes := make([]int, 1)
						n, err = tun2.Read([][]byte{buf}, sizes, 0)
						if err != nil {
							t.Fatalf("Read() error: %v", err)
						}
						if n != 1 {
							t.Errorf("Read() returned n=%d, want 1", n)
						}
						if sizes[0] != len(data) {
							t.Errorf(
								"Read() size=%d, want %d",
								sizes[0],
								len(data),
							)
						}
						if string(buf[:sizes[0]]) != string(data) {
							t.Errorf(
								"Read() data=%q, want %q",
								buf[:sizes[0]],
								data,
							)
						}
					}
				}
			}
		})
	}
}

func TestPipeDifferentMTUs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		mtu  int
	}{
		{"MTU576", 576},
		{"MTU1280", 1280},
		{"MTU1500", 1500},
		{"MTU4096", 4096},
		{"MTU9000", 9000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for mwo := range 10 {
				for mro := range 10 {
					tun1, tun2 := tun.Pipe(1, tc.mtu, mwo, mro)
					defer tun1.Close()
					defer tun2.Close()

					// Verify MTU
					mtu1, err := tun1.MTU()
					if err != nil {
						t.Fatalf("MTU() error: %v", err)
					}
					if mtu1 != tc.mtu {
						t.Errorf("tun1.MTU() = %d, want %d", mtu1, tc.mtu)
					}

					mtu2, err := tun2.MTU()
					if err != nil {
						t.Fatalf("MTU() error: %v", err)
					}
					if mtu2 != tc.mtu {
						t.Errorf("tun2.MTU() = %d, want %d", mtu2, tc.mtu)
					}

					// Test writing packet at MTU size
					packetSize := tc.mtu
					data := make([]byte, packetSize)
					for i := range data {
						data[i] = byte(i % 256)
					}

					n, err := tun1.Write([][]byte{data}, 0)
					if err != nil {
						t.Fatalf("Write() error: %v", err)
					}
					if n != 1 {
						t.Errorf("Write() returned n=%d, want 1", n)
					}

					// Read packet
					buf := make([]byte, tc.mtu+100)
					sizes := make([]int, 1)
					n, err = tun2.Read([][]byte{buf}, sizes, 0)
					if err != nil {
						t.Fatalf("Read() error: %v", err)
					}
					if n != 1 {
						t.Errorf("Read() returned n=%d, want 1", n)
					}
					if sizes[0] != packetSize {
						t.Errorf(
							"Read() size=%d, want %d",
							sizes[0],
							packetSize,
						)
					}
					if string(buf[:sizes[0]]) != string(data) {
						t.Errorf(
							"Data mismatch: first %d bytes differ",
							sizes[0],
						)
					}
				}
			}
		})
	}
}

func TestPipeBatchWithOffset(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(4, 1500, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()

			// Write 4 packets with offset, one at a time
			numPackets := 4
			for i := range numPackets {
				data := []byte{0x00, 0x00, byte(i), byte(i + 1)}

				n, err := tun1.Write([][]byte{data}, 2) // Skip first 2 bytes
				if err != nil {
					t.Fatalf("Write() error: %v", err)
				}
				if n != 1 {
					t.Errorf("Write() returned n=%d, want 1", n)
				}

				// Read packet
				buf := make([]byte, 100)
				sizes := make([]int, 1)
				n, err = tun2.Read([][]byte{buf}, sizes, 0)
				if err != nil {
					t.Fatalf("Read() error: %v", err)
				}
				if n != 1 {
					t.Errorf("Read() returned n=%d, want 1", n)
				}

				// Verify packet (should have 2 bytes after offset)
				if sizes[0] != 2 {
					t.Errorf("Packet %d: size=%d, want 2", i, sizes[0])
				}
				expected := []byte{byte(i), byte(i + 1)}
				if string(buf[:sizes[0]]) != string(expected) {
					t.Errorf(
						"Packet %d: data=%q, want %q",
						i,
						buf[:sizes[0]],
						expected,
					)
				}
			}
		}
	}
}

func TestPipeLargeBatch(t *testing.T) {
	t.Parallel()

	const batchSize = 128

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(batchSize, 1500, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()

			// Verify batch size
			bs1 := tun1.BatchSize()
			if bs1 != batchSize {
				t.Errorf("tun1.BatchSize() = %d, want %d", bs1, batchSize)
			}

			// Write and read packets one at a time
			for i := range batchSize {
				data := []byte{byte(i % 256)}

				n, err := tun1.Write([][]byte{data}, 0)
				if err != nil {
					t.Fatalf("Write() error: %v", err)
				}
				if n != 1 {
					t.Errorf("Write() returned n=%d, want 1", n)
				}

				// Read packet
				buf := make([]byte, 100)
				sizes := make([]int, 1)
				n, err = tun2.Read([][]byte{buf}, sizes, 0)
				if err != nil {
					t.Fatalf("Read() error: %v", err)
				}
				if n != 1 {
					t.Errorf("Read() returned n=%d, want 1", n)
				}
				if sizes[0] != 1 {
					t.Errorf("Packet %d: size=%d, want 1", i, sizes[0])
				}
				if buf[0] != byte(i%256) {
					t.Errorf("Packet %d: data=%d, want %d", i, buf[0], i%256)
				}
			}
		}
	}
}

func TestPipeSmallMTU(t *testing.T) {
	t.Parallel()

	const smallMTU = 64

	for mwo := range 10 {
		for mro := range 10 {
			tun1, tun2 := tun.Pipe(1, smallMTU, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()

			// Verify MTU
			mtu, err := tun1.MTU()
			if err != nil {
				t.Fatalf("MTU() error: %v", err)
			}
			if mtu != smallMTU {
				t.Errorf("MTU() = %d, want %d", mtu, smallMTU)
			}

			// Write packet at small MTU size
			data := make([]byte, smallMTU)
			for i := range data {
				data[i] = byte(i)
			}

			n, err := tun1.Write([][]byte{data}, 0)
			if err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			if n != 1 {
				t.Errorf("Write() returned n=%d, want 1", n)
			}

			// Read packet
			buf := make([]byte, smallMTU)
			sizes := make([]int, 1)
			n, err = tun2.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				t.Fatalf("Read() error: %v", err)
			}
			if n != 1 {
				t.Errorf("Read() returned n=%d, want 1", n)
			}
			if sizes[0] != smallMTU {
				t.Errorf("Read() size=%d, want %d", sizes[0], smallMTU)
			}
			if string(buf[:sizes[0]]) != string(data) {
				t.Error("Data mismatch")
			}
		}
	}
}
