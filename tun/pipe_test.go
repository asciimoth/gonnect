// nolint
package tun_test

import (
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/tun"
)

func TestPipeBasic(t *testing.T) {
	t.Parallel()

	for mwo := range 100 {
		for mro := range 100 {
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

func pipeOneDirection(t *testing.T, wg *sync.WaitGroup, tun1, tun2 tun.Tun) {
	// Write some packets from tun1
	wdata := []byte{0x01, 0x02, 0x03, 0x04}

	wg.Go(func() {
		wbuf := make([]byte, len(wdata)+tun1.MWO())
		copy(wbuf[tun1.MWO():], wdata)
		_, err := tun1.Write([][]byte{wbuf}, tun1.MWO())
		if err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	})

	// Read on tun2
	rbuf := make([]byte, 1000)
	sizes := make([]int, 1)
	n, err := tun2.Read([][]byte{rbuf}, sizes, tun2.MRO())
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if n != 1 || sizes[0] != len(wdata) {
		t.Errorf(
			"Read() returned n=%d, size=%d, want n=1, size=%d",
			n,
			sizes[0],
			len(wdata),
		)
	}
	rdata := rbuf[tun2.MRO() : tun2.MRO()+sizes[0]]
	if string(rdata) != string(wdata) {
		t.Errorf("Data mismatch: got %q, want %q", rdata, wdata)
	}
}

func TestPipeBidirectional(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			_ = mwo
			_ = mro
			func() {
				var wg sync.WaitGroup

				tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
				// tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
				defer tun1.Close()
				defer tun2.Close()

				wg.Go(func() {
					pipeOneDirection(t, &wg, tun1, tun2)
				})
				wg.Go(func() {
					pipeOneDirection(t, &wg, tun2, tun1)
				})

				wg.Wait()
			}()
		}
	}
}

func TestPipeCount(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			func() {
				var wgWriters sync.WaitGroup
				var wgReaders sync.WaitGroup

				tun1, tun2 := tun.Pipe(1, 1500, mwo, mro)
				defer tun1.Close()
				defer tun2.Close()

				wgWriters.Go(func() {
					tunWriter(tun1, tun1.MWO(), 100, 1)
				})
				wgWriters.Go(func() {
					tunWriter(tun2, tun2.MWO(), 100, 1)
				})

				wgReaders.Go(func() {
					tunReader(tun2, tun2.MRO(), 100)
				})
				wgReaders.Go(func() {
					tunReader(tun1, tun1.MRO(), 100)
				})

				wgReaders.Wait()

				_ = tun1.Close()
				_ = tun2.Close()

				wgWriters.Wait()
			}()
		}
	}
}
