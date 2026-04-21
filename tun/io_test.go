// nolint
package tun_test

import (
	"io"
	"sync"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/tun"
)

// Verify IO implements io.ReadWriteCloser at compile time
var _ io.ReadWriteCloser = (*tun.IO)(nil)

func TestIOBasic(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	defer tun1.Close()
	defer tun2.Close()

	io1 := tun.NewIO(tun1, pool)
	io2 := tun.NewIO(tun2, pool)
	defer io1.Close()
	defer io2.Close()

	// Verify non-nil
	if io1 == nil || io2 == nil {
		t.Fatal("NewIO() returned nil")
	}
}

func TestIOReadWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		orig, exp string

		mwo, mro   int
		batch, mtu int
	}{
		{
			name: "zero offset",

			orig:  "abcdefghijklmnopqrstuvwxyz",
			exp:   "abcdefghijklmnopqrstuvwxyz",
			batch: 1,
			mtu:   1500,
			mwo:   0,
			mro:   0,
		},
		{
			name: "mwo > mro",

			orig:  "abcdefghijklmnopqrstuvwxyz",
			exp:   "abcdefghijklmnopqrstuvwxyz",
			batch: 1,
			mtu:   1500,
			mwo:   50,
			mro:   1,
		},
		{
			name: "mwo < mro",

			orig:  "abcdefghijklmnopqrstuvwxyz",
			exp:   "abcdefghijklmnopqrstuvwxyz",
			batch: 1,
			mtu:   1500,
			mwo:   1,
			mro:   50,
		},
		{
			name: "small mtu",

			orig:  "abcdefghijklmnopqrstuvwxyz",
			exp:   "abcdefghijklmnopqrstuvwxyz",
			batch: 1,
			mtu:   5,
			mwo:   2,
			mro:   2,
		},
		{
			name: "batch",

			orig:  "abcdefghijklmnopqrstuvwxyz",
			exp:   "abcdefghijklmnopqrstuvwxyz",
			batch: 10,
			mtu:   1500,
			mwo:   0,
			mro:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			tun1, tun2 := tun.Pipe(tt.batch, tt.mtu, tt.mwo, tt.mro)
			defer tun1.Close()
			defer tun2.Close()

			io1 := tun.NewIO(tun1, pool)
			io2 := tun.NewIO(tun2, pool)
			defer io1.Close()
			defer io2.Close()

			resultCh := make(chan string, 3)

			var wgWrite sync.WaitGroup
			var wgRead sync.WaitGroup

			wgWrite.Go(func() {
				texToWriter(tt.orig, io1)
			})
			wgRead.Go(func() {
				resultCh <- textFromReader(io2, 1024)
			})

			wgWrite.Wait()
			io1.Close()
			wgRead.Wait()

			result := <-resultCh
			if result != tt.exp {
				t.Fatal(result)
			}
		})
	}
}

func TestIOBiderectional(t *testing.T) {
	t.Parallel()

	for mwo := range 30 {
		for mro := range 30 {
			func() {
				pool := bufpool.NewTestDebugPool(t)
				defer pool.Close()

				tun1, tun2 := tun.Pipe(1, 3, mwo, mro)
				defer tun1.Close()
				defer tun2.Close()

				io1 := tun.NewIO(tun1, pool)
				io2 := tun.NewIO(tun2, pool)
				defer io1.Close()
				defer io2.Close()

				result1Ch := make(chan string, 2)
				result2Ch := make(chan string, 2)

				var wgWrite sync.WaitGroup
				var wgRead sync.WaitGroup

				wgWrite.Go(func() {
					texToWriter("abcdefghijklmn", io1)
					texToWriter("opqrstuvwxyz", io1)
				})
				wgWrite.Go(func() {
					texToWriter("ABCD", io2)
					texToWriter("EFGH", io2)
					texToWriter("IJKL", io2)
					texToWriter("MNOP", io2)
					texToWriter("QRST", io2)
					texToWriter("UVWXYZ", io2)
				})

				wgRead.Go(func() {
					result1Ch <- textFromReader(io2, 1024)
				})
				wgRead.Go(func() {
					result2Ch <- textFromReader(io1, 1024)
				})

				wgWrite.Wait()
				io1.Close()
				wgRead.Wait()

				result := <-result1Ch
				if result != "abcdefghijklmnopqrstuvwxyz" {
					t.Fatal(result)
				}

				result2 := <-result2Ch
				if result2 != "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
					t.Fatal(result2)
				}
			}()
		}
	}
}
