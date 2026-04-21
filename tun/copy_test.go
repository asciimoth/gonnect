// nolint
package tun_test

import (
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/tun"
)

func TestCopy(t *testing.T) {
	t.Parallel()

	for mwo := range 30 {
		for mro := range 30 {
			tun1, tun2 := tun.Pipe(4, 1500, mwo, mro)
			tun3, tun4 := tun.Pipe(4, 1500, mwo, mro)
			defer tun1.Close()
			defer tun2.Close()
			defer tun3.Close()
			defer tun4.Close()

			var wg sync.WaitGroup
			wg.Go(func() {
				_ = tun.Copy(tun2, tun3)
			})
			defer wg.Wait()

			var wgWriters sync.WaitGroup
			var wgReaders sync.WaitGroup

			wgWriters.Go(func() {
				tunWriter(tun1, tun1.MWO(), 100, 1)
			})
			wgWriters.Go(func() {
				tunWriter(tun4, tun4.MWO(), 100, 1)
			})

			wgReaders.Go(func() {
				tunReader(tun4, tun4.MRO(), 100)
			})
			wgReaders.Go(func() {
				tunReader(tun1, tun1.MRO(), 100)
			})

			wgReaders.Wait()

			_ = tun1.Close()
			_ = tun4.Close()

			wgWriters.Wait()
		}
	}
}
