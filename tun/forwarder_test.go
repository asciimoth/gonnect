// nolint
package tun_test

import (
	"sync"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/tun"
)

func TestForwarderChan(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			for i := range 2 {
				func() {
					var wgWriters sync.WaitGroup
					var wgReaders sync.WaitGroup

					var pool bufpool.Pool
					if i > 0 {
						dpool := bufpool.NewTestDebugPool(t)
						pool = dpool
						defer dpool.Close()
					}

					pipeIn, pipeMid1 := tun.Pipe(1, 10, mwo, mro)
					pipeMid2, pipeOut := tun.Pipe(1, 10, mwo, mro)

					frw := tun.NewForwarder(pool)
					defer frw.Stop()

					defer pipeIn.Close()
					defer pipeOut.Close()
					defer pipeMid1.Close()
					defer pipeMid2.Close()

					frw.SetReadTun(pipeMid1)
					frw.SetWriteTun(pipeMid2)

					wgWriters.Go(func() {
						tunWriter(pipeIn, pipeIn.MWO(), 100, 2)
					})

					wgReaders.Go(func() {
						tunReader(pipeOut, pipeOut.MRO(), 100)
					})

					wgReaders.Wait()

					_ = pipeIn.Close()
					_ = pipeOut.Close()
					_ = pipeMid1.Close()
					_ = pipeMid2.Close()

					wgWriters.Wait()
				}()
			}
		}
	}
}

func TestForwarderIO(t *testing.T) {
	t.Parallel()

	for mwo := range 30 {
		for mro := range 30 {
			for i := range 2 {
				_ = mwo
				_ = mro
				func() {
					var pool bufpool.Pool
					if i > 0 {
						dpool := bufpool.NewTestDebugPool(t)
						pool = dpool
						defer dpool.Close()
					}

					pipeIn, pipeMid1 := tun.Pipe(1, 60, mwo, mro)
					pipeMid2, pipeOut := tun.Pipe(1, 60, mwo, mro)
					defer pipeMid2.Close()

					frw := tun.NewForwarder(pool)
					defer frw.Stop()

					defer pipeIn.Close()
					defer pipeOut.Close()
					defer pipeMid1.Close()
					defer pipeMid2.Close()

					frw.SetReadTun(pipeMid1)
					frw.SetWriteTun(pipeMid2)

					io1 := tun.NewIO(pipeIn, pool)
					io2 := tun.NewIO(pipeOut, pool)
					defer io1.Close()
					defer io2.Close()

					result1Ch := make(chan string, 2)
					// result2Ch := make(chan string, 2)

					var wgWrite sync.WaitGroup
					var wgRead sync.WaitGroup

					wgWrite.Go(func() {
						texToWriter("abcdefghijklmn", io1)
						texToWriter("opqrstuvwxyz", io1)
					})
					// wgWrite.Go(func() {
					// 	texToWriter("ABCD", io2)
					// 	texToWriter("EFGH", io2)
					// 	texToWriter("IJKL", io2)
					// 	texToWriter("MNOP", io2)
					// 	texToWriter("QRST", io2)
					// 	texToWriter("UVWXYZ", io2)
					// })

					wgRead.Go(func() {
						result1Ch <- textFromReaderTargetLen(io2, 1024, len("abcdefghijklmnopqrstuvwxyz"))
					})
					// wgRead.Go(func() {
					// 	result2Ch <- textFromReaderTargetLen(io1, 1024, len("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
					// })

					wgRead.Wait()
					_ = io1.Close()
					_ = io2.Close()
					wgWrite.Wait()

					result := <-result1Ch
					if result != "abcdefghijklmnopqrstuvwxyz" {
						t.Fatal(result, len(result))
					}

					// result2 := <-result2Ch
					// if result2 != "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
					// 	t.Fatal(result)
					// }
				}()
			}
		}
	}
}
