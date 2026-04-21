// nolint
package tun_test

import (
	"sync"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/tun"
)

func TestP2P(t *testing.T) {
	t.Parallel()

	for mwo := range 10 {
		for mro := range 10 {
			func() {
				var wgWriters sync.WaitGroup
				var wgReaders sync.WaitGroup

				pool := bufpool.NewTestDebugPool(t)
				defer pool.Close()

				pipeA, pipeMidA := tun.Pipe(1, 10, mwo, mro)
				pipeMidB, pipeB := tun.Pipe(1, 10, mwo, mro)

				p2p := tun.NewP2P(pool)
				defer p2p.Stop()

				defer pipeA.Close()
				defer pipeB.Close()
				defer pipeMidA.Close()
				defer pipeMidB.Close()

				p2p.SetA(pipeMidA)
				p2p.SetB(pipeMidB)

				wgWriters.Go(func() {
					tunWriter(pipeA, pipeA.MWO(), 100, 2)
				})
				wgWriters.Go(func() {
					tunWriter(pipeB, pipeB.MWO(), 100, 2)
				})

				wgReaders.Go(func() {
					tunReader(pipeB, pipeB.MRO(), 100)
				})
				wgReaders.Go(func() {
					tunReader(pipeA, pipeA.MRO(), 100)
				})

				wgReaders.Wait()

				_ = pipeA.Close()
				_ = pipeB.Close()
				_ = pipeMidA.Close()
				_ = pipeMidB.Close()

				wgWriters.Wait()
			}()
		}
	}
}

func TestP2PIO(t *testing.T) {
	t.Parallel()

	for mwo := range 30 {
		for mro := range 30 {
			func() {
				pool := bufpool.NewTestDebugPool(t)
				defer pool.Close()

				pipeIn, pipeMid1 := tun.Pipe(1, 60, mwo, mro)
				pipeMid2, pipeOut := tun.Pipe(1, 60, mwo, mro)
				defer pipeMid2.Close()

				p2p := tun.NewP2P(pool)
				defer p2p.Stop()

				defer pipeIn.Close()
				defer pipeOut.Close()
				defer pipeMid1.Close()
				defer pipeMid2.Close()

				p2p.SetA(pipeMid1)
				p2p.SetB(pipeMid2)

				io1 := tun.NewIO(pipeIn, pool)
				io2 := tun.NewIO(pipeOut, pool)
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
					result1Ch <- textFromReaderTargetLen(io2, 1024, len("abcdefghijklmnopqrstuvwxyz"))
				})
				wgRead.Go(func() {
					result2Ch <- textFromReaderTargetLen(io1, 1024, len("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
				})

				wgRead.Wait()
				_ = io1.Close()
				_ = io2.Close()
				wgWrite.Wait()

				result := <-result1Ch
				if result != "abcdefghijklmnopqrstuvwxyz" {
					t.Fatal(result, len(result))
				}

				result2 := <-result2Ch
				if result2 != "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
					t.Fatal(result2)
				}
			}()
		}
	}
}
