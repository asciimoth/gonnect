// nolint
package tun_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/asciimoth/gonnect/tun"
)

func chWriteBatch(ch *tun.Channel, batch [][]byte, offset int) (err error) {
	written := 0
	for written < len(batch) {
		var w int
		w, err = ch.Write(batch[written:], offset)
		written += w
		if err != nil {
			return
		}
	}
	return
}

func chanTextWriter(ch *tun.Channel, text string, batchSize, bufSize int) {
	defer ch.Close()

	data := []byte(text)
	offset := len(data)
	buffs := make([][]byte, batchSize)
	for i := range len(buffs) {
		buffs[i] = make([]byte, offset+bufSize)
	}
	batch := make([][]byte, batchSize)

	written := 0
	for written < len(data) {
		// Filling batch up
		var count int
		str := ""
		for i := range len(batch) {
			buf := buffs[i]
			w := copy(buf[offset:offset+bufSize], data[written:])
			batch[i] = buf[:offset+w]
			str += "'" + string(data[written:written+w]) + "' " // nolint
			written += w
			count += 1
			if written >= len(data) {
				break
			}
		}

		// Logging
		fmt.Println("writing ", str)

		// Writing
		err := chWriteBatch(ch, batch[:count], offset)
		if err != nil {
			return
		}
		offset = max(0, offset-1)
	}
}

func chanTextReader(
	ch *tun.Channel,
	maxOffset, batchSize, bufSize int,
) (text string) {
	data := []byte{}

	sizes := make([]int, batchSize)
	bufs := make([][]byte, batchSize)
	for i := range len(bufs) {
		bufs[i] = make([]byte, maxOffset+bufSize)
	}
	batch := make([][]byte, batchSize)

	offset := 0
	for {
		for i := range batchSize {
			batch[i] = bufs[i][offset : offset+bufSize]
		}
		n, err := ch.Read(batch, sizes, offset)
		if n > 0 {
			str := ""
			for i := range n {
				buf := batch[i][offset : offset+sizes[i]]
				str += "'" + string(buf) + "' " //nolint
				data = append(data, buf...)
			}
			fmt.Println("reading ", str)
		}
		if err != nil {
			return string(data)
		}
	}
}

func TestChan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		orig                           string
		writerBatchSize, writerBufSize int

		exp                            string
		readerBatchSize, readerBufSize int
	}{
		{
			name: "ok1",

			orig:            "abcdefghijklmnopqrstuvwxyz",
			writerBatchSize: 4,
			writerBufSize:   2,

			exp:             "abcdefghijklmnopqrstuvwxyz",
			readerBatchSize: 3,
			readerBufSize:   2,
		},
		{
			name: "ok1",

			orig:            "abcdefghijklmnopqrstuvwxyz",
			writerBatchSize: 3,
			writerBufSize:   2,

			exp:             "abcdefghijklmnopqrstuvwxyz",
			readerBatchSize: 4,
			readerBufSize:   2,
		},
		{
			name: "short reader",

			orig:            "abcdefghijklmnopqrstuvwxyz",
			writerBatchSize: 4,
			writerBufSize:   2,

			exp:             "acegikmoqsuwy",
			readerBatchSize: 3,
			readerBufSize:   1,
		},
		{
			name: "whole batch",

			orig:            "abcdefghijklmnopqrstuvwxyz",
			writerBatchSize: 1,
			writerBufSize:   1000,

			exp:             "abcdefghijklmnopqrstuvwxyz",
			readerBatchSize: 1,
			readerBufSize:   1000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := tun.NewChan()
			var wg sync.WaitGroup
			wg.Go(func() {
				chanTextWriter(
					ch,
					tt.orig,
					tt.writerBatchSize,
					tt.writerBufSize,
				)
			})
			text := chanTextReader(
				ch,
				max(len(tt.orig), len(tt.exp)),
				tt.readerBatchSize,
				tt.readerBufSize,
			)
			if text != tt.exp {
				t.Errorf("orig: %q exp: %q text: %q", tt.orig, tt.exp, text)
			}
			_ = ch.Close()
			wg.Wait()
		})
	}

}
