// nolint
package tun_test

import (
	"fmt"
	"io"

	"github.com/asciimoth/gonnect/tun"
)

func tunWriter(tun tun.Tun, offset, count, duplicates int) {
	data := make([]byte, offset+2)
	packets := [][]byte{data}
	for i := range count + 1 {
		for range duplicates {
			packets[0][offset] = byte(i)
			fmt.Println("tun write", data)
			_, err := tun.Write(packets, offset)
			if err != nil {
				fmt.Println("tun writer", err)
				return
			}
		}
	}
}

func tunReader(tun tun.Tun, offset, count int) {
	maxVal := 0

	buf := make([]byte, offset+200)
	sizes := make([]int, 1)
	bufs := [][]byte{buf}

	for {
		if maxVal >= count {
			return
		}

		_, err := tun.Read(bufs, sizes, offset)
		if err != nil {
			fmt.Println("tun reader", err)
			return
		}
		fmt.Println("tun read", buf, buf[offset])
		omv := maxVal
		maxVal = max(maxVal, int(buf[offset]))
		if maxVal != omv {
			fmt.Println("reader max:", maxVal)
		}
	}
}

func texToWriter(text string, writer io.Writer) {
	data := []byte(text)
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			fmt.Println("IO written", data[:n])
		}
		if err != nil {
			fmt.Println("text writer stop", err)
			return
		}
		data = data[n:]
	}
}

func textFromReader(reader io.Reader, bufSize int) string {
	data := []byte{}
	for {
		buf := make([]byte, bufSize)
		n, err := reader.Read(buf)
		if n > 0 {
			fmt.Println("IO read", buf[:n])
			data = append(data, buf[:n]...)
		}
		if err != nil {
			fmt.Println("text reader stop", err)
			return string(data)
		}
	}
}

func textFromReaderTargetLen(reader io.Reader, bufsize, tlen int) string {
	data := []byte{}
	for {
		buf := make([]byte, bufsize)
		n, err := reader.Read(buf)
		if n > 0 {
			fmt.Println("IO read", buf[:n])
			data = append(data, buf[:n]...)
			fmt.Println("IO data", string(data))
		}
		if err != nil {
			fmt.Println("text reader stop", err)
			return string(data)
		}
		if len(data) >= tlen {
			return string(data)
		}
	}
}
