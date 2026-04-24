package tun

import (
	"errors"
	"strings"
)

var errWriteNoProgress = errors.New("tun: write made no progress")

func batchSizeOf(t Tun) int {
	if batchSize := t.BatchSize(); batchSize > 0 {
		return batchSize
	}
	return 1
}

func isRetryableReadError(err error) bool {
	if err == nil {
		return false
	}

	type temporary interface {
		Temporary() bool
	}
	var tempErr temporary
	if errors.As(err, &tempErr) && tempErr.Temporary() {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "too many segments") ||
		strings.Contains(msg, "need more buffers")
}

func writePackets(t Tun, bufs [][]byte, offset int) error {
	writeBatch := batchSizeOf(t)

	for written := 0; written < len(bufs); {
		chunkEnd := min(written+writeBatch, len(bufs))
		for written < chunkEnd {
			n, err := t.Write(bufs[written:chunkEnd], offset)
			if err != nil {
				return err
			}
			if n <= 0 {
				return errWriteNoProgress
			}
			written += n
		}
	}

	return nil
}
