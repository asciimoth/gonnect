package tun

import (
	"errors"
	"os"
	"strings"
)

var errWriteNoProgress = errors.New("tun: write made no progress")

func batchSizeOf(t Tun) int {
	if batchSize := t.BatchSize(); batchSize > 0 {
		return batchSize
	}
	return 1
}

// IsTunTermError reports whether err should be treated as terminating the
// current Tun use.
//
// It returns false for nil and for known non-terminal errors where callers
// can keep using the same Tun, such as temporary errors and capacity errors
// produced when the read buffer batch is too small. It returns true for all
// other errors, including closed-device errors.
func IsTunTermError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}

	type temporary interface {
		Temporary() bool
	}
	var tempErr temporary
	if errors.As(err, &tempErr) && tempErr.Temporary() {
		return false
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "too many segments") ||
		strings.Contains(msg, "need more buffers") {
		return false
	}

	return true
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
