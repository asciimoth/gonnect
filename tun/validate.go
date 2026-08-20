package tun

import (
	"errors"
	"io"
)

var (
	errTunInvalidOffset     = errors.New("tun: invalid packet offset")
	errTunInvalidReadCount  = errors.New("tun: invalid read packet count")
	errTunInvalidPacketSize = errors.New("tun: invalid packet size")
)

func validatePacketOffset(bufs [][]byte, offset int) error {
	if offset < 0 {
		return errTunInvalidOffset
	}
	for i := range bufs {
		if offset > len(bufs[i]) {
			return io.ErrShortBuffer
		}
	}
	return nil
}

func validateReadPacketSizes(
	bufs [][]byte,
	sizes []int,
	offset int,
	count int,
) error {
	if count < 0 || count > len(bufs) || count > len(sizes) {
		return errTunInvalidReadCount
	}
	if offset < 0 {
		return errTunInvalidOffset
	}
	for i := range count {
		if sizes[i] < 0 {
			return errTunInvalidPacketSize
		}
		if offset > len(bufs[i]) || sizes[i] > len(bufs[i])-offset {
			return io.ErrShortBuffer
		}
	}
	return nil
}
