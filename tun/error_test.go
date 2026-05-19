package tun_test

import (
	"errors"
	"os"
	"testing"

	"github.com/asciimoth/gonnect/tun"
)

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary" }
func (temporaryError) Temporary() bool { return true }

func TestIsTunTermError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "temporary",
			err:  temporaryError{},
			want: false,
		},
		{
			name: "deadline exceeded",
			err:  os.ErrDeadlineExceeded,
			want: false,
		},
		{
			name: "too many segments",
			err:  errors.New("too many segments"),
			want: false,
		},
		{
			name: "need more buffers",
			err:  errors.New("read failed: need more buffers"),
			want: false,
		},
		{
			name: "closed",
			err:  os.ErrClosed,
			want: true,
		},
		{
			name: "unknown",
			err:  errors.New("route listener failed"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tun.IsTunTermError(tt.err); got != tt.want {
				t.Fatalf(
					"IsTunTermError(%v) = %v, want %v",
					tt.err,
					got,
					tt.want,
				)
			}
		})
	}
}
