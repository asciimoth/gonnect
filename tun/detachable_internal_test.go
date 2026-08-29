package tun

import (
	"errors"
	"os"
	"testing"

	"github.com/asciimoth/bufpool"
)

type detachableTestPool struct{}

func (detachableTestPool) Get(n int) []byte { return make([]byte, n) }

func (detachableTestPool) Put([]byte) {}

type namedNativeTun struct {
	fakeTun
	file   *os.File
	events chan Event
}

func (t *namedNativeTun) File() *os.File { return t.file }

func (t *namedNativeTun) IsNative() bool { return true }

func (t *namedNativeTun) MWO() int { return 4 }

func (t *namedNativeTun) MRO() int { return 6 }

func (t *namedNativeTun) BatchSize() int { return 3 }

func (t *namedNativeTun) Events() <-chan Event { return t.events }

func TestDetachedTunStateAccessors(t *testing.T) {
	base := &namedNativeTun{
		file:   os.Stdin,
		events: make(chan Event),
	}
	wrapper := Detach(base, nil, nil)
	t.Cleanup(func() {
		_ = wrapper.Close()
		close(base.events)
		wrapper.Wait()
	})

	if wrapper.File() != os.Stdin {
		t.Fatal("File() did not delegate to wrapped Tun")
	}
	if !wrapper.IsNative() {
		t.Fatal("IsNative() = false, want true")
	}
	if wrapper.MWO() != 4 || wrapper.MRO() != 6 {
		t.Fatalf("offsets = %d/%d, want 4/6", wrapper.MWO(), wrapper.MRO())
	}
	if wrapper.BatchSize() != 3 {
		t.Fatalf("BatchSize() = %d, want 3", wrapper.BatchSize())
	}
	if up, err := wrapper.IsUp(); err != nil || !up {
		t.Fatalf("IsUp() = %v, %v, want true nil", up, err)
	}
	if name, err := wrapper.Name(); err != nil || name != "fake" {
		t.Fatalf("Name() = %q, %v, want fake nil", name, err)
	}

	if err := wrapper.Down(); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if up, err := wrapper.IsUp(); err != nil || up {
		t.Fatalf("IsUp() after Down = %v, %v, want false nil", up, err)
	}
	if _, err := wrapper.Name(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Name() after Down error = %v, want closed error", err)
	}
}

func TestOptionalPool(t *testing.T) {
	if got := optionalPool(nil); got != nil {
		t.Fatalf("optionalPool(nil) = %v, want nil", got)
	}

	var pool bufpool.Pool = detachableTestPool{}
	if got := optionalPool([]bufpool.Pool{pool}); got != pool {
		t.Fatal("optionalPool() did not return first pool")
	}
}
