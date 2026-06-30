// nolint
package tun

import (
	"errors"
	"os"
	"testing"
)

func TestCallbackTUN(t *testing.T) {
	readErr := errors.New("read")
	writeErr := errors.New("write")
	base := &fakeTun{
		readN:    2,
		readErr:  readErr,
		writeN:   3,
		writeErr: writeErr,
	}
	var readN, writeN int
	var gotReadErr, gotWriteErr error
	cb := &CallbackTUN{
		Tun: base,
		OnRead: func(n int, err error) {
			readN = n
			gotReadErr = err
		},
		OnWrite: func(n int, err error) {
			writeN = n
			gotWriteErr = err
		},
	}
	if cb.IsNative() {
		t.Fatal("CallbackTUN IsNative() = true, want false")
	}
	if n, err := cb.Read(nil, nil, 0); n != 2 || !errors.Is(err, readErr) {
		t.Fatalf("Read = %d, %v, want 2 readErr", n, err)
	}
	if readN != 2 || !errors.Is(gotReadErr, readErr) {
		t.Fatalf("OnRead = %d, %v, want 2 readErr", readN, gotReadErr)
	}
	if n, err := cb.Write(nil, 0); n != 3 || !errors.Is(err, writeErr) {
		t.Fatalf("Write = %d, %v, want 3 writeErr", n, err)
	}
	if writeN != 3 || !errors.Is(gotWriteErr, writeErr) {
		t.Fatalf("OnWrite = %d, %v, want 3 writeErr", writeN, gotWriteErr)
	}
}

func TestSplitterFrontendAccessorsAndState(t *testing.T) {
	s := NewSplitter(nil, nil)
	defer s.Close()
	f := s.Get(1)
	if f == nil {
		t.Fatal("Get(1) = nil")
	}
	if s.Get(0) != nil || s.Get(splitterFrontendCount+1) != nil {
		t.Fatal("Get accepted invalid index")
	}
	if f.File() != nil || f.IsNative() {
		t.Fatal("split frontend native accessors returned unexpected values")
	}
	if f.MWO() != splitterDefaultOffset || f.MRO() != splitterDefaultOffset {
		t.Fatalf("split frontend offsets = %d/%d", f.MWO(), f.MRO())
	}
	if mtu, err := f.MTU(); err != nil || mtu != splitterDefaultMTU {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if name, err := f.Name(); err != nil || name != "TunSplitter" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	if f.BatchSize() != splitterDefaultBatch {
		t.Fatalf("BatchSize = %d, want %d", f.BatchSize(), splitterDefaultBatch)
	}
	if up, err := f.IsUp(); err != nil || !up {
		t.Fatalf("IsUp = %v, %v, want true nil", up, err)
	}
	if err := f.Down(); err != nil {
		t.Fatalf("Down error = %v", err)
	}
	if up, err := f.IsUp(); err != nil || up {
		t.Fatalf("IsUp after Down = %v, %v, want false nil", up, err)
	}
	if err := f.Up(); err != nil {
		t.Fatalf("Up error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if _, err := f.IsUp(); !errors.Is(err, ErrSplitterFrontendClosed) {
		t.Fatalf(
			"IsUp after Close error = %v, want ErrSplitterFrontendClosed",
			err,
		)
	}
}

func TestJoinerAccessorsAndClosedState(t *testing.T) {
	j := NewJoiner(nil, nil)
	if j.File() != nil || j.IsNative() {
		t.Fatal("joiner native accessors returned unexpected values")
	}
	if j.MWO() != joinerOffset || j.MRO() != joinerOffset {
		t.Fatalf("joiner offsets = %d/%d", j.MWO(), j.MRO())
	}
	if mtu, err := j.MTU(); err != nil || mtu != joinerDefaultMTU {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if name, err := j.Name(); err != nil || name != "TunJoiner" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	if j.BatchSize() != joinerDefaultBatch {
		t.Fatalf("BatchSize = %d, want %d", j.BatchSize(), joinerDefaultBatch)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if _, err := j.MTU(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("MTU after Close error = %v, want ErrJoinerClosed", err)
	}
	if _, err := j.Name(); !errors.Is(err, ErrJoinerClosed) {
		t.Fatalf("Name after Close error = %v, want ErrJoinerClosed", err)
	}
}

type fakeTun struct {
	readN    int
	readErr  error
	writeN   int
	writeErr error
}

func (t *fakeTun) File() *os.File { return nil }
func (t *fakeTun) IsNative() bool { return false }
func (t *fakeTun) Read([][]byte, []int, int) (int, error) {
	return t.readN, t.readErr
}
func (t *fakeTun) Write([][]byte, int) (int, error) {
	return t.writeN, t.writeErr
}
func (t *fakeTun) MWO() int { return 0 }
func (t *fakeTun) MRO() int { return 0 }
func (t *fakeTun) MTU() (int, error) {
	return 1280, nil
}
func (t *fakeTun) Name() (string, error) {
	return "fake", nil
}
func (t *fakeTun) Events() <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}
func (t *fakeTun) Close() error { return nil }
func (t *fakeTun) BatchSize() int {
	return 1
}
