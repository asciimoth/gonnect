package gonnect_test

import (
	"errors"
	"syscall"
	"testing"

	"github.com/asciimoth/gonnect"
)

func TestListenConfigMergeChainsControl(t *testing.T) {
	var calls []string
	base := &gonnect.ListenConfig{
		Control: func(network, address string, _ syscall.RawConn) error {
			calls = append(calls, "base:"+network+":"+address)
			return nil
		},
	}
	other := &gonnect.ListenConfig{
		Control: func(network, address string, _ syscall.RawConn) error {
			calls = append(calls, "other:"+network+":"+address)
			return nil
		},
	}

	merged := base.Merge(other)
	if merged == base || merged == other {
		t.Fatal("Merge returned one of its inputs, want a new ListenConfig")
	}
	if merged.Control == nil {
		t.Fatal("Merge Control = nil, want chained callback")
	}
	if err := merged.Control("tcp4", "127.0.0.1:0", nil); err != nil {
		t.Fatalf("merged Control error = %v", err)
	}

	want := []string{"base:tcp4:127.0.0.1:0", "other:tcp4:127.0.0.1:0"}
	if len(calls) != len(want) {
		t.Fatalf("Control calls = %#v, want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("Control calls = %#v, want %#v", calls, want)
		}
	}
}

func TestListenConfigMergeStopsOnControlError(t *testing.T) {
	wantErr := errors.New("control failed")
	var otherCalled bool

	merged := (&gonnect.ListenConfig{
		Control: func(string, string, syscall.RawConn) error {
			return wantErr
		},
	}).Merge(&gonnect.ListenConfig{
		Control: func(string, string, syscall.RawConn) error {
			otherCalled = true
			return nil
		},
	})

	if err := merged.Control(
		"tcp",
		"localhost:0",
		nil,
	); !errors.Is(
		err,
		wantErr,
	) {
		t.Fatalf("merged Control error = %v, want %v", err, wantErr)
	}
	if otherCalled {
		t.Fatal(
			"merged Control called second callback after first returned error",
		)
	}
}

func TestListenConfigMergeNilInputs(t *testing.T) {
	if merged := (*gonnect.ListenConfig)(nil).Merge(nil); merged == nil {
		t.Fatal("nil Merge returned nil, want empty ListenConfig")
	} else if merged.Control != nil {
		t.Fatal("nil Merge Control != nil")
	}

	var called bool
	merged := (*gonnect.ListenConfig)(nil).Merge(&gonnect.ListenConfig{
		Control: func(string, string, syscall.RawConn) error {
			called = true
			return nil
		},
	})
	if merged.Control == nil {
		t.Fatal("Merge with one Control returned nil Control")
	}
	if err := merged.Control("tcp", "localhost:0", nil); err != nil {
		t.Fatalf("merged Control error = %v", err)
	}
	if !called {
		t.Fatal("merged Control did not call non-nil callback")
	}
}
