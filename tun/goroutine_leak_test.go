// nolint
package tun

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJoinerCloseDoesNotLeakGoroutines(t *testing.T) {
	createdByTest := currentGoroutineCreatedByNeedle()
	j := NewJoiner(testDebugPool(t))

	defaultTun, _ := Pipe(1, 1500, 0, 0)
	secondaryTun, _ := Pipe(1, 1500, 0, 0)
	if err := j.AttachDefault(defaultTun); err != nil {
		t.Fatalf("AttachDefault() error = %v", err)
	}
	if err := j.AttachSecondary(secondaryTun); err != nil {
		t.Fatalf("AttachSecondary() error = %v", err)
	}

	waitForGoroutinesWithStack(
		t,
		"Joiner goroutines to start",
		createdByTest,
		2,
		"(*Joiner).readNested",
		"(*Joiner).watchNestedEvents",
		"(*Joiner).writePump",
	)

	if err := j.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	waitForNoGoroutinesWithStack(
		t,
		"Joiner goroutines after Close",
		createdByTest,
		"(*Joiner).readNested",
		"(*Joiner).watchNestedEvents",
		"(*Joiner).writePump",
	)
}

func TestSplitterCloseDoesNotLeakGoroutines(t *testing.T) {
	createdByTest := currentGoroutineCreatedByNeedle()
	s := NewSplitter(testDebugPool(t))
	backend, _ := Pipe(1, 1500, 0, 0)
	if err := s.Attach(backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	f1 := s.Get(1)
	f2 := s.Get(2)
	if f1 == nil || f2 == nil {
		t.Fatal("Get() returned nil frontend")
	}

	waitForGoroutinesWithStack(
		t,
		"Splitter goroutines to start",
		createdByTest,
		2,
		"(*Splitter).readBackend",
		"(*Splitter).watchBackendEvents",
		"(*Splitter).writePump",
		"(*SplitFrontend).refreshEffectiveDoneLocked.func1",
	)

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	waitForNoGoroutinesWithStack(
		t,
		"Splitter goroutines after Close",
		createdByTest,
		"(*Splitter).readBackend",
		"(*Splitter).watchBackendEvents",
		"(*Splitter).writePump",
		"(*SplitFrontend).refreshEffectiveDoneLocked.func1",
	)
}

func TestDetachedTunCloseDoesNotLeakGoroutines(t *testing.T) {
	createdByTest := currentGoroutineCreatedByNeedle()
	wrapped, peer := Pipe(1, 1500, 0, 0)
	root := Detach(wrapped, testDebugPool(t))
	child := Detach(root, testDebugPool(t))

	waitForGoroutinesWithStack(
		t,
		"DetachedTun goroutines to start",
		createdByTest,
		2,
		"(*DetachedTun).readPump",
		"(*DetachedTun).writePump",
		"(*DetachedTun).startEventPump.func1",
		"(*DetachedTun).refreshNestedLocked.func1",
	)

	if err := child.Close(); err != nil {
		t.Fatalf("child Close() error = %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("root Close() error = %v", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("wrapped peer Close() error = %v", err)
	}

	waitForNoGoroutinesWithStack(
		t,
		"DetachedTun goroutines after Close",
		createdByTest,
		"(*DetachedTun).readPump",
		"(*DetachedTun).writePump",
		"(*DetachedTun).startEventPump.func1",
		"(*DetachedTun).refreshNestedLocked.func1",
	)
}

func waitForGoroutinesWithStack(
	t *testing.T,
	label string,
	createdByNeedle string,
	minCount int,
	needles ...string,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if countGoroutinesWithStack(createdByNeedle, needles...) >= minCount {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: got fewer than %d matching goroutines\n%s",
				label,
				minCount,
				goroutineStacksWithStack(createdByNeedle, needles...),
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForNoGoroutinesWithStack(
	t *testing.T,
	label string,
	createdByNeedle string,
	needles ...string,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stacks := goroutineStacksWithStack(createdByNeedle, needles...)
		if strings.TrimSpace(stacks) == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: leaked goroutines:\n%s", label, stacks)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func countGoroutinesWithStack(createdByNeedle string, needles ...string) int {
	count := 0
	for _, stack := range splitGoroutineStacks() {
		if strings.Contains(stack, createdByNeedle) &&
			stackContainsAny(stack, needles...) {
			count++
		}
	}
	return count
}

func goroutineStacksWithStack(
	createdByNeedle string,
	needles ...string,
) string {
	var matches []string
	for _, stack := range splitGoroutineStacks() {
		if strings.Contains(stack, createdByNeedle) &&
			stackContainsAny(stack, needles...) {
			matches = append(matches, stack)
		}
	}
	return strings.Join(matches, "\n\n")
}

func splitGoroutineStacks() []string {
	size := 64 << 10
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Split(strings.TrimSpace(string(buf[:n])), "\n\n")
		}
		size *= 2
	}
}

func stackContainsAny(stack string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(stack, needle) {
			return true
		}
	}
	return false
}

func currentGoroutineCreatedByNeedle() string {
	buf := make([]byte, 128)
	n := runtime.Stack(buf, false)
	lineEnd := bytes.IndexByte(buf[:n], '\n')
	if lineEnd < 0 {
		return " in goroutine <unknown>"
	}
	header := buf[:lineEnd]
	fields := bytes.Fields(header)
	if len(fields) < 2 {
		return " in goroutine <unknown>"
	}
	return " in goroutine " + string(fields[1])
}
