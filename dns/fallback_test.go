//nolint:testpackage // These tests verify internal request cancellation.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFallbackRejectsInvalidSlotsAndEmptyConfiguration(t *testing.T) {
	f := NewFallback(nil)
	closeFallbackTest(t, f)

	if _, err := queryWithTimeout(f, "empty.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("empty Fallback query error = %v, want ErrNoUpstream", err)
	}

	upstream := newFallbackResultDNS("unused", RCodeSuccess, nil, nil)
	closeFallbackTest(t, upstream)
	for _, slot := range []int{-1, 0, FallbackSlots + 1, 100} {
		if err := f.Attach(slot, upstream); !errors.Is(
			err,
			ErrInvalidFallbackSlot,
		) {
			t.Errorf(
				"Attach(%d) error = %v, want ErrInvalidFallbackSlot",
				slot,
				err,
			)
		}
		if err := f.Detach(slot); !errors.Is(
			err,
			ErrInvalidFallbackSlot,
		) {
			t.Errorf(
				"Detach(%d) error = %v, want ErrInvalidFallbackSlot",
				slot,
				err,
			)
		}
	}
}

func TestFallbackUsesAscendingAttachedSlotOrder(t *testing.T) {
	log := &fallbackCallLog{}
	errTwo := errors.New("slot 2 failed")
	errSixteen := errors.New("slot 16 failed")
	two := newFallbackResultDNS("two", RCodeSuccess, errTwo, log)
	eight := newFallbackResultDNS("eight", RCodeSuccess, nil, log)
	sixteen := newFallbackResultDNS(
		"sixteen",
		RCodeSuccess,
		errSixteen,
		log,
	)
	closeFallbackTest(t, two)
	closeFallbackTest(t, eight)
	closeFallbackTest(t, sixteen)

	f := NewFallback(nil)
	closeFallbackTest(t, f)
	// Attach in a different order to make sure attach order has no effect.
	for slot, upstream := range map[int]Interface{
		16: sixteen,
		8:  eight,
		2:  two,
	} {
		if err := f.Attach(slot, upstream); err != nil {
			t.Fatalf("Attach(%d) error = %v", slot, err)
		}
	}

	resp, err := queryWithTimeout(f, "order.test.")
	if err != nil {
		t.Fatalf("Fallback query error = %v", err)
	}
	if got := fallbackResponseLabel(resp); got != "eight" {
		t.Fatalf("Fallback response = %q, want slot 8 response", got)
	}
	gotOrder := log.snapshot()
	wantOrder := []string{"two", "eight"}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("upstream call order = %v, want %v", gotOrder, wantOrder)
	}
	if got := sixteen.callCount(); got != 0 {
		t.Fatalf("slot 16 call count = %d, want 0", got)
	}
}

func TestFallbackReturnsLastOfSixteenErrors(t *testing.T) {
	log := &fallbackCallLog{}
	f := NewFallback(nil)
	closeFallbackTest(t, f)

	var lastErr error
	for idx := range FallbackSlots {
		slot := idx + 1
		label := fmt.Sprintf("slot-%02d", slot)
		slotErr := fmt.Errorf("%s error", label)
		lastErr = slotErr
		upstream := newFallbackResultDNS(
			label,
			RCodeServerFailure,
			slotErr,
			log,
		)
		closeFallbackTest(t, upstream)
		if err := f.Attach(slot, upstream); err != nil {
			t.Fatalf("Attach(%d) error = %v", slot, err)
		}
	}

	resp, err := queryWithTimeout(f, "all-fail.test.")
	if !errors.Is(err, lastErr) {
		t.Fatalf("Fallback error = %v, want final error %v", err, lastErr)
	}
	if got := fallbackResponseLabel(resp); got != "slot-16" {
		t.Fatalf("Fallback response = %q, want slot-16 response", got)
	}
	wantOrder := make([]string, 0, FallbackSlots)
	for idx := range FallbackSlots {
		wantOrder = append(wantOrder, fmt.Sprintf("slot-%02d", idx+1))
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("upstream call order = %v, want %v", got, wantOrder)
	}
}

func TestFallbackSkipsDNSErrorAndStopsAtNOERRORResponse(t *testing.T) {
	log := &fallbackCallLog{}
	negative := newFallbackResultDNS(
		"negative",
		RCodeNameError,
		nil,
		log,
	)
	later := newFallbackResultDNS("later", RCodeSuccess, nil, log)
	closeFallbackTest(t, negative)
	closeFallbackTest(t, later)

	f := NewFallback(nil)
	closeFallbackTest(t, f)
	if err := f.Attach(1, negative); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(2, later); err != nil {
		t.Fatal(err)
	}

	resp, err := queryWithTimeout(f, "negative.test.")
	if err != nil {
		t.Fatalf("Fallback query error = %v", err)
	}
	if resp == nil || resp.RCode != RCodeSuccess {
		t.Fatalf("Fallback response = %#v, want NOERROR response", resp)
	}
	if got, want := log.snapshot(), []string{
		"negative",
		"later",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("upstream calls = %v, want %v", got, want)
	}
}

func TestFallbackReturnsLastDNSErrorResponse(t *testing.T) {
	serverFailure := newFallbackResultDNS(
		"server-failure",
		RCodeServerFailure,
		nil,
		nil,
	)
	nameError := newFallbackResultDNS(
		"name-error",
		RCodeNameError,
		nil,
		nil,
	)
	closeFallbackTest(t, serverFailure)
	closeFallbackTest(t, nameError)

	f := NewFallback(nil)
	closeFallbackTest(t, f)
	if err := f.Attach(1, serverFailure); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(9, nameError); err != nil {
		t.Fatal(err)
	}

	resp, err := queryWithTimeout(f, "dns-errors.test.")
	if err != nil {
		t.Fatalf("Fallback query Go error = %v, want nil", err)
	}
	if resp == nil || resp.RCode != RCodeNameError {
		t.Fatalf("Fallback response = %#v, want final name error", resp)
	}
	if got := fallbackResponseLabel(resp); got != "name-error" {
		t.Fatalf("Fallback response = %q, want name-error", got)
	}
}

func TestFallbackTimeoutCancelsAttemptAndUsesNextSlot(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	slow := newFallbackTestDNS("slow", nil, func(
		root context.Context,
		req Request,
	) {
		started <- struct{}{}
		ctx := req.Context
		if ctx == nil {
			ctx = context.Background()
		}
		select {
		case <-ctx.Done():
			canceled <- struct{}{}
			sendResponse(req, nil, ctx.Err())
		case <-root.Done():
			sendResponse(req, nil, root.Err())
		}
	})
	fast := newFallbackResultDNS("fast", RCodeSuccess, nil, nil)
	closeFallbackTest(t, slow)
	closeFallbackTest(t, fast)

	f := NewFallbackWithOptions(FallbackOptions{
		AttemptTimeout: 15 * time.Millisecond,
	}, nil)
	closeFallbackTest(t, f)
	if err := f.Attach(3, slow); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(7, fast); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	resp, err := queryWithTimeout(f, "timeout.test.")
	if err != nil {
		t.Fatalf("Fallback query error = %v", err)
	}
	if got := fallbackResponseLabel(resp); got != "fast" {
		t.Fatalf("Fallback response = %q, want fast", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Fallback took %v, want less than 500ms", elapsed)
	}
	mustRecv(t, started, "slow upstream start")
	mustRecv(t, canceled, "slow upstream cancellation")
}

func TestFallbackRequestCancellationStopsTraversal(t *testing.T) {
	started := make(chan struct{}, 1)
	slow := newFallbackTestDNS("slow", nil, func(
		root context.Context,
		req Request,
	) {
		started <- struct{}{}
		ctx := req.Context
		if ctx == nil {
			ctx = context.Background()
		}
		<-ctx.Done()
		sendResponse(req, nil, ctx.Err())
	})
	later := newFallbackResultDNS("later", RCodeSuccess, nil, nil)
	closeFallbackTest(t, slow)
	closeFallbackTest(t, later)

	f := NewFallbackWithOptions(FallbackOptions{
		AttemptTimeout: time.Hour,
	}, nil)
	closeFallbackTest(t, f)
	if err := f.Attach(1, slow); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(2, later); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Query(ctx, f, aQuery("cancel.test."))
		done <- err
	}()
	mustRecv(t, started, "slow upstream start")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Fallback query error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canceled Fallback query")
	}
	if got := later.callCount(); got != 0 {
		t.Fatalf("later upstream call count = %d, want 0", got)
	}
}

func TestFallbackSupportsLiveAttachDetachAndReplacement(t *testing.T) {
	five := newFallbackResultDNS("five", RCodeSuccess, nil, nil)
	twoA := newFallbackResultDNS("two-a", RCodeSuccess, nil, nil)
	twoB := newFallbackResultDNS("two-b", RCodeSuccess, nil, nil)
	closeFallbackTest(t, five)
	closeFallbackTest(t, twoA)
	closeFallbackTest(t, twoB)

	f := NewFallback(nil)
	if err := f.Attach(5, five); err != nil {
		t.Fatal(err)
	}
	assertFallbackLabel(t, f, "five")
	if err := f.Attach(2, twoA); err != nil {
		t.Fatal(err)
	}
	assertFallbackLabel(t, f, "two-a")
	if err := f.Attach(2, twoB); err != nil {
		t.Fatal(err)
	}
	assertFallbackLabel(t, f, "two-b")
	if err := f.Detach(2); err != nil {
		t.Fatal(err)
	}
	assertFallbackLabel(t, f, "five")
	if err := f.Attach(5, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := queryWithTimeout(f, "detached.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("detached Fallback error = %v, want ErrNoUpstream", err)
	}
	if err := f.Attach(4, twoB); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := f.Attach(1, twoA); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Attach() after Close error = %v, want net.ErrClosed", err)
	}
	if err := f.Detach(1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Detach() after Close error = %v, want net.ErrClosed", err)
	}
	for name, upstream := range map[string]*fallbackTestDNS{
		"five":  five,
		"two-a": twoA,
		"two-b": twoB,
	} {
		if got := upstream.closeCount(); got != 0 {
			t.Errorf("%s close count = %d, want 0", name, got)
		}
	}
	// A direct query proves that Close did not stop an attached upstream.
	resp, err := queryWithTimeout(twoB, "ownership.test.")
	if err != nil || fallbackResponseLabel(resp) != "two-b" {
		t.Fatalf("direct upstream query: resp=%#v err=%v", resp, err)
	}
}

func TestFallbackSlotReplacementCancelsOnlyOldAttempt(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	old := newFallbackTestDNS("old", nil, func(
		root context.Context,
		req Request,
	) {
		started <- struct{}{}
		ctx := req.Context
		if ctx == nil {
			ctx = context.Background()
		}
		<-ctx.Done()
		canceled <- struct{}{}
		sendResponse(req, nil, ctx.Err())
	})
	replacement := newFallbackResultDNS(
		"replacement",
		RCodeSuccess,
		nil,
		nil,
	)
	next := newFallbackResultDNS("next", RCodeSuccess, nil, nil)
	closeFallbackTest(t, old)
	closeFallbackTest(t, replacement)
	closeFallbackTest(t, next)

	f := NewFallbackWithOptions(FallbackOptions{
		AttemptTimeout: time.Hour,
	}, nil)
	closeFallbackTest(t, f)
	if err := f.Attach(1, old); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(2, next); err != nil {
		t.Fatal(err)
	}

	result := make(chan Response, 1)
	go func() {
		msg, err := queryWithTimeout(f, "replace.test.")
		result <- Response{Message: msg, Err: err}
	}()
	mustRecv(t, started, "old upstream start")
	if err := f.Attach(1, replacement); err != nil {
		t.Fatal(err)
	}
	mustRecv(t, canceled, "old upstream cancellation")
	select {
	case got := <-result:
		if got.Err != nil || fallbackResponseLabel(got.Message) != "next" {
			t.Fatalf("in-flight query result = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight query")
	}

	assertFallbackLabel(t, f, "replacement")
	if got := next.callCount(); got != 1 {
		t.Fatalf("next upstream call count = %d, want 1", got)
	}
}

func TestFallbackComposesInNestedDynamicTopology(t *testing.T) {
	log := &fallbackCallLog{}
	outerFail := newFallbackResultDNS(
		"outer-fail",
		RCodeServerFailure,
		errors.New("outer failed"),
		log,
	)
	innerFail := newFallbackResultDNS(
		"inner-fail",
		RCodeServerFailure,
		errors.New("inner failed"),
		log,
	)
	innerGood := newFallbackResultDNS(
		"inner-good",
		RCodeSuccess,
		nil,
		log,
	)
	outerLast := newFallbackResultDNS(
		"outer-last",
		RCodeSuccess,
		nil,
		log,
	)
	closeFallbackTest(t, outerFail)
	closeFallbackTest(t, innerFail)
	closeFallbackTest(t, innerGood)
	closeFallbackTest(t, outerLast)

	inner := NewFallback(nil)
	outer := NewFallback(nil)
	closeFallbackTest(t, inner)
	closeFallbackTest(t, outer)
	if err := inner.Attach(1, innerFail); err != nil {
		t.Fatal(err)
	}
	if err := inner.Attach(16, innerGood); err != nil {
		t.Fatal(err)
	}
	if err := outer.Attach(1, outerFail); err != nil {
		t.Fatal(err)
	}
	if err := outer.Attach(3, inner); err != nil {
		t.Fatal(err)
	}
	if err := outer.Attach(16, outerLast); err != nil {
		t.Fatal(err)
	}

	assertFallbackLabel(t, outer, "inner-good")
	if got, want := log.snapshot(), []string{
		"outer-fail",
		"inner-fail",
		"inner-good",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nested call order = %v, want %v", got, want)
	}

	log.reset()
	if err := inner.Detach(16); err != nil {
		t.Fatal(err)
	}
	assertFallbackLabel(t, outer, "outer-last")
	if got, want := log.snapshot(), []string{
		"outer-fail",
		"inner-fail",
		"outer-last",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nested call order after detach = %v, want %v", got, want)
	}
}

func TestFallbackConcurrentQueriesAndSlotMutations(t *testing.T) {
	primaryA := newFallbackResultDNS("primary-a", RCodeSuccess, nil, nil)
	primaryB := newFallbackResultDNS("primary-b", RCodeSuccess, nil, nil)
	backup := newFallbackResultDNS("backup", RCodeSuccess, nil, nil)
	closeFallbackTest(t, primaryA)
	closeFallbackTest(t, primaryB)
	closeFallbackTest(t, backup)

	f := NewFallbackWithOptions(FallbackOptions{
		AttemptTimeout: 50 * time.Millisecond,
	}, nil)
	closeFallbackTest(t, f)
	if err := f.Attach(1, primaryA); err != nil {
		t.Fatal(err)
	}
	if err := f.Attach(16, backup); err != nil {
		t.Fatal(err)
	}

	const queryCount = 100
	start := make(chan struct{})
	errCh := make(chan error, queryCount+1)
	var wg sync.WaitGroup
	for range queryCount {
		wg.Go(func() {
			<-start
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Second,
			)
			defer cancel()
			resp, err := Query(ctx, f, aQuery("concurrent.test."))
			if err != nil {
				errCh <- err
				return
			}
			switch fallbackResponseLabel(resp) {
			case "primary-a", "primary-b", "backup":
			default:
				errCh <- fmt.Errorf("unexpected response: %#v", resp)
			}
		})
	}
	wg.Go(func() {
		<-start
		for i := range queryCount {
			var err error
			switch i % 3 {
			case 0:
				err = f.Attach(1, primaryA)
			case 1:
				err = f.Attach(1, primaryB)
			case 2:
				err = f.Detach(1)
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	})
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent operation error = %v", err)
	}
}

func closeFallbackTest(t *testing.T, closer interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("test cleanup Close() error = %v", err)
		}
	})
}

func assertFallbackLabel(t *testing.T, d Interface, want string) {
	t.Helper()
	resp, err := queryWithTimeout(d, "fallback.test.")
	if err != nil {
		t.Fatalf("Fallback query error = %v", err)
	}
	if got := fallbackResponseLabel(resp); got != want {
		t.Fatalf("Fallback response = %q, want %q", got, want)
	}
}

func fallbackResponseLabel(msg *Message) string {
	if msg == nil || len(msg.Answers) == 0 {
		return ""
	}
	return string(msg.Answers[0].Data)
}

// fallbackCallLog records a deterministic call order across test upstreams.
type fallbackCallLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *fallbackCallLog) add(entry string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()
}

func (l *fallbackCallLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

func (l *fallbackCallLog) reset() {
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}

// fallbackTestDNS is a small instrumented Interface for Fallback tests.
type fallbackTestDNS struct {
	p         *provider
	calls     atomic.Int64
	closes    atomic.Int64
	closeOnce sync.Once
}

func newFallbackTestDNS(
	label string,
	log *fallbackCallLog,
	handle func(context.Context, Request),
) *fallbackTestDNS {
	d := &fallbackTestDNS{}
	d.p = newProvider(func(root context.Context, req Request) {
		d.calls.Add(1)
		log.add(label)
		handle(root, req)
	}, nil)
	return d
}

func newFallbackResultDNS(
	label string,
	rcode uint8,
	err error,
	log *fallbackCallLog,
) *fallbackTestDNS {
	return newFallbackTestDNS(label, log, func(_ context.Context, req Request) {
		resp := responseFor(req.Message)
		resp.RCode = rcode
		resp.Answers = []Resource{{
			Name:  firstQuestionName(req.Message),
			Type:  TypeTXT,
			Class: ClassIN,
			TTL:   1,
			Data:  []byte(label),
		}}
		sendResponse(req, resp, err)
	})
}

func (d *fallbackTestDNS) Requests() chan<- Request { return d.p.Requests() }

func (d *fallbackTestDNS) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.closes.Add(1)
		err = d.p.Close()
	})
	return err
}

func (d *fallbackTestDNS) callCount() int64  { return d.calls.Load() }
func (d *fallbackTestDNS) closeCount() int64 { return d.closes.Load() }
