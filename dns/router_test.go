// nolint
package dns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRouterRejectsWithoutCallbackOrValidBackend(t *testing.T) {
	r := NewRouter(nil)
	defer r.Close()
	backend := newNamedDNS("blue")
	defer backend.Close()

	if err := r.Attach("blue", backend); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if _, err := queryWithTimeout(r, "example.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf(
			"query without router callback error = %v, want ErrNoUpstream",
			err,
		)
	}

	if err := r.AttachRouter(
		func(*Message) string { return "missing" },
	); err != nil {
		t.Fatalf("AttachRouter(missing) error = %v", err)
	}
	if _, err := queryWithTimeout(r, "example.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf(
			"query with missing backend error = %v, want ErrNoUpstream",
			err,
		)
	}

	if err := r.AttachRouter(
		func(*Message) string { return "blue" },
	); err != nil {
		t.Fatalf("AttachRouter(blue) error = %v", err)
	}
	assertRoutedTo(t, r, "example.test.", "blue")

	if err := r.DetachRouter(); err != nil {
		t.Fatalf("DetachRouter() error = %v", err)
	}
	if _, err := queryWithTimeout(r, "example.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("query after DetachRouter error = %v, want ErrNoUpstream", err)
	}
}

func TestRouterAttachDetachReattachBackends(t *testing.T) {
	r := NewRouter(nil)
	defer r.Close()
	blue1 := newNamedDNS("blue-1")
	blue2 := newNamedDNS("blue-2")
	green := newNamedDNS("green")
	defer blue1.Close()
	defer blue2.Close()
	defer green.Close()

	if err := r.AttachRouter(func(msg *Message) string {
		if firstQuestionName(msg) == "green.test." {
			return "green"
		}
		return "blue"
	}); err != nil {
		t.Fatalf("AttachRouter() error = %v", err)
	}
	if err := r.Attach("blue", blue1); err != nil {
		t.Fatalf("Attach blue-1 error = %v", err)
	}
	assertRoutedTo(t, r, "blue.test.", "blue-1")

	if _, err := queryWithTimeout(r, "green.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("query missing green error = %v, want ErrNoUpstream", err)
	}
	if err := r.Attach("green", green); err != nil {
		t.Fatalf("Attach green error = %v", err)
	}
	assertRoutedTo(t, r, "green.test.", "green")

	if err := r.Attach("blue", blue2); err != nil {
		t.Fatalf("reattach blue error = %v", err)
	}
	assertRoutedTo(t, r, "blue.test.", "blue-2")
	if err := r.Detach("blue"); err != nil {
		t.Fatalf("Detach blue error = %v", err)
	}
	if _, err := queryWithTimeout(r, "blue.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("query detached blue error = %v, want ErrNoUpstream", err)
	}
	assertRoutedTo(t, r, "green.test.", "green")
	if err := r.Attach("blue", blue1); err != nil {
		t.Fatalf("reattach blue-1 error = %v", err)
	}
	assertRoutedTo(t, r, "blue.test.", "blue-1")
}

func TestRouterComplexDynamicTopology(t *testing.T) {
	root := NewRouter(nil)
	east := NewRouter(nil)
	west := NewRouter(nil)
	eastA := newNamedDNS("east-a")
	eastB := newNamedDNS("east-b")
	westA := newNamedDNS("west-a")
	westB := newNamedDNS("west-b")
	defer root.Close()
	defer east.Close()
	defer west.Close()
	defer eastA.Close()
	defer eastB.Close()
	defer westA.Close()
	defer westB.Close()

	if _, err := queryWithTimeout(root, "svc.east.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("empty root error = %v, want ErrNoUpstream", err)
	}
	if err := root.Attach("east", east); err != nil {
		t.Fatalf("root attach east error = %v", err)
	}
	if err := root.AttachRouter(
		func(*Message) string { return "east" },
	); err != nil {
		t.Fatalf("root route east error = %v", err)
	}
	if err := east.AttachRouter(
		func(*Message) string { return "primary" },
	); err != nil {
		t.Fatalf("east route primary error = %v", err)
	}
	if _, err := queryWithTimeout(root, "svc.east.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("east without primary error = %v, want ErrNoUpstream", err)
	}

	if err := east.Attach("primary", eastA); err != nil {
		t.Fatalf("east attach primary A error = %v", err)
	}
	assertRoutedTo(t, root, "svc.east.test.", "east-a")
	if err := east.Attach("primary", eastB); err != nil {
		t.Fatalf("east reattach primary B error = %v", err)
	}
	assertRoutedTo(t, root, "svc.east.test.", "east-b")

	if err := root.Attach("west", west); err != nil {
		t.Fatalf("root attach west error = %v", err)
	}
	if err := root.AttachRouter(
		func(*Message) string { return "west" },
	); err != nil {
		t.Fatalf("root route west error = %v", err)
	}
	if _, err := queryWithTimeout(root, "svc.west.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("west without callback error = %v, want ErrNoUpstream", err)
	}
	if err := west.AttachRouter(
		func(*Message) string { return "active" },
	); err != nil {
		t.Fatalf("west route active error = %v", err)
	}
	if err := west.Attach("active", westA); err != nil {
		t.Fatalf("west attach active A error = %v", err)
	}
	assertRoutedTo(t, root, "svc.west.test.", "west-a")
	if err := west.Detach("active"); err != nil {
		t.Fatalf("west detach active error = %v", err)
	}
	if _, err := queryWithTimeout(root, "svc.west.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("west detached active error = %v, want ErrNoUpstream", err)
	}
	if err := west.Attach("active", westB); err != nil {
		t.Fatalf("west reattach active B error = %v", err)
	}
	assertRoutedTo(t, root, "svc.west.test.", "west-b")

	if err := root.DetachRouter(); err != nil {
		t.Fatalf("root detach callback error = %v", err)
	}
	if _, err := queryWithTimeout(root, "svc.west.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("root detached callback error = %v, want ErrNoUpstream", err)
	}
	if err := root.AttachRouter(func(msg *Message) string {
		switch firstQuestionName(msg) {
		case "svc.east.test.":
			return "east"
		case "svc.west.test.":
			return "west"
		default:
			return "unknown"
		}
	}); err != nil {
		t.Fatalf("root reattach callback error = %v", err)
	}
	assertRoutedTo(t, root, "svc.east.test.", "east-b")
	assertRoutedTo(t, root, "svc.west.test.", "west-b")
	if _, err := queryWithTimeout(root, "svc.unknown.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("unknown root route error = %v, want ErrNoUpstream", err)
	}

	if err := root.Detach("east"); err != nil {
		t.Fatalf("root detach east error = %v", err)
	}
	if _, err := queryWithTimeout(root, "svc.east.test."); !errors.Is(
		err,
		ErrNoUpstream,
	) {
		t.Fatalf("detached east route error = %v, want ErrNoUpstream", err)
	}
	assertRoutedTo(t, root, "svc.west.test.", "west-b")
}

func TestRouterMutationsCancelInFlightRequests(t *testing.T) {
	r := NewRouter(nil)
	up := newControlledDNS()
	defer r.Close()
	defer up.Close()

	if err := r.Attach("up", up); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if err := r.AttachRouter(
		func(*Message) string { return "up" },
	); err != nil {
		t.Fatalf("AttachRouter() error = %v", err)
	}
	queryDone := make(chan error, 1)
	go func() {
		_, err := Query(context.Background(), r, aQuery("slow.test."))
		queryDone <- err
	}()
	mustRecv(t, up.started, "router upstream request start")
	if err := r.Detach("up"); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	select {
	case err := <-queryDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("query error = %v, want context canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for canceled router query")
	}
	if !up.sawCancel() {
		t.Fatal("upstream did not observe router cancellation")
	}
}

func TestRouterMutationCancelsStaleRouteResult(t *testing.T) {
	r := NewRouter(nil)
	up := newControlledDNS()
	other := newNamedDNS("other")
	defer r.Close()
	defer up.Close()
	defer other.Close()

	if err := r.Attach("up", up); err != nil {
		t.Fatalf("Attach(up) error = %v", err)
	}
	routeStarted := make(chan struct{})
	routeContinue := make(chan struct{})
	var once sync.Once
	if err := r.AttachRouter(func(*Message) string {
		once.Do(func() { close(routeStarted) })
		<-routeContinue
		return "up"
	}); err != nil {
		t.Fatalf("AttachRouter() error = %v", err)
	}

	queryDone := make(chan error, 1)
	go func() {
		_, err := Query(context.Background(), r, aQuery("stale.test."))
		queryDone <- err
	}()
	mustRecv(t, routeStarted, "router route function start")
	if err := r.Attach("other", other); err != nil {
		t.Fatalf("Attach(other) error = %v", err)
	}
	close(routeContinue)

	select {
	case err := <-queryDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("query error = %v, want context canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for stale router query")
	}
	select {
	case <-up.started:
		t.Fatal("stale route result started backend lookup")
	default:
	}
}

func assertRoutedTo(t *testing.T, d Interface, name, backendName string) {
	t.Helper()
	resp, err := queryWithTimeout(d, name)
	if err != nil {
		t.Fatalf("query %q error = %v", name, err)
	}
	if resp == nil || len(resp.Answers) != 1 {
		t.Fatalf("query %q resp=%#v, want one answer", name, resp)
	}
	if got := string(resp.Answers[0].Data); got != backendName {
		t.Fatalf("query %q routed to %q, want %q", name, got, backendName)
	}
}

func firstQuestionName(msg *Message) string {
	if msg == nil || len(msg.Questions) == 0 {
		return ""
	}
	return msg.Questions[0].Name
}

type namedDNS struct {
	name string
	p    *provider
}

func newNamedDNS(name string) *namedDNS {
	d := &namedDNS{name: name}
	d.p = newProvider(func(root context.Context, req Request) {
		resp := responseFor(req.Message)
		resp.Answers = []Resource{
			{
				Name:  firstQuestionName(req.Message),
				Type:  TypeA,
				Class: ClassIN,
				TTL:   1,
				Data:  []byte(d.name),
			},
		}
		sendResponse(req, resp, nil)
	}, nil)
	return d
}

func (d *namedDNS) Requests() chan<- Request { return d.p.Requests() }
func (d *namedDNS) Close() error             { return d.p.Close() }
