// nolint
package tun

import (
	"os"
	"testing"
	"time"
)

func TestJoinerSplitterDetachedTunComplexTopologyChanges(t *testing.T) {
	root := NewJoiner(testDebugPool(t))
	defer root.Close()
	left := NewSplitter(testDebugPool(t))
	defer left.Close()
	right := NewSplitter(testDebugPool(t))
	defer right.Close()
	branch := NewJoiner(testDebugPool(t))
	defer branch.Close()

	rootDefault := newMockTun(2, 1450, 0, 0)
	branchDefault := newMockTun(3, 1400, 0, 0)
	edge := newMockTun(5, 1300, 0, 0)

	left.SetRouter(&staticSplitRouter{targets: []int{1}})
	right.SetRouter(&staticSplitRouter{targets: []int{2}})

	if err := right.Attach(edge); err != nil {
		t.Fatalf("right.Attach(edge) error = %v", err)
	}
	rightFront2 := right.Get(2)
	assertTunEvent(t, "right frontend 2 initial", rightFront2.Events(), EventUp)
	rightDetached2 := Detach(rightFront2)
	assertTunEvent(
		t,
		"right detached 2 initial",
		rightDetached2.Events(),
		EventUp,
	)
	assertTunShape(
		t,
		"right frontend 2 after edge attach",
		rightFront2,
		0,
		0,
		1300,
		5,
	)
	assertTunShape(
		t,
		"right detached 2 after edge attach",
		rightDetached2,
		0,
		0,
		1300,
		5,
	)

	if err := branch.AttachDefault(branchDefault); err != nil {
		t.Fatalf("branch.AttachDefault() error = %v", err)
	}
	assertJoinerEvent(t, branch, EventMTUUpdate)
	assertTunShape(t, "branch after default", branch, 256, 256, 1400, 3)

	if err := branch.AttachSecondary(rightDetached2); err != nil {
		t.Fatalf("branch.AttachSecondary(rightDetached2) error = %v", err)
	}
	assertJoinerEvent(t, branch, EventMTUUpdate)
	assertTunShape(t, "branch after right attach", branch, 256, 256, 1300, 5)

	if err := left.Attach(branch); err != nil {
		t.Fatalf("left.Attach(branch) error = %v", err)
	}
	leftFront1 := left.Get(1)
	assertTunEvent(t, "left frontend 1 initial", leftFront1.Events(), EventUp)
	leftDetached1 := Detach(leftFront1)
	assertTunEvent(
		t,
		"left detached 1 initial",
		leftDetached1.Events(),
		EventUp,
	)
	assertTunShape(
		t,
		"left frontend 1 after branch attach",
		leftFront1,
		256,
		256,
		1300,
		5,
	)
	assertTunShape(
		t,
		"left detached 1 after branch attach",
		leftDetached1,
		256,
		256,
		1300,
		5,
	)

	if err := root.AttachDefault(rootDefault); err != nil {
		t.Fatalf("root.AttachDefault() error = %v", err)
	}
	assertJoinerEvent(t, root, EventMTUUpdate)
	assertTunShape(t, "root after default", root, 256, 256, 1450, 2)

	if err := root.AttachSecondary(leftDetached1); err != nil {
		t.Fatalf("root.AttachSecondary(leftDetached1) error = %v", err)
	}
	assertJoinerEvent(t, root, EventMTUUpdate)
	assertTunShape(t, "root after left attach", root, 256, 256, 1300, 5)

	edgeIP := [4]byte{10, 88, 0, 2}
	peerIP := [4]byte{10, 88, 0, 1}
	assertTopologyFlow(
		t,
		"initial left-1/right-2 edge path",
		root,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	leftFront2 := left.Get(2)
	assertTunEvent(t, "left frontend 2 initial", leftFront2.Events(), EventUp)
	leftDetached2 := Detach(leftFront2)
	assertTunEvent(
		t,
		"left detached 2 initial",
		leftDetached2.Events(),
		EventUp,
	)
	assertTunShape(
		t,
		"left detached 2 before root attach",
		leftDetached2,
		256,
		256,
		1300,
		5,
	)
	if err := root.AttachSecondary(leftDetached2); err != nil {
		t.Fatalf("root.AttachSecondary(leftDetached2) error = %v", err)
	}
	assertNoTunEvent(
		t,
		"root after equal-MTU leftDetached2 attach",
		root.Events(),
	)
	assertTunShape(
		t,
		"root after leftDetached2 attach",
		root,
		256,
		256,
		1300,
		5,
	)

	left.ResetRouter(&staticSplitRouter{targets: []int{2}})
	assertTopologyFlow(
		t,
		"router moved edge path to left frontend 2",
		root,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := branch.Detach(rightDetached2); err != nil {
		t.Fatalf("branch.Detach(rightDetached2) error = %v", err)
	}
	assertTunEventEventually(
		t,
		"root after right branch detach",
		root.Events(),
		EventMTUUpdate,
	)
	assertTunShape(t, "branch after right detach", branch, 256, 256, 1400, 3)
	assertTunShape(
		t,
		"left frontend 2 after right detach",
		leftFront2,
		256,
		256,
		1400,
		3,
	)
	assertTunShape(t, "root after right detach", root, 256, 256, 1400, 5)
	assertWriteDeliveredTo(
		t,
		"detached right branch falls back to branch default",
		root,
		edgeIP,
		peerIP,
		branchDefault,
	)
	assertRoutedWriteDropped(
		t,
		"detached right branch no longer writes edge",
		root,
		edgeIP,
		peerIP,
		edge,
	)

	rightReplacement := Detach(rightFront2)
	assertTunEvent(
		t,
		"right replacement initial",
		rightReplacement.Events(),
		EventUp,
	)
	assertTunShape(
		t,
		"right replacement before attach",
		rightReplacement,
		0,
		0,
		1300,
		5,
	)
	if err := branch.AttachSecondary(rightReplacement); err != nil {
		t.Fatalf("branch.AttachSecondary(rightReplacement) error = %v", err)
	}
	assertTunEventEventually(
		t,
		"root after right replacement attach",
		root.Events(),
		EventMTUUpdate,
	)
	assertTunShape(
		t,
		"branch after right replacement",
		branch,
		256,
		256,
		1300,
		5,
	)
	assertTunShape(t, "root after right replacement", root, 256, 256, 1300, 5)
	assertTopologyFlow(
		t,
		"edge path after right replacement",
		root,
		edge,
		edgeIP,
		peerIP,
		edge,
	)

	if err := left.Detach(); err != nil {
		t.Fatalf("left.Detach() error = %v", err)
	}
	assertTunEventEventually(
		t,
		"root after left backend detach",
		root.Events(),
		EventMTUUpdate,
	)
	assertTunMTUErr(t, "branch closed by left detach", branch, os.ErrClosed)
	assertTunShape(
		t,
		"left frontend 2 after backend detach",
		leftFront2,
		256,
		256,
		1500,
		256,
	)
	assertTunShape(t, "root after left backend detach", root, 256, 256, 1450, 5)
	assertRoutedWriteDropped(
		t,
		"left backend detach drops learned edge route",
		root,
		edgeIP,
		peerIP,
		edge,
	)
	assertUnknownRoutesToDefault(
		t,
		"root unknown route after left detach",
		root,
		rootDefault,
	)
}

func assertTunShape(
	t *testing.T,
	label string,
	tun Tun,
	wantMRO int,
	wantMWO int,
	wantMTU int,
	wantBatch int,
) {
	t.Helper()
	if got := tun.MRO(); got != wantMRO {
		t.Fatalf("%s: MRO() = %d, want %d", label, got, wantMRO)
	}
	if got := tun.MWO(); got != wantMWO {
		t.Fatalf("%s: MWO() = %d, want %d", label, got, wantMWO)
	}
	assertTunMTU(t, label, tun, wantMTU)
	assertTunBatch(t, label, tun, wantBatch)
}

func assertTunEventEventually(
	t *testing.T,
	label string,
	events <-chan Event,
	want Event,
) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got, ok := <-events:
			if !ok {
				t.Fatalf("%s: Events() closed, want %v", label, want)
			}
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("%s: timed out waiting for event %v", label, want)
		}
	}
}
