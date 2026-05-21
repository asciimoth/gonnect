package gonnect_test

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/asciimoth/gonnect"
)

type lifecycleCloser struct {
	count atomic.Int32
}

func (c *lifecycleCloser) Close() error {
	c.count.Add(1)
	return nil
}

func (c *lifecycleCloser) closes() int32 {
	return c.count.Load()
}

type lifecycleUpDown struct {
	ups   atomic.Int32
	downs atomic.Int32
}

func (u *lifecycleUpDown) Up() error {
	u.ups.Add(1)
	return nil
}

func (u *lifecycleUpDown) Down() error {
	u.downs.Add(1)
	return nil
}

func (u *lifecycleUpDown) IsUp() (bool, error) {
	return u.ups.Load() > u.downs.Load(), nil
}

func TestNetworkCloserSubscriberImplementations(t *testing.T) {
	tests := []struct {
		name string
		net  interface {
			gonnect.Network
			gonnect.UpDown
			io.Closer
			gonnect.CloserSubscriber
		}
	}{
		{
			name: "DetachedNetwork",
			net:  gonnect.DetachNetwork(&gonnect.RejectNetwork{}),
		},
		{name: "LoopbackNetwork", net: gonnect.NewLoopbackNetwok()},
		{name: "Router", net: gonnect.NewRouter()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept := &lifecycleCloser{}
			removed := &lifecycleCloser{}

			unsubscribeKept, err := tt.net.SubscribeCloser(kept)
			if err != nil {
				t.Fatalf("SubscribeCloser() error = %v", err)
			}
			defer unsubscribeKept()

			unsubscribeRemoved, err := tt.net.SubscribeCloser(removed)
			if err != nil {
				t.Fatalf("SubscribeCloser() error = %v", err)
			}
			unsubscribeRemoved()
			unsubscribeRemoved()

			if err := tt.net.Down(); err != nil {
				t.Fatalf("Down() error = %v", err)
			}
			if kept.closes() != 0 {
				t.Fatalf(
					"subscribed closer closes after Down = %d, want 0",
					kept.closes(),
				)
			}

			if err := tt.net.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if kept.closes() != 1 {
				t.Fatalf("subscribed closer closes = %d, want 1", kept.closes())
			}
			if removed.closes() != 0 {
				t.Fatalf(
					"unsubscribed closer closes = %d, want 0",
					removed.closes(),
				)
			}

			late := &lifecycleCloser{}
			unsubscribeLate, err := tt.net.SubscribeCloser(late)
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf(
					"SubscribeCloser() error = %v, want net.ErrClosed",
					err,
				)
			}
			if unsubscribeLate != nil {
				t.Fatal("SubscribeCloser() returned unsubscribe after error")
			}
			if late.closes() != 1 {
				t.Fatalf("late closer closes = %d, want 1", late.closes())
			}
		})
	}
}

func TestNetworkUpDownSubscriberImplementations(t *testing.T) {
	tests := []struct {
		name string
		net  interface {
			gonnect.Network
			gonnect.UpDown
			io.Closer
			gonnect.UpDownSubscriber
		}
	}{
		{
			name: "DetachedNetwork",
			net:  gonnect.DetachNetwork(&gonnect.RejectNetwork{}),
		},
		{name: "LoopbackNetwork", net: gonnect.NewLoopbackNetwok()},
		{name: "Router", net: gonnect.NewRouter()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kept := &lifecycleUpDown{}
			removed := &lifecycleUpDown{}

			unsubscribeKept, err := tt.net.SubscribeUpDown(kept)
			if err != nil {
				t.Fatalf("SubscribeUpDown() error = %v", err)
			}
			defer unsubscribeKept()

			unsubscribeRemoved, err := tt.net.SubscribeUpDown(removed)
			if err != nil {
				t.Fatalf("SubscribeUpDown() error = %v", err)
			}
			unsubscribeRemoved()
			unsubscribeRemoved()

			if err := tt.net.Down(); err != nil {
				t.Fatalf("Down() error = %v", err)
			}
			if kept.downs.Load() != 1 {
				t.Fatalf(
					"subscribed Down calls = %d, want 1",
					kept.downs.Load(),
				)
			}
			if removed.downs.Load() != 0 {
				t.Fatalf(
					"unsubscribed Down calls = %d, want 0",
					removed.downs.Load(),
				)
			}

			late := &lifecycleUpDown{}
			unsubscribeLate, err := tt.net.SubscribeUpDown(late)
			if err != nil {
				t.Fatalf("SubscribeUpDown() while down error = %v", err)
			}
			defer unsubscribeLate()
			if late.downs.Load() != 1 {
				t.Fatalf("late Down calls = %d, want 1", late.downs.Load())
			}

			if err := tt.net.Up(); err != nil {
				t.Fatalf("Up() error = %v", err)
			}
			if kept.ups.Load() != 1 {
				t.Fatalf("subscribed Up calls = %d, want 1", kept.ups.Load())
			}
			if late.ups.Load() != 1 {
				t.Fatalf("late Up calls = %d, want 1", late.ups.Load())
			}
			if removed.ups.Load() != 0 {
				t.Fatalf(
					"unsubscribed Up calls = %d, want 0",
					removed.ups.Load(),
				)
			}

			if err := tt.net.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if kept.downs.Load() != 2 {
				t.Fatalf(
					"subscribed Down calls after Close = %d, want 2",
					kept.downs.Load(),
				)
			}
			if late.downs.Load() != 2 {
				t.Fatalf(
					"late Down calls after Close = %d, want 2",
					late.downs.Load(),
				)
			}
			if up, err := tt.net.IsUp(); err != nil || up {
				t.Fatalf("IsUp() after Close = %v, %v, want false nil", up, err)
			}
			if err := tt.net.Down(); err != nil {
				t.Fatalf("Down() after Close error = %v, want nil", err)
			}
			if kept.downs.Load() != 2 {
				t.Fatalf(
					"subscribed Down calls after Down on closed = %d, want 2",
					kept.downs.Load(),
				)
			}
			if err := tt.net.Up(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Up() after Close error = %v, want net.ErrClosed", err)
			}

			afterClose := &lifecycleUpDown{}
			unsubscribeAfterClose, err := tt.net.SubscribeUpDown(afterClose)
			if err != nil {
				t.Fatalf("SubscribeUpDown() after Close error = %v", err)
			}
			defer unsubscribeAfterClose()
			if afterClose.downs.Load() != 1 {
				t.Fatalf(
					"SubscribeUpDown() after Close Down calls = %d, want 1",
					afterClose.downs.Load(),
				)
			}
		})
	}
}

func TestDetachedNetworkNestedClosePropagation(t *testing.T) {
	root := gonnect.NewLoopbackNetwok()
	parent := gonnect.DetachNetwork(root)
	child := gonnect.DetachNetwork(parent)
	closer := &lifecycleCloser{}
	if _, err := child.SubscribeCloser(closer); err != nil {
		t.Fatalf("SubscribeCloser() error = %v", err)
	}

	if err := root.Close(); err != nil {
		t.Fatalf("root Close() error = %v", err)
	}
	if closer.closes() != 1 {
		t.Fatalf("nested closer closes = %d, want 1", closer.closes())
	}
	if up, err := parent.IsUp(); err != nil || up {
		t.Fatalf("parent IsUp() = %v, %v, want false nil", up, err)
	}
	if up, err := child.IsUp(); err != nil || up {
		t.Fatalf("child IsUp() = %v, %v, want false nil", up, err)
	}
}

func TestDetachedNetworkNestedUpDownPropagation(t *testing.T) {
	root := gonnect.NewLoopbackNetwok()
	parent := gonnect.DetachNetwork(root)
	child := gonnect.DetachNetwork(parent)
	watcher := &lifecycleUpDown{}
	if _, err := child.SubscribeUpDown(watcher); err != nil {
		t.Fatalf("SubscribeUpDown() error = %v", err)
	}

	if err := root.Down(); err != nil {
		t.Fatalf("root Down() error = %v", err)
	}
	if watcher.downs.Load() != 1 {
		t.Fatalf("watcher Down calls = %d, want 1", watcher.downs.Load())
	}
	if up, err := child.IsUp(); err != nil || up {
		t.Fatalf(
			"child IsUp() after root Down = %v, %v, want false nil",
			up,
			err,
		)
	}

	if err := root.Up(); err != nil {
		t.Fatalf("root Up() error = %v", err)
	}
	if watcher.ups.Load() != 1 {
		t.Fatalf("watcher Up calls = %d, want 1", watcher.ups.Load())
	}
	if up, err := child.IsUp(); err != nil || !up {
		t.Fatalf("child IsUp() after root Up = %v, %v, want true nil", up, err)
	}
}

func TestDetachedNetworkChainLifecyclePropagationDirection(t *testing.T) {
	isUp := func(t *testing.T, name string, n gonnect.UpDown) bool {
		t.Helper()
		up, err := n.IsUp()
		if err != nil {
			t.Fatalf("%s IsUp() error = %v", name, err)
		}
		return up
	}
	assertStates := func(
		t *testing.T,
		root *gonnect.LoopbackNetwork,
		chain []*gonnect.DetachedNetwork,
		want ...bool,
	) {
		t.Helper()
		if len(want) != len(chain)+1 {
			t.Fatalf("state count = %d, want %d", len(want), len(chain)+1)
		}
		if got := isUp(t, "root", root); got != want[0] {
			t.Fatalf("root IsUp() = %v, want %v", got, want[0])
		}
		for i, n := range chain {
			if got := isUp(t, "chain", n); got != want[i+1] {
				t.Fatalf("chain[%d] IsUp() = %v, want %v", i, got, want[i+1])
			}
		}
	}
	makeChain := func() (*gonnect.LoopbackNetwork, []*gonnect.DetachedNetwork) {
		root := gonnect.NewLoopbackNetwok()
		parent := gonnect.DetachNetwork(root)
		child := gonnect.DetachNetwork(parent)
		grandchild := gonnect.DetachNetwork(child)
		return root, []*gonnect.DetachedNetwork{parent, child, grandchild}
	}

	t.Run("Close_propagates_from_wrapped_to_wrapping", func(t *testing.T) {
		root, chain := makeChain()

		if err := root.Close(); err != nil {
			t.Fatalf("root Close() error = %v", err)
		}
		assertStates(t, root, chain, false, false, false, false)
	})

	t.Run("Down_and_Up_propagate_from_wrapped_to_wrapping", func(t *testing.T) {
		root, chain := makeChain()

		if err := root.Down(); err != nil {
			t.Fatalf("root Down() error = %v", err)
		}
		assertStates(t, root, chain, false, false, false, false)

		if err := root.Up(); err != nil {
			t.Fatalf("root Up() error = %v", err)
		}
		assertStates(t, root, chain, true, true, true, true)
	})

	t.Run(
		"Close_and_Down_do_not_propagate_from_wrapping_to_wrapped",
		func(t *testing.T) {
			root, chain := makeChain()

			if err := chain[2].Close(); err != nil {
				t.Fatalf("grandchild Close() error = %v", err)
			}
			assertStates(t, root, chain, true, true, true, false)

			if err := chain[1].Down(); err != nil {
				t.Fatalf("child Down() error = %v", err)
			}
			assertStates(t, root, chain, true, true, false, false)
		},
	)

	t.Run("Up_does_not_propagate_from_wrapping_to_wrapped", func(t *testing.T) {
		root, chain := makeChain()

		if err := root.Down(); err != nil {
			t.Fatalf("root Down() error = %v", err)
		}
		assertStates(t, root, chain, false, false, false, false)

		if err := chain[2].Up(); err != nil {
			t.Fatalf("grandchild Up() error = %v", err)
		}
		assertStates(t, root, chain, false, false, false, true)
	})
}
