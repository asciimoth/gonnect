package sysnetdebug_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/asciimoth/gonnect/sysnet"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func TestDefaultTunSourceRoutesRecordCopyAndReplace(t *testing.T) {
	system := &sysnetdebug.System{}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})

	firstRoutes := []sysnet.TunSourceRoute{
		{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		},
		{
			Destination: netip.MustParsePrefix("100.64.1.1/10"),
			Source:      netip.MustParseAddr("100.64.0.2"),
		},
	}
	tunDev, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:     []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: firstRoutes,
	})
	if err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}

	firstRoutes[0].Source = netip.MustParseAddr("100.64.0.2")
	entry, ok := system.GetDefaultTunPeer()
	if !ok {
		t.Fatal("GetDefaultTunPeer() did not return the default TUN")
	}
	wantOverlay := netip.MustParsePrefix("100.64.0.0/10")
	if len(entry.Config.SourceRoutes) != 2 {
		t.Fatalf("recorded source routes = %+v", entry.Config.SourceRoutes)
	}
	if entry.Config.SourceRoutes[0].Source !=
		netip.MustParseAddr("10.20.0.2") ||
		entry.Config.SourceRoutes[1].Destination != wantOverlay {
		t.Fatalf("recorded source routes = %+v", entry.Config.SourceRoutes)
	}

	entry.Config.SourceRoutes[0].Source = netip.MustParseAddr("100.64.0.2")
	entry, ok = system.GetDefaultTunPeer()
	if !ok || len(entry.Config.SourceRoutes) != 2 {
		t.Fatalf("source-route snapshot aliases system state: %+v", entry)
	}
	if entry.Config.SourceRoutes[0].Source !=
		netip.MustParseAddr("10.20.0.2") {
		t.Fatalf("source-route snapshot aliases system state: %+v", entry)
	}

	wantSecondRoute := sysnet.TunSourceRoute{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Source:      netip.MustParseAddr("100.64.0.2"),
	}
	secondRoutes := []sysnet.TunSourceRoute{wantSecondRoute}
	rebuilt, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		TunAddrs:     []string{"10.20.0.2/32", "100.64.0.2/32"},
		SourceRoutes: secondRoutes,
	})
	if err != nil {
		t.Fatalf("second BuildDefaultTun() error = %v", err)
	}
	if rebuilt != tunDev {
		t.Fatal("second BuildDefaultTun() returned a different TUN")
	}
	entry, ok = system.GetDefaultTunPeer()
	if !ok || len(entry.Config.SourceRoutes) != 1 {
		t.Fatalf("replacement source routes = %+v", entry.Config.SourceRoutes)
	}
	if entry.Config.SourceRoutes[0] != wantSecondRoute {
		t.Fatalf("replacement source routes = %+v", entry.Config.SourceRoutes)
	}

	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{}); err != nil {
		t.Fatalf("BuildDefaultTun(empty source routes) error = %v", err)
	}
	entry, ok = system.GetDefaultTunPeer()
	if !ok || entry.Config.SourceRoutes != nil {
		t.Fatalf("empty source routes did not clear old routes: %+v", entry)
	}
}

func TestDefaultTunSourceRoutesAcceptIPv4IPv6AndDuplicates(t *testing.T) {
	system := &sysnetdebug.System{}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})

	v4Source := netip.MustParseAddr("10.20.0.2")
	v6Source := netip.MustParseAddr("2001:db8:1::2")
	opts := sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/24", "2001:db8:1::2/64"},
		SourceRoutes: []sysnet.TunSourceRoute{
			{
				Destination: netip.MustParsePrefix("192.0.2.1/24"),
				Source:      v4Source,
			},
			{
				Destination: netip.MustParsePrefix("192.0.2.200/24"),
				Source:      v4Source,
			},
			{
				Destination: netip.MustParsePrefix("fd00:1234::abcd/48"),
				Source:      v6Source,
			},
		},
	}

	if err := system.VerifyDefaultTunOpts(opts); err != nil {
		t.Fatalf("VerifyDefaultTunOpts() error = %v", err)
	}
	if _, err := system.BuildDefaultTun(opts); err != nil {
		t.Fatalf("BuildDefaultTun() error = %v", err)
	}
	entry, ok := system.GetDefaultTunPeer()
	if !ok || len(entry.Config.SourceRoutes) != 2 {
		t.Fatalf("normalized source routes = %+v", entry.Config.SourceRoutes)
	}
	if entry.Config.SourceRoutes[0].Destination !=
		netip.MustParsePrefix("192.0.2.0/24") ||
		entry.Config.SourceRoutes[1].Destination !=
			netip.MustParsePrefix("fd00:1234::/48") {
		t.Fatalf("destinations were not masked: %+v", entry.Config.SourceRoutes)
	}
}

func TestDefaultTunSourceRoutesRejectInvalidValues(t *testing.T) {
	v4Source := netip.MustParseAddr("10.20.0.2")
	v6Source := netip.MustParseAddr("2001:db8:1::2")
	tests := []struct {
		name   string
		addrs  []string
		routes []sysnet.TunSourceRoute
	}{
		{
			name:  "invalid destination",
			addrs: []string{"10.20.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Source: v4Source,
			}},
		},
		{
			name:  "invalid source",
			addrs: []string{"10.20.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
			}},
		},
		{
			name:  "unspecified source",
			addrs: []string{"0.0.0.0/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("0.0.0.0"),
			}},
		},
		{
			name:  "multicast source",
			addrs: []string{"224.0.0.1/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("224.0.0.1"),
			}},
		},
		{
			name:  "loopback source",
			addrs: []string{"127.0.0.2/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      netip.MustParseAddr("127.0.0.2"),
			}},
		},
		{
			name:  "mixed families",
			addrs: []string{"2001:db8:1::2/128"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      v6Source,
			}},
		},
		{
			name:  "unassigned source",
			addrs: []string{"10.20.0.3/32"},
			routes: []sysnet.TunSourceRoute{{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Source:      v4Source,
			}},
		},
		{
			name:  "conflicting masked destination",
			addrs: []string{"10.20.0.2/32", "100.64.0.2/32"},
			routes: []sysnet.TunSourceRoute{
				{
					Destination: netip.MustParsePrefix("192.0.2.1/24"),
					Source:      v4Source,
				},
				{
					Destination: netip.MustParsePrefix("192.0.2.200/24"),
					Source:      netip.MustParseAddr("100.64.0.2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := &sysnetdebug.System{}
			opts := sysnet.DefaultTunOpts{
				TunAddrs:     test.addrs,
				SourceRoutes: test.routes,
			}
			if err := system.VerifyDefaultTunOpts(opts); err == nil {
				t.Fatal("VerifyDefaultTunOpts() error = nil")
			}
			if _, err := system.BuildDefaultTun(opts); err == nil {
				t.Fatal("BuildDefaultTun() error = nil")
			}
		})
	}
}

func TestDefaultTunSourceRoutesCapability(t *testing.T) {
	system := &sysnetdebug.System{DisableDefaultTunSourceRoutes: true}
	t.Cleanup(func() {
		if err := system.Close(); err != nil {
			t.Errorf("System.Close() error = %v", err)
		}
	})
	if system.Features().DefaultTunSourceRoutes {
		t.Fatal("DefaultTunSourceRoutes feature = true, want false")
	}

	opts := sysnet.DefaultTunOpts{
		TunAddrs: []string{"10.20.0.2/32"},
		SourceRoutes: []sysnet.TunSourceRoute{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Source:      netip.MustParseAddr("10.20.0.2"),
		}},
	}
	if err := system.VerifyDefaultTunOpts(opts); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("VerifyDefaultTunOpts() error = %v, want ErrNotSupported", err)
	}
	if _, err := system.BuildDefaultTun(opts); !errors.Is(
		err,
		sysnet.ErrNotSupported,
	) {
		t.Fatalf("BuildDefaultTun() error = %v, want ErrNotSupported", err)
	}

	if err := system.VerifyDefaultTunOpts(sysnet.DefaultTunOpts{}); err != nil {
		t.Fatalf("VerifyDefaultTunOpts(empty routes) error = %v", err)
	}
	if _, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{}); err != nil {
		t.Fatalf("BuildDefaultTun(empty routes) error = %v", err)
	}
}
