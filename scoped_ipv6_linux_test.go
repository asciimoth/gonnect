//go:build linux

package gonnect_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
)

func closeScopedIPv6Test(t *testing.T, c io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close scoped socket: %v", err)
		}
	})
}

// Use an assigned link-local address when the host has one. This covers the
// kernel bind and connect path without requiring a fixed interface name.
func TestScopedIPv6LinkLocalSockets(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var host string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() == nil && ipNet.IP.IsLinkLocalUnicast() {
				host = ipNet.IP.String() + "%" + iface.Name
				break
			}
		}
		if host != "" {
			break
		}
	}
	if host == "" {
		t.Skip("no assigned IPv6 link-local address")
	}

	base := gonnect.NativeConfig{}.Build()
	for _, tt := range []struct {
		name    string
		network gonnect.Network
	}{
		{"NativeNetwork", base},
		{"NetworkWithResolver", gonnect.NewNetworkWithResolver(base, &detachedResolver{})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				3*time.Second,
			)
			defer cancel()
			listener, err := tt.network.ListenTCP(
				ctx,
				"tcp6",
				net.JoinHostPort(host, "0"),
			)
			if err != nil {
				t.Fatal(err)
			}
			closeScopedIPv6Test(t, listener)
			listenerAddr, ok := listener.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("listener address has type %T", listener.Addr())
			}
			port := listenerAddr.Port
			// Linux can omit the zone in getsockname for a bound local
			// address. The bind and connect below verify the socket path.
			remote := net.JoinHostPort(host, strconv.Itoa(port))
			client, err := tt.network.DialTCP(
				ctx,
				"tcp6",
				net.JoinHostPort(host, "0"),
				remote,
			)
			if err != nil {
				t.Fatal(err)
			}
			closeScopedIPv6Test(t, client)
			server, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			closeScopedIPv6Test(t, server)

			udp, err := tt.network.ListenUDP(
				ctx,
				"udp6",
				net.JoinHostPort(host, "0"),
			)
			if err != nil {
				t.Fatal(err)
			}
			closeScopedIPv6Test(t, udp)
			udpAddr, ok := udp.LocalAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("UDP address has type %T", udp.LocalAddr())
			}
			udpPort := udpAddr.Port
			peer, err := tt.network.DialUDP(
				ctx,
				"udp6",
				net.JoinHostPort(host, "0"),
				net.JoinHostPort(host, strconv.Itoa(udpPort)),
			)
			if err != nil {
				t.Fatal(err)
			}
			closeScopedIPv6Test(t, peer)
			if _, err := peer.Write([]byte("scoped")); err != nil {
				t.Fatal(err)
			}
			if err := udp.SetReadDeadline(
				time.Now().Add(3 * time.Second),
			); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 16)
			if n, _, err := udp.ReadFrom(
				buf,
			); err != nil ||
				string(buf[:n]) != "scoped" {
				t.Fatalf("UDP read = %q, %v", buf[:n], err)
			}
		})
	}
}
