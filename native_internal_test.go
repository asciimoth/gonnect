package gonnect

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNativeConfigBuildPreservesResolverDial(t *testing.T) {
	t.Parallel()

	dialErr := errors.New("resolver dial stopped")
	var dialNetwork, dialAddress string
	var filterNetwork, filterAddress string
	n := NativeConfig{
		Filter: func(network, address string) bool {
			if address == "9.9.9.9:53" {
				filterNetwork = network
				filterAddress = address
			}
			return false
		},
		ResolverCfg: &ResolverCfg{
			Server: &DnsServer{Net: "tcp", Addr: "9.9.9.9:dns"},
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialNetwork = network
				dialAddress = address
				return nil, dialErr
			},
		},
	}.Build()

	resolver, ok := n.resolver.(*net.Resolver)
	if !ok {
		t.Fatalf("resolver = %T, want *net.Resolver", n.resolver)
	}
	if _, err := resolver.Dial(
		context.Background(),
		"udp",
		"ignored:53",
	); !errors.Is(err, dialErr) {
		t.Fatalf("resolver Dial error = %v, want %v", err, dialErr)
	}
	if filterNetwork != "tcp" || filterAddress != "9.9.9.9:53" {
		t.Fatalf(
			"resolver filter target = %s/%s, want tcp/9.9.9.9:53",
			filterNetwork,
			filterAddress,
		)
	}
	if dialNetwork != "tcp" || dialAddress != "9.9.9.9:53" {
		t.Fatalf(
			"resolver dial target = %s/%s, want tcp/9.9.9.9:53",
			dialNetwork,
			dialAddress,
		)
	}
}
