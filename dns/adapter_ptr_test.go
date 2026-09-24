//nolint:testpackage // Tests need the package's resolver test double.
package dns

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestResolverProviderPTRPassesIPToResolver(t *testing.T) {
	tests := []struct {
		name     string
		question string
		wantAddr string
	}{
		{
			name:     "IPv4",
			question: "10.2.0.192.in-addr.arpa.",
			wantAddr: "192.0.2.10",
		},
		{
			name: "IPv6 compressed canonical address",
			question: "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			wantAddr: "2001:db8::10",
		},
		{
			name:     "case insensitive suffix",
			question: "255.0.0.127.IN-ADDR.ARPA.",
			wantAddr: "127.0.0.255",
		},
		{
			name: "case insensitive IPv6 nibble and suffix",
			question: "F.F.F.F.F.F.F.F.F.F.F.F.F.F.F.F." +
				"F.F.F.F.F.F.F.F.F.F.F.F.F.F.F.F.IP6.ARPA.",
			wantAddr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &strictPTRResolver{
				names: []string{"host.example", "alias.example."},
			}
			provider := NewResolverProvider(resolver, 90*time.Second, nil)
			closeProvider(t, provider)

			resp, err := ptrQuery(provider, tt.question)
			if err != nil {
				t.Fatal(err)
			}
			if resp.RCode != RCodeSuccess {
				t.Fatalf("RCode = %d, want %d", resp.RCode, RCodeSuccess)
			}
			if !slices.Equal(resolver.calls, []string{tt.wantAddr}) {
				t.Fatalf(
					"LookupAddr calls = %v, want [%s]",
					resolver.calls,
					tt.wantAddr,
				)
			}
			if len(resp.Answers) != 2 {
				t.Fatalf("answer count = %d, want 2", len(resp.Answers))
			}
			gotNames := make([]string, 0, len(resp.Answers))
			for i, answer := range resp.Answers {
				if answer.Name != tt.question {
					t.Errorf(
						"answer %d name = %q, want %q",
						i,
						answer.Name,
						tt.question,
					)
				}
				if answer.Type != TypePTR || answer.Class != ClassIN {
					t.Errorf("answer %d metadata = %#v", i, answer)
				}
				if answer.TTL != 90 {
					t.Errorf("answer %d TTL = %d, want 90", i, answer.TTL)
				}
				gotNames = append(gotNames, string(answer.Data))
			}
			wantNames := []string{"host.example.", "alias.example."}
			if !slices.Equal(gotNames, wantNames) {
				t.Errorf("answer data = %q, want %q", gotNames, wantNames)
			}
		})
	}
}

func TestResolverProviderPTRRejectsMalformedReverseNames(t *testing.T) {
	tests := []struct {
		name     string
		question string
	}{
		{name: "ordinary domain", question: "host.example."},
		{name: "empty name", question: "."},
		{name: "IPv4 too few octets", question: "10.2.192.in-addr.arpa."},
		{name: "IPv4 too many octets", question: "1.10.2.0.192.in-addr.arpa."},
		{name: "IPv4 empty octet", question: "10..0.192.in-addr.arpa."},
		{name: "IPv4 negative octet", question: "10.2.-1.192.in-addr.arpa."},
		{name: "IPv4 signed octet", question: "+10.2.0.192.in-addr.arpa."},
		{name: "IPv4 leading zero", question: "010.2.0.192.in-addr.arpa."},
		{name: "IPv4 non-decimal octet", question: "a.2.0.192.in-addr.arpa."},
		{name: "IPv4 octet overflow", question: "256.2.0.192.in-addr.arpa."},
		{name: "IPv4 extra suffix", question: "10.2.0.192.in-addr.arpa.test."},
		{
			name: "IPv6 too few nibbles",
			question: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			name: "IPv6 too many nibbles",
			question: "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			name: "IPv6 empty nibble",
			question: "1..0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			name: "IPv6 multi-character nibble",
			question: "10.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			name: "IPv6 non-hexadecimal nibble",
			question: "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
		{
			name: "IPv6 wrong suffix",
			question: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." +
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.example.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &strictPTRResolver{}
			provider := NewResolverProvider(resolver, time.Second, nil)
			closeProvider(t, provider)

			resp, err := ptrQuery(provider, tt.question)
			if err != nil {
				t.Fatal(err)
			}
			if resp.RCode != RCodeFormatError {
				t.Fatalf(
					"RCode = %d, want %d",
					resp.RCode,
					RCodeFormatError,
				)
			}
			if len(resp.Answers) != 0 {
				t.Fatalf("answers = %#v, want none", resp.Answers)
			}
			if len(resolver.calls) != 0 {
				t.Fatalf(
					"LookupAddr was called with %v for malformed name",
					resolver.calls,
				)
			}
		})
	}
}

type strictPTRResolver struct {
	fakeResolver
	calls []string
	names []string
}

func (r *strictPTRResolver) LookupAddr(
	_ context.Context,
	addr string,
) ([]string, error) {
	r.calls = append(r.calls, addr)
	if _, err := netip.ParseAddr(addr); err != nil {
		return nil, fmt.Errorf(
			"LookupAddr argument %q is not an IP address",
			addr,
		)
	}
	return slices.Clone(r.names), nil
}

func ptrQuery(provider Interface, name string) (*Message, error) {
	return Query(context.Background(), provider, &Message{
		ID: NextID(),
		Questions: []Question{{
			Name:  name,
			Type:  TypePTR,
			Class: ClassIN,
		}},
	})
}

func closeProvider(t *testing.T, provider *ResolverProvider) {
	t.Helper()
	t.Cleanup(func() {
		if err := provider.Close(); err != nil {
			t.Errorf("close resolver provider: %v", err)
		}
	})
}
