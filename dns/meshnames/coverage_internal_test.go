package meshnames

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolverInternalDefaultsAndNameClassification(t *testing.T) {
	r := &Resolver{}
	if got := r.port(); got != defaultDNSPort {
		t.Fatalf("port() = %d, want %d", got, defaultDNSPort)
	}
	if got := r.timeout(); got != defaultTimeout {
		t.Fatalf("timeout() = %v, want %v", got, defaultTimeout)
	}

	r.Port = 8053
	r.Timeout = time.Second
	if got := r.port(); got != 8053 {
		t.Fatalf("custom port() = %d, want 8053", got)
	}
	if got := r.timeout(); got != time.Second {
		t.Fatalf("custom timeout() = %v, want 1s", got)
	}

	if !r.isSpecialName("aiag7sesed2aaxgcgbnevruwpy.meship") {
		t.Fatal("meship name was not classified as special")
	}
	if !r.isSpecialName("svc.020212a900e54474d47382be16ac9381.ygg") {
		t.Fatal("ygg name was not classified as special")
	}
	if r.isSpecialName("example.com") {
		t.Fatal("ordinary name was classified as special")
	}
}

func TestMeshnameDecodeAndLabelHelpers(t *testing.T) {
	if got := splitLabels(
		" A.B. ",
	); !reflect.DeepEqual(
		got,
		[]string{"a", "b"},
	) {
		t.Fatalf("splitLabels() = %v, want [a b]", got)
	}
	if got := splitLabels(" . "); got != nil {
		t.Fatalf("splitLabels(blank) = %v, want nil", got)
	}

	if _, err := decodeMeshnameLabel("bad!"); err == nil {
		t.Fatal("decodeMeshnameLabel(bad) error = nil, want error")
	}
	if _, err := decodeMeshnameLabel("abc"); err == nil {
		t.Fatal("decodeMeshnameLabel(short) error = nil, want error")
	}
	ip, err := decodeMeshnameLabel("aiag7sesed2aaxgcgbnevruwpy")
	if err != nil {
		t.Fatalf("decodeMeshnameLabel(valid) error = %v", err)
	}
	if got := ip.String(); got != "200:6fc8:9220:f400:5cc2:305a:4ac6:967e" {
		t.Fatalf("decodeMeshnameLabel(valid) = %s", got)
	}
	if _, err := decodeYggPublicKeyLabel("not-hex"); err == nil {
		t.Fatal("decodeYggPublicKeyLabel(non-hex) error = nil, want error")
	}
	if _, err := decodeYggPublicKeyLabel("abcd"); err == nil {
		t.Fatal("decodeYggPublicKeyLabel(short) error = nil, want error")
	}

	if _, err := authorityIP("name.example"); err == nil {
		t.Fatal("authorityIP(ordinary) error = nil, want no such host")
	}
	if _, err := authorityIP("bad.meshname"); err == nil {
		t.Fatal("authorityIP(bad meshname) error = nil, want no such host")
	}
	ip, err = authorityIP("svc.aiag7sesed2aaxgcgbnevruwpy.meshname")
	if err != nil {
		t.Fatalf("authorityIP(meshname) error = %v", err)
	}
	if got := ip.String(); got != "200:6fc8:9220:f400:5cc2:305a:4ac6:967e" {
		t.Fatalf("authorityIP(meshname) = %s", got)
	}
}

func TestYggDecodeErrorBranchesAndBitHelpers(t *testing.T) {
	if got := bitAt([]byte{0x80}, 0); got != 1 {
		t.Fatalf("bitAt high bit = %d, want 1", got)
	}
	if got := bitAt([]byte{0x80}, -1); got != 0 {
		t.Fatalf("bitAt negative = %d, want 0", got)
	}
	if got := bitAt([]byte{0x80}, 8); got != 0 {
		t.Fatalf("bitAt outside = %d, want 0", got)
	}

	var addr [net.IPv6len]byte
	setByte(&addr, -1, 0xff)
	setByte(&addr, net.IPv6len, 0xff)
	setByte(&addr, 1, 0x02)
	if addr[1] != 0x02 {
		t.Fatalf("setByte valid index = 0x%x, want 0x02", addr[1])
	}

	if _, err := decodeYggLabel("not-ygg"); err == nil {
		t.Fatal("decodeYggLabel(unknown) error = nil, want error")
	}
	for _, label := range []string{
		"020212a900e54474d47382be16ac9381",
		"2aijksahfir2ni44cxylkze4b",
		"202-12a9-e5-4474-d473-82be-16ac-9381",
	} {
		ip, err := decodeYggLabel(label)
		if err != nil {
			t.Fatalf("decodeYggLabel(%q) error = %v", label, err)
		}
		if got := ip.String(); got != "202:12a9:e5:4474:d473:82be:16ac:9381" {
			t.Fatalf("decodeYggLabel(%q) = %s", label, got)
		}
	}
	if _, err := decodeYggStraight(
		"020212a900e54474d47382be16ac938x",
	); err == nil {
		t.Fatal("decodeYggStraight(non-hex) error = nil, want error")
	}
	if _, err := decodeYggBase32("2bad"); err == nil {
		t.Fatal("decodeYggBase32(bad length) error = nil, want error")
	}
	if _, err := decodeYggBase32("2!!!!!!!!!!!!!!!!!!!!!!!!"); err == nil {
		t.Fatal("decodeYggBase32(bad alphabet) error = nil, want error")
	}
	if _, err := decodeYggDashed("2001-db8--1"); err == nil {
		t.Fatal("decodeYggDashed(invalid IP) error = nil, want error")
	}
	if _, err := validateYggIP(net.ParseIP("2001:db8::1")); err == nil {
		t.Fatal("validateYggIP(outside ygg net) error = nil, want error")
	}
	if _, err := validateYggIP(nil); err == nil {
		t.Fatal("validateYggIP(nil) error = nil, want error")
	}
}

func TestDNSRecordExtractionAndIPFilters(t *testing.T) {
	a := net.ParseIP("192.0.2.10")
	aaaa := net.ParseIP("2001:db8::10")
	rrs := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "host.", Rrtype: dns.TypeA}, A: a},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "host.", Rrtype: dns.TypeAAAA},
			AAAA: aaaa,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "host.", Rrtype: dns.TypeTXT},
			Txt: []string{"x"},
		},
	}

	if got := extractIPs(rrs, dns.TypeA); len(got) != 1 || !got[0].Equal(a) {
		t.Fatalf("extractIPs A = %v, want %v", got, a)
	}
	if got := extractIPs(
		rrs,
		dns.TypeAAAA,
	); len(got) != 1 ||
		!got[0].Equal(aaaa) {
		t.Fatalf("extractIPs AAAA = %v, want %v", got, aaaa)
	}

	ips := []net.IP{a, aaaa, a}
	if got := filterNetIPs(ips, "tcp4"); len(got) != 2 ||
		!got[0].Equal(a.To4()) ||
		!got[1].Equal(a.To4()) {
		t.Fatalf("filterNetIPs tcp4 = %v, want two IPv4 entries", got)
	}
	if got := filterNetIPs(ips, "udp6"); len(got) != 1 || !got[0].Equal(aaaa) {
		t.Fatalf("filterNetIPs udp6 = %v, want %v", got, aaaa)
	}
	if got := dedupeIPs(ips); len(got) != 2 {
		t.Fatalf("dedupeIPs() length = %d, want 2", len(got))
	}

	for network, want := range map[string][]uint16{
		"ip4":  {dns.TypeA},
		"TCP6": {dns.TypeAAAA},
		"ip":   {dns.TypeA, dns.TypeAAAA},
	} {
		if got := qtypesForNetwork(network); !reflect.DeepEqual(got, want) {
			t.Fatalf("qtypesForNetwork(%q) = %v, want %v", network, got, want)
		}
	}
}

func TestNoSuchHostShape(t *testing.T) {
	err := noSuchHost("example.test")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("noSuchHost error type = %T, want *net.DNSError", err)
	}
	if dnsErr.Name != "example.test" || !dnsErr.IsNotFound {
		t.Fatalf("noSuchHost() = %#v, want named not-found error", dnsErr)
	}
}
