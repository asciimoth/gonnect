package tls //nolint:testpackage // Fuzzes internal CA and filter parsers.

import (
	stdtls "crypto/tls"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sniffer"
)

func FuzzTLSConfigInputs(f *testing.F) {
	ca, _ := internalTestCA(f, time.Hour)
	f.Add(uint8(0), ca.Certificate[0])
	f.Add(uint8(1), []byte("*.example.test"))
	f.Add(uint8(0), []byte{})

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		switch kind % 2 {
		case 0:
			_, _, _ = parseCA(stdtls.Certificate{
				Certificate: [][]byte{data},
				PrivateKey:  ca.PrivateKey,
			})
		case 1:
			value := string(data)
			_, _ = compileInterceptionFilter(InterceptionFilter{
				Mode: InterceptionFilterInclusive,
				Rules: []InterceptionRule{{
					Networks:    []string{value},
					ConnSrcs:    []string{value},
					ConnDsts:    []string{value},
					SNIHosts:    []string{value},
					ALPNs:       []string{value},
					TLSVersions: []uint16{uint16(kind)},
				}},
			})
			classifier := sniffer.TLSWithConfig(sniffer.TLSConfig{
				HostnamePatterns: []string{value},
				ALPNPatterns:     []string{value},
			})
			_ = classifier.Feed(data)
		}
	})
}
