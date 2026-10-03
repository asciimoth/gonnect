package sniffer_test

import (
	"testing"

	"github.com/asciimoth/gonnect/sniffer"
)

func FuzzProtocolClassifiers(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		[]byte("SSH-2.0-test\r\n"),
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		[]byte("\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"),
		[]byte("*1\r\n$4\r\nPING\r\n"),
		[]byte("OPTIONS * RTSP/1.0\r\n"),
	} {
		f.Add(seed, uint8(1))
	}

	f.Fuzz(func(t *testing.T, data []byte, chunkByte uint8) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		chunkSize := int(chunkByte%64) + 1
		for _, factory := range fuzzProtocolFactories() {
			whole := factory.NewClassifier()
			want := whole.Feed(data)

			chunked := factory.NewClassifier()
			got := chunked.Feed(nil)
			for offset := 0; offset < len(data) && got == sniffer.NeedMore; {
				end := min(offset+chunkSize, len(data))
				got = chunked.Feed(data[offset:end])
				offset = end
			}
			if got != want {
				t.Fatalf(
					"%T chunked state = %v, whole state = %v",
					chunked,
					got,
					want,
				)
			}
			if got != sniffer.NeedMore &&
				chunked.Feed([]byte("ignored")) != got {
				t.Fatalf("%T changed terminal state %v", chunked, got)
			}
		}
	})
}

func fuzzProtocolFactories() []sniffer.Factory {
	return []sniffer.Factory{
		sniffer.HTTPFactory(),
		sniffer.HTTPFactoryWithConfig(
			sniffer.HTTPConfig{HostnamePatterns: []string{"*"}},
		),
		sniffer.TLSFactory(),
		sniffer.SSHFactory(),
		sniffer.HTTP2Factory(),
		sniffer.AMQPFactory(),
		sniffer.MQTTFactory(),
		sniffer.PostgreSQLFactory(),
		sniffer.MongoDBFactory(),
		sniffer.RedisFactory(),
		sniffer.ProxyProtocolFactory(),
		sniffer.SOCKSFactory(),
		sniffer.DNSOverTCPFactory(),
		sniffer.RTSPFactory(),
		sniffer.SIPFactory(),
		sniffer.STUNFactory(),
		sniffer.RDPFactory(),
		sniffer.SMBFactory(),
		sniffer.LDAPFactory(),
		sniffer.CassandraFactory(),
		sniffer.MemcachedFactory(),
	}
}
