package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestNetworkLeafCertificateCache(t *testing.T) {
	ca, caCert := internalTestCA(t, time.Hour)
	network := &Network{
		ca:      ca,
		caCert:  caCert,
		leafTTL: time.Hour,
	}

	first, err := network.leafCertificate("Example.TEST.")
	if err != nil {
		t.Fatalf("leafCertificate() error = %v", err)
	}
	second, err := network.leafCertificate("example.test")
	if err != nil {
		t.Fatalf("leafCertificate() second error = %v", err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("leafCertificate() did not reuse cached certificate")
	}
}

func TestNetworkLeafCertificateCacheRefreshesExpiredEntry(t *testing.T) {
	ca, caCert := internalTestCA(t, time.Hour)
	network := &Network{
		ca:      ca,
		caCert:  caCert,
		leafTTL: time.Hour,
		leafCache: map[string]stdtls.Certificate{
			"example.test": {
				Leaf: &x509.Certificate{
					NotAfter: time.Now().Add(-time.Second),
				},
			},
		},
	}

	cert, err := network.leafCertificate("example.test")
	if err != nil {
		t.Fatalf("leafCertificate() error = %v", err)
	}
	if !cert.Leaf.NotAfter.After(time.Now()) {
		t.Fatal("leafCertificate() returned expired certificate")
	}
}

func internalTestCA(
	t *testing.T,
	ttl time.Duration,
) (stdtls.Certificate, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gonnect.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        cert,
	}, cert
}

func TestSniffRouteUsesConfiguredLargeBuffer(t *testing.T) {
	const host = "large.example.test"
	hello := largeTestClientHello(t, host)
	if len(hello) <= sniffer.DefaultTLSClientHelloMaxBytes {
		t.Fatalf(
			"large ClientHello length = %d, want > %d",
			len(hello),
			sniffer.DefaultTLSClientHelloMaxBytes,
		)
	}

	conn := putback.New(&readOnlyTestConn{
		Reader: bytes.NewReader(hello),
	}, nil)
	network := &Network{sniffBufferSize: len(hello)}
	route, err := network.sniffRoute(conn, interceptionConnInfo{
		network: "tcp",
	})
	if err != nil {
		t.Fatalf("sniffRoute() error = %v", err)
	}
	if route != routeInterceptTLS {
		t.Fatalf("sniffRoute() route = %v, want routeInterceptTLS", route)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatal("sniffRoute() did not put ClientHello bytes back")
	}
}

type readOnlyTestConn struct {
	*bytes.Reader
}

func (c *readOnlyTestConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *readOnlyTestConn) Close() error { return nil }

func (c *readOnlyTestConn) LocalAddr() net.Addr {
	return testAddr("local")
}

func (c *readOnlyTestConn) RemoteAddr() net.Addr {
	return testAddr("remote")
}

func (c *readOnlyTestConn) SetDeadline(time.Time) error { return nil }

func (c *readOnlyTestConn) SetReadDeadline(time.Time) error { return nil }

func (c *readOnlyTestConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }

func (a testAddr) String() string { return string(a) }

type testClientHelloExtension struct {
	typ  uint16
	data []byte
}

func largeTestClientHello(t *testing.T, host string) []byte {
	t.Helper()

	sni := testClientHelloServerName(t, host)
	const maxExtensionBlockLen = math.MaxUint16 - 47
	paddingLen := maxExtensionBlockLen - (4 + len(sni.data)) - 4
	if paddingLen <= 0 {
		t.Fatal("test SNI extension is too large")
	}
	hello := testClientHelloBytes(
		t,
		sni,
		testClientHelloExtension{
			typ:  21,
			data: bytes.Repeat([]byte{0}, paddingLen),
		},
	)
	return splitTestClientHelloRecords(t, hello, 16*1024)
}

func testClientHelloBytes(
	t *testing.T,
	extensions ...testClientHelloExtension,
) []byte {
	t.Helper()

	body := make([]byte, 0, 256)
	body = binary.BigEndian.AppendUint16(body, stdtls.VersionTLS12)
	body = append(body, bytes.Repeat([]byte{0x01}, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(
		body,
		stdtls.TLS_AES_128_GCM_SHA256,
	)
	body = append(body, 1, 0)

	if len(extensions) != 0 {
		extensionBlock := make([]byte, 0, 128)
		for _, extension := range extensions {
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				extension.typ,
			)
			extensionBlock = binary.BigEndian.AppendUint16(
				extensionBlock,
				testUint16Length(t, "extension data", len(extension.data)),
			)
			extensionBlock = append(extensionBlock, extension.data...)
		}
		body = binary.BigEndian.AppendUint16(
			body,
			testUint16Length(t, "extension block", len(extensionBlock)),
		)
		body = append(body, extensionBlock...)
	}

	handshake := make([]byte, 4, 4+len(body))
	handshake[0] = 1
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	handshake = append(handshake, body...)

	record := []byte{22, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(
		record[3:],
		testUint16Length(t, "TLS handshake", len(handshake)),
	)
	return append(record, handshake...)
}

func splitTestClientHelloRecords(
	t *testing.T,
	hello []byte,
	maxFragment int,
) []byte {
	t.Helper()

	if len(hello) < 5 || hello[0] != 22 {
		t.Fatal("test input is not a TLS handshake record")
	}
	if maxFragment <= 0 || maxFragment > 16*1024 {
		t.Fatal("invalid TLS record fragment size")
	}
	recordLength := int(binary.BigEndian.Uint16(hello[3:5]))
	if len(hello) != 5+recordLength {
		t.Fatal("test input must contain one complete TLS record")
	}

	payload := hello[5:]
	out := make([]byte, 0, len(hello)+(len(payload)/maxFragment)*5)
	for len(payload) != 0 {
		fragmentLen := maxFragment
		if fragmentLen > len(payload) {
			fragmentLen = len(payload)
		}
		out = append(out, hello[0], hello[1], hello[2], 0, 0)
		binary.BigEndian.PutUint16(
			out[len(out)-2:],
			testUint16Length(t, "TLS record fragment", fragmentLen),
		)
		out = append(out, payload[:fragmentLen]...)
		payload = payload[fragmentLen:]
	}
	return out
}

func testClientHelloServerName(
	t *testing.T,
	hostname string,
) testClientHelloExtension {
	t.Helper()

	hostBytes := []byte(hostname)
	name := []byte{0}
	name = binary.BigEndian.AppendUint16(
		name,
		testUint16Length(t, "SNI host", len(hostBytes)),
	)
	name = append(name, hostBytes...)

	data := binary.BigEndian.AppendUint16(
		nil,
		testUint16Length(t, "SNI list", len(name)),
	)
	data = append(data, name...)
	return testClientHelloExtension{typ: 0, data: data}
}

func testUint16Length(t *testing.T, name string, length int) uint16 {
	t.Helper()
	if length > math.MaxUint16 {
		t.Fatalf("%s length = %d, want <= %d", name, length, math.MaxUint16)
	}
	return uint16(length) //nolint:gosec // length is checked above.
}
