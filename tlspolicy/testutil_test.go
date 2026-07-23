package tlspolicy //nolint:testpackage // Uses shared in-package TLS fixtures.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

type testPKI struct {
	rootAuthority Authority
	rootCert      *x509.Certificate
	rootKey       *ecdsa.PrivateKey

	intermediateDER  []byte
	intermediateCert *x509.Certificate
	intermediateKey  *ecdsa.PrivateKey

	leafDER  []byte
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

type testLeafOptions struct {
	dnsNames []string
	ipAddrs  []net.IP
	usages   []x509.ExtKeyUsage
	aiaURL   string
	ocspURL  string
	crlURL   string
}

func newTestPKI(t *testing.T, options testLeafOptions) testPKI {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlspolicy test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootAuthority, err := ParseAuthorityDER(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "tlspolicy test intermediate",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		rootCert,
		&intermediateKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "tlspolicy test leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  append([]x509.ExtKeyUsage(nil), options.usages...),
		DNSNames:     append([]string(nil), options.dnsNames...),
		IPAddresses:  append([]net.IP(nil), options.ipAddrs...),
	}
	if options.aiaURL != "" {
		leafTemplate.IssuingCertificateURL = []string{options.aiaURL}
	}
	if options.ocspURL != "" {
		leafTemplate.OCSPServer = []string{options.ocspURL}
	}
	if options.crlURL != "" {
		leafTemplate.CRLDistributionPoints = []string{options.crlURL}
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		intermediateCert,
		&leafKey.PublicKey,
		intermediateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return testPKI{
		rootAuthority:    rootAuthority,
		rootCert:         rootCert,
		rootKey:          rootKey,
		intermediateDER:  intermediateDER,
		intermediateCert: intermediateCert,
		intermediateKey:  intermediateKey,
		leafDER:          leafDER,
		leafCert:         leafCert,
		leafKey:          leafKey,
	}
}

func (p testPKI) tlsCertificate(includeIntermediate bool) tls.Certificate {
	chain := [][]byte{append([]byte(nil), p.leafDER...)}
	if includeIntermediate {
		chain = append(chain, append([]byte(nil), p.intermediateDER...))
	}
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  p.leafKey,
		Leaf:        p.leafCert,
	}
}

func dialTestTLS(address string, config *tls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return (&tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    config,
	}).DialContext(ctx, "tcp", address)
}

func listenTestTCP(t *testing.T) net.Listener {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func verifiedState(
	t *testing.T,
	p testPKI,
	dnsName string,
	usage x509.ExtKeyUsage,
) tls.ConnectionState {
	t.Helper()

	roots := x509.NewCertPool()
	roots.AddCert(p.rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(p.intermediateCert)
	chains, err := p.leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dnsName,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		t.Fatalf("verify test certificate: %v", err)
	}

	return tls.ConnectionState{
		ServerName:       dnsName,
		PeerCertificates: []*x509.Certificate{p.leafCert, p.intermediateCert},
		VerifiedChains:   chains,
	}
}
