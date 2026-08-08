package sniffer_test

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

func TestSniffFactoriesMixedConfiguredClassifierSet(t *testing.T) {
	const (
		apiHost = "api.example.test"
		opsHost = "ops.example.test"
	)

	tlsH2 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "h2", "http/1.1"),
	)
	tlsHTTP1 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "http/1.1"),
	)
	tlsNoMatch := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "acme-tls/1"),
	)
	tlsLimit := maxLen(tlsH2, tlsHTTP1, tlsNoMatch)

	factories := []sniffer.Factory{
		sniffer.SSHFactory(),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 128,
			MaxHeaderBytes:      256,
			Method:              http.MethodGet,
			URLPatterns:         []string{"/api/*"},
			Hostname:            apiHost,
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 128,
			MaxHeaderBytes:      256,
			Method:              http.MethodGet,
			URLPatterns:         []string{"/api/*"},
			HostnamePatterns:    []string{"*.example.test"},
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 128,
			MaxHeaderBytes:      256,
			Method:              http.MethodGet,
			URL:                 "/health",
			Hostname:            opsHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagForbidden,
			Hostname:            apiHost,
			ALPN:                "h2",
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagForbidden,
			Hostname:            apiHost,
			ALPN:                "http/1.1",
		}),
		sniffer.RedisFactory(),
	}
	bufferSize := sniffer.MinFactorySniffBufferSize(factories...)

	tests := []struct {
		name   string
		chunks []string
		want   int
	}{
		{
			name: "SSH wins before slower classifiers decide",
			chunks: []string{
				"SS",
				"H-2.0-test\r\npayload",
			},
			want: 0,
		},
		{
			name: "HTTP exact host wins over wildcard host",
			chunks: []string{
				"GET /api/users HTTP/1.1\r\nHost: ",
				"API.EXAMPLE.TEST:8443\r\n\r\nbody",
			},
			want: 1,
		},
		{
			name: "HTTP wildcard host catches another API host",
			chunks: []string{
				"GET /api/users HTTP/1.1\r\n",
				"User-Agent: test\r\n",
				"Host: edge.example.test\r\n\r\nbody",
			},
			want: 2,
		},
		{
			name: "HTTP health route uses different URL and host config",
			chunks: []string{
				"GET /health HTTP/1.1\r\nHost: ",
				"ops.example.test\r\n\r\nbody",
			},
			want: 3,
		},
		{
			name: "TLS h2 route wins when both TLS routes can parse",
			chunks: []string{
				string(tlsH2[:7]),
				string(tlsH2[7:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "TLS HTTP1 route matches after h2 route rejects",
			chunks: []string{
				string(tlsHTTP1[:13]),
				string(tlsHTTP1[13:]),
				"encrypted",
			},
			want: 5,
		},
		{
			name: "Redis route coexists with HTTP GET tokens",
			chunks: []string{
				"*2\r\n$3\r\n",
				"GET\r\n$3\r\nkey\r\n",
			},
			want: 6,
		},
		{
			name: "HTTP request with unmatched host has no route",
			chunks: []string{
				"GET /api/users HTTP/1.1\r\n",
				"Host: example.invalid\r\n\r\nbody",
			},
			want: sniffer.NoMatch,
		},
		{
			name: "TLS request with unmatched ALPN has no route",
			chunks: []string{
				string(tlsNoMatch[:5]),
				string(tlsNoMatch[5:]),
				"encrypted",
			},
			want: sniffer.NoMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.SniffFactories(
				make([]byte, bufferSize),
				conn,
				factories...,
			)
			if err != nil {
				t.Fatalf("SniffFactories: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffFactoriesMixedRepeatedClassifierConfigurations(t *testing.T) {
	const apiHost = "api.example.test"

	tlsH2 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "h2", "http/1.1"),
	)
	tlsHTTP1 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "http/1.1"),
	)
	tlsLimit := maxLen(tlsH2, tlsHTTP1)
	dnsQuery := testDNSOverTCPQuery("api.example.test")
	dnsMessageBytes := len(dnsQuery) - 2
	proxyV2 := validProxyProtocolV2Header()

	factories := []sniffer.Factory{
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      36,
			Method:              http.MethodGet,
			URLPatterns:         []string{"/tenant/*"},
			Hostname:            apiHost,
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      256,
			Method:              http.MethodGet,
			URLPatterns:         []string{"/tenant/*"},
			Hostname:            apiHost,
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      256,
			Method:              http.MethodPost,
			URLPatterns:         []string{"/tenant/*"},
			Hostname:            apiHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: 16,
			Version:             tls.VersionTLS13,
			Hostname:            apiHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagForbidden,
			Hostname:            apiHost,
			ALPN:                "h2",
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagForbidden,
			Hostname:            apiHost,
			ALPN:                "http/1.1",
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes - 1,
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes,
		}),
		sniffer.ProxyProtocolFactory(),
	}
	bufferSize := sniffer.MinFactorySniffBufferSize(factories...)

	tests := []struct {
		name   string
		chunks []string
		want   int
	}{
		{
			name: "HTTP GET route survives smaller header limit",
			chunks: []string{
				"GET /tenant/alpha HTTP/1.1\r\n",
				"X-Fill: 123456789012345678901234567890\r\n",
				"Host: api.example.test\r\n\r\npayload",
			},
			want: 1,
		},
		{
			name: "HTTP POST route uses same host and URL pattern",
			chunks: []string{
				"POST /tenant/alpha HTTP/1.1\r\nHost: ",
				"api.example.test\r\n\r\npayload",
			},
			want: 2,
		},
		{
			name: "TLS h2 route survives smaller ClientHello limit",
			chunks: []string{
				string(tlsH2[:5]),
				string(tlsH2[5:23]),
				string(tlsH2[23:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "TLS HTTP1 route uses different ALPN config",
			chunks: []string{
				string(tlsHTTP1[:11]),
				string(tlsHTTP1[11:]),
				"encrypted",
			},
			want: 5,
		},
		{
			name: "DNS route survives smaller DNS message limit",
			chunks: []string{
				string(dnsQuery[:2]),
				string(dnsQuery[2:18]),
				string(dnsQuery[18:]),
				"payload",
			},
			want: 7,
		},
		{
			name: "PROXY protocol route shares the binary set",
			chunks: []string{
				string(proxyV2[:12]),
				string(proxyV2[12:]),
				"upstream",
			},
			want: 8,
		},
		{
			name: "unmatched HTTP host has no route",
			chunks: []string{
				"GET /tenant/alpha HTTP/1.1\r\n",
				"Host: other.example.test\r\n\r\npayload",
			},
			want: sniffer.NoMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.SniffFactories(
				make([]byte, bufferSize),
				conn,
				factories...,
			)
			if err != nil {
				t.Fatalf("SniffFactories: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffFactoriesComplexMixedProtocolMatrix(t *testing.T) {
	const (
		apiHost    = "api.example.test"
		publicHost = "public.example.test"
	)

	tlsECH := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2"),
		tlsTestExtension{typ: 0xfe0d},
	)
	tlsClear := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2"),
	)
	tlsLimit := maxLen(tlsECH, tlsClear)
	dnsQuery := testDNSOverTCPQuery("matrix.example.test")
	dnsMessageBytes := len(dnsQuery) - 2
	mqttConnect := testMQTTConnectPrefix("MQTT", 4, 12)
	postgresStartup := testPostgreSQLStartupHeader(9, 196608)
	mongoRequest := testMongoDBHeader(16, 0, 2013)
	socks5Greeting := []byte{5, 2, 0, 2}
	proxyV2 := validProxyProtocolV2Header()

	factories := []sniffer.Factory{
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      128,
			Method:              http.MethodGet,
			URL:                 "/admin",
			Hostname:            "control.example.test",
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      256,
			Methods: []string{
				http.MethodGet,
				http.MethodPost,
			},
			URLPatterns: []string{"/tenant/*"},
			Hostnames: []string{
				apiHost,
				"edge.example.test",
			},
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 128,
			MaxHeaderBytes:      128,
			Method:              http.MethodGet,
			URLPatterns:         []string{"http://*.example.test/proxy/*"},
			HostnamePatterns:    []string{"*.example.test"},
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: 16,
			Version:             tls.VersionTLS13,
			Hostname:            publicHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagRequired,
			Hostname:            publicHost,
			ALPNPatterns:        []string{"h?"},
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagForbidden,
			Hostname:            publicHost,
			ALPN:                "h2",
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes - 1,
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes,
		}),
		sniffer.MQTTFactory(),
		sniffer.RedisFactory(),
		sniffer.PostgreSQLFactory(),
		sniffer.MongoDBFactory(),
		sniffer.SOCKSFactory(),
		sniffer.ProxyProtocolFactory(),
		sniffer.HTTP2Factory(),
	}
	bufferSize := sniffer.MinFactorySniffBufferSize(factories...)

	tests := []struct {
		name   string
		chunks []string
		want   int
	}{
		{
			name: "HTTP tenant route shares the text prefix set",
			chunks: []string{
				"GET /tenant/alpha HTTP/1.1\r\n",
				"X-Trace: 123456789012345678901234567890\r\n",
				"Host: edge.example.test\r\n\r\npayload",
			},
			want: 1,
		},
		{
			name: "HTTP absolute-form route uses URL hostname",
			chunks: []string{
				"GET http://node.example.test/proxy/status HTTP/1.1\r\n",
				"Host: ignored.invalid\r\n\r\npayload",
			},
			want: 2,
		},
		{
			name: "TLS ECH route survives smaller TLS limit",
			chunks: []string{
				string(tlsECH[:6]),
				string(tlsECH[6:31]),
				string(tlsECH[31:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "TLS clear route uses forbidden ECH config",
			chunks: []string{
				string(tlsClear[:9]),
				string(tlsClear[9:]),
				"encrypted",
			},
			want: 5,
		},
		{
			name: "DNS exact limit route shares binary classifier set",
			chunks: []string{
				string(dnsQuery[:2]),
				string(dnsQuery[2:17]),
				string(dnsQuery[17:]),
				"payload",
			},
			want: 7,
		},
		{
			name: "MQTT route coexists with binary headers",
			chunks: []string{
				string(mqttConnect[:3]),
				string(mqttConnect[3:]),
				"\x00\x00client",
			},
			want: 8,
		},
		{
			name: "Redis route coexists with HTTP token bytes",
			chunks: []string{
				"*2\r\n$4\r\n",
				"PING\r\n$0\r\n\r\n",
			},
			want: 9,
		},
		{
			name: "PostgreSQL route coexists with DNS length bytes",
			chunks: []string{
				string(postgresStartup[:3]),
				string(postgresStartup[3:]),
				"user\x00",
			},
			want: 10,
		},
		{
			name: "MongoDB route coexists with MQTT leading byte",
			chunks: []string{
				string(mongoRequest[:5]),
				string(mongoRequest[5:]),
				"{}",
			},
			want: 11,
		},
		{
			name: "SOCKS route coexists with short binary protocols",
			chunks: []string{
				string(socks5Greeting[:1]),
				string(socks5Greeting[1:]),
			},
			want: 12,
		},
		{
			name: "PROXY v2 route coexists with text routes",
			chunks: []string{
				string(proxyV2[:12]),
				string(proxyV2[12:]),
				"upstream",
			},
			want: 13,
		},
		{
			name: "HTTP2 route survives configured HTTP mismatches",
			chunks: []string{
				"PRI * HTTP/2.0\r\n",
				"\r\nSM\r\n\r\n",
				"frames",
			},
			want: 14,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.SniffFactories(
				make([]byte, bufferSize),
				conn,
				factories...,
			)
			if err != nil {
				t.Fatalf("SniffFactories: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffMixedConfiguredCombinators(t *testing.T) {
	const apiHost = "api.example.test"

	tlsHTTP1 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "http/1.1"),
	)

	tests := []struct {
		name        string
		chunks      []string
		classifiers []sniffer.Classifier
		want        int
	}{
		{
			name: "HTTP route accepts non-admin URL with nested HTTP configs",
			chunks: []string{
				"GET /tenant/users HTTP/1.1\r\n",
				"Host: api.example.test\r\n\r\n",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.HTTPWithConfig(sniffer.HTTPConfig{
						Method: http.MethodGet,
						URLPatterns: []string{
							"/tenant/*",
						},
						Hostname: apiHost,
					}),
					sniffer.Not(sniffer.HTTPWithConfig(
						sniffer.HTTPConfig{
							Method: http.MethodGet,
							URL:    "/tenant/admin",
						},
					)),
				),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/tenant/admin",
					Hostname: apiHost,
				}),
			},
			want: 0,
		},
		{
			name: "HTTP route excludes admin URL with nested HTTP configs",
			chunks: []string{
				"GET /tenant/admin HTTP/1.1\r\n",
				"Host: api.example.test\r\n\r\n",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.HTTPWithConfig(sniffer.HTTPConfig{
						Method: http.MethodGet,
						URLPatterns: []string{
							"/tenant/*",
						},
						Hostname: apiHost,
					}),
					sniffer.Not(sniffer.HTTPWithConfig(
						sniffer.HTTPConfig{
							Method: http.MethodGet,
							URL:    "/tenant/admin",
						},
					)),
				),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/tenant/admin",
					Hostname: apiHost,
				}),
			},
			want: 1,
		},
		{
			name: "TLS OR route matches one of two ALPN configs",
			chunks: []string{
				string(tlsHTTP1[:9]),
				string(tlsHTTP1[9:]),
				"encrypted",
			},
			classifiers: []sniffer.Classifier{
				sniffer.Or(
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: len(tlsHTTP1),
						Version:             tls.VersionTLS13,
						Hostname:            apiHost,
						ALPN:                "h2",
					}),
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: len(tlsHTTP1),
						Version:             tls.VersionTLS13,
						Hostname:            apiHost,
						ALPN:                "http/1.1",
					}),
				),
				sniffer.TLSWithConfig(sniffer.TLSConfig{
					MaxClientHelloBytes: len(tlsHTTP1),
					Version:             tls.VersionTLS13,
					Hostname:            "other.example.test",
				}),
			},
			want: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.Sniff(
				make(
					[]byte,
					sniffer.MinSniffBufferSize(test.classifiers...),
				),
				conn,
				test.classifiers...,
			)
			if err != nil {
				t.Fatalf("Sniff: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffMixedRepeatedConfiguredCombinators(t *testing.T) {
	const (
		apiHost    = "api.example.test"
		publicHost = "public.example.test"
	)

	tlsClear := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2", "http/1.1"),
	)
	tlsECH := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2"),
		tlsTestExtension{typ: 0xfe0d},
	)
	tlsLimit := maxLen(tlsClear, tlsECH)

	tests := []struct {
		name        string
		chunks      []string
		classifiers []sniffer.Classifier
		want        int
	}{
		{
			name: "clear TLS route excludes ECH with repeated TLS configs",
			chunks: []string{
				string(tlsClear[:8]),
				string(tlsClear[8:]),
				"encrypted",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: tlsLimit,
						Version:             tls.VersionTLS13,
						SNIAvailable:        sniffer.TLSFlagRequired,
						HostnamePatterns:    []string{"*.example.test"},
						ALPNs: []string{
							"h2",
							"http/1.1",
						},
					}),
					sniffer.Not(sniffer.TLSWithConfig(
						sniffer.TLSConfig{
							MaxClientHelloBytes: tlsLimit,
							SNIEncrypted:        sniffer.TLSFlagRequired,
						},
					)),
				),
				sniffer.TLSWithConfig(sniffer.TLSConfig{
					MaxClientHelloBytes: tlsLimit,
					SNIEncrypted:        sniffer.TLSFlagRequired,
					Hostname:            publicHost,
				}),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/api/health",
					Hostname: apiHost,
				}),
				sniffer.Or(sniffer.Redis(), sniffer.MQTT()),
			},
			want: 0,
		},
		{
			name: "ECH route wins after clear TLS route rejects it",
			chunks: []string{
				string(tlsECH[:10]),
				string(tlsECH[10:]),
				"encrypted",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: tlsLimit,
						Version:             tls.VersionTLS13,
						SNIAvailable:        sniffer.TLSFlagRequired,
						HostnamePatterns:    []string{"*.example.test"},
						ALPN:                "h2",
					}),
					sniffer.Not(sniffer.TLSWithConfig(
						sniffer.TLSConfig{
							MaxClientHelloBytes: tlsLimit,
							SNIEncrypted:        sniffer.TLSFlagRequired,
						},
					)),
				),
				sniffer.TLSWithConfig(sniffer.TLSConfig{
					MaxClientHelloBytes: tlsLimit,
					SNIEncrypted:        sniffer.TLSFlagRequired,
					Hostname:            publicHost,
				}),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/api/health",
					Hostname: apiHost,
				}),
				sniffer.Or(sniffer.Redis(), sniffer.MQTT()),
			},
			want: 1,
		},
		{
			name: "HTTP route uses a separate configured classifier",
			chunks: []string{
				"GET /api/health HTTP/1.1\r\n",
				"Host: api.example.test\r\n\r\n",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: tlsLimit,
						Version:             tls.VersionTLS13,
						HostnamePatterns:    []string{"*.example.test"},
					}),
					sniffer.Not(sniffer.TLSWithConfig(
						sniffer.TLSConfig{
							MaxClientHelloBytes: tlsLimit,
							SNIEncrypted:        sniffer.TLSFlagRequired,
						},
					)),
				),
				sniffer.TLSWithConfig(sniffer.TLSConfig{
					MaxClientHelloBytes: tlsLimit,
					SNIEncrypted:        sniffer.TLSFlagRequired,
					Hostname:            publicHost,
				}),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/api/health",
					Hostname: apiHost,
				}),
				sniffer.Or(sniffer.Redis(), sniffer.MQTT()),
			},
			want: 2,
		},
		{
			name: "protocol OR route mixes non-HTTP non-TLS classifiers",
			chunks: []string{
				"*1\r\n$4\r\n",
				"PING\r\n",
			},
			classifiers: []sniffer.Classifier{
				sniffer.And(
					sniffer.TLSWithConfig(sniffer.TLSConfig{
						MaxClientHelloBytes: tlsLimit,
						Version:             tls.VersionTLS13,
						HostnamePatterns:    []string{"*.example.test"},
					}),
					sniffer.Not(sniffer.TLSWithConfig(
						sniffer.TLSConfig{
							MaxClientHelloBytes: tlsLimit,
							SNIEncrypted:        sniffer.TLSFlagRequired,
						},
					)),
				),
				sniffer.TLSWithConfig(sniffer.TLSConfig{
					MaxClientHelloBytes: tlsLimit,
					SNIEncrypted:        sniffer.TLSFlagRequired,
					Hostname:            publicHost,
				}),
				sniffer.HTTPWithConfig(sniffer.HTTPConfig{
					Method:   http.MethodGet,
					URL:      "/api/health",
					Hostname: apiHost,
				}),
				sniffer.Or(sniffer.Redis(), sniffer.MQTT()),
			},
			want: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.Sniff(
				make(
					[]byte,
					sniffer.MinSniffBufferSize(test.classifiers...),
				),
				conn,
				test.classifiers...,
			)
			if err != nil {
				t.Fatalf("Sniff: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffFactoriesNestedMixedConfiguredRoutes(t *testing.T) {
	const (
		apiHost    = "api.example.test"
		publicHost = "public.example.test"
	)

	tlsAPIH2 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "h2", "http/1.1"),
	)
	tlsAPIHTTP1 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, apiHost),
		tlsTestALPN(t, "http/1.1"),
	)
	tlsPublicECH := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2"),
		tlsTestExtension{typ: 0xfe0d},
	)
	tlsPublicClear := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2"),
	)
	tlsLimit := maxLen(
		tlsAPIH2,
		tlsAPIHTTP1,
		tlsPublicECH,
		tlsPublicClear,
	)
	dnsQuery := testDNSOverTCPQuery("nested.example.test")
	dnsMessageBytes := len(dnsQuery) - 2
	mqttConnect := testMQTTConnectPrefix("MQTT", 5, 13)
	proxyV2 := validProxyProtocolV2Header()

	factories := []sniffer.Factory{
		sniffer.AndFactory(
			sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
				MaxRequestLineBytes: 96,
				MaxHeaderBytes:      192,
				Method:              http.MethodGet,
				URLPatterns:         []string{"/edge/*"},
				Hostname:            apiHost,
			}),
			sniffer.NotFactory(
				sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
					MaxRequestLineBytes: 96,
					MaxHeaderBytes:      192,
					Method:              http.MethodGet,
					URL:                 "/edge/private",
					Hostname:            apiHost,
				}),
			),
		),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      192,
			Method:              http.MethodGet,
			URL:                 "/edge/private",
			Hostname:            apiHost,
		}),
		sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
			MaxRequestLineBytes: 96,
			MaxHeaderBytes:      192,
			Method:              http.MethodPost,
			URLPatterns:         []string{"/edge/*"},
			Hostname:            apiHost,
		}),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: 20,
			Version:             tls.VersionTLS13,
			Hostname:            apiHost,
			ALPN:                "h2",
		}),
		sniffer.OrFactory(
			sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
				MaxClientHelloBytes: tlsLimit,
				Version:             tls.VersionTLS13,
				SNIAvailable:        sniffer.TLSFlagRequired,
				SNIEncrypted:        sniffer.TLSFlagForbidden,
				Hostname:            apiHost,
				ALPN:                "h2",
			}),
			sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
				MaxClientHelloBytes: tlsLimit,
				Version:             tls.VersionTLS13,
				SNIAvailable:        sniffer.TLSFlagRequired,
				SNIEncrypted:        sniffer.TLSFlagForbidden,
				Hostname:            apiHost,
				ALPN:                "http/1.1",
			}),
		),
		sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
			MaxClientHelloBytes: tlsLimit,
			Version:             tls.VersionTLS13,
			SNIAvailable:        sniffer.TLSFlagRequired,
			SNIEncrypted:        sniffer.TLSFlagRequired,
			Hostname:            publicHost,
			ALPN:                "h2",
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes - 1,
		}),
		sniffer.DNSOverTCPFactoryWithConfig(sniffer.DNSOverTCPConfig{
			MaxMessageBytes: dnsMessageBytes,
		}),
		sniffer.OrFactory(
			sniffer.AMQPFactory(),
			sniffer.MQTTFactory(),
		),
		sniffer.ProxyProtocolFactory(),
	}
	bufferSize := sniffer.MinFactorySniffBufferSize(factories...)

	tests := []struct {
		name   string
		chunks []string
		want   int
	}{
		{
			name: "HTTP edge route excludes exact private route",
			chunks: []string{
				"GET /edge/status HTTP/1.1\r\n",
				"X-Scope: public\r\n",
				"Host: api.example.test\r\n\r\npayload",
			},
			want: 0,
		},
		{
			name: "HTTP private route wins after negated route rejects it",
			chunks: []string{
				"GET /edge/private HTTP/1.1\r\n",
				"Host: api.example.test\r\n\r\npayload",
			},
			want: 1,
		},
		{
			name: "HTTP POST route uses same URL pattern and host",
			chunks: []string{
				"POST /edge/status HTTP/1.1\r\nHost: ",
				"api.example.test\r\n\r\npayload",
			},
			want: 2,
		},
		{
			name: "TLS h2 route survives smaller TLS limit",
			chunks: []string{
				string(tlsAPIH2[:5]),
				string(tlsAPIH2[5:27]),
				string(tlsAPIH2[27:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "TLS HTTP1 route uses alternate TLS child config",
			chunks: []string{
				string(tlsAPIHTTP1[:11]),
				string(tlsAPIHTTP1[11:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "TLS ECH route uses encrypted SNI config",
			chunks: []string{
				string(tlsPublicECH[:7]),
				string(tlsPublicECH[7:]),
				"encrypted",
			},
			want: 5,
		},
		{
			name: "DNS route survives smaller DNS limit",
			chunks: []string{
				string(dnsQuery[:2]),
				string(dnsQuery[2:19]),
				string(dnsQuery[19:]),
				"payload",
			},
			want: 7,
		},
		{
			name: "AMQP route shares an OR with MQTT",
			chunks: []string{
				"AMQP\x00",
				"\x01\x00\x00frames",
			},
			want: 8,
		},
		{
			name: "MQTT route shares an OR with AMQP",
			chunks: []string{
				string(mqttConnect[:4]),
				string(mqttConnect[4:]),
				"\x00\x00client",
			},
			want: 8,
		},
		{
			name: "PROXY protocol route stays after text and TLS routes",
			chunks: []string{
				string(proxyV2[:12]),
				string(proxyV2[12:]),
				"upstream",
			},
			want: 9,
		},
		{
			name: "clear public TLS has no ECH route",
			chunks: []string{
				string(tlsPublicClear[:8]),
				string(tlsPublicClear[8:]),
				"encrypted",
			},
			want: sniffer.NoMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)

			index, err := sniffer.SniffFactories(
				make([]byte, bufferSize),
				conn,
				factories...,
			)
			if err != nil {
				t.Fatalf("SniffFactories: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func TestSniffRepeatedConfiguredClassifierPriority(t *testing.T) {
	const (
		reportsHost = "reports.example.test"
		publicHost  = "public.example.test"
	)

	tlsH2 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "h2", "http/1.1"),
	)
	tlsHTTP1 := tlsTestClientHello(t, tls.VersionTLS13,
		tlsTestSupportedVersions(t, tls.VersionTLS13),
		tlsTestServerName(t, publicHost),
		tlsTestALPN(t, "http/1.1"),
	)
	tlsLimit := maxLen(tlsH2, tlsHTTP1)
	dnsQuery := testDNSOverTCPQuery("reports.example.test")
	dnsMessageBytes := len(dnsQuery) - 2

	newClassifiers := func() []sniffer.Classifier {
		return []sniffer.Classifier{
			sniffer.HTTPWithConfig(sniffer.HTTPConfig{
				Method:   http.MethodGet,
				URL:      "/reports/latest",
				Hostname: reportsHost,
			}),
			sniffer.HTTPWithConfig(sniffer.HTTPConfig{
				Method:              http.MethodGet,
				URLPatterns:         []string{"/reports/*"},
				HostnamePatterns:    []string{"*.example.test"},
				MaxRequestLineBytes: 96,
				MaxHeaderBytes:      192,
			}),
			sniffer.HTTPWithConfig(sniffer.HTTPConfig{
				Method:      http.MethodPost,
				URLPatterns: []string{"/reports/*"},
				Hostname:    reportsHost,
			}),
			sniffer.TLSWithConfig(sniffer.TLSConfig{
				MaxClientHelloBytes: tlsLimit,
				Hostname:            publicHost,
				ALPN:                "h2",
			}),
			sniffer.TLSWithConfig(sniffer.TLSConfig{
				MaxClientHelloBytes: tlsLimit,
				Hostname:            publicHost,
				ALPN:                "http/1.1",
			}),
			sniffer.DNSOverTCPWithConfig(sniffer.DNSOverTCPConfig{
				MaxMessageBytes: dnsMessageBytes - 1,
			}),
			sniffer.DNSOverTCPWithConfig(sniffer.DNSOverTCPConfig{
				MaxMessageBytes: dnsMessageBytes,
			}),
		}
	}

	tests := []struct {
		name   string
		chunks []string
		want   int
	}{
		{
			name: "exact HTTP route beats wildcard HTTP route",
			chunks: []string{
				"GET /reports/latest HTTP/1.1\r\n",
				"Host: reports.example.test\r\n\r\npayload",
			},
			want: 0,
		},
		{
			name: "wildcard HTTP route catches another report URL",
			chunks: []string{
				"GET /reports/2026 HTTP/1.1\r\nHost: ",
				"reports.example.test\r\n\r\npayload",
			},
			want: 1,
		},
		{
			name: "POST HTTP route shares URL pattern with GET routes",
			chunks: []string{
				"POST /reports/latest HTTP/1.1\r\n",
				"Host: reports.example.test\r\n\r\npayload",
			},
			want: 2,
		},
		{
			name: "TLS h2 route beats later HTTP1 ALPN route",
			chunks: []string{
				string(tlsH2[:6]),
				string(tlsH2[6:]),
				"encrypted",
			},
			want: 3,
		},
		{
			name: "TLS HTTP1 route matches after h2 ALPN rejects",
			chunks: []string{
				string(tlsHTTP1[:10]),
				string(tlsHTTP1[10:]),
				"encrypted",
			},
			want: 4,
		},
		{
			name: "DNS exact limit route follows smaller DNS config",
			chunks: []string{
				string(dnsQuery[:2]),
				string(dnsQuery[2:]),
				"payload",
			},
			want: 6,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)
			classifiers := newClassifiers()

			index, err := sniffer.Sniff(
				make(
					[]byte,
					sniffer.MinSniffBufferSize(classifiers...),
				),
				conn,
				classifiers...,
			)
			if err != nil {
				t.Fatalf("Sniff: %v", err)
			}
			if index != test.want {
				t.Fatalf("index = %d, want %d", index, test.want)
			}

			if got, want := []byte(readAll(t, conn)), joinChunkBytes(
				test.chunks,
			); !bytes.Equal(got, want) {
				t.Fatalf("replayed stream changed: got %x, want %x", got, want)
			}
		})
	}
}

func maxLen(slices ...[]byte) int {
	maximum := 0
	for _, slice := range slices {
		if len(slice) > maximum {
			maximum = len(slice)
		}
	}
	return maximum
}

func joinChunkBytes(chunks []string) []byte {
	total := 0
	for _, chunk := range chunks {
		total += len(chunk)
	}

	joined := make([]byte, 0, total)
	for _, chunk := range chunks {
		joined = append(joined, []byte(chunk)...)
	}
	return joined
}
