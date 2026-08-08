# sniffer

`sniffer` classifies the client-first prefix of a `net.Conn` without consuming
that prefix from the next handler. It reads from a `putback.Conn`, then puts all
inspected bytes back before it returns.

## Classifiers

A classifier is an incremental state machine:

```go
type Classifier interface {
	MinSniffBufferSize() int
	Feed(next []byte) State
}
```

`MinSniffBufferSize` reports the byte count that lets the classifier make its
bounded decision.

`Feed` receives only newly read bytes. Its result is one of:

- `NeedMore`: the prefix is still possible but incomplete.
- `Match`: the classifier has matched.
- `Mismatch`: no future suffix can make it match.

`Match` and `Mismatch` are terminal. `Feed(nil)` queries the initial or current
state. The slice passed to `Feed` is read-only and can be reused after the call.

Factories create a fresh classifier for each connection:

```go
type Factory interface {
	MinSniffBufferSize() int
	NewClassifier() Classifier
}
```

The factory size is the size needed by the classifiers it creates.

Included building blocks:

- `Prefix` and `PrefixFactory`
- `SSH` and `SSHFactory`, which match `SSH-` at offset zero
- `HTTP`, `HTTPWithConfig`, `HTTPFactory`, and `HTTPFactoryWithConfig`, which
  match HTTP request lines and can filter by method, URL request-target,
  HTTP-version token, and hostname
- `HTTP2` and `HTTP2Factory`, which match the cleartext HTTP/2 client
  connection preface
- `AMQP` and `AMQPFactory`, which match AMQP 0-9-1, AMQP 1.0, and
  AMQP 1.0 SASL protocol headers
- `MQTT` and `MQTTFactory`, which match MQTT CONNECT headers
- `PostgreSQL` and `PostgreSQLFactory`, which match PostgreSQL startup,
  SSLRequest, GSSENCRequest, and CancelRequest packets
- `MongoDB` and `MongoDBFactory`, which match MongoDB wire protocol request
  headers
- `Redis` and `RedisFactory`, which match Redis RESP array requests
- `TLS`, `TLSWithConfig`, `TLSFactory`, and `TLSFactoryWithConfig`, which match
  TLS ClientHello records and can filter by offered version, visible SNI
  availability, ECH presence, visible SNI hostname, and ALPN
- `ProxyProtocolV1`, `ProxyProtocolV2`, `ProxyProtocol`,
  `ProxyProtocolV1Factory`, `ProxyProtocolV2Factory`, and
  `ProxyProtocolFactory`, which match HAProxy PROXY protocol headers
- `SOCKS4`, `SOCKS5`, `SOCKS`, `SOCKS4Factory`, `SOCKS5Factory`, and
  `SOCKSFactory`, which match SOCKS client requests or greetings
- `DNSOverTCP`, `DNSOverTCPWithConfig`, `DNSOverTCPFactory`, and
  `DNSOverTCPFactoryWithConfig`, which match DNS-over-TCP query messages
- `RTSP` and `RTSPFactory`, which match RTSP request lines
- `SIP` and `SIPFactory`, which match SIP request lines
- `STUN` and `STUNFactory`, which match STUN and TURN message headers
- `RDP` and `RDPFactory`, which match RDP TPKT/X.224 connection requests
- `SMB` and `SMBFactory`, which match SMB-over-TCP negotiate requests
- `LDAP` and `LDAPFactory`, which match LDAP client request message prefixes
- `Cassandra` and `CassandraFactory`, which match Cassandra native protocol
  STARTUP and OPTIONS requests
- `MemcachedBinary`, `MemcachedASCII`, `Memcached`,
  `MemcachedBinaryFactory`, `MemcachedASCIIFactory`, and
  `MemcachedFactory`, which match memcached binary and text requests
- `And`, `Or`, and `Not`
- `AndFactory`, `OrFactory`, and `NotFactory`
- `Limit` and `LimitFactory` for classifier-local byte limits
- `MinSniffBufferSize` and `MinFactorySniffBufferSize` helpers
- `WithMinSniffBufferSize` and `FactoryWithMinSniffBufferSize` wrappers for
  function adapters or other classifiers that need a non-zero size

`HTTP` accepts any valid method token, non-empty URL request-target, and
HTTP-version token that starts with `HTTP/`. Use `HTTPWithConfig` or
`HTTPFactoryWithConfig` for exact fields, multi-value fields, and glob
patterns:

```go
factory := sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
	Methods:          []string{"GET", "POST"},
	URLPatterns:      []string{"/api/*"},
	HostnamePatterns: []string{"*.example.test"},
})
```

Empty field groups are wildcards, so leaving `Version` and `Versions` empty
accepts any HTTP version token. Non-empty values in one group are ORed, and all
configured groups must match.

`URLPatterns` and `HostnamePatterns` are byte-oriented glob patterns over the
whole value. `*` matches any byte sequence, `?` matches one byte, and `\`
escapes the next byte. Use `URL` or `URLs` for literal request-targets that
contain `?`.

Hostname filters match a normalized hostname from an absolute-form
request-target or the `Host` header. Matching is case-insensitive, and an
optional port is removed before matching. Hostname filters make the classifier
inspect headers until a matching `Host` header, a non-matching `Host` header,
the header terminator, or the header byte limit.

`HTTPConfig.MaxRequestLineBytes` bounds the request line, including LF.
`HTTPConfig.MaxHeaderBytes` bounds header inspection when hostname matching is
enabled. Zero values use `DefaultHTTPRequestLineMaxBytes` and
`DefaultHTTPHeaderMaxBytes`.

`TLS` accepts any syntactically valid TLS ClientHello. Use `TLSWithConfig` or
`TLSFactoryWithConfig` for exact fields, multi-value fields, and glob patterns:

```go
factory := sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
	Versions:         []uint16{tls.VersionTLS13},
	SNIAvailable:    sniffer.TLSFlagRequired,
	SNIEncrypted:    sniffer.TLSFlagForbidden,
	HostnamePatterns: []string{"*.example.test"},
	ALPNs:           []string{"h2", "http/1.1"},
})
```

`TLSConfig.Version` and `TLSConfig.Versions` match versions offered by the
ClientHello. If the `supported_versions` extension is present, the classifier
uses it. Otherwise it uses the ClientHello `legacy_version` field. The
server-selected TLS version is not visible before routing.

`TLSConfig.SNIAvailable` matches whether the ClientHello contains a visible SNI
`host_name`. `TLSConfig.SNIEncrypted` matches whether the
`encrypted_client_hello` extension is present. This is an observable ECH signal
only; the classifier cannot verify server ECH acceptance or reveal an encrypted
inner hostname.

`Hostname`, `Hostnames`, and `HostnamePatterns` match the visible SNI hostname
case-insensitively. With ECH, this is the outer ClientHello hostname, if the
client sends one. `ALPN`, `ALPNs`, and `ALPNPatterns` match any protocol name
in the ALPN extension case-sensitively. TLS hostname and ALPN patterns use the
same whole-value glob syntax as HTTP patterns.

`TLSConfig.MaxClientHelloBytes` bounds the bytes inspected while parsing the
first ClientHello, including TLS record headers and handshake headers. Zero
uses `DefaultTLSClientHelloMaxBytes`.

`HTTP2` matches the cleartext HTTP/2 prior-knowledge preface:
`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`. TLS connections that negotiate HTTP/2 by
ALPN are still TLS streams; use `TLSWithConfig` with `ALPN: "h2"` for those
connections.

`AMQP` matches the eight-byte protocol header for AMQP 0-9-1, AMQP 1.0, and
AMQP 1.0 SASL negotiation. It does not inspect later connection tuning, SASL
frames, or AMQP frames.

`MQTT` matches MQTT CONNECT packets. It validates the fixed header packet type,
Remaining Length field, protocol name, protocol level, connect flags, and
keep-alive bytes. It accepts MQTT 3.1, 3.1.1, and 5. It matches before reading
the client identifier or other payload fields.

`PostgreSQL` matches PostgreSQL client startup-family packets. It accepts
normal protocol 3.0 startup messages, SSLRequest, GSSENCRequest, and
CancelRequest packets. It does not inspect startup parameters, user names,
databases, or cancellation keys.

`MongoDB` matches MongoDB wire protocol request messages. It validates the
16-byte wire message header, requires a client request opcode, and requires
`responseTo` to be zero. It does not inspect BSON command documents or
compressed message bodies.

`Redis` matches Redis RESP array requests. It validates the first request array
and its first bulk-string command name. Inline Redis commands are not matched
because their text forms are ambiguous with other line-oriented protocols. The
command name must be non-empty, use printable non-space bytes, and be no larger
than 128 bytes.

`ProxyProtocolV1` matches the ASCII `PROXY ` prefix. It is a routing
heuristic, not a full v1 line parser. `ProxyProtocolV2` validates the binary
signature and fixed 16-byte header. It checks the version, command, address
family, transport protocol, and minimum address payload length, but it does not
inspect address values or TLVs. `ProxyProtocol` accepts either version.

`SOCKS4` matches SOCKS4 and SOCKS4a request headers with CONNECT or BIND
commands. It matches after the fixed eight-byte header and does not read the
user ID or SOCKS4a hostname. `SOCKS5` validates the version byte and waits for
the declared method list. `SOCKS` accepts either SOCKS4 or SOCKS5.

`DNSOverTCP` matches a DNS query with the two-byte TCP length prefix. It
validates the DNS header and question section, requires a client query rather
than a response, and requires at least one question.
`DNSOverTCPConfig.MaxMessageBytes` bounds the message bytes after the length
prefix. Zero uses `DefaultDNSOverTCPMessageMaxBytes`.

`RTSP` matches a known RTSP method, a non-empty request URI, and the RTSP/1.0
version token on the first CRLF-terminated line. It does not inspect headers,
Transport parameters, CSeq, or message bodies.

`SIP` matches a known SIP method, a non-empty Request-URI, and the SIP/2.0
version token on the first CRLF-terminated line. It does not inspect Via, To,
From, Call-ID, CSeq, or message bodies.

`STUN` matches the fixed STUN header used by STUN and TURN. It validates the
message type top bits, length alignment, magic cookie, and known method. It
does not inspect attributes or integrity.

`RDP` matches an RDP connection request over TPKT. It validates the TPKT header
and the X.224 Connection Request fixed fields, then matches before optional
cookies, routing tokens, or negotiation data.

`SMB` matches SMB-over-TCP client negotiate requests. It validates the NetBIOS
Session Service header and the start of an SMB1 or SMB2/3 negotiate request. It
does not inspect dialects, security modes, capabilities, or later SMB messages.

`LDAP` matches LDAP client messages. It validates enough BER to find a non-zero
message ID and a client request protocolOp tag. It does not parse request
fields, controls, filters, or authentication data.

`Cassandra` matches Cassandra native protocol STARTUP and OPTIONS requests for
protocol v3, v4, and v5. It validates the request header and body length rules
for those first client messages, but it does not inspect the body string map or
compression.

`MemcachedBinary` matches memcached binary protocol requests by validating the
fixed request header. `MemcachedASCII` matches common memcached text protocol
request lines and matches before storage value bytes. `Memcached` accepts either
form.

## Sniffing and routing

```go
func route(raw net.Conn, pool bufpool.Pool) error {
	conn := putback.New(raw, pool)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}

	factories := []sniffer.Factory{
		sniffer.HTTPFactory(),
		sniffer.SSHFactory(),
	}
	index, err := sniffer.SniffFactoriesWithPool(
		sniffer.MinFactorySniffBufferSize(factories...),
		pool,
		conn,
		factories...,
	)

	if clearErr := conn.SetReadDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	if err != nil {
		if gonnect.IsTimeout(err) {
			return proxyToOriginalDestination(conn)
		}
		return err
	}

	switch index {
	case 0:
		return handleHTTP(conn)
	case 1:
		return proxySSH(conn)
	case sniffer.NoMatch:
		return proxyToOriginalDestination(conn)
	default:
		panic("unreachable")
	}
}
```

`SniffWithPool` and `SniffFactoriesWithPool` get the scratch buffer from
`bufpool` and return it before they return. Pass the same pool to `putback.New`
if replay copies must also use the pool. Call `Sniff` or `SniffFactories`
directly when the caller already owns the scratch buffer.

When a scratch buffer is passed directly, its contents are ignored on entry and
can be overwritten. The buffer length, not capacity, is the total inspection
limit. A zero-length buffer returns `NoMatch` unless a classifier matches on
`Feed(nil)`.

Every byte read by `Sniff` is copied back before it returns. This is true for
match, no-match, buffer-exhaustion, and read-error paths. You can chain
sniffers on the same wrapper:

```go
index, err := sniffer.SniffWithPool(tlsBudget, pool, conn, tlsClassifier)
if err != nil {
	return err
}
if index == sniffer.NoMatch {
	classifiers := []sniffer.Classifier{
		httpClassifier,
		sniffer.SSH(),
	}
	index, err = sniffer.SniffWithPool(
		sniffer.MinSniffBufferSize(classifiers...),
		pool,
		conn,
		classifiers...,
	)
}
```

## Incomplete prefixes

If a classifier needs four bytes and the peer sends only three, the only correct
state is `NeedMore`. The next byte can complete the signature, or the peer can
be using another protocol.

The caller must set the policy boundary. A common policy treats a classification
timeout as fallback and returns other read errors:

```go
_ = conn.SetReadDeadline(time.Now().Add(classificationBudget))
index, err := sniffer.SniffFactoriesWithPool(
	classificationMaxBytes,
	pool,
	conn,
	factories...,
)
_ = conn.SetReadDeadline(time.Time{})

if err != nil {
	if gonnect.IsTimeout(err) {
		return proxyToOriginalDestination(conn)
	}
	return err
}
```

Use an absolute caller-owned classification deadline. Do not reset it after
every byte, because a slow peer can keep an ambiguous connection alive without
end.

## Match selection

`Sniff` performs normal batched connection reads, but feeds classifiers one byte
at a time and checks their states after every byte. The route does not depend on
how TCP splits the stream across `Read` calls.

`Sniff` returns as soon as any classifier reports `Match`. If several classifiers
match after the same byte, the lowest index wins. It does not wait for a
lower-index classifier that still reports `NeedMore`.

For example, with `Prefix("AB")` followed by `Prefix("A")`, input `A` selects
the second classifier immediately, even when `AB` arrived in one underlying
`Read`. List order only breaks matches observed at the same byte position. It
is not a longest-match parser. Use a combined classifier when overlapping
signatures require another policy.

## Limits

- Server-first or silent-client protocols have no client bytes to classify. Use
  listener metadata, original-destination metadata, a caller-owned deadline, or
  a fallback route.
- Some prefixes are ambiguous. Only more bytes or an external policy boundary
  can decide them.
- `Sniff` has a fixed caller-provided budget. Complex classifiers must also
  enforce their own field or header limits.
- TCP is a byte stream. Classifiers must not attach protocol meaning to `Read`
  boundaries.
- Classifiers must not perform connection I/O, mutate the read-only `Feed`
  slice, or mutate external protocol state.
- EOF is returned by `Sniff`; it is not fed to classifiers.
- `Sniff` requires exclusive read-side ownership until it returns.
- Put-back bytes are returned without calling the wrapped connection. Its read
  deadline is observed after the put-back buffer drains.

SNI, HTTP request lines, PROXY protocol, and similar formats should be bounded
incremental classifiers. Malformed or over-limit input should return
`Mismatch`. Classifier errors are intentionally not part of the API. Only errors
returned by `Conn.Read` are returned from `Sniff`.
