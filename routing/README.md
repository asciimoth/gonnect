# routing
Package `github.com/asciimoth/gonnect/routing` provides bytecode based routing
rules for Gonnect Network, DNS, Sniffer, and Tun middleware.

The package can build:

- `gonnect.RouterCfg` for `gonnect.Router`
- `tun.SplitRouter` for `gonnect/tun.Splitter`
- `sniffer.Control` and `sniffer.SniffControl` for `gonnect/sniffer.Sniffer`
- `[]gonnect.RemapRule` for `gonnect.Remapper`
- `dns.RouteFunc` for `gonnect/dns.Router`

Rules can be created from immutable bytecode tables or parsed from a small text
format.

## DNS bytecode rules

`NewDNSBytecodeRules` parses one DNS route program. `NewBytecodeDNSRouteFunc`
turns the parsed rules into a `dns.RouteFunc` for `gonnect/dns.Router`:

```go
rules, err := routing.NewDNSBytecodeRules(routeText)
if err != nil {
	// handle error
}
route, err := routing.NewBytecodeDNSRouteFunc(rules)
if err != nil {
	// handle error
}
router.SetRouter(route)
```

Each route segment ends with `BACKEND <name>` or `DROP`. `BACKEND` returns the
fixed backend name when its condition is true. `DROP` returns an empty backend
name when its condition is true. An empty backend name, an unmatched rule, or a
name without an attached `dns.Router` backend makes the request fail with
`dns.ErrNoUpstream`.

DNS rules evaluate the first DNS question. Remote address predicates match that
question name:

- `FQDN`
- `ADDR_S`, `ADDR_RE`
- `ADDR4`, `ADDR6`
- `SNET4`, `SNET6`

`ADDR_S` compares DNS names case-insensitively. Regexps match the question name
as supplied. `NET4` is true for `A` questions, and `NET6` is true for `AAAA`
questions.

DNS-specific predicates are:

- `QTYPE <number|A|AAAA|PTR|TXT|MX|SRV|CNAME|NS|SOA>`
- `QCLASS <number|IN>`
- `OPCODE <number|QUERY>`

Transport and socket predicates such as `TCP`, `UDP`, `PORT`, `LPORT`, and
local-address predicates are not valid for DNS rules because `dns.Router` sees
only the DNS message.

### Route internal names to a private resolver

```text
ADDR_RE \.internal\.$
BACKEND private

TRUE
BACKEND public
```

Action:

- `api.internal.` routes to backend `private`.
- `example.com.` routes to backend `public`.
- If `public` is not attached to `dns.Router`, that request fails with
  `dns.ErrNoUpstream`.

### Route AAAA requests separately

```text
QTYPE AAAA
BACKEND ipv6

TRUE
BACKEND default
```

Action:

- Any first-question `AAAA` request routes to backend `ipv6`.
- Other DNS request types route to backend `default`.

### Reject selected names

```text
ADDR_S blocked.test.
DROP

TRUE
BACKEND default
```

Action:

- `blocked.test.` returns no backend and is rejected by `dns.Router`.
- Other first-question names route to backend `default`.

## Sniffer bytecode rules

`NewSnifferBytecodeRules` builds both `sniffer.Control` and
`sniffer.SniffControl` from one rule text. `SNIFF` can refer to a named
classifier from the classifier list, or it can construct an inline classifier
from the built-in constructor collection.

Sniffer-only operations are split by phase:

- `INTERCEPT` stays only in the pre-sniff control program.
- `SNIFF ...` and `SNIFF_NONE` stay only in the sniff-control program.
- Normal address, network, method, and slot rules stay in both programs.
- `ROUTE` works in sniffer bytecode only. In a `SNIFF` segment it stays only in
  sniff control. In a segment without `SNIFF`, it is copied to both phases.

Sniff errors always reject the connection by routing to slot `0`.

`ROUTE` selects a slot and can change call fields before that slot is used:

```text
ROUTE <slot> [<field>:<value> ...]
```

Supported fields:

- `NETWORK`, `SRC`, `DST`
- `SRC_ADDR`, `SRC_PORT`, `DST_ADDR`, `DST_PORT`
- `HOST`, `SERVICE`, `PROTO`

`SRC` and `DST` replace the full endpoint string. Address-part fields preserve
the current port when the endpoint is a valid `host:port`; otherwise they
replace the full endpoint. Port-part fields preserve the current host when the
endpoint is a valid `host:port`; otherwise they leave the endpoint unchanged.
Values are fixed strings from the rule text. Metadata templates such as
`${tls.sni}` are not supported.

Inline classifier specifications use this form:

```text
SNIFF <constructor> [<option>:<value> ...]
```

Constructor names are case-sensitive. The built-in constructors are `HTTP` and
`TLS`. Options do not allow spaces; values are passed as written. Repeated
equivalent inline specifications share one generated classifier. Generated
classifiers are appended after named classifiers, in first-use order.

Supported `HTTP` options:

- `METHOD`, `URL`, `URL_PATTERN`, `VERSION`
- `HOST` or `HOSTNAME`
- `HOST_PATTERN` or `HOSTNAME_PATTERN`
- `MAX_REQUEST_LINE_BYTES`, `MAX_HEADER_BYTES`

Supported `TLS` options:

- `VERSION`
- `SNI`, `HOST`, or `HOSTNAME`
- `SNI_PATTERN`, `HOST_PATTERN`, or `HOSTNAME_PATTERN`
- `ALPN`, `ALPN_PATTERN`
- `SNI_AVAILABLE`, `SNI_ENCRYPTED`
- `MAX_CLIENT_HELLO_BYTES`

`VERSION` accepts `1.0`, `1.1`, `1.2`, `1.3`, or a numeric TLS version.
`SNI_AVAILABLE` and `SNI_ENCRYPTED` accept `ANY`, `REQUIRED`, or `FORBIDDEN`.

### Block a specific HTTP URL

This example uses inline HTTP classifiers. No pre-built classifier list is
needed:

```go
rules, err := routing.NewSnifferBytecodeRules(nil, routeText)
```

Use one rule text:

```text
DIAL
TCP
AND
INTERCEPT

SNIFF HTTP URL:/blocked
SNIFF HTTP URL:/blocked2
OR
DROP

SNIFF HTTP
SLOT 1

TRUE
DROP
```

Action:

- TCP dials are intercepted and sniffed.
- HTTP requests for `/blocked` or `/blocked2` reject.
- Other HTTP requests route to slot `1`.
- Non-HTTP traffic rejects.

### Route TLS by ALPN

This example uses an inline TLS classifier:

```go
rules, err := routing.NewSnifferBytecodeRules(nil, routeText)
```

Use one rule text:

```text
DIAL
TCP
AND
PORT 443
AND
INTERCEPT

SNIFF TLS ALPN:h2
SLOT 2

SNIFF_NONE
SLOT 1
```

Action:

- TCP dials to port `443` are intercepted and sniffed.
- TLS ClientHello with ALPN `h2` routes to slot `2`.
- Traffic that does not match a classifier routes to slot `1`.

Named classifiers are still supported when Go code must build custom
`sniffer.Factory` values:

```go
rules, err := routing.NewSnifferBytecodeRules(
	[]routing.NamedSniffClassifier{
		{Name: "custom", Factory: customFactory},
	},
	"SNIFF custom\nSLOT 1\n",
)
```

Use `ROUTE` when a sniffer rule must choose a slot and rewrite call fields in
one step. A `gonnect.Remapper` can still sit behind a slot when the same remap
must apply to all traffic routed to that slot.

### Remap HTTP by URL

This example routes one HTTP URL to a fixed backend address:

```text
DIAL
TCP
AND
INTERCEPT

SNIFF HTTP URL:/blocked
ROUTE 1 DST:127.0.0.1:8080

SNIFF HTTP URL:/allowed
SLOT 2

TRUE
DROP
```

Action:

- `/blocked` routes to slot `1` with destination `127.0.0.1:8080`.
- `/allowed` routes to slot `2` with the original destination.
- Other traffic rejects.

### Remap TLS by ALPN

This example routes a TLS ALPN match to a fixed backend address:

```text
DIAL
TCP
AND
INTERCEPT

SNIFF TLS ALPN:myproto
ROUTE 1 DST:127.0.0.1:9443

TRUE
DROP
```

Action:

- TLS ClientHello with ALPN `myproto` routes to slot `1` with destination
  `127.0.0.1:9443`.
- Other traffic rejects.

## Remapper bytecode rules

`NewRemapRules` parses normal bytecode predicates into `gonnect.RemapRule`
values for `gonnect.NewRemapper`:

```go
rules, err := routing.NewRemapRules(routeText)
if err != nil {
	// handle error
}
network := gonnect.NewRemapper(baseNetwork, rules)
```

Each segment ends with `REMAP`:

```text
REMAP <endpoint> <field> <value>
```

Endpoint values:

- `SRC` or `DST`

Field values:

- `ADDR_PORT`: replace the full endpoint. Value must be `host:port`, such as
  `127.0.0.1:8080` or `[::1]:9443`.
- `ADDR`: replace only the host/address part and preserve the current port when
  possible.
- `PORT`: replace only the port part and preserve the current host when
  possible.

Rules are evaluated in order. Every matching rule applies, and later rules see
the network and addresses left by earlier rules. Values are fixed strings from
the rule text. The generated filters do not perform live DNS lookups.

### Remap dial destination host and port

```text
DIAL
TCP
AND
ADDR_S service.test
AND
REMAP DST ADDR 127.0.0.1

DIAL
PORT 80
AND
REMAP DST PORT 8080
```

Action:

- A TCP dial to `service.test:80` first changes destination address to
  `127.0.0.1:80`.
- The next rule sees port `80`, then changes the destination to
  `127.0.0.1:8080`.
- If the original network was `tcp6`, `gonnect.Remapper` changes it to `tcp4`
  because the new destination is an IPv4 literal.

### Remap UDP listen address

```text
LISTEN
UDP
AND
REMAP SRC ADDR_PORT 127.0.0.1:5353
```

Action:

- UDP listen operations change their listen address to `127.0.0.1:5353`.
- If the original network was `udp6`, `gonnect.Remapper` changes it to `udp4`.

## License
Files in this repository are distributed under the CC0 license.  

<p xmlns:dct="http://purl.org/dc/terms/">
  <a rel="license"
     href="http://creativecommons.org/publicdomain/zero/1.0/">
    <img src="http://i.creativecommons.org/p/zero/1.0/88x31.png" style="border-style: none;" alt="CC0" />
  </a>
  <br />
  To the extent possible under law,
  <a rel="dct:publisher"
     href="https://github.com/asciimoth">
    <span property="dct:title">ASCIIMoth</span></a>
  has waived all copyright and related or neighboring rights to
  <span property="dct:title">gonnect</span>.
</p>
