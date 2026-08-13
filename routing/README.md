# routing
Package `github.com/asciimoth/gonnect/routing` provides bytecode based routing
rules for Gonnect Network, Sniffer, and Tun middleware.

The package can build:

- `gonnect.RouterCfg` for `gonnect.Router`
- `tun.SplitRouter` for `gonnect/tun.Splitter`
- `sniffer.Control` and `sniffer.SniffControl` for `gonnect/sniffer.Sniffer`

Rules can be created from immutable bytecode tables or parsed from a small text
format.

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
