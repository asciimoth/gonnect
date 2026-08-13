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
`sniffer.SniffControl` from one rule text. Use named classifiers in the
classifier list, then refer to them with `SNIFF <name>` in rules.

Sniffer-only operations are split by phase:

- `INTERCEPT` stays only in the pre-sniff control program.
- `SNIFF <name>` and `SNIFF_NONE` stay only in the sniff-control program.
- Normal address, network, method, and slot rules stay in both programs.

Sniff errors always reject the connection by routing to slot `0`.

### Block a specific HTTP URL

Configure classifiers:

```go
rules, err := routing.NewSnifferBytecodeRules(
	[]routing.NamedSniffClassifier{
		{
			Name: "blocked_http",
			Factory: sniffer.HTTPFactoryWithConfig(sniffer.HTTPConfig{
				URL: "/blocked",
			}),
		},
		{Name: "http", Factory: sniffer.HTTPFactory()},
	},
	routeText,
)
```

Use one rule text:

```text
DIAL
TCP
AND
INTERCEPT

SNIFF blocked_http
DROP

SNIFF http
SLOT 1

TRUE
DROP
```

Action:

- TCP dials are intercepted and sniffed.
- HTTP requests for `/blocked` reject.
- Other HTTP requests route to slot `1`.
- Non-HTTP traffic rejects.

### Route TLS by ALPN

Configure the classifier:

```go
rules, err := routing.NewSnifferBytecodeRules(
	[]routing.NamedSniffClassifier{
		{
			Name: "tls_h2",
			Factory: sniffer.TLSFactoryWithConfig(sniffer.TLSConfig{
				ALPN: "h2",
			}),
		},
	},
	routeText,
)
```

Use one rule text:

```text
DIAL
TCP
AND
PORT 443
AND
INTERCEPT

SNIFF tls_h2
SLOT 2

SNIFF_NONE
SLOT 1
```

Action:

- TCP dials to port `443` are intercepted and sniffed.
- TLS ClientHello with ALPN `h2` routes to slot `2`.
- Traffic that does not match a classifier routes to slot `1`.

To redirect matched traffic to a specific port, put a `gonnect.Remapper` behind
the selected output slot and let the rule choose that slot.

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
