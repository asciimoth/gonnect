# meshnames
[![Go Reference](https://pkg.go.dev/badge/github.com/asciimoth/gonnect/dns/meshnames.svg)](https://pkg.go.dev/github.com/asciimoth/gonnect/dns/meshnames)

`meshnames` is a Go package in the
[Gonnect ecosystem](https://github.com/asciimoth/gonnect#related-projects).
It resolves mesh-oriented DNS names.

It is meant for naming schemes where the authoritative DNS server can be
derived from the name itself. Instead of sending DNS queries through the host
OS resolver, `meshnames` sends them through a caller-provided `gonnect.Network`.

## Supported Naming Schemes

`meshnames` currently understands these name formats:

| Scheme | What it does | Reference |
| --- | --- | --- |
| `.meshname` | Uses the second-level label as a Meshname authority address and resolves the full name via DNS on that node | [meshname](https://github.com/zhoreeq/meshname) |
| `.meship` | Decodes the left label directly into an IPv6 address without doing DNS | [meshname](https://github.com/zhoreeq/meshname) |
| `.pk.ygg` | Derives a Yggdrasil IPv6 address directly from an Ed25519 public key encoded in the label | [yggstack](https://github.com/yggdrasil-network/yggstack) |
| `.ygg` | Uses a Yggdrasil/YggNS authority label and resolves the full name via DNS on that node | [YggNS](https://github.com/ru-crypto-anarchy/YggNS/blob/master/README.md), [yggstack](https://github.com/yggdrasil-network/yggstack) |
| `.ipv6-literal.net` | Decodes the address label directly as an IPv6 address using the Windows literal-host spelling | [Microsoft MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/62e862f4-2a51-452e-8eeb-dc4ff5ee33cc) |

For `.ygg`, these authority-label formats are supported:

- straight hex form
- base32 form
- dashed YggNS form

## Supported Domain Examples

Examples of names accepted by the resolver:

- `svc.aiag7sesed2aaxgcgbnevruwpy.meshname`
- `aiag7sesed2aaxgcgbnevruwpy.meship`
- `svc.d40d4a7153cf288ea28f1865f6cfe95143a478b5c8c9e7cb002a0633d10a53eb.pk.ygg`
- `svc.020212a900e54474d47382be16ac9381.ygg`
- `svc.2aijksahfir2ni44cxylkze4b.ygg`
- `svc.202-12a9-e5-4474-d473-82be-16ac-9381.ygg`
- `2001-db8--42.ipv6-literal.net`

Each supported name can include or omit the final root dot. For example,
`svc.2aijksahfir2ni44cxylkze4b.ygg` and
`svc.2aijksahfir2ni44cxylkze4b.ygg.` are equivalent.

The left-hand side can contain regular host or service labels. `meshnames` derives
the authoritative node from the suffix and then asks that node for records such
as `A`, `AAAA`, `TXT`, `MX`, `NS`, `SRV`, `PTR`, and `CNAME`.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/dns/meshnames"
)

func main() {
	ctx := context.Background()

	// Use the host network stack as the transport for mesh DNS exchanges.
	network := gonnect.NativeConfig{}.Build()

	resolver := meshnames.NewResolver(network)

	// Optional: use the native resolver for names outside mesh schemes.
	resolver.Fallback = network

	addrs, err := resolver.LookupHost(ctx, "svc.aiag7sesed2aaxgcgbnevruwpy.meshname")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(addrs)
}
```

If `Fallback` is not set, unsupported names are rejected instead of being sent
to the system resolver.

`Network` can be `nil` when network access is not available. The resolver still
resolves `.meship`, `.pk.ygg`, and `.ipv6-literal.net` names because these
formats are decoded locally. Lookups that need DNS, such as `.meshname` and
`.ygg`, return an error. A nil `Network` never causes `meshnames` to use the host
network as a substitute.

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
  <span property="dct:title">meshnames</span>.
</p>
