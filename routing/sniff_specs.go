package routing

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect/sniffer"
)

var defaultSniffClassifierConstructors = []NamedSniffClassifierConstructor{
	{Name: "HTTP", Constructor: buildHTTPSniffClassifier},
	{Name: "TLS", Constructor: buildTLSSniffClassifier},
}

// DefaultSniffClassifierConstructors returns the built-in inline SNIFF
// classifier constructors.
//
// The current collection contains HTTP and TLS. The returned slice is a copy
// and can be changed by the caller before it is passed to
// NewSnifferBytecodeRulesWithConstructors.
func DefaultSniffClassifierConstructors() []NamedSniffClassifierConstructor {
	return append(
		[]NamedSniffClassifierConstructor(nil),
		defaultSniffClassifierConstructors...,
	)
}

func (p *bytecodeParser) constructSniffClassifier(arg string) (uint16, error) {
	constructorName, options, err := parseSniffClassifierSpec(arg)
	if err != nil {
		return 0, err
	}
	constructor, ok := p.sniffConstructors[constructorName]
	if !ok {
		if len(options) == 0 {
			return 0, fmt.Errorf(
				"unknown sniff classifier %q",
				strings.TrimSpace(arg),
			)
		}
		return 0, fmt.Errorf(
			"unknown sniff classifier constructor %q",
			constructorName,
		)
	}

	canonical, factory, err := constructor(options)
	if err != nil {
		return 0, fmt.Errorf(
			"sniff classifier constructor %q: %w",
			constructorName,
			err,
		)
	}
	if factory == nil {
		return 0, fmt.Errorf(
			"sniff classifier constructor %q returned nil factory",
			constructorName,
		)
	}

	specKey := constructorName
	if canonical = strings.TrimSpace(canonical); canonical != "" {
		specKey += " " + canonical
	}
	if idx, ok := p.sniffSpecIndex[specKey]; ok {
		return idx, nil
	}

	idx, err := p.addSniffClassifier(NamedSniffClassifier{
		Name:    p.nextInlineSniffClassifierName(),
		Factory: factory,
	})
	if err != nil {
		return 0, fmt.Errorf("inline sniff classifier %q: %w", specKey, err)
	}
	p.sniffSpecIndex[specKey] = idx
	return idx, nil
}

func (p *bytecodeParser) nextInlineSniffClassifierName() string {
	for i := len(p.sniffClassifiers); ; i++ {
		name := fmt.Sprintf("@inline-%d", i)
		if _, ok := p.sniffIndex[name]; !ok {
			return name
		}
	}
}

func parseSniffClassifierSpec(
	arg string,
) (constructorName string, options []SniffClassifierOption, err error) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return "", nil, fmt.Errorf("empty sniff classifier specification")
	}

	constructorName, err = normalizeSniffClassifierConstructorName(fields[0])
	if err != nil {
		return "", nil, err
	}

	options = make([]SniffClassifierOption, 0, len(fields)-1)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, ":")
		if !ok || key == "" {
			return "", nil, fmt.Errorf(
				"sniff classifier option %q must use KEY:VALUE",
				field,
			)
		}
		key = strings.ToUpper(key)
		if strings.ContainsAny(key, " \t\r\n:") {
			return "", nil, fmt.Errorf(
				"sniff classifier option key %q is invalid",
				key,
			)
		}
		if value == "" {
			return "", nil, fmt.Errorf(
				"sniff classifier option %q has empty value",
				key,
			)
		}
		options = append(options, SniffClassifierOption{
			Key:   key,
			Value: value,
		})
	}
	return constructorName, options, nil
}

func normalizeSniffClassifierConstructorName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty sniff classifier constructor name")
	}
	if strings.ContainsAny(name, " \t\r\n:") {
		return "", fmt.Errorf(
			"sniff classifier constructor name %q is invalid",
			name,
		)
	}
	return name, nil
}

func buildHTTPSniffClassifier(
	options []SniffClassifierOption,
) (string, sniffer.Factory, error) {
	var config sniffer.HTTPConfig
	canonical := make([]SniffClassifierOption, 0, len(options))
	scalars := make(map[string]struct{}, 2)

	for _, option := range options {
		if option.Value == "" {
			return "", nil, fmt.Errorf(
				"HTTP option %q has empty value",
				option.Key,
			)
		}
		switch option.Key {
		case "METHOD":
			config.Methods = append(config.Methods, option.Value)
			canonical = appendSniffOption(canonical, "METHOD", option.Value)
		case "URL":
			config.URLs = append(config.URLs, option.Value)
			canonical = appendSniffOption(canonical, "URL", option.Value)
		case "URL_PATTERN":
			config.URLPatterns = append(config.URLPatterns, option.Value)
			canonical = appendSniffOption(
				canonical,
				"URL_PATTERN",
				option.Value,
			)
		case "VERSION":
			config.Versions = append(config.Versions, option.Value)
			canonical = appendSniffOption(canonical, "VERSION", option.Value)
		case "HOST", "HOSTNAME":
			config.Hostnames = append(config.Hostnames, option.Value)
			canonical = appendSniffOption(canonical, "HOST", option.Value)
		case "HOST_PATTERN", "HOSTNAME_PATTERN":
			config.HostnamePatterns = append(
				config.HostnamePatterns,
				option.Value,
			)
			canonical = appendSniffOption(
				canonical,
				"HOST_PATTERN",
				option.Value,
			)
		case "MAX_REQUEST_LINE_BYTES":
			value, err := parseNonNegativeSniffInt(option.Key, option.Value)
			if err != nil {
				return "", nil, err
			}
			if err := setSniffScalarOption(scalars, option.Key); err != nil {
				return "", nil, err
			}
			config.MaxRequestLineBytes = value
			canonical = appendSniffOption(
				canonical,
				option.Key,
				strconv.Itoa(value),
			)
		case "MAX_HEADER_BYTES":
			value, err := parseNonNegativeSniffInt(option.Key, option.Value)
			if err != nil {
				return "", nil, err
			}
			if err := setSniffScalarOption(scalars, option.Key); err != nil {
				return "", nil, err
			}
			config.MaxHeaderBytes = value
			canonical = appendSniffOption(
				canonical,
				option.Key,
				strconv.Itoa(value),
			)
		default:
			return "", nil, fmt.Errorf(
				"unknown HTTP sniff classifier option %q",
				option.Key,
			)
		}
	}

	return formatSniffOptions(
			canonical,
		), sniffer.HTTPFactoryWithConfig(
			config,
		), nil
}

func buildTLSSniffClassifier(
	options []SniffClassifierOption,
) (string, sniffer.Factory, error) {
	var config sniffer.TLSConfig
	canonical := make([]SniffClassifierOption, 0, len(options))
	scalars := make(map[string]struct{}, 3)

	for _, option := range options {
		if option.Value == "" {
			return "", nil, fmt.Errorf(
				"TLS option %q has empty value",
				option.Key,
			)
		}
		switch option.Key {
		case "VERSION":
			version, text, err := parseTLSVersionOption(option.Value)
			if err != nil {
				return "", nil, err
			}
			config.Versions = append(config.Versions, version)
			canonical = appendSniffOption(canonical, "VERSION", text)
		case "SNI", "HOST", "HOSTNAME":
			config.Hostnames = append(config.Hostnames, option.Value)
			canonical = appendSniffOption(canonical, "SNI", option.Value)
		case "SNI_PATTERN", "HOST_PATTERN", "HOSTNAME_PATTERN":
			config.HostnamePatterns = append(
				config.HostnamePatterns,
				option.Value,
			)
			canonical = appendSniffOption(
				canonical,
				"SNI_PATTERN",
				option.Value,
			)
		case "ALPN":
			config.ALPNs = append(config.ALPNs, option.Value)
			canonical = appendSniffOption(canonical, "ALPN", option.Value)
		case "ALPN_PATTERN":
			config.ALPNPatterns = append(config.ALPNPatterns, option.Value)
			canonical = appendSniffOption(
				canonical,
				"ALPN_PATTERN",
				option.Value,
			)
		case "SNI_AVAILABLE":
			flag, text, err := parseTLSFlagOption(option.Key, option.Value)
			if err != nil {
				return "", nil, err
			}
			if err := setSniffScalarOption(scalars, option.Key); err != nil {
				return "", nil, err
			}
			config.SNIAvailable = flag
			canonical = appendSniffOption(canonical, option.Key, text)
		case "SNI_ENCRYPTED":
			flag, text, err := parseTLSFlagOption(option.Key, option.Value)
			if err != nil {
				return "", nil, err
			}
			if err := setSniffScalarOption(scalars, option.Key); err != nil {
				return "", nil, err
			}
			config.SNIEncrypted = flag
			canonical = appendSniffOption(canonical, option.Key, text)
		case "MAX_CLIENT_HELLO_BYTES":
			value, err := parseNonNegativeSniffInt(option.Key, option.Value)
			if err != nil {
				return "", nil, err
			}
			if err := setSniffScalarOption(scalars, option.Key); err != nil {
				return "", nil, err
			}
			config.MaxClientHelloBytes = value
			canonical = appendSniffOption(
				canonical,
				option.Key,
				strconv.Itoa(value),
			)
		default:
			return "", nil, fmt.Errorf(
				"unknown TLS sniff classifier option %q",
				option.Key,
			)
		}
	}

	return formatSniffOptions(
			canonical,
		), sniffer.TLSFactoryWithConfig(
			config,
		), nil
}

func appendSniffOption(
	options []SniffClassifierOption,
	key, value string,
) []SniffClassifierOption {
	return append(options, SniffClassifierOption{Key: key, Value: value})
}

func formatSniffOptions(options []SniffClassifierOption) string {
	options = canonicalSniffOptions(options)
	if len(options) == 0 {
		return ""
	}
	fields := make([]string, 0, len(options))
	for _, option := range options {
		fields = append(fields, option.Key+":"+option.Value)
	}
	return strings.Join(fields, " ")
}

func canonicalSniffOptions(
	options []SniffClassifierOption,
) []SniffClassifierOption {
	out := append([]SniffClassifierOption(nil), options...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Value < out[j].Value
	})

	n := 0
	for _, option := range out {
		if n != 0 &&
			out[n-1].Key == option.Key &&
			out[n-1].Value == option.Value {
			continue
		}
		out[n] = option
		n++
	}
	return out[:n]
}

func setSniffScalarOption(seen map[string]struct{}, key string) error {
	if _, ok := seen[key]; ok {
		return fmt.Errorf("duplicate %s sniff classifier option", key)
	}
	seen[key] = struct{}{}
	return nil
}

func parseNonNegativeSniffInt(key, value string) (int, error) {
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"%s sniff classifier option must be a non-negative integer",
			key,
		)
	}
	maxInt := int64(int(^uint(0) >> 1))
	if v < 0 || v > maxInt {
		return 0, fmt.Errorf(
			"%s sniff classifier option must be a non-negative integer",
			key,
		)
	}
	return int(v), nil
}

func parseTLSVersionOption(value string) (uint16, string, error) {
	switch strings.ToUpper(value) {
	case "1.0", "TLS1.0", "TLS10":
		return tls.VersionTLS10, "1.0", nil
	case "1.1", "TLS1.1", "TLS11":
		return tls.VersionTLS11, "1.1", nil
	case "1.2", "TLS1.2", "TLS12":
		return tls.VersionTLS12, "1.2", nil
	case "1.3", "TLS1.3", "TLS13":
		return tls.VersionTLS13, "1.3", nil
	}

	v, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf(
			"VERSION sniff classifier option must be a TLS version",
		)
	}
	version := uint16(v) //nolint:gosec // ParseUint checked the range.
	switch version {
	case tls.VersionTLS10:
		return version, "1.0", nil
	case tls.VersionTLS11:
		return version, "1.1", nil
	case tls.VersionTLS12:
		return version, "1.2", nil
	case tls.VersionTLS13:
		return version, "1.3", nil
	default:
		return version, strconv.FormatUint(v, 10), nil
	}
}

func parseTLSFlagOption(
	key, value string,
) (sniffer.TLSFlag, string, error) {
	switch strings.ToUpper(value) {
	case "ANY":
		return sniffer.TLSFlagAny, "ANY", nil
	case "REQUIRED", "TRUE", "YES", "1":
		return sniffer.TLSFlagRequired, "REQUIRED", nil
	case "FORBIDDEN", "FALSE", "NO", "0":
		return sniffer.TLSFlagForbidden, "FORBIDDEN", nil
	default:
		return sniffer.TLSFlagAny, "", fmt.Errorf(
			"%s sniff classifier option must be ANY, REQUIRED, or FORBIDDEN",
			key,
		)
	}
}
