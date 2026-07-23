package tlspolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Fingerprint is a SHA-256 digest used to identify a complete certificate or
// a certificate's SubjectPublicKeyInfo value.
//
// Fingerprints compare by value and are safe to use as map keys. String returns
// 64 lowercase hexadecimal characters without separators. ParseFingerprint
// also accepts colon-separated hexadecimal input commonly shown by certificate
// inspection tools.
type Fingerprint [sha256.Size]byte //nolint:recvcheck // Unmarshal mutates.

// String returns f as 64 lowercase hexadecimal characters without separators.
func (f Fingerprint) String() string {
	return hex.EncodeToString(f[:])
}

// MarshalText implements encoding.TextMarshaler.
func (f Fingerprint) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *Fingerprint) UnmarshalText(text []byte) error {
	if f == nil {
		return errors.New(
			"tlspolicy: cannot unmarshal fingerprint into a nil receiver",
		)
	}

	parsed, err := ParseFingerprint(string(text))
	if err != nil {
		return err
	}
	*f = parsed
	return nil
}

// ParseFingerprint parses a SHA-256 fingerprint.
//
// The accepted representation is hexadecimal, with optional colon separators.
// Leading and trailing whitespace is ignored. Other separators and
// algorithms are rejected.
func ParseFingerprint(value string) (Fingerprint, error) {
	var result Fingerprint

	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ":", "")
	if len(value) != hex.EncodedLen(len(result)) {
		return result, fmt.Errorf(
			"tlspolicy: SHA-256 fingerprint has %d hexadecimal characters; want %d",
			len(value),
			hex.EncodedLen(len(result)),
		)
	}

	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, fmt.Errorf(
			"tlspolicy: parse SHA-256 fingerprint: %w",
			err,
		)
	}
	copy(result[:], decoded)
	return result, nil
}
