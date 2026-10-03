package tlspolicy //nolint:testpackage // Uses the package certificate fixture.

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func FuzzPolicyInputs(f *testing.F) {
	pki := newTestPKI(f, testLeafOptions{})
	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pki.rootCert.Raw,
	})
	f.Add(uint8(0), []byte("example.test"))
	f.Add(uint8(0), []byte("[2001:db8::1]"))
	f.Add(
		uint8(1),
		[]byte(
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		),
	)
	f.Add(
		uint8(2),
		[]byte(
			"certificate:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		),
	)
	f.Add(uint8(3), pki.rootCert.Raw)
	f.Add(uint8(4), validPEM)
	f.Add(uint8(3), []byte{})

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		switch kind % 5 {
		case 0:
			identity, err := ParseServerIdentity(string(data))
			if err == nil {
				roundTrip, roundTripErr := ParseServerIdentity(
					identity.String(),
				)
				if roundTripErr != nil || roundTrip != identity {
					t.Fatalf(
						"identity round trip = %#v, %v; want %#v",
						roundTrip,
						roundTripErr,
						identity,
					)
				}
			}
		case 1:
			fingerprint, err := ParseFingerprint(string(data))
			if err == nil {
				roundTrip, roundTripErr := ParseFingerprint(
					fingerprint.String(),
				)
				if roundTripErr != nil || roundTrip != fingerprint {
					t.Fatalf("fingerprint round trip failed: %v", roundTripErr)
				}
			}
		case 2:
			var pin Pin
			if err := pin.UnmarshalText(data); err == nil {
				text, marshalErr := pin.MarshalText()
				if marshalErr != nil {
					t.Fatalf("MarshalText after UnmarshalText: %v", marshalErr)
				}
				var roundTrip Pin
				if err := roundTrip.UnmarshalText(
					text,
				); err != nil ||
					roundTrip != pin {
					t.Fatalf("pin round trip failed: %v", err)
				}
			}
		case 3:
			authority, err := ParseAuthorityDER(data)
			if err == nil {
				if !bytes.Equal(authority.DER(), data) {
					t.Fatal("authority did not preserve DER")
				}
				if _, err := NewCertificatePin(data); err != nil {
					t.Fatalf(
						"certificate pin rejected parsed certificate: %v",
						err,
					)
				}
				if _, err := NewSPKIPin(data); err != nil {
					t.Fatalf("SPKI pin rejected parsed certificate: %v", err)
				}
			}
		case 4:
			authorities, err := ParseAuthoritiesPEM(data)
			if err == nil {
				for i, authority := range authorities {
					if !authority.Valid() {
						t.Fatalf("authority %d is invalid", i)
					}
					if _, err := ParseAuthorityDER(
						authority.DER(),
					); err != nil {
						t.Fatalf("reparse authority %d: %v", i, err)
					}
				}
			}
		}
	})
}
