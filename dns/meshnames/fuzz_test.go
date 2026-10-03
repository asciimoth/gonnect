package meshnames //nolint:testpackage // Fuzzes internal label decoders.

import "testing"

func FuzzMeshNameInputs(f *testing.F) {
	f.Add("040G2081040G2081040G208104")
	f.Add("0200-0000-0000-0000-0000-0000-0000-0001")
	f.Add("0000000000000000000000000000000000000000000000000000000000000000")
	f.Add("")

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4<<10 {
			t.Skip()
		}
		_, _ = decodeMeshnameLabel(value)
		_, _ = decodeYggLabel(value)
		_, _ = decodeYggStraight(value)
		_, _ = decodeYggBase32(value)
		_, _ = decodeYggDashed(value)
		_, _ = decodeYggPublicKeyLabel(value)
		_, _ = authorityIP(value)
		resolver := &Resolver{}
		_, _, _ = resolver.lookupDirectIP(value)
	})
}
