//nolint:testpackage
package dns

import (
	"strings"
	"testing"
)

func TestWirePackRejectsInvalidResourceData(t *testing.T) {
	for _, tt := range []struct {
		name string
		typ  uint16
		data []byte
	}{
		{name: "a", typ: TypeA, data: []byte{127, 0, 0}},
		{name: "aaaa", typ: TypeAAAA, data: []byte{0, 1}},
		{name: "mx", typ: TypeMX, data: []byte{0, 10}},
		{name: "srv", typ: TypeSRV, data: []byte{0, 1, 0, 2, 0, 3}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Pack(&Message{
				Response: true,
				Answers: []Resource{{
					Name:  "example.test.",
					Type:  tt.typ,
					Class: ClassIN,
					Data:  tt.data,
				}},
			})
			if err == nil {
				t.Fatal("Pack() error = nil, want invalid data error")
			}
		})
	}
}

func TestWirePackRejectsInvalidNamesInAllSections(t *testing.T) {
	invalid := strings.Repeat("a", 64) + ".example.test."
	for _, tt := range []struct {
		name string
		msg  *Message
	}{
		{
			name: "answer owner",
			msg: &Message{Answers: []Resource{{
				Name:  invalid,
				Type:  TypeA,
				Class: ClassIN,
				Data:  []byte{127, 0, 0, 1},
			}}},
		},
		{
			name: "authority owner",
			msg: &Message{Authorities: []Resource{{
				Name:  invalid,
				Type:  TypeA,
				Class: ClassIN,
				Data:  []byte{127, 0, 0, 1},
			}}},
		},
		{
			name: "additional owner",
			msg: &Message{Additionals: []Resource{{
				Name:  invalid,
				Type:  TypeA,
				Class: ClassIN,
				Data:  []byte{127, 0, 0, 1},
			}}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Pack(tt.msg); err == nil {
				t.Fatal("Pack() error = nil, want invalid name error")
			}
		})
	}
}

func TestWireUnpackRejectsMalformedPackets(t *testing.T) {
	if _, err := Unpack([]byte{0, 1, 2}); err == nil {
		t.Fatal("Unpack(short packet) error = nil, want parse error")
	}

	pkt := []byte{
		0, 1,
		0, 0,
		0, 1,
		0, 0,
		0, 0,
		0, 0,
	}
	if _, err := Unpack(pkt); err == nil {
		t.Fatal("Unpack(missing question) error = nil, want parse error")
	}
}
