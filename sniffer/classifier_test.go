package sniffer_test

import (
	"testing"

	"github.com/asciimoth/gonnect/sniffer"
)

type negativeSizeClassifier struct{}

func (negativeSizeClassifier) Feed([]byte) sniffer.State {
	return sniffer.NeedMore
}

func (negativeSizeClassifier) MinSniffBufferSize() int {
	return -1
}

type negativeSizeFactory struct{}

func (negativeSizeFactory) NewClassifier() sniffer.Classifier {
	return sniffer.SSH()
}

func (negativeSizeFactory) MinSniffBufferSize() int {
	return -1
}

func TestPrefixFragmentation(t *testing.T) {
	want := []byte("SSH-")
	for split := 0; split <= len(want); split++ {
		classifier := sniffer.Prefix(want)
		if got := classifier.Feed(nil); got != sniffer.NeedMore {
			t.Fatalf("split %d: initial state = %v, want NeedMore", split, got)
		}

		if got := classifier.Feed(
			want[:split],
		); split < len(want) &&
			got != sniffer.NeedMore {
			t.Fatalf("split %d: first state = %v, want NeedMore", split, got)
		} else if split == len(want) &&
			got != sniffer.Match {
			t.Fatalf("split %d: first state = %v, want Match", split, got)
		}

		if split < len(want) {
			if got := classifier.Feed(want[split:]); got != sniffer.Match {
				t.Fatalf("split %d: final state = %v, want Match", split, got)
			}
		}
	}
}

func TestPrefixByteByByteAndStickyTerminalStates(t *testing.T) {
	classifier := sniffer.Prefix([]byte("ABC"))
	for _, b := range []byte("AB") {
		if got := classifier.Feed([]byte{b}); got != sniffer.NeedMore {
			t.Fatalf("Feed(%q) = %v, want NeedMore", b, got)
		}
	}
	if got := classifier.Feed([]byte("Ctail")); got != sniffer.Match {
		t.Fatalf("matching Feed = %v, want Match", got)
	}
	if got := classifier.Feed([]byte("anything")); got != sniffer.Match {
		t.Fatalf("state after Match = %v, want Match", got)
	}

	classifier = sniffer.Prefix([]byte("ABC"))
	if got := classifier.Feed([]byte("AX")); got != sniffer.Mismatch {
		t.Fatalf("mismatching Feed = %v, want Mismatch", got)
	}
	if got := classifier.Feed([]byte("BC")); got != sniffer.Mismatch {
		t.Fatalf("state after Mismatch = %v, want Mismatch", got)
	}
}

func TestPrefixCopiesPattern(t *testing.T) {
	pattern := []byte("ABC")
	classifier := sniffer.Prefix(pattern)
	copy(pattern, "XYZ")
	if got := classifier.Feed([]byte("ABC")); got != sniffer.Match {
		t.Fatalf("state = %v, want Match", got)
	}
}

func TestEmptyPrefixMatchesInitially(t *testing.T) {
	if got := sniffer.Prefix(nil).Feed(nil); got != sniffer.Match {
		t.Fatalf("empty Prefix initial state = %v, want Match", got)
	}
}

func TestAnd(t *testing.T) {
	classifier := sniffer.And(
		sniffer.Prefix([]byte("AB")),
		sniffer.Prefix([]byte("ABC")),
	)
	if got := classifier.Feed([]byte("A")); got != sniffer.NeedMore {
		t.Fatalf("after A = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("B")); got != sniffer.NeedMore {
		t.Fatalf("after B = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("C")); got != sniffer.Match {
		t.Fatalf("after C = %v, want Match", got)
	}

	classifier = sniffer.And(
		sniffer.Prefix([]byte("AB")),
		sniffer.Prefix([]byte("AX")),
	)
	if got := classifier.Feed([]byte("AB")); got != sniffer.Mismatch {
		t.Fatalf("mismatching And = %v, want Mismatch", got)
	}
}

func TestOr(t *testing.T) {
	classifier := sniffer.Or(
		sniffer.Prefix([]byte("AB")),
		sniffer.Prefix([]byte("XY")),
	)
	if got := classifier.Feed([]byte("X")); got != sniffer.NeedMore {
		t.Fatalf("after X = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("Y")); got != sniffer.Match {
		t.Fatalf("after Y = %v, want Match", got)
	}

	classifier = sniffer.Or(
		sniffer.Prefix([]byte("AB")),
		sniffer.Prefix([]byte("XY")),
	)
	if got := classifier.Feed([]byte("Q")); got != sniffer.Mismatch {
		t.Fatalf("mismatching Or = %v, want Mismatch", got)
	}
}

func TestNot(t *testing.T) {
	matching := sniffer.Not(sniffer.Prefix([]byte("AB")))
	if got := matching.Feed([]byte("X")); got != sniffer.Match {
		t.Fatalf("Not mismatch = %v, want Match", got)
	}

	mismatching := sniffer.Not(sniffer.Prefix([]byte("AB")))
	if got := mismatching.Feed([]byte("AB")); got != sniffer.Mismatch {
		t.Fatalf("Not match = %v, want Mismatch", got)
	}
}

func TestEmptyCombinators(t *testing.T) {
	if got := sniffer.And().Feed(nil); got != sniffer.Match {
		t.Fatalf("empty And = %v, want Match", got)
	}
	if got := sniffer.Or().Feed(nil); got != sniffer.Mismatch {
		t.Fatalf("empty Or = %v, want Mismatch", got)
	}
}

func TestFactoriesCreateIndependentClassifiers(t *testing.T) {
	factory := sniffer.AndFactory(
		sniffer.PrefixFactory([]byte("AB")),
		sniffer.NotFactory(sniffer.PrefixFactory([]byte("AX"))),
	)

	first := factory.NewClassifier()
	second := factory.NewClassifier()
	if got := first.Feed([]byte("A")); got != sniffer.NeedMore {
		t.Fatalf("first after A = %v, want NeedMore", got)
	}
	if got := second.Feed([]byte("AB")); got != sniffer.Match {
		t.Fatalf("second after AB = %v, want Match", got)
	}
	if got := first.Feed([]byte("B")); got != sniffer.Match {
		t.Fatalf("first after B = %v, want Match", got)
	}
}

func TestLimit(t *testing.T) {
	classifier := sniffer.Limit(3, sniffer.Prefix([]byte("ABCD")))
	if got := classifier.Feed([]byte("AB")); got != sniffer.NeedMore {
		t.Fatalf("after AB = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("CDEF")); got != sniffer.Mismatch {
		t.Fatalf("at limit = %v, want Mismatch", got)
	}

	classifier = sniffer.Limit(4, sniffer.Prefix([]byte("ABCD")))
	if got := classifier.Feed([]byte("ABCDE")); got != sniffer.Match {
		t.Fatalf("match at limit = %v, want Match", got)
	}

	classifier = sniffer.Limit(0, sniffer.Prefix(nil))
	if got := classifier.Feed(nil); got != sniffer.Match {
		t.Fatalf("empty match at zero limit = %v, want Match", got)
	}
}

func TestSSHClassifier(t *testing.T) {
	classifier := sniffer.SSH()
	if got := classifier.Feed([]byte("SS")); got != sniffer.NeedMore {
		t.Fatalf("after SS = %v, want NeedMore", got)
	}
	if got := classifier.Feed([]byte("H-2.0-test\r\n")); got != sniffer.Match {
		t.Fatalf("SSH state = %v, want Match", got)
	}
}

func TestMinSniffBufferSize(t *testing.T) {
	unknown := sniffer.ClassifierFunc(
		func([]byte) sniffer.State { return sniffer.NeedMore },
	)
	tests := []struct {
		name       string
		classifier sniffer.Classifier
		want       int
	}{
		{
			name:       "prefix",
			classifier: sniffer.Prefix([]byte("ABC")),
			want:       3,
		},
		{name: "empty prefix", classifier: sniffer.Prefix(nil), want: 0},
		{name: "ssh", classifier: sniffer.SSH(), want: 4},
		{
			name: "and uses largest child",
			classifier: sniffer.And(
				sniffer.Prefix([]byte("AB")),
				sniffer.Prefix([]byte("ABCD")),
			),
			want: 4,
		},
		{
			name: "or uses largest child",
			classifier: sniffer.Or(
				sniffer.Prefix([]byte("AB")),
				sniffer.Prefix([]byte("ABCD")),
			),
			want: 4,
		},
		{
			name:       "not uses child",
			classifier: sniffer.Not(sniffer.Prefix([]byte("ABC"))),
			want:       3,
		},
		{
			name: "limit below child",
			classifier: sniffer.Limit(
				2,
				sniffer.Prefix([]byte("ABC")),
			),
			want: 2,
		},
		{
			name: "limit above child",
			classifier: sniffer.Limit(
				8,
				sniffer.Prefix([]byte("ABC")),
			),
			want: 3,
		},
		{
			name:       "limit uses default func size",
			classifier: sniffer.Limit(5, unknown),
			want:       0,
		},
		{
			name: "custom wrapper",
			classifier: sniffer.WithMinSniffBufferSize(
				7,
				unknown,
			),
			want: 7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.classifier.MinSniffBufferSize(); got != test.want {
				t.Fatalf("MinSniffBufferSize = %d, want %d", got, test.want)
			}
		})
	}

	if got := sniffer.MinSniffBufferSize(
		sniffer.Prefix([]byte("A")),
		sniffer.SSH(),
		unknown,
	); got != 4 {
		t.Fatalf("helper MinSniffBufferSize = %d, want 4", got)
	}
}

func TestMinFactorySniffBufferSize(t *testing.T) {
	unknown := sniffer.FactoryFunc(func() sniffer.Classifier {
		return sniffer.ClassifierFunc(
			func([]byte) sniffer.State { return sniffer.NeedMore },
		)
	})
	tests := []struct {
		name    string
		factory sniffer.Factory
		want    int
	}{
		{
			name:    "prefix",
			factory: sniffer.PrefixFactory([]byte("ABC")),
			want:    3,
		},
		{name: "ssh", factory: sniffer.SSHFactory(), want: 4},
		{
			name: "and uses largest child",
			factory: sniffer.AndFactory(
				sniffer.PrefixFactory([]byte("AB")),
				sniffer.PrefixFactory([]byte("ABCD")),
			),
			want: 4,
		},
		{
			name: "or uses largest child",
			factory: sniffer.OrFactory(
				sniffer.PrefixFactory([]byte("AB")),
				sniffer.PrefixFactory([]byte("ABCD")),
			),
			want: 4,
		},
		{
			name:    "not uses child",
			factory: sniffer.NotFactory(sniffer.PrefixFactory([]byte("ABC"))),
			want:    3,
		},
		{
			name: "limit below child",
			factory: sniffer.LimitFactory(
				2,
				sniffer.PrefixFactory([]byte("ABC")),
			),
			want: 2,
		},
		{
			name: "limit above child",
			factory: sniffer.LimitFactory(
				8,
				sniffer.PrefixFactory([]byte("ABC")),
			),
			want: 3,
		},
		{
			name:    "limit uses default func size",
			factory: sniffer.LimitFactory(5, unknown),
			want:    0,
		},
		{
			name: "custom wrapper",
			factory: sniffer.FactoryWithMinSniffBufferSize(
				7,
				unknown,
			),
			want: 7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.factory.MinSniffBufferSize(); got != test.want {
				t.Fatalf("MinSniffBufferSize = %d, want %d", got, test.want)
			}
		})
	}

	if got := sniffer.MinFactorySniffBufferSize(
		sniffer.PrefixFactory([]byte("A")),
		sniffer.SSHFactory(),
		unknown,
	); got != 4 {
		t.Fatalf("helper MinFactorySniffBufferSize = %d, want 4", got)
	}
}

func FuzzPrefixFragmentation(f *testing.F) {
	f.Add([]byte("SSH-"), []byte("SSH-2.0-test\r\n"), uint8(1))
	f.Add([]byte("GET "), []byte("GET / HTTP/1.1\r\n"), uint8(3))
	f.Add([]byte("ABC"), []byte("AXC"), uint8(2))

	f.Fuzz(func(t *testing.T, prefix, input []byte, chunkSize uint8) {
		if len(prefix) > 256 || len(input) > 1024 {
			t.Skip()
		}
		size := int(chunkSize%32) + 1
		classifier := sniffer.Prefix(prefix)
		state := classifier.Feed(nil)
		for offset := 0; offset < len(input) && state == sniffer.NeedMore; {
			end := offset + size
			if end > len(input) {
				end = len(input)
			}
			state = classifier.Feed(input[offset:end])
			offset = end
		}

		want := sniffer.NeedMore
		switch {
		case len(prefix) == 0:
			want = sniffer.Match
		case len(input) >= len(prefix) && string(input[:len(prefix)]) == string(prefix):
			want = sniffer.Match
		case len(input) > 0:
			n := len(input)
			if n > len(prefix) {
				n = len(prefix)
			}
			if string(input[:n]) != string(prefix[:n]) {
				want = sniffer.Mismatch
			}
		}

		if state != want {
			t.Fatalf(
				"Prefix(%x) on %x = %v, want %v",
				prefix,
				input,
				state,
				want,
			)
		}
	})
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state sniffer.State
		want  string
	}{
		{sniffer.NeedMore, "need more"},
		{sniffer.Match, "match"},
		{sniffer.Mismatch, "mismatch"},
		{sniffer.State(99), "State(99)"},
	}
	for _, test := range tests {
		if got := test.state.String(); got != test.want {
			t.Errorf(
				"State(%d).String() = %q, want %q",
				test.state,
				got,
				test.want,
			)
		}
	}
}

func TestClassifierFunc(t *testing.T) {
	calls := 0
	classifier := sniffer.ClassifierFunc(func(p []byte) sniffer.State {
		calls++
		if string(p) == "ok" {
			return sniffer.Match
		}
		return sniffer.NeedMore
	})
	if got := classifier.Feed([]byte("ok")); got != sniffer.Match {
		t.Fatalf("Feed = %v, want Match", got)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestOrAndLimitFactories(t *testing.T) {
	orFactory := sniffer.OrFactory(
		sniffer.PrefixFactory([]byte("AB")),
		sniffer.PrefixFactory([]byte("XY")),
	)
	if got := orFactory.NewClassifier().
		Feed([]byte("XY")); got != sniffer.Match {
		t.Fatalf("OrFactory classifier = %v, want Match", got)
	}

	limitFactory := sniffer.LimitFactory(
		2,
		sniffer.PrefixFactory([]byte("ABC")),
	)
	if got := limitFactory.NewClassifier().
		Feed([]byte("ABC")); got != sniffer.Mismatch {
		t.Fatalf("LimitFactory classifier = %v, want Mismatch", got)
	}
}

func TestClassifierProgrammingErrorsPanic(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"nil And child", func() { _ = sniffer.And(nil) }},
		{"nil Or factory", func() { _ = sniffer.OrFactory(nil) }},
		{"nil Not child", func() { _ = sniffer.Not(nil) }},
		{"negative Limit", func() { _ = sniffer.Limit(-1, sniffer.SSH()) }},
		{
			"negative MinSniffBufferSize",
			func() {
				_ = sniffer.WithMinSniffBufferSize(-1, sniffer.SSH())
			},
		},
		{
			"nil classifier size wrapper child",
			func() { _ = sniffer.WithMinSniffBufferSize(1, nil) },
		},
		{
			"classifier reports negative MinSniffBufferSize",
			func() { _ = sniffer.MinSniffBufferSize(negativeSizeClassifier{}) },
		},
		{
			"negative LimitFactory",
			func() { _ = sniffer.LimitFactory(-1, sniffer.SSHFactory()) },
		},
		{
			"negative factory MinSniffBufferSize",
			func() {
				_ = sniffer.FactoryWithMinSniffBufferSize(
					-1,
					sniffer.SSHFactory(),
				)
			},
		},
		{
			"nil factory size wrapper child",
			func() { _ = sniffer.FactoryWithMinSniffBufferSize(1, nil) },
		},
		{
			"factory reports negative MinSniffBufferSize",
			func() {
				_ = sniffer.MinFactorySniffBufferSize(negativeSizeFactory{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("did not panic")
				}
			}()
			test.fn()
		})
	}
}
