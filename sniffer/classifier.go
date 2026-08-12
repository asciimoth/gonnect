package sniffer

import "fmt"

// State is the current terminal or non-terminal result of a Classifier.
type State uint8

const (
	// NeedMore means the bytes seen so far are compatible with the classifier,
	// but are insufficient for a definitive decision.
	NeedMore State = iota

	// Match means the classifier has definitively recognized its input.
	Match

	// Mismatch means no future suffix can make the classifier match.
	Mismatch
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case NeedMore:
		return "need more"
	case Match:
		return "match"
	case Mismatch:
		return "mismatch"
	default:
		return fmt.Sprintf("State(%d)", uint8(s))
	}
}

// MinSniffBufferSizer reports a minimum Sniff buffer size.
//
// The value is the number of bytes needed by a classifier, or by classifiers
// made by a factory, to make its bounded decision. A caller that sniffs with
// several classifiers should use the largest reported size.
type MinSniffBufferSizer interface {
	MinSniffBufferSize() int
}

// Classifier incrementally recognizes a byte stream prefix.
//
// Feed receives only bytes not supplied in earlier calls, in stream order, and
// returns the state after consuming p. Feed may be called with an empty slice
// to query the initial/current state without advancing input. Implementations
// must therefore handle empty input.
//
// Match and Mismatch are terminal: after returning either state, a classifier
// must return the same state from all later Feed calls. Sniff and the supplied
// combinators normally stop feeding terminal classifiers.
//
// p is read-only. A classifier must not modify it and must not retain it
// unless it copies the bytes it needs. The caller's sniff buffer may be
// reused after Sniff returns.
//
// Classifiers do not return errors. Invalid, malformed, unsupported, or
// classifier-specific over-limit data should result in Mismatch.
type Classifier interface {
	MinSniffBufferSizer

	Feed(p []byte) State
}

// ClassifierFunc adapts a function to Classifier. It reports a minimum Sniff
// buffer size of 0. Use WithMinSniffBufferSize when f needs a larger buffer.
type ClassifierFunc func(p []byte) State

// Feed calls f(p).
func (f ClassifierFunc) Feed(p []byte) State {
	return f(p)
}

// MinSniffBufferSize returns 0.
func (f ClassifierFunc) MinSniffBufferSize() int {
	return 0
}

// WithMinSniffBufferSize wraps classifier and reports minSize as its minimum
// Sniff buffer size. It is useful for custom classifiers.
func WithMinSniffBufferSize(
	minSize int,
	classifier Classifier,
) Classifier {
	return &sizedClassifier{
		classifier: requireClassifier(classifier),
		minSize:    checkedMinSniffBufferSize(minSize),
	}
}

type sizedClassifier struct {
	classifier Classifier
	minSize    int
}

func (c *sizedClassifier) Feed(p []byte) State {
	return c.classifier.Feed(p)
}

func (c *sizedClassifier) MinSniffBufferSize() int {
	return c.minSize
}

func (c *sizedClassifier) Metadata() any {
	return Metadata(c.classifier)
}

// Factory constructs a fresh classifier for one stream.
//
// NewClassifier must return an independent instance on every call. A Factory
// may be shared by goroutines and should therefore be safe for concurrent use.
type Factory interface {
	MinSniffBufferSizer

	NewClassifier() Classifier
}

// FactoryFunc adapts a function to Factory. It reports a minimum Sniff buffer
// size of 0. Use FactoryWithMinSniffBufferSize when f needs a larger buffer.
type FactoryFunc func() Classifier

// NewClassifier calls f.
func (f FactoryFunc) NewClassifier() Classifier {
	return f()
}

// MinSniffBufferSize returns 0.
func (f FactoryFunc) MinSniffBufferSize() int {
	return 0
}

// FactoryWithMinSniffBufferSize wraps factory and reports minSize as the
// minimum Sniff buffer size needed by classifiers it creates.
func FactoryWithMinSniffBufferSize(
	minSize int,
	factory Factory,
) Factory {
	return &sizedFactory{
		factory: requireFactory(factory),
		minSize: checkedMinSniffBufferSize(minSize),
	}
}

type sizedFactory struct {
	factory Factory
	minSize int
}

func (f *sizedFactory) NewClassifier() Classifier {
	return requireClassifier(f.factory.NewClassifier())
}

func (f *sizedFactory) MinSniffBufferSize() int {
	return f.minSize
}

// MinSniffBufferSize returns the largest reported minimum Sniff buffer size
// from classifiers.
func MinSniffBufferSize(classifiers ...Classifier) int {
	minSize := 0
	for _, classifier := range classifiers {
		classifier = requireClassifier(classifier)
		if size := checkedMinSniffBufferSize(
			classifier.MinSniffBufferSize(),
		); size > minSize {
			minSize = size
		}
	}
	return minSize
}

// MinFactorySniffBufferSize returns the largest reported minimum Sniff buffer
// size from factories.
func MinFactorySniffBufferSize(factories ...Factory) int {
	minSize := 0
	for _, factory := range factories {
		factory = requireFactory(factory)
		if size := checkedMinSniffBufferSize(
			factory.MinSniffBufferSize(),
		); size > minSize {
			minSize = size
		}
	}
	return minSize
}

func checkedMinSniffBufferSize(size int) int {
	if size < 0 {
		panic("sniffer: negative minimum sniff buffer size")
	}
	return size
}

func checkedState(s State) State {
	switch s {
	case NeedMore, Match, Mismatch:
		return s
	default:
		panic(fmt.Sprintf("sniffer: classifier returned invalid state %d", s))
	}
}

func requireClassifier(c Classifier) Classifier {
	if c == nil {
		panic("sniffer: nil Classifier")
	}
	return c
}

func requireFactory(f Factory) Factory {
	if f == nil {
		panic("sniffer: nil Factory")
	}
	return f
}
