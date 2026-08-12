package sniffer

// MetadataProvider is implemented by classifiers that expose parsed metadata.
//
// Metadata returns data that is meaningful to the classifier implementation.
// It should return nil when no metadata is available. A classifier that returns
// Match should return a stable value after the matching Feed call completes.
//
// Sniff does not depend on metadata. Callers can type-assert the matched
// classifier to MetadataProvider after Sniff returns.
type MetadataProvider interface {
	Metadata() any
}

// Metadata returns metadata from classifier when it implements
// MetadataProvider. Otherwise it returns nil.
func Metadata(classifier Classifier) any {
	if provider, ok := classifier.(MetadataProvider); ok {
		return provider.Metadata()
	}
	return nil
}

// CompositeMetadata stores child metadata from a composite classifier.
//
// Children has the same order as the child classifiers. A nil child value means
// that child had no metadata.
type CompositeMetadata struct {
	Children []any
}
