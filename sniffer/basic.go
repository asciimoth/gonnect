package sniffer

// Prefix returns a classifier that matches when the stream begins with prefix.
// It mismatches at the first differing byte and needs more bytes while the
// bytes seen so far are a proper prefix of prefix.
//
// Prefix copies prefix. An empty prefix matches immediately on an empty Feed.
func Prefix(prefix []byte) Classifier {
	return &prefixClassifier{
		want:  append([]byte(nil), prefix...),
		state: NeedMore,
	}
}

type prefixClassifier struct {
	want   []byte
	offset int
	state  State
}

func (c *prefixClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}
	if len(c.want) == 0 {
		c.state = Match
		return c.state
	}

	for _, b := range p {
		if b != c.want[c.offset] {
			c.state = Mismatch
			return c.state
		}
		c.offset++
		if c.offset == len(c.want) {
			c.state = Match
			return c.state
		}
	}
	return NeedMore
}

func (c *prefixClassifier) MinSniffBufferSize() int {
	return len(c.want)
}

// PrefixFactory returns a factory for Prefix classifiers. It copies prefix when
// the factory is created, so later caller mutation does not affect instances.
func PrefixFactory(prefix []byte) Factory {
	want := append([]byte(nil), prefix...)
	return FactoryWithMinSniffBufferSize(
		len(want),
		FactoryFunc(func() Classifier {
			return Prefix(want)
		}),
	)
}

// SSH returns a simple SSH transport classifier.
//
// It matches the four-byte ASCII prefix "SSH-" at stream offset zero. This is
// intentionally a routing heuristic, not a complete SSH identification-line
// validator. It does not validate protocol/software versions and does not
// accept non-SSH preamble lines before the identification string.
func SSH() Classifier {
	return Prefix([]byte("SSH-"))
}

// SSHFactory returns a factory for SSH classifiers.
func SSHFactory() Factory {
	return PrefixFactory([]byte("SSH-"))
}

// Limit wraps child and changes NeedMore to Mismatch after limit bytes have
// been fed to it. It is useful for making a classifier's own inspection bound
// explicit independently of Sniff's total buffer bound.
//
// At most limit bytes are passed to child. If a Feed chunk crosses the limit,
// only the portion within the limit is passed. A child that matches or
// mismatches within that portion keeps its result. limit must be non-negative.
func Limit(limit int, child Classifier) Classifier {
	if limit < 0 {
		panic("sniffer: negative classifier byte limit")
	}
	child = requireClassifier(child)
	minSize := limit
	if childSize := checkedMinSniffBufferSize(
		child.MinSniffBufferSize(),
	); childSize < minSize {
		minSize = childSize
	}
	return &limitClassifier{
		child:   child,
		limit:   limit,
		minSize: minSize,
		state:   NeedMore,
	}
}

type limitClassifier struct {
	child   Classifier
	limit   int
	minSize int
	seen    int
	state   State
}

func (c *limitClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	remaining := c.limit - c.seen
	if remaining < len(p) {
		p = p[:remaining]
	}

	state := checkedState(c.child.Feed(p))
	c.seen += len(p)
	if state != NeedMore {
		c.state = state
		return c.state
	}
	if c.seen == c.limit {
		c.state = Mismatch
	}
	return c.state
}

func (c *limitClassifier) MinSniffBufferSize() int {
	return c.minSize
}

// LimitFactory returns a factory that applies Limit to fresh child instances.
func LimitFactory(limit int, child Factory) Factory {
	if limit < 0 {
		panic("sniffer: negative classifier byte limit")
	}
	child = requireFactory(child)
	minSize := limit
	if childSize := checkedMinSniffBufferSize(
		child.MinSniffBufferSize(),
	); childSize < minSize {
		minSize = childSize
	}
	return FactoryWithMinSniffBufferSize(
		minSize,
		FactoryFunc(func() Classifier {
			return Limit(limit, requireClassifier(child.NewClassifier()))
		}),
	)
}
