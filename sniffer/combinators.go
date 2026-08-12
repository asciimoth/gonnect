package sniffer

// And returns a classifier that matches when every child matches, mismatches
// when any child mismatches, and otherwise needs more bytes.
//
// And with no children is the boolean identity true and therefore matches on
// its initial empty Feed.
func And(children ...Classifier) Classifier {
	copyOfChildren := append([]Classifier(nil), children...)
	minSize := 0
	for i, child := range copyOfChildren {
		copyOfChildren[i] = requireClassifier(child)
		if childSize := checkedMinSniffBufferSize(
			child.MinSniffBufferSize(),
		); childSize > minSize {
			minSize = childSize
		}
	}
	return &andClassifier{
		children: copyOfChildren,
		states:   make([]State, len(copyOfChildren)),
		minSize:  minSize,
		state:    NeedMore,
	}
}

type andClassifier struct {
	children []Classifier
	states   []State
	minSize  int
	state    State
}

func (c *andClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}
	if len(c.children) == 0 {
		c.state = Match
		return c.state
	}

	allMatched := true
	for i, child := range c.children {
		state := c.states[i]
		if state == NeedMore {
			state = checkedState(child.Feed(p))
			c.states[i] = state
		}
		if state == Mismatch {
			c.state = Mismatch
			return c.state
		}
		if state != Match {
			allMatched = false
		}
	}

	if allMatched {
		c.state = Match
	}
	return c.state
}

func (c *andClassifier) MinSniffBufferSize() int {
	return c.minSize
}

func (c *andClassifier) Metadata() any {
	if c.state != Match {
		return nil
	}

	metadata := make([]any, len(c.children))
	count := 0
	var first any
	for i, child := range c.children {
		childMetadata := Metadata(child)
		metadata[i] = childMetadata
		if childMetadata == nil {
			continue
		}
		if first == nil {
			first = childMetadata
		}
		count++
	}
	if count == 0 {
		return nil
	}
	if count == 1 {
		return first
	}
	return CompositeMetadata{Children: metadata}
}

// Or returns a classifier that matches when any child matches, mismatches when
// every child mismatches, and otherwise needs more bytes.
//
// Or with no children is the boolean identity false and therefore mismatches on
// its initial empty Feed.
func Or(children ...Classifier) Classifier {
	copyOfChildren := append([]Classifier(nil), children...)
	minSize := 0
	for i, child := range copyOfChildren {
		copyOfChildren[i] = requireClassifier(child)
		if childSize := checkedMinSniffBufferSize(
			child.MinSniffBufferSize(),
		); childSize > minSize {
			minSize = childSize
		}
	}
	return &orClassifier{
		children: copyOfChildren,
		states:   make([]State, len(copyOfChildren)),
		minSize:  minSize,
		state:    NeedMore,
		match:    -1,
	}
}

type orClassifier struct {
	children []Classifier
	states   []State
	minSize  int
	state    State
	match    int
}

func (c *orClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}
	if len(c.children) == 0 {
		c.state = Mismatch
		return c.state
	}

	allMismatched := true
	for i, child := range c.children {
		state := c.states[i]
		if state == NeedMore {
			state = checkedState(child.Feed(p))
			c.states[i] = state
		}
		if state == Match {
			c.state = Match
			c.match = i
			return c.state
		}
		if state != Mismatch {
			allMismatched = false
		}
	}

	if allMismatched {
		c.state = Mismatch
	}
	return c.state
}

func (c *orClassifier) MinSniffBufferSize() int {
	return c.minSize
}

func (c *orClassifier) Metadata() any {
	if c.state != Match || c.match < 0 || c.match >= len(c.children) {
		return nil
	}
	return Metadata(c.children[c.match])
}

// Not returns the boolean negation of child. NeedMore remains NeedMore, Match
// becomes Mismatch, and Mismatch becomes Match.
func Not(child Classifier) Classifier {
	child = requireClassifier(child)
	return &notClassifier{
		child:   child,
		minSize: checkedMinSniffBufferSize(child.MinSniffBufferSize()),
		state:   NeedMore,
	}
}

type notClassifier struct {
	child   Classifier
	minSize int
	state   State
}

func (c *notClassifier) Feed(p []byte) State {
	if c.state != NeedMore {
		return c.state
	}

	switch checkedState(c.child.Feed(p)) {
	case NeedMore:
		return NeedMore
	case Match:
		c.state = Mismatch
	case Mismatch:
		c.state = Match
	}
	return c.state
}

func (c *notClassifier) MinSniffBufferSize() int {
	return c.minSize
}

// AndFactory returns a factory that constructs a fresh And classifier around
// fresh classifiers from children.
func AndFactory(children ...Factory) Factory {
	copyOfChildren := append([]Factory(nil), children...)
	for i, child := range copyOfChildren {
		copyOfChildren[i] = requireFactory(child)
	}
	return FactoryWithMinSniffBufferSize(
		MinFactorySniffBufferSize(copyOfChildren...),
		FactoryFunc(func() Classifier {
			classifiers := make([]Classifier, len(copyOfChildren))
			for i, child := range copyOfChildren {
				classifiers[i] = requireClassifier(child.NewClassifier())
			}
			return And(classifiers...)
		}),
	)
}

// OrFactory returns a factory that constructs a fresh Or classifier around
// fresh classifiers from children.
func OrFactory(children ...Factory) Factory {
	copyOfChildren := append([]Factory(nil), children...)
	for i, child := range copyOfChildren {
		copyOfChildren[i] = requireFactory(child)
	}
	return FactoryWithMinSniffBufferSize(
		MinFactorySniffBufferSize(copyOfChildren...),
		FactoryFunc(func() Classifier {
			classifiers := make([]Classifier, len(copyOfChildren))
			for i, child := range copyOfChildren {
				classifiers[i] = requireClassifier(child.NewClassifier())
			}
			return Or(classifiers...)
		}),
	)
}

// NotFactory returns a factory that constructs a fresh Not classifier around a
// fresh classifier from child.
func NotFactory(child Factory) Factory {
	child = requireFactory(child)
	return FactoryWithMinSniffBufferSize(
		MinFactorySniffBufferSize(child),
		FactoryFunc(func() Classifier {
			return Not(requireClassifier(child.NewClassifier()))
		}),
	)
}
