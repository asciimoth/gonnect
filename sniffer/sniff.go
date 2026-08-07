package sniffer

import (
	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/putback"
)

// NoMatch is returned by Sniff when no classifier produced Match.
const NoMatch = -1

// Sniff incrementally classifies bytes read from conn.
//
// buffer is both scratch storage and the total byte budget for this call. Its
// length, not its capacity, is the maximum number of bytes Sniff may inspect.
// The contents on entry are ignored and may be overwritten. A zero-length
// buffer causes an immediate NoMatch unless a classifier matches on its initial
// empty Feed.
//
// classifiers are stateful instances intended for this one sniffing operation.
// Sniff first calls Feed(nil) on each classifier. It reads from conn in normal
// batches, but feeds classifiers one byte at a time and checks their states
// after every byte. This makes selection independent of net.Conn Read chunking.
// As soon as one or more classifiers match on a byte, Sniff returns the lowest
// matching index. It does not delay a match while another classifier still
// needs more bytes.
//
// Every byte read by Sniff is put back before Sniff returns, including on no
// match and read-error paths. Thus callers may invoke another Sniff on the same
// putback.Conn or hand it to a protocol implementation without losing bytes.
//
// Return values are:
//
//   - index >= 0, err == nil: classifiers[index] matched.
//   - index == NoMatch, err == nil: all classifiers mismatched, buffer was
//     exhausted, buffer was empty, no classifiers were supplied, or a Read
//     made no progress by returning (0, nil).
//   - index == NoMatch, err != nil: conn.Read returned that error before a
//     definitive classifier result.
//
// Sniff creates no errors of its own. A nil conn or nil/invalid classifier is a
// programming error and causes a panic.
//
// The caller must provide exclusive read-side access to conn until Sniff
// returns. Deadline policy is deliberately outside this function; set any read
// deadline before calling Sniff and clear or replace it afterward.
func Sniff(
	buffer []byte,
	conn putback.Conn,
	classifiers ...Classifier,
) (index int, err error) {
	if conn == nil {
		panic("sniffer: nil putback.Conn")
	}

	states := make([]State, len(classifiers))
	active := 0
	for i, classifier := range classifiers {
		classifier = requireClassifier(classifier)
		classifiers[i] = classifier
		state := checkedState(classifier.Feed(nil))
		states[i] = state
		if state == Match {
			return i, nil
		}
		if state == NeedMore {
			active++
		}
	}

	if active == 0 || len(buffer) == 0 {
		return NoMatch, nil
	}

	used := 0
	defer func() {
		if used != 0 {
			conn.PutBack(buffer[:used])
		}
	}()

	for used < len(buffer) {
		n, readErr := conn.Read(buffer[used:])
		if n > 0 {
			chunkStart := used
			used += n

			// Feed one byte at a time even though the network read is batched.
			// Otherwise overlapping classifiers could select different routes
			// depending only on how TCP happened to fragment the same stream.
			for offset := chunkStart; offset < used; offset++ {
				next := buffer[offset : offset+1]
				matchingIndex := NoMatch
				for i, classifier := range classifiers {
					if states[i] != NeedMore {
						continue
					}

					state := checkedState(classifier.Feed(next))
					states[i] = state
					switch state {
					case NeedMore:
					case Match:
						if matchingIndex == NoMatch {
							matchingIndex = i
						}
						active--
					case Mismatch:
						active--
					}
				}

				if matchingIndex != NoMatch {
					return matchingIndex, nil
				}
				if active == 0 {
					return NoMatch, nil
				}
			}
		}

		if readErr != nil {
			return NoMatch, readErr
		}
		if n == 0 {
			// net.Conn implementations should not return (0, nil) for a
			// non-empty destination, but treating it as NoMatch avoids a busy
			// loop for a broken or unusual implementation without inventing an
			// error that did not come from Read.
			return NoMatch, nil
		}
	}

	return NoMatch, nil
}

// SniffWithPool gets the inspection buffer from pool, calls Sniff, and returns
// the buffer to pool before it returns.
//
// bufferSize is the total byte budget for this call. A zero bufferSize has the
// same behavior as passing a zero-length buffer to Sniff. bufferSize must not
// be negative.
func SniffWithPool(
	bufferSize int,
	pool bufpool.Pool,
	conn putback.Conn,
	classifiers ...Classifier,
) (int, error) {
	if bufferSize < 0 {
		panic("sniffer: negative sniff buffer size")
	}

	buffer := bufpool.GetBuffer(pool, bufferSize)
	defer bufpool.PutBuffer(pool, buffer)

	return Sniff(buffer, conn, classifiers...)
}

// SniffFactories is a convenience wrapper that creates one fresh classifier
// from each factory and calls Sniff. The returned index refers to factories.
func SniffFactories(
	buffer []byte,
	conn putback.Conn,
	factories ...Factory,
) (int, error) {
	classifiers := make([]Classifier, len(factories))
	for i, factory := range factories {
		factory = requireFactory(factory)
		classifiers[i] = requireClassifier(factory.NewClassifier())
	}
	return Sniff(buffer, conn, classifiers...)
}

// SniffFactoriesWithPool is a convenience wrapper that creates one fresh
// classifier from each factory and calls SniffWithPool. The returned index
// refers to factories.
func SniffFactoriesWithPool(
	bufferSize int,
	pool bufpool.Pool,
	conn putback.Conn,
	factories ...Factory,
) (int, error) {
	classifiers := make([]Classifier, len(factories))
	for i, factory := range factories {
		factory = requireFactory(factory)
		classifiers[i] = requireClassifier(factory.NewClassifier())
	}
	return SniffWithPool(bufferSize, pool, conn, classifiers...)
}
