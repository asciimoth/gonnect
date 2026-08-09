// Package putback provides a net.Conn wrapper with a byte buffer that can be
// prepended to the connection's unread input.
//
// A Conn is useful when code must inspect bytes and later present the same byte
// stream to another consumer. PutBack copies its argument and prepends it to
// the unread stream. Bytes within one PutBack call retain their order. Across
// calls, the most recent call is read first:
//
//	c.PutBack([]byte("one"))
//	c.PutBack([]byte("two"))
//	// Subsequent reads produce "twoone" before underlying bytes.
//
// This stack-like ordering is intentional. If a caller reads a prefix while
// older put-back bytes remain, putting that prefix back must place it before
// the remaining bytes to reconstruct the original stream.
//
// Conn preserves byte order, but it cannot preserve read chunk boundaries,
// concrete connection identity, or the exact time at which an underlying read
// error was reported. New takes a bufpool.Pool for copied put-back buffers. If
// the pool argument is nil, each put-back copy is allocated with make.
// New returns nil if the connection argument is nil.
//
// The pool is only used for internal copies made by PutBack. Conn never stores
// or returns caller-owned slices. A pooled put-back buffer is returned to the
// pool when its bytes are fully read, when a later PutBack replaces it with a
// combined buffer, when TCPConn.WriteTo fully writes it, or when PostClose
// releases it. After a buffer is returned to the pool, Conn does not read from
// it or write to it again. Partially read or partially written put-back buffers
// stay owned by Conn until the remaining bytes are consumed, replaced, or
// released by PostClose.
//
// If New receives a gonnect.TCPConn, the returned value also implements TCPConn
// and gonnect.TCPConn. If the TCP connection has standard library socket methods
// such as File, SyscallConn, SetReadBuffer, SetWriteBuffer, or MultipathTCP,
// those methods are preserved and delegate to the wrapped connection. Raw socket
// methods operate on the wrapped connection and do not include bytes held in the
// put-back buffer.
//
// If an underlying Read returns both bytes and an error, Conn returns the bytes
// first and defers the error to the next Read. This normalization makes byte
// replay reliable and follows the io.Reader requirement to process bytes before
// an accompanying error.
//
// Conn is not safe for concurrent read-side operations. Do not call Read,
// PutBack, Buffered, or PostClose concurrently with each other. For TCPConn,
// WriteTo is also a read-side operation. PreClose can be called while reads or
// writes are active. Like a normal net.Conn, Conn can still be used concurrently
// by one goroutine that reads and one goroutine that writes, subject to the
// underlying connection's guarantees. Writes, address queries, and deadline
// methods are delegated directly to the underlying connection. Close is
// equivalent to PostClose, which first runs PreClose if needed.
//
// Buffered reads do not call the underlying connection, so an underlying read
// deadline is not consulted until the put-back buffer has been drained.
package putback
