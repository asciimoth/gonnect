package sniffer_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

type chunkConn struct {
	mu        sync.Mutex
	chunks    [][]byte
	current   []byte
	readCalls int
	endErr    error
}

func newChunkConn(chunks ...string) *chunkConn {
	data := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		data[i] = []byte(chunk)
	}
	return &chunkConn{chunks: data, endErr: io.EOF}
}

func (c *chunkConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCalls++

	for len(c.current) == 0 && len(c.chunks) != 0 {
		c.current = c.chunks[0]
		c.chunks = c.chunks[1:]
	}
	if len(c.current) == 0 {
		return 0, c.endErr
	}

	n := copy(p, c.current)
	c.current = c.current[n:]
	return n, nil
}

func (c *chunkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *chunkConn) Close() error                     { return nil }
func (c *chunkConn) LocalAddr() net.Addr              { return addr("local") }
func (c *chunkConn) RemoteAddr() net.Addr             { return addr("remote") }
func (c *chunkConn) SetDeadline(time.Time) error      { return nil }
func (c *chunkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chunkConn) SetWriteDeadline(time.Time) error { return nil }

type addr string

func (a addr) Network() string { return "test" }
func (a addr) String() string  { return string(a) }

func readAll(t *testing.T, conn net.Conn) string {
	t.Helper()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(got)
}

func TestSniffMatchAndReplay(t *testing.T) {
	raw := newChunkConn("S", "SH-2.0-test\r\npayload")
	conn := putback.New(raw, nil)

	index, err := sniffer.Sniff(
		make([]byte, 64),
		conn,
		sniffer.Prefix([]byte("GET ")),
		sniffer.SSH(),
	)
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if index != 1 {
		t.Fatalf("index = %d, want 1", index)
	}

	if got, want := readAll(t, conn), "SSH-2.0-test\r\npayload"; got != want {
		t.Fatalf("replayed stream = %q, want %q", got, want)
	}
}

func TestSniffNoMatchAndReplay(t *testing.T) {
	conn := putback.New(newChunkConn("GET / HTTP/1.1\r\n"), nil)
	index, err := sniffer.Sniff(make([]byte, 64), conn, sniffer.SSH())
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if index != sniffer.NoMatch {
		t.Fatalf("index = %d, want NoMatch", index)
	}
	if got, want := readAll(t, conn), "GET / HTTP/1.1\r\n"; got != want {
		t.Fatalf("replayed stream = %q, want %q", got, want)
	}
}

func TestSniffCanBeChained(t *testing.T) {
	conn := putback.New(newChunkConn("SSH-2.0-test\r\n"), nil)

	index, err := sniffer.Sniff(
		make([]byte, 8),
		conn,
		sniffer.Prefix([]byte{0x16, 0x03}),
	)
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("first Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}

	index, err = sniffer.Sniff(make([]byte, 4), conn, sniffer.SSH())
	if err != nil || index != 0 {
		t.Fatalf("second Sniff = (%d, %v), want (0, nil)", index, err)
	}

	if got, want := readAll(t, conn), "SSH-2.0-test\r\n"; got != want {
		t.Fatalf("replayed stream = %q, want %q", got, want)
	}
}

func TestSniffBufferExhaustionIsNoMatchAndReplays(t *testing.T) {
	conn := putback.New(newChunkConn("SS", "H-2.0-test\r\n"), nil)
	index, err := sniffer.Sniff(make([]byte, 2), conn, sniffer.SSH())
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if got, want := readAll(t, conn), "SSH-2.0-test\r\n"; got != want {
		t.Fatalf("replayed stream = %q, want %q", got, want)
	}
}

func TestSniffStopsWhenAllClassifiersMismatch(t *testing.T) {
	raw := newChunkConn("X", "remaining")
	conn := putback.New(raw, nil)
	index, err := sniffer.Sniff(
		make([]byte, 64),
		conn,
		sniffer.Prefix([]byte("A")),
		sniffer.Prefix([]byte("B")),
	)
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if raw.readCalls != 1 {
		t.Fatalf("Read calls = %d, want 1", raw.readCalls)
	}
	if got, want := readAll(t, conn), "Xremaining"; got != want {
		t.Fatalf("replayed stream = %q, want %q", got, want)
	}
}

func TestSniffImmediateMatchDoesNotWaitForEarlierNeedMore(t *testing.T) {
	conn := putback.New(newChunkConn("A"), nil)
	index, err := sniffer.Sniff(
		make([]byte, 8),
		conn,
		sniffer.Prefix([]byte("AB")),
		sniffer.Prefix([]byte("A")),
	)
	if err != nil || index != 1 {
		t.Fatalf("Sniff = (%d, %v), want (1, nil)", index, err)
	}
}

func TestSniffLowestIndexWinsSameFeed(t *testing.T) {
	conn := putback.New(newChunkConn("ABC"), nil)
	index, err := sniffer.Sniff(
		make([]byte, 8),
		conn,
		sniffer.Prefix([]byte("A")),
		sniffer.Prefix([]byte("AB")),
	)
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}
}

func TestSniffNoClassifiersDoesNotRead(t *testing.T) {
	raw := newChunkConn("data")
	conn := putback.New(raw, nil)
	index, err := sniffer.Sniff(make([]byte, 8), conn)
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if raw.readCalls != 0 {
		t.Fatalf("Read calls = %d, want 0", raw.readCalls)
	}
}

func TestSniffInitialMatchDoesNotRead(t *testing.T) {
	raw := newChunkConn("data")
	conn := putback.New(raw, nil)
	index, err := sniffer.Sniff(make([]byte, 8), conn, sniffer.Prefix(nil))
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}
	if raw.readCalls != 0 {
		t.Fatalf("Read calls = %d, want 0", raw.readCalls)
	}
}

func TestSniffZeroLengthBufferDoesNotRead(t *testing.T) {
	raw := newChunkConn("SSH-")
	conn := putback.New(raw, nil)
	index, err := sniffer.Sniff(nil, conn, sniffer.SSH())
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if raw.readCalls != 0 {
		t.Fatalf("Read calls = %d, want 0", raw.readCalls)
	}
}

func TestSniffReturnsReadError(t *testing.T) {
	marker := errors.New("read failed")
	raw := newChunkConn()
	raw.endErr = marker
	conn := putback.New(raw, nil)

	index, err := sniffer.Sniff(make([]byte, 8), conn, sniffer.SSH())
	if index != sniffer.NoMatch || !errors.Is(err, marker) {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, marker)", index, err)
	}
}

type dataAndErrorConn struct {
	mu       sync.Mutex
	data     []byte
	err      error
	returned bool
}

func (c *dataAndErrorConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.returned {
		c.returned = true
		return copy(p, c.data), c.err
	}
	return 0, c.err
}

func (c *dataAndErrorConn) Write(
	p []byte,
) (int, error) {
	return len(p), nil
}
func (c *dataAndErrorConn) Close() error { return nil }

func (c *dataAndErrorConn) LocalAddr() net.Addr { return addr("local") }

func (c *dataAndErrorConn) RemoteAddr() net.Addr             { return addr("remote") }
func (c *dataAndErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *dataAndErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dataAndErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestSniffCanMatchBytesReturnedWithError(t *testing.T) {
	raw := &dataAndErrorConn{data: []byte("SSH-"), err: io.EOF}
	conn := putback.New(raw, nil)

	index, err := sniffer.Sniff(make([]byte, 8), conn, sniffer.SSH())
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "SSH-" {
		t.Fatalf("replayed Read = (%d, %q, %v), want SSH-", n, buf[:n], err)
	}
	n, err = conn.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("deferred error Read = (%d, %v), want EOF", n, err)
	}
}

func TestSniffRestoresBytesBeforeReadError(t *testing.T) {
	marker := errors.New("truncated")
	raw := &dataAndErrorConn{data: []byte("SS"), err: marker}
	conn := putback.New(raw, nil)

	index, err := sniffer.Sniff(make([]byte, 8), conn, sniffer.SSH())
	if index != sniffer.NoMatch || !errors.Is(err, marker) {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, marker)", index, err)
	}

	buf := make([]byte, 2)
	n, readErr := conn.Read(buf)
	if readErr != nil || string(buf[:n]) != "SS" {
		t.Fatalf("replayed Read = (%d, %q, %v), want SS", n, buf[:n], readErr)
	}
}

func TestSniffRestoresPreviouslyBufferedPrefix(t *testing.T) {
	conn := putback.New(newChunkConn("DEF"), nil)
	conn.PutBack([]byte("ABC"))

	index, err := sniffer.Sniff(
		make([]byte, 2),
		conn,
		sniffer.Prefix([]byte("ABCD")),
	)
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if got, want := readAll(t, conn), "ABCDEF"; got != want {
		t.Fatalf("restored stream = %q, want %q", got, want)
	}
}

func TestSniffFactoriesBuildFreshInstances(t *testing.T) {
	factory := sniffer.SSHFactory()
	for iteration := range 2 {
		conn := putback.New(newChunkConn("SSH-2.0\r\n"), nil)
		index, err := sniffer.SniffFactories(make([]byte, 8), conn, factory)
		if err != nil || index != 0 {
			t.Fatalf(
				"iteration %d: SniffFactories = (%d, %v), want (0, nil)",
				iteration,
				index,
				err,
			)
		}
	}
}

func TestSniffWithPoolReturnsBuffers(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	t.Cleanup(pool.Close)

	conn := putback.New(newChunkConn("SSH-2.0\r\n"), pool)
	index, err := sniffer.SniffWithPool(8, pool, conn, sniffer.SSH())
	if err != nil || index != 0 {
		t.Fatalf("SniffWithPool = (%d, %v), want (0, nil)", index, err)
	}
	if got := readAll(t, conn); got != "SSH-2.0\r\n" {
		t.Fatalf("replayed stream = %q, want SSH-2.0\\r\\n", got)
	}
}

func TestSniffFactoriesWithPoolReturnsBuffers(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	t.Cleanup(pool.Close)

	conn := putback.New(newChunkConn("SSH-2.0\r\n"), pool)
	index, err := sniffer.SniffFactoriesWithPool(
		8,
		pool,
		conn,
		sniffer.SSHFactory(),
	)
	if err != nil || index != 0 {
		t.Fatalf(
			"SniffFactoriesWithPool = (%d, %v), want (0, nil)",
			index,
			err,
		)
	}
	if got := readAll(t, conn); got != "SSH-2.0\r\n" {
		t.Fatalf("replayed stream = %q, want SSH-2.0\\r\\n", got)
	}
}

type noProgressConn struct{ readCalls int }

func (c *noProgressConn) Read(
	[]byte,
) (int, error) {
	c.readCalls++
	return 0, nil
}

func (c *noProgressConn) Write(
	p []byte,
) (int, error) {
	return len(p), nil
}
func (c *noProgressConn) Close() error { return nil }

func (c *noProgressConn) LocalAddr() net.Addr { return addr("local") }

func (c *noProgressConn) RemoteAddr() net.Addr             { return addr("remote") }
func (c *noProgressConn) SetDeadline(time.Time) error      { return nil }
func (c *noProgressConn) SetReadDeadline(time.Time) error  { return nil }
func (c *noProgressConn) SetWriteDeadline(time.Time) error { return nil }

func TestSniffZeroProgressIsNoMatch(t *testing.T) {
	raw := &noProgressConn{}
	conn := putback.New(raw, nil)
	index, err := sniffer.Sniff(make([]byte, 8), conn, sniffer.SSH())
	if err != nil || index != sniffer.NoMatch {
		t.Fatalf("Sniff = (%d, %v), want (NoMatch, nil)", index, err)
	}
	if raw.readCalls != 1 {
		t.Fatalf("Read calls = %d, want 1", raw.readCalls)
	}
}

func TestSniffFragmentedOneByteAtATime(t *testing.T) {
	conn := putback.New(newChunkConn("S", "S", "H", "-"), nil)
	index, err := sniffer.Sniff(make([]byte, 4), conn, sniffer.SSH())
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}
	if got := readAll(t, conn); got != "SSH-" {
		t.Fatalf("replayed stream = %q, want SSH-", got)
	}
}

func TestSniffDoesNotDependOnBufferContents(t *testing.T) {
	conn := putback.New(newChunkConn("SSH-"), nil)
	buffer := bytes.Repeat([]byte{0xff}, 8)
	index, err := sniffer.Sniff(buffer, conn, sniffer.SSH())
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}
}

func FuzzSniffPreservesStream(f *testing.F) {
	f.Add([]byte("SSH-2.0-test\r\n"), []byte("SSH-"), uint8(8))
	f.Add([]byte("GET / HTTP/1.1\r\n"), []byte("SSH-"), uint8(4))
	f.Add([]byte{0, 1, 2, 3, 4}, []byte{0, 1, 9}, uint8(2))

	f.Fuzz(func(t *testing.T, data, prefix []byte, budget uint8) {
		if len(data) > 64<<10 || len(prefix) > 256 {
			t.Skip()
		}

		raw := newChunkConn(string(data))
		conn := putback.New(raw, nil)
		_, _ = sniffer.Sniff(
			make([]byte, int(budget)),
			conn,
			sniffer.Prefix(prefix),
		)

		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("ReadAll after Sniff: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("stream changed: got %x, want %x", got, data)
		}
	})
}

func TestSniffInvalidClassifierStatePanics(t *testing.T) {
	conn := putback.New(newChunkConn("data"), nil)
	bad := sniffer.ClassifierFunc(
		func([]byte) sniffer.State { return sniffer.State(99) },
	)
	defer func() {
		if recover() == nil {
			t.Fatal("Sniff did not panic for an invalid classifier state")
		}
	}()
	_, _ = sniffer.Sniff(make([]byte, 8), conn, bad)
}

func TestSniffNilArgumentsPanic(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Sniff did not panic for nil connection")
			}
		}()
		_, _ = sniffer.Sniff(make([]byte, 1), nil, sniffer.SSH())
	})

	t.Run("classifier", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Sniff did not panic for nil classifier")
			}
		}()
		_, _ = sniffer.Sniff(
			make([]byte, 1),
			putback.New(newChunkConn("x"), nil),
			nil,
		)
	})

	t.Run("factory", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("SniffFactories did not panic for nil factory")
			}
		}()
		_, _ = sniffer.SniffFactories(
			make([]byte, 1),
			putback.New(newChunkConn("x"), nil),
			nil,
		)
	})
}

func TestSniffSelectionIsIndependentOfReadChunking(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
	}{
		{name: "coalesced", chunks: []string{"AB"}},
		{name: "fragmented", chunks: []string{"A", "B"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := putback.New(newChunkConn(test.chunks...), nil)
			index, err := sniffer.Sniff(
				make([]byte, 8),
				conn,
				sniffer.Prefix([]byte("AB")),
				sniffer.Prefix([]byte("A")),
			)
			if err != nil || index != 1 {
				t.Fatalf("Sniff = (%d, %v), want (1, nil)", index, err)
			}
			if got := readAll(t, conn); got != "AB" {
				t.Fatalf("replayed stream = %q, want AB", got)
			}
		})
	}
}

func TestSniffFeedsClassifiersOneByteAtATime(t *testing.T) {
	seen := 0
	classifier := sniffer.ClassifierFunc(func(p []byte) sniffer.State {
		if len(p) == 0 {
			return sniffer.NeedMore
		}
		if len(p) != 1 {
			t.Fatalf("Feed received %d bytes, want 1", len(p))
		}
		seen++
		if seen == 2 {
			return sniffer.Match
		}
		return sniffer.NeedMore
	})

	conn := putback.New(newChunkConn("ABCD"), nil)
	index, err := sniffer.Sniff(make([]byte, 8), conn, classifier)
	if err != nil || index != 0 {
		t.Fatalf("Sniff = (%d, %v), want (0, nil)", index, err)
	}
	if seen != 2 {
		t.Fatalf("classifier saw %d bytes, want 2", seen)
	}
	if got := readAll(t, conn); got != "ABCD" {
		t.Fatalf("replayed stream = %q, want ABCD", got)
	}
}
