package putback_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
)

type memoryConn struct {
	mu        sync.Mutex
	reader    *bytes.Reader
	readCalls int
	writes    bytes.Buffer
	closed    bool
	deadlines [3]time.Time
}

func newMemoryConn(data string) *memoryConn {
	return &memoryConn{reader: bytes.NewReader([]byte(data))}
}

func (c *memoryConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCalls++
	return c.reader.Read(p)
}

func (c *memoryConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.Write(p)
}

func (c *memoryConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *memoryConn) LocalAddr() net.Addr  { return testAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr { return testAddr("remote") }
func (c *memoryConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines[0] = deadline
	return nil
}
func (c *memoryConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines[1] = deadline
	return nil
}
func (c *memoryConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines[2] = deadline
	return nil
}

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type phaseCloseMemoryConn struct {
	*memoryConn
	preCloses  int
	postCloses int
	closes     int
}

func (c *phaseCloseMemoryConn) PreClose() error {
	c.preCloses++
	return c.memoryConn.Close()
}

func (c *phaseCloseMemoryConn) PostClose() error {
	c.postCloses++
	return nil
}

func (c *phaseCloseMemoryConn) Close() error {
	c.closes++
	return errors.Join(c.PreClose(), c.PostClose())
}

type tcpMemoryConn struct {
	*memoryConn

	readFromCalls        int
	writeToCalls         int
	keepAlive            bool
	keepAliveConfigCalls int
	keepAlivePeriod      time.Duration
	linger               int
	noDelay              bool
	closeReadCalls       int
	closeWriteCalls      int
}

var _ gonnect.TCPConn = (*tcpMemoryConn)(nil)

func newTCPMemoryConn(data string) *tcpMemoryConn {
	return &tcpMemoryConn{memoryConn: newMemoryConn(data)}
}

func (c *tcpMemoryConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalls++
	return io.Copy(&c.writes, r)
}

func (c *tcpMemoryConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls++

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.WriteTo(w)
}

func (c *tcpMemoryConn) SetKeepAlive(keepalive bool) error {
	c.keepAlive = keepalive
	return nil
}

func (c *tcpMemoryConn) SetKeepAliveConfig(net.KeepAliveConfig) error {
	c.keepAliveConfigCalls++
	return nil
}

func (c *tcpMemoryConn) SetKeepAlivePeriod(d time.Duration) error {
	c.keepAlivePeriod = d
	return nil
}

func (c *tcpMemoryConn) SetLinger(sec int) error {
	c.linger = sec
	return nil
}

func (c *tcpMemoryConn) SetNoDelay(noDelay bool) error {
	c.noDelay = noDelay
	return nil
}

func (c *tcpMemoryConn) CloseRead() error {
	c.closeReadCalls++
	return nil
}

func (c *tcpMemoryConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

type tcpSocketMemoryConn struct {
	*tcpMemoryConn

	multipathCalls int
	readBuffer     int
	writeBuffer    int
	syscallCalls   int
	fileCalls      int
}

func (c *tcpSocketMemoryConn) MultipathTCP() (bool, error) {
	c.multipathCalls++
	return true, nil
}

func (c *tcpSocketMemoryConn) SetReadBuffer(bytes int) error {
	c.readBuffer = bytes
	return nil
}

func (c *tcpSocketMemoryConn) SetWriteBuffer(bytes int) error {
	c.writeBuffer = bytes
	return nil
}

func (c *tcpSocketMemoryConn) SyscallConn() (syscall.RawConn, error) {
	c.syscallCalls++
	return nil, nil //nolint:nilnil
}

func (c *tcpSocketMemoryConn) File() (*os.File, error) {
	c.fileCalls++
	return nil, nil //nolint:nilnil
}

type tcpBytesAndErrorConn struct {
	*bytesAndErrorConn

	writeToCalls int
}

var _ gonnect.TCPConn = (*tcpBytesAndErrorConn)(nil)

func (c *tcpBytesAndErrorConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(io.Discard, r)
}

func (c *tcpBytesAndErrorConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls++
	n, err := w.Write([]byte("unexpected"))
	return int64(n), err
}

func (c *tcpBytesAndErrorConn) SetKeepAlive(bool) error { return nil }

func (c *tcpBytesAndErrorConn) SetKeepAliveConfig(net.KeepAliveConfig) error {
	return nil
}

func (c *tcpBytesAndErrorConn) SetKeepAlivePeriod(time.Duration) error {
	return nil
}

func (c *tcpBytesAndErrorConn) SetLinger(int) error { return nil }

func (c *tcpBytesAndErrorConn) SetNoDelay(bool) error { return nil }

func (c *tcpBytesAndErrorConn) CloseRead() error { return nil }

func (c *tcpBytesAndErrorConn) CloseWrite() error { return nil }

type poisonPool struct {
	t     *testing.T
	inUse map[string][]byte
	gets  int
	puts  int
}

func newPoisonPool(t *testing.T) *poisonPool {
	t.Helper()
	return &poisonPool{
		t:     t,
		inUse: make(map[string][]byte),
	}
}

func (p *poisonPool) Get(length int) []byte {
	p.t.Helper()
	p.gets++
	buf := bytes.Repeat([]byte{0xa5}, length)
	if length == 0 {
		return buf
	}
	p.inUse[poolKey(buf)] = buf
	return buf
}

func (p *poisonPool) Put(buf []byte) {
	p.t.Helper()
	if cap(buf) == 0 {
		return
	}

	full := buf[:cap(buf)]
	key := poolKey(full)
	if _, ok := p.inUse[key]; !ok {
		p.t.Fatalf("buffer %s was put twice or was not allocated by pool", key)
	}
	delete(p.inUse, key)
	for i := range full {
		full[i] = '!'
	}
	p.puts++
}

func (p *poisonPool) assertIdle() {
	p.t.Helper()
	if len(p.inUse) != 0 {
		p.t.Fatalf("pool has %d buffer(s) still in use", len(p.inUse))
	}
}

func poolKey(buf []byte) string {
	return fmt.Sprintf("%p", &buf[:cap(buf)][0])
}

type partialErrWriter struct {
	bytes.Buffer
	limit int
	err   error
}

func (w *partialErrWriter) Write(p []byte) (int, error) {
	n := min(w.limit, len(p))
	if n > 0 {
		_, _ = w.Buffer.Write(p[:n])
	}
	return n, w.err
}

func TestPutBackOrdering(t *testing.T) {
	raw := newMemoryConn("tail")
	conn := putback.New(raw, nil)

	conn.PutBack([]byte("one"))
	conn.PutBack([]byte("two"))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := "twoonetail"; string(got) != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

func TestPutBackRestoresPartiallyConsumedBuffer(t *testing.T) {
	conn := putback.New(newMemoryConn("tail"), nil)
	conn.PutBack([]byte("abcdef"))

	prefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	conn.PutBack(prefix)

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if want := "abcdeftail"; string(got) != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

func TestPutBackCopiesInput(t *testing.T) {
	conn := putback.New(newMemoryConn(""), nil)
	p := []byte("abc")
	conn.PutBack(p)
	copy(p, "XYZ")

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("stream = %q, want %q", got, "abc")
	}
}

func TestPutBackWithNilPoolWorks(t *testing.T) {
	conn := putback.New(newMemoryConn("tail"), nil)
	conn.PutBack([]byte("one"))
	conn.PutBack([]byte("two"))

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	want := "two" + "o"
	if string(buf) != want {
		t.Fatalf("prefix = %q, want %q", buf, want)
	}
	if got := conn.Buffered(); got != len("ne") {
		t.Fatalf("Buffered = %d, want %d", got, len("ne"))
	}
	conn.PutBack([]byte("X"))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "Xnetail" {
		t.Fatalf("stream = %q, want Xnetail", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestTCPWriteToWithNilPoolWorks(t *testing.T) {
	raw := newTCPMemoryConn("tail")
	conn := putback.New(raw, nil)
	conn.PutBack([]byte("head"))

	tcp, ok := conn.(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned non-TCP wrapper")
	}
	var out bytes.Buffer
	written, err := tcp.WriteTo(&out)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if out.String() != "headtail" {
		t.Fatalf("WriteTo output = %q, want headtail", out.String())
	}
	if written != int64(len("headtail")) {
		t.Fatalf("WriteTo bytes = %d, want %d", written, len("headtail"))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPutBackWithPoolReturnsBufferAfterRead(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	conn := putback.New(newMemoryConn(""), pool)
	conn.PutBack([]byte("abcdef"))

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull prefix: %v", err)
	}
	if string(buf) != "ab" {
		t.Fatalf("prefix = %q, want ab", buf)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "cdef" {
		t.Fatalf("remaining stream = %q, want cdef", got)
	}

	pool.Close()
}

func TestPutBackWithPoolReturnsReplacedBuffer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	conn := putback.New(newMemoryConn("tail"), pool)
	conn.PutBack([]byte("one"))
	conn.PutBack([]byte("two"))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "twoonetail" {
		t.Fatalf("stream = %q, want twoonetail", got)
	}

	pool.Close()
}

func TestPutBackPreCloseLeavesBufferedBytesOwned(t *testing.T) {
	raw := newMemoryConn("tail")
	conn := putback.New(raw, nil)
	conn.PutBack([]byte("head"))

	if err := conn.PreClose(); err != nil {
		t.Fatalf("PreClose: %v", err)
	}
	if !raw.closed {
		t.Fatal("wrapped connection was not closed")
	}
	if got := conn.Buffered(); got != len("head") {
		t.Fatalf("Buffered after PreClose = %d, want %d", got, len("head"))
	}
}

func TestPutBackPostCloseReturnsBuffer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	conn := putback.New(newMemoryConn("tail"), pool)
	conn.PutBack([]byte("head"))

	if err := conn.PreClose(); err != nil {
		t.Fatalf("PreClose: %v", err)
	}
	if got := conn.Buffered(); got != len("head") {
		t.Fatalf("Buffered after PreClose = %d, want %d", got, len("head"))
	}
	if err := conn.PostClose(); err != nil {
		t.Fatalf("PostClose: %v", err)
	}
	if got := conn.Buffered(); got != 0 {
		t.Fatalf("Buffered after PostClose = %d, want 0", got)
	}
	if err := conn.PostClose(); err != nil {
		t.Fatalf("second PostClose: %v", err)
	}

	pool.Close()
}

func TestPutBackCloseReturnsBuffer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	conn := putback.New(newMemoryConn("tail"), pool)
	conn.PutBack([]byte("head"))

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	pool.Close()
}

func TestTCPWriteToWithPoolReturnsBuffer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	raw := newTCPMemoryConn("tail")
	conn := putback.New(raw, pool)
	conn.PutBack([]byte("head"))

	var out bytes.Buffer
	tcp, ok := conn.(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned non-TCP wrapper")
	}
	written, err := tcp.WriteTo(&out)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if out.String() != "headtail" {
		t.Fatalf("WriteTo output = %q, want headtail", out.String())
	}
	if written != int64(len("headtail")) {
		t.Fatalf("WriteTo bytes = %d, want %d", written, len("headtail"))
	}

	pool.Close()
}

func TestPutBackWithPoolCloseAfterDrainDoesNotDoublePut(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	conn := putback.New(newMemoryConn(""), pool)
	conn.PutBack([]byte("head"))

	if got, err := io.ReadAll(conn); err != nil || string(got) != "head" {
		t.Fatalf("ReadAll = (%q, %v), want (head, nil)", got, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	pool.Close()
}

func TestPutBackClosePhasesDelegateToWrappedClosePhases(t *testing.T) {
	raw := &phaseCloseMemoryConn{memoryConn: newMemoryConn("tail")}
	conn := putback.New(raw, nil)
	conn.PutBack([]byte("head"))

	if err := conn.PreClose(); err != nil {
		t.Fatalf("PreClose: %v", err)
	}
	if err := conn.PostClose(); err != nil {
		t.Fatalf("PostClose: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if raw.preCloses != 1 {
		t.Fatalf("wrapped PreClose calls = %d, want 1", raw.preCloses)
	}
	if raw.postCloses != 1 {
		t.Fatalf("wrapped PostClose calls = %d, want 1", raw.postCloses)
	}
	if raw.closes != 0 {
		t.Fatalf("wrapped Close calls = %d, want 0", raw.closes)
	}
}

func TestPutBackWithPoolDoesNotReadReleasedBufferAfterPartialRead(
	t *testing.T,
) {
	pool := newPoisonPool(t)
	conn := putback.New(newMemoryConn("tail"), pool)
	conn.PutBack([]byte("abcdef"))

	prefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		t.Fatalf("ReadFull prefix: %v", err)
	}
	conn.PutBack([]byte("XY"))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "XYcdeftail" {
		t.Fatalf("stream = %q, want XYcdeftail", got)
	}
	if pool.gets != pool.puts {
		t.Fatalf("pool gets = %d, puts = %d", pool.gets, pool.puts)
	}
	pool.assertIdle()
}

func TestTCPWriteToWithPoolKeepsBufferAfterPartialWriteError(t *testing.T) {
	pool := newPoisonPool(t)
	raw := newTCPMemoryConn("tail")
	conn := putback.New(raw, pool)
	conn.PutBack([]byte("head"))

	tcp, ok := conn.(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned non-TCP wrapper")
	}
	marker := errors.New("write stopped")
	first := &partialErrWriter{limit: 2, err: marker}
	written, err := tcp.WriteTo(first)
	if !errors.Is(err, marker) {
		t.Fatalf("first WriteTo error = %v, want marker", err)
	}
	if written != 2 || first.String() != "he" {
		t.Fatalf(
			"first WriteTo = (%d, %q), want (2, he)",
			written,
			first.String(),
		)
	}
	if pool.puts != 0 {
		t.Fatalf("pool puts after partial write = %d, want 0", pool.puts)
	}

	var second bytes.Buffer
	written, err = tcp.WriteTo(&second)
	if err != nil {
		t.Fatalf("second WriteTo: %v", err)
	}
	if written != int64(len("adtail")) || second.String() != "adtail" {
		t.Fatalf(
			"second WriteTo = (%d, %q), want (%d, adtail)",
			written,
			second.String(),
			len("adtail"),
		)
	}
	if pool.gets != pool.puts {
		t.Fatalf("pool gets = %d, puts = %d", pool.gets, pool.puts)
	}
	pool.assertIdle()
}

func TestBufferedReadDoesNotAlsoReadUnderlying(t *testing.T) {
	raw := newMemoryConn("underlying")
	conn := putback.New(raw, nil)
	conn.PutBack([]byte("x"))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read buffered: %v", err)
	}
	if n != 1 || string(buf[:n]) != "x" {
		t.Fatalf("first Read = (%d, %q), want (1, %q)", n, buf[:n], "x")
	}
	if raw.readCalls != 0 {
		t.Fatalf("underlying Read calls = %d, want 0", raw.readCalls)
	}

	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read underlying: %v", err)
	}
	if string(buf[:n]) != "underlying" {
		t.Fatalf("second Read = %q, want %q", buf[:n], "underlying")
	}
	if raw.readCalls != 1 {
		t.Fatalf("underlying Read calls = %d, want 1", raw.readCalls)
	}
}

func TestBufferedCount(t *testing.T) {
	conn := putback.New(newMemoryConn(""), nil)
	conn.PutBack([]byte("abcd"))
	if got := conn.Buffered(); got != 4 {
		t.Fatalf("Buffered = %d, want 4", got)
	}

	buf := make([]byte, 3)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := conn.Buffered(); got != 1 {
		t.Fatalf("Buffered = %d, want 1", got)
	}
}

type bytesAndErrorConn struct {
	mu       sync.Mutex
	data     []byte
	err      error
	returned bool
}

func (c *bytesAndErrorConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.returned {
		c.returned = true
		n := copy(p, c.data)
		return n, c.err
	}
	return 0, c.err
}

func (c *bytesAndErrorConn) Write(
	p []byte,
) (int, error) {
	return len(p), nil
}
func (c *bytesAndErrorConn) Close() error { return nil }

func (c *bytesAndErrorConn) LocalAddr() net.Addr { return testAddr("local") }

func (c *bytesAndErrorConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *bytesAndErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *bytesAndErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bytesAndErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestReadDefersErrorReturnedWithBytes(t *testing.T) {
	marker := errors.New("read failed")
	conn := putback.New(
		&bytesAndErrorConn{data: []byte("abc"), err: marker},
		nil,
	)

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("first Read error = %v, want nil", err)
	}
	if string(buf[:n]) != "abc" {
		t.Fatalf("first Read bytes = %q, want %q", buf[:n], "abc")
	}

	conn.PutBack([]byte("XY"))
	n, err = conn.Read(buf)
	if err != nil || string(buf[:n]) != "XY" {
		t.Fatalf(
			"buffered Read = (%d, %q, %v), want (2, %q, nil)",
			n,
			buf[:n],
			err,
			"XY",
		)
	}

	n, err = conn.Read(buf)
	if n != 0 || !errors.Is(err, marker) {
		t.Fatalf("deferred Read = (%d, %v), want (0, marker)", n, err)
	}
}

func TestDelegatesNetConnMethods(t *testing.T) {
	raw := newMemoryConn("")
	conn := putback.New(raw, nil)

	if got := conn.LocalAddr().String(); got != "local" {
		t.Fatalf("LocalAddr = %q, want local", got)
	}
	if got := conn.RemoteAddr().String(); got != "remote" {
		t.Fatalf("RemoteAddr = %q, want remote", got)
	}
	if _, err := conn.Write([]byte("written")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := raw.writes.String(); got != "written" {
		t.Fatalf("underlying writes = %q, want written", got)
	}
	deadlines := [3]time.Time{
		time.Unix(1, 0),
		time.Unix(2, 0),
		time.Unix(3, 0),
	}
	if err := conn.SetDeadline(deadlines[0]); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(deadlines[1]); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(deadlines[2]); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if raw.deadlines != deadlines {
		t.Fatalf("underlying deadlines = %v, want %v", raw.deadlines, deadlines)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !raw.closed {
		t.Fatal("underlying connection was not closed")
	}
}

func TestNewPreservesTCPConnInterface(t *testing.T) {
	raw := newTCPMemoryConn("tail")
	conn := putback.New(raw, nil)

	if _, ok := conn.(putback.TCPConn); !ok {
		t.Fatalf("New returned %T, want putback.TCPConn", conn)
	}
	tcp, ok := conn.(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned %T, want gonnect.TCPConn", conn)
	}
	if got := conn.GetWrapped(); got != raw {
		t.Fatalf("GetWrapped = %T, want raw TCP connection", got)
	}

	conn.PutBack([]byte("head"))

	var out bytes.Buffer
	n, err := tcp.WriteTo(&out)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if want := "headtail"; out.String() != want {
		t.Fatalf("WriteTo output = %q, want %q", out.String(), want)
	}
	if n != int64(out.Len()) {
		t.Fatalf("WriteTo bytes = %d, want %d", n, out.Len())
	}
	if raw.writeToCalls != 1 {
		t.Fatalf("underlying WriteTo calls = %d, want 1", raw.writeToCalls)
	}
}

func TestTCPConnMethodsDelegateToUnderlying(t *testing.T) {
	raw := newTCPMemoryConn("")
	conn, ok := putback.New(raw, nil).(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned non-TCP wrapper")
	}

	n, err := conn.ReadFrom(bytes.NewBufferString("written"))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != int64(len("written")) {
		t.Fatalf("ReadFrom bytes = %d, want %d", n, len("written"))
	}
	if raw.readFromCalls != 1 {
		t.Fatalf("underlying ReadFrom calls = %d, want 1", raw.readFromCalls)
	}
	if got := raw.writes.String(); got != "written" {
		t.Fatalf("underlying writes = %q, want written", got)
	}

	if err := conn.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive: %v", err)
	}
	if err := conn.SetKeepAliveConfig(net.KeepAliveConfig{}); err != nil {
		t.Fatalf("SetKeepAliveConfig: %v", err)
	}
	if err := conn.SetKeepAlivePeriod(time.Second); err != nil {
		t.Fatalf("SetKeepAlivePeriod: %v", err)
	}
	if err := conn.SetLinger(10); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay: %v", err)
	}
	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	if !raw.keepAlive || raw.keepAliveConfigCalls != 1 ||
		raw.keepAlivePeriod != time.Second || raw.linger != 10 ||
		!raw.noDelay || raw.closeReadCalls != 1 ||
		raw.closeWriteCalls != 1 {
		t.Fatalf("TCP method delegation state = %#v", raw)
	}
}

func TestTCPWriteToStopsOnDeferredEOF(t *testing.T) {
	raw := &tcpBytesAndErrorConn{
		bytesAndErrorConn: &bytesAndErrorConn{
			data: []byte("tail"),
			err:  io.EOF,
		},
	}
	conn := putback.New(raw, nil)

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "tail" {
		t.Fatalf("Read bytes = %q, want tail", got)
	}

	conn.PutBack([]byte("head"))

	var out bytes.Buffer
	tcp, ok := conn.(gonnect.TCPConn)
	if !ok {
		t.Fatalf("New returned non-TCP wrapper")
	}
	written, err := tcp.WriteTo(&out)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if out.String() != "head" {
		t.Fatalf("WriteTo output = %q, want head", out.String())
	}
	if written != int64(len("head")) {
		t.Fatalf("WriteTo bytes = %d, want %d", written, len("head"))
	}
	if raw.writeToCalls != 0 {
		t.Fatalf("underlying WriteTo calls = %d, want 0", raw.writeToCalls)
	}
}

func TestNewPreservesStdlibTCPMethods(t *testing.T) {
	raw := &tcpSocketMemoryConn{tcpMemoryConn: newTCPMemoryConn("")}
	conn := putback.New(raw, nil)

	tcp, ok := conn.(interface {
		MultipathTCP() (bool, error)
		SetReadBuffer(bytes int) error
		SetWriteBuffer(bytes int) error
		SyscallConn() (syscall.RawConn, error)
		File() (*os.File, error)
	})
	if !ok {
		t.Fatalf("New returned %T, want stdlib TCP methods", conn)
	}

	mptcp, err := tcp.MultipathTCP()
	if err != nil {
		t.Fatalf("MultipathTCP: %v", err)
	}
	if !mptcp {
		t.Fatal("MultipathTCP = false, want true")
	}
	if err := tcp.SetReadBuffer(1024); err != nil {
		t.Fatalf("SetReadBuffer: %v", err)
	}
	if err := tcp.SetWriteBuffer(2048); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}
	if _, err := tcp.SyscallConn(); err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if _, err := tcp.File(); err != nil {
		t.Fatalf("File: %v", err)
	}

	if raw.multipathCalls != 1 || raw.readBuffer != 1024 ||
		raw.writeBuffer != 2048 || raw.syscallCalls != 1 ||
		raw.fileCalls != 1 {
		t.Fatalf("stdlib TCP delegation state = %#v", raw)
	}
}

func TestZeroLengthReadAndEmptyPutBackDoNotTouchUnderlying(t *testing.T) {
	raw := newMemoryConn("data")
	conn := putback.New(raw, nil)
	conn.PutBack(nil)

	n, err := conn.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if raw.readCalls != 0 {
		t.Fatalf("underlying Read calls = %d, want 0", raw.readCalls)
	}
}

func TestNewNilReturnsNil(t *testing.T) {
	if got := putback.New(nil, nil); got != nil {
		t.Fatalf("New(nil, nil) = %T, want nil", got)
	}
}
