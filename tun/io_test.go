// nolint
package tun_test

import (
	"io"
	"testing"

	"github.com/asciimoth/gonnect/tun"
)

// Verify IO implements io.ReadWriteCloser at compile time
var _ io.ReadWriteCloser = (*tun.IO)(nil)

func TestIOBasic(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	defer tun1.Close()
	defer tun2.Close()

	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)
	defer io1.Close()
	defer io2.Close()

	// Verify non-nil
	if io1 == nil || io2 == nil {
		t.Fatal("NewIO() returned nil")
	}
}

func TestIOReadWrite(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	defer tun1.Close()
	defer tun2.Close()

	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)
	defer io1.Close()
	defer io2.Close()

	// Test io1 -> io2
	data1 := []byte{0x01, 0x02, 0x03, 0x04}
	n, err := io1.Write(data1)
	if err != nil {
		t.Fatalf("io1.Write() error: %v", err)
	}
	if n != len(data1) {
		t.Errorf("io1.Write() returned n=%d, want %d", n, len(data1))
	}

	buf2 := make([]byte, 100)
	n, err = io2.Read(buf2)
	if err != nil {
		t.Fatalf("io2.Read() error: %v", err)
	}
	if n != len(data1) {
		t.Errorf("io2.Read() returned n=%d, want %d", n, len(data1))
	}
	if string(buf2[:n]) != string(data1) {
		t.Errorf("io2.Read() data=%q, want %q", buf2[:n], data1)
	}

	// Test io2 -> io1
	data2 := []byte{0x05, 0x06, 0x07}
	n, err = io2.Write(data2)
	if err != nil {
		t.Fatalf("io2.Write() error: %v", err)
	}
	if n != len(data2) {
		t.Errorf("io2.Write() returned n=%d, want %d", n, len(data2))
	}

	buf1 := make([]byte, 100)
	n, err = io1.Read(buf1)
	if err != nil {
		t.Fatalf("io1.Read() error: %v", err)
	}
	if n != len(data2) {
		t.Errorf("io1.Read() returned n=%d, want %d", n, len(data2))
	}
	if string(buf1[:n]) != string(data2) {
		t.Errorf("io1.Read() data=%q, want %q", buf1[:n], data2)
	}
}

func TestIOClose(t *testing.T) {
	t.Parallel()

	tun1, _ := tun.Pipe(1, 1500, 0, 0)
	io1 := tun.NewIO(tun1)

	// Close via IO
	err := io1.Close()
	if err != nil {
		t.Fatalf("IO.Close() error: %v", err)
	}

	// Double close should be OK (underlying pipeTun handles it)
	err = io1.Close()
	if err != nil {
		t.Errorf("Double IO.Close() error: %v", err)
	}
}

func TestIOReadOnClosed(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)

	// Close both ends
	io1.Close()
	io2.Close()

	// Read on closed IO should return an error
	buf := make([]byte, 100)
	_, err := io2.Read(buf)
	if err == nil {
		t.Error("Expected error reading from closed IO")
	}
}

func TestIOWriteOnClosed(t *testing.T) {
	t.Parallel()

	tun1, _ := tun.Pipe(1, 1500, 0, 0)
	io1 := tun.NewIO(tun1)

	io1.Close()

	// Write on closed IO should return an error
	_, err := io1.Write([]byte{0x01})
	if err == nil {
		t.Error("Expected error writing to closed IO")
	}
}

func TestIOReadEOF(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)

	// Close the writer side (tun1)
	io1.Close()

	// Read should return an error when the other end is closed
	buf := make([]byte, 100)
	_, err := io2.Read(buf)
	if err == nil {
		t.Error("Expected error reading from closed IO")
	}
}

func TestIOWriteZeroLength(t *testing.T) {
	t.Parallel()

	tun1, tun2 := tun.Pipe(1, 1500, 0, 0)
	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)
	defer io1.Close()
	defer io2.Close()

	// Write empty slice
	n, err := io1.Write([]byte{})
	if err != nil {
		t.Fatalf("IO.Write([]byte{}) error: %v", err)
	}
	if n != 0 {
		t.Errorf("IO.Write([]byte{}) returned n=%d, want 0", n)
	}
}

func TestIOLargePacket(t *testing.T) {
	t.Parallel()

	const mtu = 9000
	tun1, tun2 := tun.Pipe(1, mtu, 0, 0)
	io1 := tun.NewIO(tun1)
	io2 := tun.NewIO(tun2)
	defer io1.Close()
	defer io2.Close()

	// Write a large packet
	data := make([]byte, mtu)
	for i := range data {
		data[i] = byte(i % 256)
	}

	n, err := io1.Write(data)
	if err != nil {
		t.Fatalf("IO.Write() error: %v", err)
	}
	if n != len(data) {
		t.Errorf("IO.Write() returned n=%d, want %d", n, len(data))
	}

	buf := make([]byte, mtu)
	n, err = io2.Read(buf)
	if err != nil {
		t.Fatalf("IO.Read() error: %v", err)
	}
	if n != len(data) {
		t.Errorf("IO.Read() returned n=%d, want %d", n, len(data))
	}
	if string(buf[:n]) != string(data) {
		t.Error("Data mismatch")
	}
}

func TestIOWithDifferentBatchSizes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		batch int
	}{
		{"BatchSize1", 1},
		{"BatchSize4", 4},
		{"BatchSize16", 16},
		{"BatchSize64", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for mwo := range 10 {
				for mro := range 10 {
					tun1, tun2 := tun.Pipe(tc.batch, 1500, mwo, mro)
					io1 := tun.NewIO(tun1)
					io2 := tun.NewIO(tun2)
					defer io1.Close()
					defer io2.Close()

					// Write and read multiple packets
					for i := range 10 {
						data := []byte{byte(i), byte(i + 1), byte(i + 2)}

						n, err := io1.Write(data)
						if err != nil {
							t.Fatalf("IO.Write() error: %v", err)
						}
						if n != len(data) {
							t.Errorf(
								"IO.Write() returned n=%d, want %d",
								n,
								len(data),
							)
						}

						buf := make([]byte, 100)
						n, err = io2.Read(buf)
						if err != nil {
							t.Fatalf("IO.Read() error: %v", err)
						}
						if n != len(data) {
							t.Errorf(
								"IO.Read() returned n=%d, want %d",
								n,
								len(data),
							)
						}
						if string(buf[:n]) != string(data) {
							t.Errorf(
								"Data mismatch: got %q, want %q",
								buf[:n],
								data,
							)
						}
					}
				}
			}
		})
	}
}
