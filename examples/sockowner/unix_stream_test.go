//go:build unix

package main

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestHandleUnixStreamConnWritesReport(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleUnixStreamConn(server)
	}()

	if _, err := client.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	data, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	<-done

	got := string(data)
	if !strings.Contains(got, `"transport": "unix/stream"`) ||
		!strings.Contains(got, `"payload_len": 5`) {
		t.Fatalf("handleUnixStreamConn() wrote %q, want stream report", got)
	}
}

func TestHandleUnixStreamConnEmptyRead(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleUnixStreamConn(server)
	}()

	_ = client.Close()
	<-done
}
