package sniffer_test

import (
	"fmt"
	"net"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/putback"
	"github.com/asciimoth/gonnect/sniffer"
)

func closeExampleConn(conn net.Conn) {
	_ = conn.Close()
}

// ExampleSniff shows routing by a client-first prefix. A real server would wrap
// the net.Conn returned by Accept and set its own classification deadline.
func ExampleSniff() {
	server, client := net.Pipe()
	defer closeExampleConn(server)
	defer closeExampleConn(client)

	go func() {
		_, _ = client.Write([]byte("SSH-2.0-example\r\n"))
	}()

	var pool bufpool.Pool
	conn := putback.New(server, pool)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	factories := []sniffer.Factory{
		sniffer.PrefixFactory([]byte("GET ")),
		sniffer.SSHFactory(),
	}
	index, err := sniffer.SniffFactoriesWithPool(
		sniffer.MinFactorySniffBufferSize(factories...),
		pool,
		conn,
		factories...,
	)
	_ = conn.SetReadDeadline(time.Time{})

	fmt.Println(index, err)

	// Output:
	// 1 <nil>
}

// ExampleSniff_chain shows that a no-match result does not consume the stream.
func ExampleSniff_chain() {
	server, client := net.Pipe()
	defer closeExampleConn(server)
	defer closeExampleConn(client)

	go func() {
		_, _ = client.Write([]byte("SSH-2.0-example\r\n"))
	}()

	var pool bufpool.Pool
	conn := putback.New(server, pool)
	first, _ := sniffer.SniffWithPool(
		8,
		pool,
		conn,
		sniffer.Prefix([]byte{0x16, 0x03}), // simple TLS record prefix
	)
	second, _ := sniffer.SniffWithPool(4, pool, conn, sniffer.SSH())

	fmt.Println(first == sniffer.NoMatch, second)

	// Output:
	// true 0
}

// ExampleSniff_timeoutFallback shows how callers can turn a classification
// timeout into a fallback route while returning other read errors.
func ExampleSniff_timeoutFallback() {
	server, client := net.Pipe()
	defer closeExampleConn(server)
	defer closeExampleConn(client)

	var pool bufpool.Pool
	conn := putback.New(server, pool)
	_ = conn.SetReadDeadline(time.Now().Add(-time.Nanosecond))
	index, err := sniffer.SniffWithPool(64, pool, conn, sniffer.SSH())
	_ = conn.SetReadDeadline(time.Time{})

	fmt.Println(index == sniffer.NoMatch, gonnect.IsTimeout(err))

	// Output:
	// true true
}
