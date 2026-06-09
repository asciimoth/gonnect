//go:build !unix

package main

func runUnixStreamServer(_ []string) {
	fatalf("unix stream demo is only available on Unix platforms")
}

func runUnixStreamClient(_ []string) {
	fatalf("unix stream demo is only available on Unix platforms")
}

func runUnixgramServer(_ []string) {
	fatalf("unixgram credential demo is only available on Linux")
}

func runUnixgramClient(_ []string) {
	fatalf("unixgram credential demo is only available on Linux")
}
