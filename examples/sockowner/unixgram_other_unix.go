//go:build unix && !linux

package main

func runUnixgramServer(_ []string) {
	fatalf("unixgram credential demo is only implemented on Linux")
}

func runUnixgramClient(_ []string) {
	fatalf("unixgram credential demo is only implemented on Linux")
}
