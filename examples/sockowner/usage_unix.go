//go:build unix

package main

import "fmt"

func unixUsage(exe string) string {
	return fmt.Sprintf(`
  %[1]s unix-stream-server   [-path /tmp/sockowner-stream.sock]
  %[1]s unix-stream-client   [-path /tmp/sockowner-stream.sock] [-msg ping]

  %[1]s unixgram-server      [-path /tmp/sockowner-dgram.sock]
  %[1]s unixgram-client      [-path /tmp/sockowner-dgram.sock] [-msg ping]`, exe)
}

func unixUsageNotes() string {
	return `
  - Unix stream owner lookup uses platform peer credential support through
    sockowner.GetIncomingConnOwner. This is currently implemented on Linux.
  - Unix datagram owner lookup uses Linux SO_PASSCRED + SCM_CREDENTIALS.`
}
