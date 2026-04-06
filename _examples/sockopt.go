//go:build ignore

package main

import (
	"fmt"
	"net"

	"github.com/asciimoth/gonnect/sockopt"
)

func main() {
	fmt.Println(sockopt.CheckSupport())

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(l)

	fmt.Println("Bufsize:")
	fmt.Println(sockopt.GetBuffSize(l))
	fmt.Println(sockopt.SetBufSize(l, 65555))
	fmt.Println(sockopt.GetBuffSize(l))

	fmt.Println("Rmark:")
	fmt.Println(sockopt.GetRoutingMark(l))
	fmt.Println(sockopt.SetRoutingMark(l, 42))
	fmt.Println(sockopt.GetRoutingMark(l))

	fmt.Println("Unsupported operation:")
	rtt, err := sockopt.GetTCPRTT(l)
	fmt.Println(rtt, err)
	fmt.Println(rtt, sockopt.IgnoreUnsupported(err))
}
