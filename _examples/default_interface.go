//go:build ignore

package main

import (
	"context"
	"fmt"

	"github.com/asciimoth/gonnect/defnet"
	"github.com/asciimoth/gonnect/helpers"
)

func main() {
	ifc, err := helpers.DefaultInterface(
		context.Background(),
		defnet.DefaultNetwork(nil),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("ID:", ifc.ID())
	fmt.Println("Index:", ifc.Index())
	fmt.Println("Name:", ifc.Name())
	fmt.Println("MTU:", ifc.MTU())
	fmt.Println("hardwareAddr:", ifc.HardwareAddr())
	fmt.Println("Flags:", ifc.Flags())
	addrs, err := ifc.Addrs()
	if err != nil {
		panic(err)
	}
	fmt.Println("Addrs:", addrs)
	maddrs, err := ifc.MulticastAddrs()
	if err != nil {
		panic(err)
	}
	fmt.Println("MulticastAddrs:", maddrs)
}
