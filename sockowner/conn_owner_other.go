//go:build !linux

package sockowner

import "net"

func getIncomingUnixPeerOwner(_ net.Conn) (*SocketOwner, error) {
	return nil, nil
}
