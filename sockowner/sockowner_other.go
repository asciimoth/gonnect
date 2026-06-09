//go:build !linux

package sockowner

func getSockOwner(_ FlowTuple) (*SocketOwner, error) {
	return nil, nil
}
