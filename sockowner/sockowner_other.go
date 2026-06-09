//go:build !linux && !windows

package sockowner

func getSockOwner(_ FlowTuple) (*SocketOwner, error) {
	return nil, nil
}
