//go:build windows

package sockowner

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestFindWindowsUDP4OwnerPIDAmbiguous(t *testing.T) {
	localIP := net.IPv4(192, 0, 2, 10)
	flow := FlowTuple{
		Proto:     "udp",
		LocalIP:   localIP,
		LocalPort: 5353,
		RemoteIP:  net.IPv4(198, 51, 100, 20),
	}

	rows := []mibUDPRowOwnerPID{
		{
			LocalAddr: binary.LittleEndian.Uint32(localIP.To4()),
			LocalPort: windowsTestPort(5353),
			OwningPID: 100,
		},
		{
			LocalAddr: binary.LittleEndian.Uint32(localIP.To4()),
			LocalPort: windowsTestPort(5353),
			OwningPID: 200,
		},
	}

	if _, err := findWindowsUDP4OwnerPID(flow, rows); !errors.Is(err, ErrAUW) {
		t.Fatalf("findWindowsUDP4OwnerPID() err = %v, want %v", err, ErrAUW)
	}
}

func TestFindWindowsUDP4OwnerPIDAllowsDuplicateRowsForSameOwner(t *testing.T) {
	localIP := net.IPv4(192, 0, 2, 10)
	flow := FlowTuple{
		Proto:     "udp",
		LocalIP:   localIP,
		LocalPort: 5353,
		RemoteIP:  net.IPv4(198, 51, 100, 20),
	}

	rows := []mibUDPRowOwnerPID{
		{
			LocalAddr: binary.LittleEndian.Uint32(localIP.To4()),
			LocalPort: windowsTestPort(5353),
			OwningPID: 100,
		},
		{
			LocalAddr: binary.LittleEndian.Uint32(localIP.To4()),
			LocalPort: windowsTestPort(5353),
			OwningPID: 100,
		},
	}

	pid, err := findWindowsUDP4OwnerPID(flow, rows)
	if err != nil {
		t.Fatalf("findWindowsUDP4OwnerPID() err = %v", err)
	}
	if pid != 100 {
		t.Fatalf("findWindowsUDP4OwnerPID() pid = %d, want 100", pid)
	}
}

func TestFindWindowsUDP6OwnerPIDAmbiguous(t *testing.T) {
	localIP := net.ParseIP("2001:db8::10")
	flow := FlowTuple{
		Proto:     "udp",
		LocalIP:   localIP,
		LocalPort: 5353,
		RemoteIP:  net.ParseIP("2001:db8::20"),
	}

	rows := []mibUDP6RowOwnerPID{
		{
			LocalAddr: ip16Array(localIP),
			LocalPort: windowsTestPort(5353),
			OwningPID: 100,
		},
		{
			LocalAddr: ip16Array(localIP),
			LocalPort: windowsTestPort(5353),
			OwningPID: 200,
		},
	}

	if _, err := findWindowsUDP6OwnerPID(flow, rows); !errors.Is(err, ErrAUW) {
		t.Fatalf("findWindowsUDP6OwnerPID() err = %v, want %v", err, ErrAUW)
	}
}

func windowsTestPort(port uint16) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint16(b[:2], port)

	return binary.LittleEndian.Uint32(b[:])
}
