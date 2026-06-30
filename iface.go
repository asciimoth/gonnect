package gonnect

import (
	"net"
	"strconv"
	"sync"
)

var (
	_ NetworkInterface = &NativeInterface{}
	_ NetworkInterface = &LiteralInterface{}
)

type NetworkInterface interface {
	ID() string
	Index() int
	Name() string
	MTU() int
	HardwareAddr() net.HardwareAddr
	Flags() net.Flags
	Addrs() ([]net.Addr, error)
	MulticastAddrs() ([]net.Addr, error)
}

// Spawner should be used instead of spawning goroutines directly with the go
// keyword or using waitgroups directly for long-running tasks or tasks whose
// lifecycle is worth logging or tracking.
//
// Spawner should not be used to track short-lived goroutines like ones spawned
// only to drain a channel.
//
// Spawner should always be passed to code directly as a function or method
// argument, or as a struct field. There should not be a global spawner.
//
// A passed Spawner instance may be nil. In that case direct spawning should be
// used instead.
type Spawner interface {
	// Spawn runs worker in a new goroutine.
	// It returns worker id (only some implementations support it) and error.
	// Name is optional worker metadata. Pass an empty string for unnamed workers.
	Spawn(worker func(), name string) (uint64, error)

	// SpawnWg runs worker in a new goroutine and also tracks it in waitgroup.
	// It returns worker id (only some implementations support it) and error.
	// Name is optional worker metadata. Pass an empty string for unnamed workers.
	SpawnWg(
		worker func(),
		waitgroup *sync.WaitGroup,
		name string,
	) (uint64, error)
}

func WrapNativeInterfaces(in []net.Interface) []NetworkInterface {
	if in == nil {
		return nil
	}
	ret := make([]NetworkInterface, 0, len(in))
	for _, i := range in {
		ret = append(ret, &NativeInterface{Iface: i})
	}
	return ret
}

type NativeInterface struct {
	Iface net.Interface
}

func (i *NativeInterface) ID() string {
	return "native:" + i.Iface.Name + ":" + strconv.Itoa(i.Iface.Index)
}

func (i *NativeInterface) Index() int {
	return i.Iface.Index
}

func (i *NativeInterface) Name() string {
	return i.Iface.Name
}

func (i *NativeInterface) MTU() int {
	return i.Iface.MTU
}

func (i *NativeInterface) HardwareAddr() net.HardwareAddr {
	return i.Iface.HardwareAddr
}

func (i *NativeInterface) Flags() net.Flags {
	return i.Iface.Flags
}

func (i *NativeInterface) Addrs() ([]net.Addr, error) {
	return i.Iface.Addrs()
}

func (i *NativeInterface) MulticastAddrs() ([]net.Addr, error) {
	return i.Iface.MulticastAddrs()
}

type LiteralInterface struct {
	IDVal             string
	IndexVal          int
	NameVal           string
	MTUVal            int
	HardwareAddrVal   net.HardwareAddr
	FlagsVal          net.Flags
	AddrsVal          []net.Addr
	MulticastAddrsVal []net.Addr
}

func (i *LiteralInterface) ID() string {
	return i.IDVal
}

func (i *LiteralInterface) Index() int {
	return i.IndexVal
}

func (i *LiteralInterface) Name() string {
	return i.NameVal
}

func (i *LiteralInterface) MTU() int {
	return i.MTUVal
}

func (i *LiteralInterface) HardwareAddr() net.HardwareAddr {
	return i.HardwareAddrVal
}

func (i *LiteralInterface) Flags() net.Flags {
	return i.FlagsVal
}

func (i *LiteralInterface) Addrs() ([]net.Addr, error) {
	addrs := i.AddrsVal
	if addrs == nil {
		addrs = make([]net.Addr, 0)
	}
	return addrs, nil
}

func (i *LiteralInterface) MulticastAddrs() ([]net.Addr, error) {
	addrs := i.MulticastAddrsVal
	if addrs == nil {
		addrs = make([]net.Addr, 0)
	}
	return addrs, nil
}
