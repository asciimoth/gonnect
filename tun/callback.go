package tun

// CallbackTUN wraps a Tun interface adding callbacks for read and write operations.
type CallbackTUN struct {
	Tun
	OnRead  func(n int, err error)
	OnWrite func(n int, err error)
}

func (t *CallbackTUN) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (n int, err error) {
	n, err = t.Tun.Read(bufs, sizes, offset)
	t.OnRead(n, err)
	return
}

func (t *CallbackTUN) Write(bufs [][]byte, offset int) (n int, err error) {
	n, err = t.Tun.Write(bufs, offset)
	t.OnWrite(n, err)
	return
}
