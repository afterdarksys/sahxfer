//go:build darwin || linux

package udp

import (
	"net"

	"golang.org/x/sys/unix"
)

// TuneBuffers asks for want bytes of SO_RCVBUF and SO_SNDBUF, halving a
// refused size down to 64 KiB, and returns the sizes getsockopt reports.
// Linux caps the request at net.core.rmem_max / wmem_max without an error
// and reports twice what it allows for data; Darwin refuses a size above
// kern.ipc.maxsockbuf with ENOBUFS. A size it cannot read back is 0.
// docs/design.md section 7.4.
func TuneBuffers(conn *net.UDPConn, want int) (rcv, snd int) {
	if conn == nil {
		return 0, 0
	}
	for n := want; n >= 64<<10; n /= 2 {
		if conn.SetReadBuffer(n) == nil {
			break
		}
	}
	for n := want; n >= 64<<10; n /= 2 {
		if conn.SetWriteBuffer(n) == nil {
			break
		}
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0
	}
	_ = rc.Control(func(fd uintptr) {
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			rcv = v
		}
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			snd = v
		}
	})
	return rcv, snd
}
