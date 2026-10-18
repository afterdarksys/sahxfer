//go:build !linux && !darwin

package udp

import (
	"net"
	"syscall"
	"time"
)

// readNow waits at most 100 µs: this build has no non-blocking recvfrom
// here, and a deadline already passed would not read at all.
func readNow(conn *net.UDPConn, _ syscall.RawConn, buf []byte) (int, *net.UDPAddr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Microsecond)); err != nil {
		return -1, nil, errDeadline
	}
	n, addr, err := conn.ReadFromUDP(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return -1, nil, nil
	}
	return n, addr, err
}
