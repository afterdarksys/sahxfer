//go:build !darwin && !linux

package udp

import "net"

// TuneBuffers asks for want bytes in each direction. Without getsockopt
// here, the granted sizes are reported as 0 (unknown).
func TuneBuffers(conn *net.UDPConn, want int) (rcv, snd int) {
	if conn != nil {
		_ = conn.SetReadBuffer(want)
		_ = conn.SetWriteBuffer(want)
	}
	return 0, 0
}

// usableRcv is the granted receive buffer as data bytes.
func usableRcv(n int) int { return n }
