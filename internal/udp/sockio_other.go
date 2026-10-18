//go:build !linux && !darwin

package udp

import (
	"net"
	"syscall"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

// sockIO is one recvfrom and one sendto per datagram (Darwin, portable).
type sockIO struct {
	conn      *net.UDPConn
	rc        syscall.RawConn
	connected bool
	buf       []byte
	out       [1]rxPkt
}

func newSockIO(conn *net.UDPConn, connected bool) *sockIO {
	s := &sockIO{conn: conn, connected: connected, buf: make([]byte, frame.MaxDatagram)}
	if rc, err := conn.SyscallConn(); err == nil {
		s.rc = rc
	}
	return s
}

// read waits at most wait for one datagram. The slice and its bytes are
// valid until the next read.
//
// A wait of 0 is one non-blocking attempt: a deadline already passed makes
// Go return a timeout without reading, so a peer that always has work
// (WakeAt is now) would otherwise never see a queued datagram.
func (s *sockIO) read(wait time.Duration) ([]rxPkt, error) {
	if wait <= 0 {
		n, addr, err := readNow(s.conn, s.rc, s.buf)
		if err != nil || n < 0 {
			return nil, err
		}
		s.out[0] = rxPkt{b: s.buf[:n], addr: addr}
		return s.out[:], nil
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, errDeadline
	}
	n, addr, err := s.conn.ReadFromUDP(s.buf)
	if err != nil {
		return nil, err
	}
	s.out[0] = rxPkt{b: s.buf[:n], addr: addr}
	return s.out[:], nil
}

// write sends each datagram, to the connected peer or to to. A refused
// send is skipped, as an ICMP port unreachable is not authenticated.
func (s *sockIO) write(pkts [][]byte, to *net.UDPAddr) error {
	for _, p := range pkts {
		var err error
		if s.connected {
			_, err = s.conn.Write(p)
		} else {
			_, err = s.conn.WriteToUDP(p, to)
		}
		if err != nil && !refused(err) {
			return err
		}
	}
	return nil
}
