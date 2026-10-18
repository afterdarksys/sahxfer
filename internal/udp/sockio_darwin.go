package udp

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"golang.org/x/sys/unix"
)

// batchLen is the most datagrams one recvmsg_x or sendmsg_x moves.
const batchLen = 32

// XNU syscall numbers for the batched socket calls. They are not in the
// userland SDK's sys/syscall.h as a stable API, but the numbers are the BSD
// syscall numbers XNU assigns (unified across amd64 and arm64) and are
// confirmed against the MacOSX SDK on this toolchain. sockio_darwin_test.go
// pins the struct layout these depend on.
const (
	sysRecvmsgX = 480
	sysSendmsgX = 481
)

// msghdrX is struct msghdr_x from XNU bsd/sys/socket.h: a classic msghdr
// plus a trailing msg_datalen (size_t), the per-datagram byte count. socklen_t
// is uint32 and C int is int32, so the pads below mirror what C inserts on
// LP64. recvmsg_x writes each datagram's length into Datalen (and its source
// into Name/Namelen on an unconnected socket); sendmsg_x reads Datalen as the
// iov total. Expected size 56, offsets 0/8/16/24/32/40/44/48; the test asserts
// it, because a wrong offset corrupts the batch silently.
type msghdrX struct {
	Name       *byte
	Namelen    uint32
	_          [4]byte
	Iov        *unix.Iovec
	Iovlen     int32
	_          [4]byte
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

// sockIO batches with recvmsg_x and sendmsg_x, the Darwin analogs of Linux
// recvmmsg/sendmmsg (docs/design.md section 7.4). Both wait through the
// netpoller, so read deadlines hold as for ReadFrom. macOS has no UDP
// segmentation offload (no UDP_SEGMENT/UDP_GRO), so this syscall-batching is
// the ceiling here; it still cuts one syscall per datagram to one per batch.
//
// recvmsg_x returns only the datagrams already queued, not a full batch, so a
// call may return fewer than batchLen (even one) with more still arriving.
// That is fine: read returns what it got and the run loop reads again.
type sockIO struct {
	conn      *net.UDPConn
	rc        syscall.RawConn
	connected bool
	family    int

	rbufs  [batchLen][]byte
	rmsgs  [batchLen]msghdrX
	riovs  [batchLen]unix.Iovec
	rnames [batchLen]unix.RawSockaddrAny
	out    [batchLen]rxPkt

	wmsgs []msghdrX
	wiovs []unix.Iovec
	// wname is the encoded destination of an unconnected socket, cached
	// for the address it was built for.
	wname  unix.RawSockaddrAny
	wlen   uint32
	wfor   string
	wready bool
}

func newSockIO(conn *net.UDPConn, connected bool) *sockIO {
	s := &sockIO{conn: conn, connected: connected, family: unix.AF_INET6}
	rc, err := conn.SyscallConn()
	if err == nil {
		s.rc = rc
		_ = rc.Control(func(fd uintptr) {
			if sa, err := unix.Getsockname(int(fd)); err == nil {
				if _, ok := sa.(*unix.SockaddrInet4); ok {
					s.family = unix.AF_INET
				}
			}
		})
	}
	for i := range s.rbufs {
		s.rbufs[i] = make([]byte, frame.MaxDatagram)
		s.riovs[i].Base = &s.rbufs[i][0]
		s.riovs[i].SetLen(frame.MaxDatagram)
	}
	return s
}

// read waits at most wait, then takes up to batchLen datagrams in one
// recvmsg_x. The slices are valid until the next read.
func (s *sockIO) read(wait time.Duration) ([]rxPkt, error) {
	if s.rc == nil {
		return nil, errDeadline
	}
	// A wait of 0 is one non-blocking attempt: a deadline already passed
	// makes Go return a timeout without calling recvmsg_x at all.
	now := wait <= 0
	dl := time.Now().Add(wait)
	if now {
		dl = time.Time{}
	}
	if err := s.conn.SetReadDeadline(dl); err != nil {
		return nil, errDeadline
	}
	for i := range s.rmsgs {
		s.rmsgs[i] = msghdrX{Iov: &s.riovs[i], Iovlen: 1}
		if !s.connected {
			s.rmsgs[i].Name = (*byte)(unsafe.Pointer(&s.rnames[i]))
			s.rmsgs[i].Namelen = uint32(unsafe.Sizeof(s.rnames[i]))
		}
	}
	var got int
	var serr error
	err := s.rc.Read(func(fd uintptr) bool {
		r, _, e := unix.Syscall6(sysRecvmsgX, fd, uintptr(unsafe.Pointer(&s.rmsgs[0])), batchLen, unix.MSG_DONTWAIT, 0, 0)
		for e == unix.EINTR {
			r, _, e = unix.Syscall6(sysRecvmsgX, fd, uintptr(unsafe.Pointer(&s.rmsgs[0])), batchLen, unix.MSG_DONTWAIT, 0, 0)
		}
		if e == unix.EAGAIN {
			return now
		}
		if e != 0 {
			serr = e
			return true
		}
		got = int(r)
		return true
	})
	if err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	out := s.out[:0]
	for i := 0; i < got; i++ {
		p := rxPkt{b: s.rbufs[i][:s.rmsgs[i].Datalen]}
		if !s.connected {
			p.addr = decodeName(&s.rnames[i])
		}
		out = append(out, p)
	}
	return out, nil
}

// write sends pkts with sendmsg_x, retrying the rest of a partial send. A
// datagram refused by an ICMP port unreachable is skipped, as before.
func (s *sockIO) write(pkts [][]byte, to *net.UDPAddr) error {
	if len(pkts) == 0 {
		return nil
	}
	if s.rc == nil {
		return errDeadline
	}
	if !s.connected {
		if to == nil {
			return errors.New("udp: no destination")
		}
		if !s.wready || s.wfor != to.String() {
			if !s.encodeName(to) {
				return errors.New("udp: bad destination")
			}
		}
	}
	for len(pkts) > 0 {
		n := len(pkts)
		if n > batchLen {
			n = batchLen
		}
		if err := s.writeBatch(pkts[:n]); err != nil {
			return err
		}
		pkts = pkts[n:]
	}
	return nil
}

func (s *sockIO) writeBatch(pkts [][]byte) error {
	if cap(s.wmsgs) < len(pkts) {
		s.wmsgs = make([]msghdrX, batchLen)
		s.wiovs = make([]unix.Iovec, batchLen)
	}
	msgs := s.wmsgs[:len(pkts)]
	iovs := s.wiovs[:len(pkts)]
	for i, p := range pkts {
		iovs[i] = unix.Iovec{Base: &p[0]}
		iovs[i].SetLen(len(p))
		msgs[i] = msghdrX{Iov: &iovs[i], Iovlen: 1, Datalen: uint64(len(p))}
		if !s.connected {
			msgs[i].Name = (*byte)(unsafe.Pointer(&s.wname))
			msgs[i].Namelen = s.wlen
		}
	}
	sent := 0
	var serr error
	err := s.rc.Write(func(fd uintptr) bool {
		for sent < len(msgs) {
			r, _, e := unix.Syscall6(sysSendmsgX, fd, uintptr(unsafe.Pointer(&msgs[sent])), uintptr(len(msgs)-sent), unix.MSG_DONTWAIT, 0, 0)
			switch {
			case e == unix.EAGAIN:
				return false
			case e == unix.EINTR:
				continue
			case e == unix.ECONNREFUSED:
				// The kernel reports a queued ICMP error on the next send;
				// that datagram did not leave. Skip it, as a sendto loop does.
				sent++
				continue
			case e != 0:
				serr = e
				return true
			}
			sent += int(r)
		}
		return true
	})
	for i := range iovs {
		iovs[i].Base = nil
	}
	if err != nil {
		return err
	}
	return serr
}

func (s *sockIO) encodeName(to *net.UDPAddr) bool {
	s.wname = unix.RawSockaddrAny{}
	if s.family == unix.AF_INET {
		ip4 := to.IP.To4()
		if ip4 == nil {
			return false
		}
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&s.wname))
		sa.Family = unix.AF_INET
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(to.Port))
		copy(sa.Addr[:], ip4)
		s.wlen = unix.SizeofSockaddrInet4
	} else {
		ip16 := to.IP.To16()
		if ip16 == nil {
			return false
		}
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&s.wname))
		sa.Family = unix.AF_INET6
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:], uint16(to.Port))
		copy(sa.Addr[:], ip16)
		if to.Zone != "" {
			if ifi, err := net.InterfaceByName(to.Zone); err == nil {
				sa.Scope_id = uint32(ifi.Index)
			}
		}
		s.wlen = unix.SizeofSockaddrInet6
	}
	s.wfor = to.String()
	s.wready = true
	return true
}

func decodeName(rsa *unix.RawSockaddrAny) *net.UDPAddr {
	switch rsa.Addr.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		return &net.UDPAddr{IP: net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]), Port: int(port)}
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		a := &net.UDPAddr{IP: append(net.IP(nil), sa.Addr[:]...), Port: int(port)}
		if sa.Scope_id != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.Scope_id)); err == nil {
				a.Zone = ifi.Name
			}
		}
		return a
	}
	return nil
}
