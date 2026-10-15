// Package relay forwards sealed datagrams for admitted grants.
//
// Threats: a third source, a wrong route token, a byte cap, and a held
// datagram older than one second. The relay does not have the AEAD key,
// does not decrypt, does not log the token, and does not rewrite seq or
// offset. Quiet drops do not report. A forgotten grant can be admitted again.
// expires uses the same clock as Handle. Serve passes unix time in nanoseconds.
package relay

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

const holdFor = time.Second

// Datagram is one forwarded packet. To is the pinned peer address.
type Datagram struct {
	To   string
	Data []byte
}

type slot struct {
	addr string
	hold []byte
	born time.Duration
	held bool
}

type flow struct {
	token   [seal.TokenSize]byte
	cap     uint64
	used    uint64
	expires time.Duration
	fails   int
	a, b    slot
}

// Relay is an in-memory admission table. Serve binds it to one socket.
type Relay struct {
	mu    sync.Mutex
	flows map[uint64]*flow
}

// New returns an empty relay.
func New() *Relay {
	return &Relay{flows: make(map[uint64]*flow)}
}

func (r *Relay) init() {
	if r.flows == nil {
		r.flows = make(map[uint64]*flow)
	}
}

// Admit copies the route token. The caller may wipe token after Admit returns.
// A live id returns exists and is not replaced. expires is an absolute time
// on the clock passed to Handle.
func (r *Relay) Admit(id uint64, token []byte, byteCap uint64, expires time.Duration) error {
	if r == nil || id == 0 || len(token) != seal.TokenSize {
		return code.New("bad_grant")
	}
	var tok [seal.TokenSize]byte
	copy(tok[:], token)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	if _, ok := r.flows[id]; ok {
		return code.New("exists")
	}
	r.flows[id] = &flow{token: tok, cap: byteCap, expires: expires}
	return nil
}

// Handle classifies one datagram. report is "auth" or "byte_cap", or empty.
// A quiet drop returns id 0. The returned bytes are copies.
func (r *Relay) Handle(now time.Duration, from string, dgram []byte) (outs []Datagram, report string, id uint64) {
	if r == nil {
		return nil, "", 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	h, err := frame.Peek(dgram)
	if err != nil || h.Version != frame.Version || !frame.LengthOK(dgram, h) {
		return nil, "", 0
	}
	f := r.flows[h.TransferID]
	if f == nil {
		return nil, "", 0
	}
	id = h.TransferID
	if now >= f.expires {
		delete(r.flows, id)
		return nil, "", id
	}
	if !seal.TokenEqual(h.RouteToken[:], f.token[:]) {
		f.fails++
		if f.fails >= seal.AuthBudget {
			delete(r.flows, id)
			return nil, "auth", id
		}
		return nil, "", id
	}
	me, other, just, ok := f.pin(from)
	if !ok {
		return nil, "", id
	}
	if other.addr == "" {
		if me.held {
			return nil, "", id
		}
		if f.charge(h) {
			delete(r.flows, id)
			return nil, "byte_cap", id
		}
		me.hold = append([]byte(nil), dgram...)
		me.born = now
		me.held = true
		return nil, "", id
	}
	if f.charge(h) {
		delete(r.flows, id)
		return nil, "byte_cap", id
	}
	outs = []Datagram{{To: other.addr, Data: append([]byte(nil), dgram...)}}
	if just && other.held {
		if now <= other.born+holdFor {
			outs = append(outs, Datagram{To: from, Data: other.hold})
		}
		other.hold = nil
		other.held = false
	}
	return outs, "", id
}

func (f *flow) pin(from string) (me, other *slot, just, ok bool) {
	if from == "" {
		return nil, nil, false, false
	}
	switch {
	case f.a.addr == from:
		return &f.a, &f.b, false, true
	case f.b.addr == from:
		return &f.b, &f.a, false, true
	case f.a.addr == "":
		f.a.addr = from
		return &f.a, &f.b, true, true
	case f.b.addr == "":
		f.b.addr = from
		return &f.b, &f.a, true, true
	default:
		return nil, nil, false, false
	}
}

// charge counts DATA plaintext, including retransmits. A zero length does
// not trip. A wrap or a cap breach trips and does not add.
func (f *flow) charge(h frame.Header) bool {
	if h.Type != frame.TypeDATA {
		return false
	}
	n := h.PayloadLen
	if f.used+n < f.used || f.used+n > f.cap {
		return true
	}
	f.used += n
	return false
}

// Serve reads the socket until ctx is done. A done context returns nil.
// Write errors are ignored. report receives auth and byte_cap only.
func (r *Relay) Serve(ctx context.Context, conn *net.UDPConn, report func(id uint64, code string)) error {
	if r == nil || conn == nil {
		return code.New("internal")
	}
	buf := make([]byte, frame.MaxDatagram)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return code.New("io")
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return code.New("io")
		}
		if n == 0 || addr == nil {
			continue
		}
		now := time.Duration(time.Now().UnixNano())
		outs, rep, id := r.Handle(now, addr.String(), buf[:n])
		if rep != "" && report != nil {
			report(id, rep)
		}
		for _, o := range outs {
			ua, rerr := net.ResolveUDPAddr("udp", o.To)
			if rerr != nil {
				continue
			}
			_, _ = conn.WriteToUDP(o.Data, ua)
		}
	}
}
