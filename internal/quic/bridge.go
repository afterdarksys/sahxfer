// Threats: the bridge forwards sealed frames and does not hold the AEAD
// key. A third peer is dropped. One connection is one grant. The 4 MiB
// queue stops the QUIC read. Tokens and file bytes are not logged.
package quic

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qgo "github.com/quic-go/quic-go"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/relay"
)

// QueueCap is the UDP-bound byte limit for one grant. A full queue stops
// the QUIC read. It does not drop a datagram already accepted.
const QueueCap = 4 << 20

type udpItem struct {
	to   string
	data []byte
	id   uint64
}

// Bridge copies sealed datagrams between one QUIC listener and one UDP socket.
// It does not decrypt. Admit stores the route token. Serve does not.
type Bridge struct {
	relay      *relay.Relay
	mu         sync.Mutex
	cond       *sync.Cond
	conns      map[string]chan []byte
	bound      map[string]uint64
	grantBytes map[uint64]int
	udpq       []udpItem
	nextID     atomic.Uint64
}

// New returns a bridge with an empty admission table.
func New() *Bridge {
	b := &Bridge{
		relay:      relay.New(),
		conns:      make(map[string]chan []byte),
		bound:      make(map[string]uint64),
		grantBytes: make(map[uint64]int),
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Admit copies the route token into the relay. A nil bridge is internal.
func (b *Bridge) Admit(id uint64, token []byte, byteCap uint64, expires time.Duration) error {
	if b == nil || b.relay == nil {
		return code.New("internal")
	}
	return b.relay.Admit(id, token, byteCap, expires)
}

// Serve accepts QUIC connections and forwards sealed datagrams until ctx is done.
// A done context returns nil. report receives auth and byte_cap only.
func (b *Bridge) Serve(ctx context.Context, ln *qgo.Listener, udp *net.UDPConn, report func(uint64, string)) error {
	if b == nil || b.relay == nil || b.cond == nil || ln == nil || udp == nil {
		return code.New("internal")
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	}()
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.readUDP(ctx, udp, report)
	}()
	go func() {
		defer wg.Done()
		b.writeUDP(ctx, udp)
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return mapDial(err)
		}
		if conn == nil {
			if ctx.Err() != nil {
				return nil
			}
			return code.New("internal")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.serveConn(ctx, conn, report)
		}()
	}
}

func (b *Bridge) serveConn(ctx context.Context, conn *qgo.Conn, report func(uint64, string)) {
	ident := "q:" + strconv.FormatUint(b.nextID.Add(1), 10)
	ch := make(chan []byte, 32)
	b.mu.Lock()
	b.conns[ident] = ch
	b.mu.Unlock()
	stop := make(chan struct{})
	go b.pumpQUIC(ctx, conn, ch, stop)
	defer func() {
		b.mu.Lock()
		delete(b.conns, ident)
		delete(b.bound, ident)
		b.mu.Unlock()
		close(stop)
		if err := conn.CloseWithError(0, ""); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			return
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := b.awaitRoom(ctx, ident); err != nil {
			return
		}
		dgram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		h, ok := frameOK(dgram)
		if !ok {
			continue
		}
		if !b.bind(ident, h.TransferID) {
			continue
		}
		now := time.Duration(time.Now().UnixNano())
		outs, rep, id := b.relay.Handle(now, ident, dgram)
		if rep != "" && report != nil {
			report(id, rep)
		}
		b.dispatch(id, outs)
	}
}

func (b *Bridge) pumpQUIC(ctx context.Context, conn *qgo.Conn, ch <-chan []byte, stop <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case pkt := <-ch:
			if err := conn.SendDatagram(pkt); err != nil {
				return
			}
		}
	}
}

func (b *Bridge) readUDP(ctx context.Context, conn *net.UDPConn, report func(uint64, string)) {
	buf := make([]byte, frame.MaxDatagram)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n == 0 || addr == nil {
			continue
		}
		dgram := append([]byte(nil), buf[:n]...)
		now := time.Duration(time.Now().UnixNano())
		outs, rep, id := b.relay.Handle(now, addr.String(), dgram)
		if rep != "" && report != nil {
			report(id, rep)
		}
		b.dispatch(id, outs)
	}
}

func (b *Bridge) writeUDP(ctx context.Context, conn *net.UDPConn) {
	for {
		b.mu.Lock()
		for len(b.udpq) == 0 {
			if err := ctx.Err(); err != nil {
				b.mu.Unlock()
				return
			}
			b.cond.Wait()
		}
		item := b.udpq[0]
		b.mu.Unlock()
		ua, err := net.ResolveUDPAddr("udp", item.to)
		if err != nil {
			b.popFront()
			continue
		}
		if _, err = conn.WriteToUDP(item.data, ua); err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Millisecond)
			continue
		}
		b.popFront()
	}
}

func (b *Bridge) dispatch(id uint64, outs []relay.Datagram) {
	for _, o := range outs {
		if o.To == "" {
			continue
		}
		if strings.HasPrefix(o.To, "q:") {
			b.sendQUIC(o.To, o.Data)
			continue
		}
		b.enqueueUDP(o.To, id, o.Data)
	}
}

func (b *Bridge) sendQUIC(to string, data []byte) {
	cp := append([]byte(nil), data...)
	b.mu.Lock()
	ch := b.conns[to]
	b.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- cp:
	default:
	}
}

func (b *Bridge) enqueueUDP(to string, id uint64, data []byte) {
	cp := append([]byte(nil), data...)
	b.mu.Lock()
	b.udpq = append(b.udpq, udpItem{to: to, data: cp, id: id})
	b.grantBytes[id] += len(cp)
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *Bridge) popFront() {
	b.mu.Lock()
	if len(b.udpq) == 0 {
		b.mu.Unlock()
		return
	}
	item := b.udpq[0]
	b.udpq = b.udpq[1:]
	b.grantBytes[item.id] -= len(item.data)
	if b.grantBytes[item.id] <= 0 {
		delete(b.grantBytes, item.id)
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *Bridge) awaitRoom(ctx context.Context, ident string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b.roomForLocked(b.bound[ident]) {
			return nil
		}
		b.cond.Wait()
	}
}

func (b *Bridge) room(id uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.roomForLocked(id)
}

func (b *Bridge) roomForLocked(id uint64) bool {
	if id == 0 {
		return true
	}
	return b.grantBytes[id] < QueueCap
}

func (b *Bridge) bind(ident string, tid uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	have, ok := b.bound[ident]
	if !ok {
		b.bound[ident] = tid
		return true
	}
	return have == tid
}

func frameOK(d []byte) (frame.Header, bool) {
	h, err := frame.Peek(d)
	if err != nil || !frame.LengthOK(d, h) || h.Version != frame.Version {
		return frame.Header{}, false
	}
	return h, true
}
