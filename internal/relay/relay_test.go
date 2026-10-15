package relay

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

func tok(b byte) [seal.TokenSize]byte {
	var t [seal.TokenSize]byte
	for i := range t {
		t[i] = b
	}
	return t
}

func pkt(id, seq uint64, typ uint8, flags uint16, n int, token [seal.TokenSize]byte) []byte {
	b := make([]byte, frame.Overhead+n)
	frame.Put(b[:frame.HeaderSize], frame.Header{
		Version:    frame.Version,
		Type:       typ,
		Flags:      flags,
		TransferID: id,
		Seq:        seq,
		PayloadLen: uint64(n),
		RouteToken: token,
	})
	return b
}

func admit(t *testing.T, r *Relay, id uint64, token [seal.TokenSize]byte, cap uint64) {
	t.Helper()
	if err := r.Admit(id, token[:], cap, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestAdmitRejects(t *testing.T) {
	r := New()
	good := tok(1)
	if err := (*Relay)(nil).Admit(1, good[:], 0, time.Hour); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("nil: %v", err)
	}
	if err := r.Admit(0, good[:], 0, time.Hour); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("id 0: %v", err)
	}
	if err := r.Admit(1, good[:15], 0, time.Hour); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("short: %v", err)
	}
	if err := r.Admit(1, append(good[:], 0), 0, time.Hour); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("long: %v", err)
	}
	outs, rep, id := (*Relay)(nil).Handle(0, "a", pkt(1, 1, frame.TypePING, 0, 0, good))
	if outs != nil || rep != "" || id != 0 {
		t.Fatalf("nil handle: %v %q %d", outs, rep, id)
	}
	if err := (*Relay)(nil).Serve(context.Background(), &net.UDPConn{}, nil); err == nil || err.Error() != "internal" {
		t.Fatalf("nil serve: %v", err)
	}
	if err := r.Serve(context.Background(), nil, nil); err == nil || err.Error() != "internal" {
		t.Fatalf("nil conn: %v", err)
	}
}

func TestAdmitCopyAndDuplicate(t *testing.T) {
	r := New()
	raw := tok(7)
	buf := append([]byte(nil), raw[:]...)
	if err := r.Admit(4, buf, 10, time.Hour); err != nil {
		t.Fatal(err)
	}
	buf[0] = 9
	if err := r.Admit(4, raw[:], 10, time.Hour); err == nil || err.Error() != "exists" {
		t.Fatalf("dup: %v", err)
	}
	// Expired but not yet forgotten is still live.
	r.flows[4].expires = 0
	if err := r.Admit(4, raw[:], 10, time.Hour); err == nil || err.Error() != "exists" {
		t.Fatalf("dup expired: %v", err)
	}
	outs, rep, id := r.Handle(0, "a", pkt(4, 1, frame.TypePING, 0, 0, raw))
	if outs != nil || rep != "" || id != 4 {
		t.Fatalf("expire: outs=%v rep=%q id=%d", outs, rep, id)
	}
	if err := r.Admit(4, raw[:], 10, time.Hour); err != nil {
		t.Fatalf("readmit: %v", err)
	}
	// Mutated caller buffer must not have replaced the stored token.
	if _, rep, id := r.Handle(0, "a", pkt(4, 1, frame.TypePING, 0, 0, tok(9))); rep != "" || id != 4 || r.flows[4].fails != 1 {
		t.Fatalf("mutated token was accepted rep=%q id=%d fails=%d", rep, id, r.flows[4].fails)
	}
}

func TestQuietDrop(t *testing.T) {
	r := New()
	good := tok(3)
	admit(t, r, 8, good, 100)
	cases := [][]byte{
		{0, 0, 0, 0},
		pkt(8, 1, frame.TypePING, 0, 0, good)[:10],
		func() []byte {
			b := pkt(8, 1, frame.TypePING, 0, 0, good)
			b[4] = 2
			return b
		}(),
		pkt(8, 1, frame.TypeDATA, 0, 10, good)[:frame.Overhead],
		pkt(99, 1, frame.TypePING, 0, 0, good),
	}
	for i, b := range cases {
		outs, rep, id := r.Handle(0, "a", b)
		if outs != nil || rep != "" || id != 0 {
			t.Fatalf("case %d: outs=%d rep=%q id=%d", i, len(outs), rep, id)
		}
	}
	if r.flows[8].fails != 0 {
		t.Fatalf("junk burned budget: %d", r.flows[8].fails)
	}
}

func TestHoldRelease(t *testing.T) {
	good := tok(4)
	bad := tok(5)

	t.Run("exact", func(t *testing.T) {
		r := New()
		admit(t, r, 1, good, 1000)
		a := pkt(1, 1, frame.TypePING, 0, 0, good)
		if outs, _, id := r.Handle(0, "A", a); outs != nil || id != 1 {
			t.Fatalf("hold: %v %d", outs, id)
		}
		extra := pkt(1, 2, frame.TypeDATA, 0, 10, good)
		if outs, rep, _ := r.Handle(500*time.Millisecond, "A", extra); outs != nil || rep != "" {
			t.Fatalf("extra: %v %q", outs, rep)
		}
		if r.flows[1].used != 0 || r.flows[1].a.born != 0 || !r.flows[1].a.held {
			t.Fatalf("refreshed used=%d born=%s held=%v", r.flows[1].used, r.flows[1].a.born, r.flows[1].a.held)
		}
		b := pkt(1, 3, frame.TypePING, 0, 0, good)
		outs, rep, id := r.Handle(time.Second, "B", b)
		if rep != "" || id != 1 || len(outs) != 2 {
			t.Fatalf("release: %d %q %d", len(outs), rep, id)
		}
		if outs[0].To != "A" || !bytes.Equal(outs[0].Data, b) {
			t.Fatalf("forward: %+v", outs[0].To)
		}
		if outs[1].To != "B" || !bytes.Equal(outs[1].Data, a) {
			t.Fatal("hold not released")
		}
		b[0] = 0
		if outs[0].Data[0] == 0 {
			t.Fatal("forward aliases caller")
		}
	})

	t.Run("stale", func(t *testing.T) {
		r := New()
		admit(t, r, 1, good, 1000)
		a := pkt(1, 1, frame.TypePING, 0, 0, good)
		r.Handle(0, "A", a)
		r.Handle(500*time.Millisecond, "A", pkt(1, 2, frame.TypePING, 0, 0, good))
		b := pkt(1, 3, frame.TypePING, 0, 0, good)
		outs, _, _ := r.Handle(time.Second+1, "B", b)
		if len(outs) != 1 || outs[0].To != "A" || !bytes.Equal(outs[0].Data, b) {
			t.Fatalf("stale: %+v", outs)
		}
	})

	t.Run("wrong token does not pin", func(t *testing.T) {
		r := New()
		admit(t, r, 1, good, 1000)
		if _, rep, id := r.Handle(0, "X", pkt(1, 1, frame.TypePING, 0, 0, bad)); rep != "" || id != 1 || r.flows[1].fails != 1 {
			t.Fatalf("bad pin fails=%d", r.flows[1].fails)
		}
		if r.flows[1].a.addr != "" {
			t.Fatal("bad token pinned")
		}
		y := pkt(1, 2, frame.TypePING, 0, 0, good)
		r.Handle(0, "Y", y)
		z := pkt(1, 3, frame.TypePING, 0, 0, good)
		outs, _, _ := r.Handle(time.Millisecond, "Z", z)
		if len(outs) != 2 || outs[0].To != "Y" || outs[1].To != "Z" {
			t.Fatalf("Y/Z: %+v", outs)
		}
		if !bytes.Equal(outs[1].Data, y) {
			t.Fatal("Y hold missing")
		}
		before := r.flows[1].fails
		if outs, _, _ := r.Handle(time.Millisecond, "X", pkt(1, 4, frame.TypePING, 0, 0, good)); outs != nil || r.flows[1].fails != before {
			t.Fatal("third source counted")
		}
	})

	t.Run("empty from", func(t *testing.T) {
		r := New()
		admit(t, r, 1, good, 1000)
		if outs, _, id := r.Handle(0, "", pkt(1, 1, frame.TypePING, 0, 0, good)); outs != nil || id != 1 {
			t.Fatalf("empty: %v %d", outs, id)
		}
		if r.flows[1].a.addr != "" {
			t.Fatal("empty pinned")
		}
	})
}

func TestChargeAndCap(t *testing.T) {
	good := tok('k')
	ascii := string(good[:])

	r := New()
	admit(t, r, 2, good, 20)
	r.Handle(0, "A", pkt(2, 1, frame.TypePING, 0, 0, good))
	r.Handle(0, "B", pkt(2, 2, frame.TypePING, 0, 0, good))
	outs, _, _ := r.Handle(0, "A", pkt(2, 3, frame.TypeDATA, frame.FlagRETX, 5, good))
	if len(outs) != 1 || r.flows[2].used != 5 {
		t.Fatalf("retx used=%d outs=%d", r.flows[2].used, len(outs))
	}
	r.Handle(0, "A", pkt(2, 4, frame.TypeNACK, 0, 8, good))
	r.Handle(0, "B", pkt(2, 5, frame.TypePING, 0, 0, good))
	if r.flows[2].used != 5 {
		t.Fatalf("control counted: %d", r.flows[2].used)
	}

	// used == cap, zero-length DATA does not trip, and a later PING still forwards.
	r.flows[2].used = 20
	outs, rep, _ := r.Handle(0, "A", pkt(2, 6, frame.TypeDATA, 0, 0, good))
	if rep != "" || len(outs) != 1 || r.flows[2].used != 20 {
		t.Fatalf("zero: rep=%q used=%d", rep, r.flows[2].used)
	}
	outs, rep, _ = r.Handle(0, "A", pkt(2, 7, frame.TypePING, 0, 0, good))
	if rep != "" || len(outs) != 1 {
		t.Fatal("ping after full cap")
	}

	outs, rep, id := r.Handle(0, "B", pkt(2, 8, frame.TypeDATA, 0, 1, good))
	if rep != "byte_cap" || outs != nil || id != 2 || strings.Contains(rep, ascii) {
		t.Fatalf("cap: rep=%q outs=%v id=%d", rep, outs, id)
	}
	if _, ok := r.flows[2]; ok {
		t.Fatal("not forgotten")
	}
	if _, _, id := r.Handle(0, "A", pkt(2, 9, frame.TypePING, 0, 0, good)); id != 0 {
		t.Fatal("forgotten id still known")
	}

	r = New()
	admit(t, r, 3, good, 0)
	_, rep, _ = r.Handle(0, "A", pkt(3, 1, frame.TypeDATA, 0, 1, good))
	if rep != "byte_cap" || strings.Contains(rep, ascii) {
		t.Fatalf("cap 0: %q", rep)
	}
}

func TestTokenBudget(t *testing.T) {
	r := New()
	good := tok(1)
	bad := tok(2)
	admit(t, r, 6, good, 10)
	for i := 0; i < seal.AuthBudget-1; i++ {
		_, rep, id := r.Handle(0, "A", pkt(6, uint64(i+1), frame.TypePING, 0, 0, bad))
		if rep != "" || id != 6 {
			t.Fatalf("fail %d: %q %d", i, rep, id)
		}
	}
	if r.flows[6].fails != seal.AuthBudget-1 || r.flows[6].a.addr != "" {
		t.Fatal("budget pinned or reset")
	}
	if outs, _, _ := r.Handle(0, "A", pkt(6, 100, frame.TypePING, 0, 0, good)); outs != nil || r.flows[6].fails != seal.AuthBudget-1 {
		t.Fatal("good reset the counter")
	}
	_, rep, id := r.Handle(0, "B", pkt(6, 101, frame.TypePING, 0, 0, bad))
	if rep != "auth" || id != 6 || strings.Contains(rep, string(bad[:])) {
		t.Fatalf("32: rep=%q id=%d", rep, id)
	}
	if _, ok := r.flows[6]; ok {
		t.Fatal("still admitted")
	}
	if _, _, id := r.Handle(0, "A", pkt(6, 102, frame.TypePING, 0, 0, good)); id != 0 {
		t.Fatal("auth did not forget")
	}
}

func TestChargeWrap(t *testing.T) {
	f := &flow{cap: 100, used: ^uint64(0) - 10}
	if !f.charge(frame.Header{Type: frame.TypeDATA, PayloadLen: 11}) {
		t.Fatal("wrap did not trip")
	}
	if f.used != ^uint64(0)-10 {
		t.Fatalf("wrap added: %d", f.used)
	}
	if f.charge(frame.Header{Type: frame.TypePING, PayloadLen: 11}) {
		t.Fatal("ping charged")
	}
	r := New()
	good := tok(8)
	admit(t, r, 1, good, 100)
	r.flows[1].used = ^uint64(0) - 10
	outs, rep, id := r.Handle(0, "A", pkt(1, 1, frame.TypeDATA, 0, 11, good))
	if rep != "byte_cap" || outs != nil || id != 1 {
		t.Fatalf("handle wrap: %q %v %d", rep, outs, id)
	}
}

func TestServeForwardAndCancel(t *testing.T) {
	r := New()
	good := tok(9)
	exp := time.Duration(time.Now().UnixNano()) + time.Hour
	if err := r.Admit(9, good[:], 0, exp); err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- r.Serve(ctx, pc, nil) }()

	a, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pa := pkt(9, 1, frame.TypePING, 0, 0, good)
	pb := pkt(9, 2, frame.TypePING, 0, 0, good)
	if _, err := a.Write(pa); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(pb); err != nil {
		t.Fatal(err)
	}
	gotA := readUDP(t, a)
	gotB := readUDP(t, b)
	if !bytes.Equal(gotA, pb) || !bytes.Equal(gotB, pa) {
		t.Fatalf("crossed a=%x b=%x", gotA, gotB)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve hung")
	}
}

func readUDP(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, frame.MaxDatagram)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf[:n]...)
}
