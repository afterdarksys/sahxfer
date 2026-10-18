package engine

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

func testMaterial() ([]byte, []byte) {
	return bytes.Repeat([]byte("K"), seal.KeySize), bytes.Repeat([]byte("T"), seal.TokenSize)
}

type memFile struct {
	b      []byte
	writes int
}

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(m.b)) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	end := int(off) + len(p)
	if end > len(m.b) {
		nb := make([]byte, end)
		copy(nb, m.b)
		m.b = nb
	}
	copy(m.b[off:], p)
	m.writes++
	return len(p), nil
}

type pair struct {
	s, r                      *Peer
	src, dst                  *memFile
	commits, cleansS, cleansR int
}

func newPair(t *testing.T, file []byte, mss uint64, alter func(s, r *Config)) *pair {
	t.Helper()
	key, tok := testMaterial()
	sum := sha256.Sum256(file)
	sc := Config{
		TransferID:  7,
		Size:        uint64(len(file)),
		MSS:         mss,
		Key:         append([]byte(nil), key...),
		Token:       append([]byte(nil), tok...),
		LocalDir:    seal.DirClient,
		PeerDir:     seal.DirAgent,
		Sender:      true,
		Transport:   TransportUDP,
		HaveHash:    true,
		ExpectHash:  sum,
		Idle:        5 * time.Second,
		Max:         30 * time.Second,
		FirstPacket: 2 * time.Second,
	}
	rc := sc
	rc.Key = append([]byte(nil), key...)
	rc.Token = append([]byte(nil), tok...)
	rc.LocalDir = seal.DirAgent
	rc.PeerDir = seal.DirClient
	rc.Sender = false
	if alter != nil {
		alter(&sc, &rc)
	}
	s, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rc)
	if err != nil {
		t.Fatal(err)
	}
	pr := &pair{s: s, r: r, src: &memFile{b: append([]byte(nil), file...)}, dst: &memFile{}}
	if err := s.AttachSource(pr.src); err != nil {
		t.Fatal(err)
	}
	r.AttachDest(pr.dst)
	s.SetHooks(Hooks{Cleanup: func() { pr.cleansS++ }})
	r.SetHooks(Hooks{
		Commit:  func() error { pr.commits++; return nil },
		Cleanup: func() { pr.cleansR++ },
	})
	return pr
}

type queued struct {
	at time.Duration
	d  []byte
}

type pipe struct {
	delay time.Duration
	q     []queued
	filt  func(frame.Header) (drop bool, extra time.Duration)
	// bps, when set, serializes datagrams at that many bytes per second
	// ahead of the delay, so a queue builds instead of infinite bandwidth.
	bps  float64
	free time.Duration
	// qcap, with bps, is the bottleneck buffer as queueing delay. A
	// datagram that would wait longer is tail-dropped.
	qcap  time.Duration
	drops int
	// From stepAt on, delay becomes delay2 (a route change).
	stepAt, delay2 time.Duration
}

func newPipe() *pipe { return &pipe{delay: time.Millisecond} }

func (p *pipe) send(now time.Duration, ds [][]byte) {
	for _, d := range ds {
		extra := time.Duration(0)
		if p.filt != nil {
			h, err := frame.Peek(d)
			if err == nil {
				drop, ex := p.filt(h)
				if drop {
					continue
				}
				extra = ex
			}
		}
		at := now
		if p.bps > 0 {
			if p.free > at {
				at = p.free
			}
			if p.qcap > 0 && at-now > p.qcap {
				p.drops++
				continue
			}
			at += time.Duration(float64(len(d)) / p.bps * 1e9)
			p.free = at
		}
		delay := p.delay
		if p.stepAt > 0 && now >= p.stepAt {
			delay = p.delay2
		}
		p.q = append(p.q, queued{at: at + delay + extra, d: append([]byte(nil), d...)})
	}
}

func (p *pipe) due(now time.Duration) [][]byte {
	var out [][]byte
	rest := make([]queued, 0, len(p.q))
	for _, it := range p.q {
		if it.at <= now {
			out = append(out, it.d)
		} else {
			rest = append(rest, it)
		}
	}
	p.q = rest
	return out
}

func (p *pipe) next(now time.Duration) (time.Duration, bool) {
	var at time.Duration
	ok := false
	for _, it := range p.q {
		if it.at <= now {
			continue
		}
		if !ok || it.at < at {
			at = it.at
			ok = true
		}
	}
	return at, ok
}

func runUntil(pr *pair, ab, ba *pipe, limit time.Duration) (time.Duration, error) {
	var now time.Duration
	const maxSteps = 2_000_000
	for step := 0; step < maxSteps; step++ {
		if pr.s.OK() && pr.r.OK() {
			return now, nil
		}
		if err := pr.failed(); err != nil {
			return now, err
		}
		if now > limit {
			return now, fmt.Errorf("stuck at %s step %d sender %d receiver %d", now, step, pr.s.Delivered(), pr.r.Delivered())
		}
		for _, d := range ab.due(now) {
			pr.r.Recv(now, d)
		}
		for _, d := range ba.due(now) {
			pr.s.Recv(now, d)
		}
		if err := pr.failed(); err != nil {
			return now, err
		}
		pr.s.Pump(now)
		pr.r.Pump(now)
		if err := pr.failed(); err != nil {
			return now, err
		}
		sd, rd := pr.s.Take(), pr.r.Take()
		ab.send(now, sd)
		ba.send(now, rd)
		// Report the time both finished, not the next wake (now + Max).
		if pr.s.OK() && pr.r.OK() {
			return now, nil
		}
		next := now + time.Hour
		consider := func(t0 time.Duration) {
			if t0 > now && t0 < next {
				next = t0
			}
		}
		consider(pr.s.WakeAt(now))
		consider(pr.r.WakeAt(now))
		if t0, ok := ab.next(now); ok {
			consider(t0)
		}
		if t0, ok := ba.next(now); ok {
			consider(t0)
		}
		if next <= now {
			now += time.Microsecond
			continue
		}
		now = next
	}
	return 0, fmt.Errorf("step cap")
}

func (pr *pair) failed() error {
	if pr.s.Err() == nil && pr.r.Err() == nil {
		return nil
	}
	return fmt.Errorf("sender %v receiver %v", pr.s.Err(), pr.r.Err())
}

func mustFinish(t *testing.T, pr *pair, ab, ba *pipe) {
	t.Helper()
	now, err := runUntil(pr, ab, ba, 3*time.Second)
	if err != nil {
		t.Fatalf("at %s: %v", now, err)
	}
}

func countType(ds [][]byte, typ uint8) int {
	n := 0
	for _, d := range ds {
		h, err := frame.Peek(d)
		if err == nil && h.Type == typ {
			n++
		}
	}
	return n
}

func forge(t *testing.T, h frame.Header, pt []byte, dir byte) []byte {
	t.Helper()
	key, tok := testMaterial()
	sess, err := seal.New(key, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wipe()
	d, err := sess.Seal(h, pt, dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func containsSecret(s string) bool {
	return strings.Contains(s, "KKK") || strings.Contains(s, "TTT")
}

func TestCleanPutAndEmpty(t *testing.T) {
	file := bytes.Repeat([]byte{7}, 350)
	pr := newPair(t, file, 100, nil)
	mustFinish(t, pr, newPipe(), newPipe())
	if pr.commits != 1 || !bytes.Equal(pr.dst.b, file) {
		t.Fatalf("commits %d len %d", pr.commits, len(pr.dst.b))
	}

	empty := newPair(t, nil, 100, nil)
	mustFinish(t, empty, newPipe(), newPipe())
	if empty.commits != 1 || len(empty.dst.b) != 0 || !empty.s.OK() {
		t.Fatalf("empty commits %d len %d ok %v", empty.commits, len(empty.dst.b), empty.s.OK())
	}
	sum := sha256.Sum256(nil)
	if !sameSum(sum[:], empty.s.hash.Sum(nil)) {
		t.Fatal("empty hash")
	}
}

func TestWindowNeedsFeedback(t *testing.T) {
	file := bytes.Repeat([]byte{3}, 2500)
	pr := newPair(t, file, 100, nil)
	mustFinish(t, pr, newPipe(), newPipe())
	if !bytes.Equal(pr.dst.b, file) || pr.commits != 1 {
		t.Fatalf("len %d commits %d", len(pr.dst.b), pr.commits)
	}
}

func TestGetSwapsDirection(t *testing.T) {
	file := []byte("get-me")
	pr := newPair(t, file, 100, func(s, r *Config) {
		s.LocalDir, s.PeerDir = seal.DirAgent, seal.DirClient
		r.LocalDir, r.PeerDir = seal.DirClient, seal.DirAgent
	})
	mustFinish(t, pr, newPipe(), newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatalf("got %q", pr.dst.b)
	}
}

func TestReorderDoesNotTruncate(t *testing.T) {
	file := bytes.Repeat([]byte{9}, 400)
	pr := newPair(t, file, 100, nil)
	ab := newPipe()
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypeDATA && h.Offset == 0 {
			return false, 15 * time.Millisecond
		}
		return false, 0
	}
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("truncated or corrupted")
	}
}

func TestLossRepaired(t *testing.T) {
	file := bytes.Repeat([]byte{4}, 2000)
	pr := newPair(t, file, 100, nil)
	seen := map[uint64]int{}
	ab := newPipe()
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type != frame.TypeDATA || h.Offset != 500 {
			return false, 0
		}
		seen[h.Offset]++
		return seen[h.Offset] == 1, 0
	}
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("loss not repaired")
	}
}

func TestDroppedNACKAndFIN(t *testing.T) {
	file := bytes.Repeat([]byte{5}, 600)
	pr := newPair(t, file, 100, nil)
	nacks, data := 0, map[uint64]int{}
	ab := newPipe()
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypeDATA && h.Offset == 200 {
			data[h.Offset]++
			return data[h.Offset] == 1, 0
		}
		return false, 0
	}
	ba := newPipe()
	ba.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypeNACK {
			nacks++
			return nacks == 1, 0
		}
		return false, 0
	}
	mustFinish(t, pr, ab, ba)
	if nacks < 2 {
		t.Fatalf("nacks %d", nacks)
	}

	pr = newPair(t, file, 100, nil)
	fins := 0
	ab = newPipe()
	ba = newPipe()
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypeFIN && h.Flags&frame.FlagCloseAck == 0 {
			fins++
			return fins == 1, 0
		}
		return false, 0
	}
	mustFinish(t, pr, ab, ba)
	if fins < 2 || pr.commits != 1 {
		t.Fatalf("fins %d commits %d", fins, pr.commits)
	}
}

func TestNACKOnlyAfterMature(t *testing.T) {
	file := bytes.Repeat([]byte{8}, 300)
	pr := newPair(t, file, 100, nil)
	pr.s.Pump(0)
	pr.s.Recv(2*time.Millisecond, forge(t, frame.Header{
		Type: frame.TypePONG, Seq: 1, Offset: 1, TransferID: 7,
	}, frame.EncodePong(0, 0), seal.DirAgent))
	var pkts [][]byte
	now := 2 * time.Millisecond
	for now < time.Second {
		pr.s.Pump(now)
		pkts = append(pkts, pr.s.Take()...)
		if countType(pkts, frame.TypeFIN) > 0 && countType(pkts, frame.TypeDATA) >= 3 {
			break
		}
		w := pr.s.WakeAt(now)
		if w <= now {
			now += time.Microsecond
		} else {
			now = w
		}
	}
	var rest [][]byte
	var fin []byte
	for _, d := range pkts {
		h, err := frame.Peek(d)
		if err != nil {
			continue
		}
		if h.Type == frame.TypeFIN {
			fin = d
			continue
		}
		if h.Type == frame.TypeDATA && h.Offset == 200 {
			rest = append(rest, d)
			continue
		}
		if h.Type == frame.TypeDATA {
			pr.r.Recv(now, d)
		}
	}
	pr.r.Pump(now)
	if countType(pr.r.Take(), frame.TypeNACK) != 0 {
		t.Fatal("trailing gap NACKed before FIN")
	}
	if fin == nil {
		t.Fatal("no FIN")
	}
	pr.r.Recv(now, fin)
	pr.r.Pump(now)
	if countType(pr.r.Take(), frame.TypeNACK) != 0 {
		t.Fatal("trailing gap NACKed before it was mature")
	}
	pr.r.Pump(now + time.Millisecond)
	if countType(pr.r.Take(), frame.TypeNACK) != 1 {
		t.Fatal("mature trailing gap was not NACKed")
	}
	_ = rest

	// Last packet before the first: the interior hole is mature at once.
	pr = newPair(t, file, 100, nil)
	pr.r.Recv(0, forge(t, frame.Header{
		Type: frame.TypeDATA, Seq: 4, Offset: 200, TransferID: 7,
	}, bytes.Repeat([]byte{8}, 100), seal.DirClient))
	pr.r.Pump(0)
	nacks := 0
	for _, d := range pr.r.Take() {
		h, err := frame.Peek(d)
		if err != nil || h.Type != frame.TypeNACK {
			continue
		}
		nacks++
		holes, err := frame.DecodeNACK(mustOpen(t, d, seal.DirAgent), 300)
		if err != nil || len(holes) == 0 || holes[0].Start != 0 {
			t.Fatalf("holes %v %v", holes, err)
		}
	}
	if nacks != 1 {
		t.Fatalf("interior nacks %d", nacks)
	}
}

func mustOpen(t *testing.T, d []byte, dir byte) []byte {
	t.Helper()
	key, tok := testMaterial()
	sess, err := seal.New(key, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wipe()
	_, pt, err := sess.Open(d, dir)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestReplayAndFirstWrite(t *testing.T) {
	file := bytes.Repeat([]byte{9}, 100)
	pr := newPair(t, file, 100, nil)
	pr.s.Pump(0)
	pr.s.Recv(2*time.Millisecond, forge(t, frame.Header{
		Type: frame.TypePONG, Seq: 1, Offset: 1, TransferID: 7,
	}, frame.EncodePong(0, 0), seal.DirAgent))
	pr.s.Pump(2 * time.Millisecond)
	var data []byte
	for _, d := range pr.s.Take() {
		h, err := frame.Peek(d)
		if err == nil && h.Type == frame.TypeDATA {
			data = d
		}
	}
	if data == nil {
		t.Fatal("no data")
	}
	pr.r.Recv(3*time.Millisecond, data)
	if pr.r.Delivered() != 100 {
		t.Fatalf("delivered %d", pr.r.Delivered())
	}
	w := pr.dst.writes
	pr.r.Recv(3*time.Millisecond, data)
	if pr.r.Delivered() != 100 || pr.dst.writes != w || pr.r.Err() != nil {
		t.Fatalf("replay delivered %d writes %d err %v", pr.r.Delivered(), pr.dst.writes, pr.r.Err())
	}

	pr = newPair(t, bytes.Repeat([]byte{1}, 150), 200, nil)
	pr.r.Recv(0, forge(t, frame.Header{
		Type: frame.TypeDATA, Seq: 1, Offset: 0, TransferID: 7,
	}, bytes.Repeat([]byte{0x11}, 100), seal.DirClient))
	pr.r.Recv(0, forge(t, frame.Header{
		Type: frame.TypeDATA, Seq: 2, Offset: 50, TransferID: 7,
	}, bytes.Repeat([]byte{0x22}, 100), seal.DirClient))
	if pr.r.Delivered() != 150 || pr.r.Err() != nil {
		t.Fatalf("delivered %d %v", pr.r.Delivered(), pr.r.Err())
	}
	for i := 0; i < 100; i++ {
		if pr.dst.b[i] != 0x11 {
			t.Fatalf("first write lost at %d", i)
		}
	}
	for i := 100; i < 150; i++ {
		if pr.dst.b[i] != 0x22 {
			t.Fatalf("tail %d", i)
		}
	}
}

func TestDropsDoNotWrite(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{1}, 100), 100, nil)
	good := forge(t, frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 0, TransferID: 7}, bytes.Repeat([]byte{1}, 50), seal.DirClient)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	pr.r.Recv(0, bad)
	short := good[:20]
	pr.r.Recv(0, short)
	magic := append([]byte(nil), good...)
	magic[0] ^= 0xff
	pr.r.Recv(0, magic)
	ver := append([]byte(nil), good...)
	ver[4] = 2
	pr.r.Recv(0, ver)
	if pr.r.Err() != nil || pr.dst.writes != 0 || pr.r.Delivered() != 0 {
		t.Fatalf("err %v writes %d", pr.r.Err(), pr.dst.writes)
	}
	// A version-2 drop did not spend the budget: a real packet still opens.
	pr.r.Recv(0, good)
	if pr.r.Delivered() != 50 || pr.r.Err() != nil {
		t.Fatalf("after drop delivered %d %v", pr.r.Delivered(), pr.r.Err())
	}
}

func TestBadPacketsAbortWithoutWrite(t *testing.T) {
	cases := []struct {
		name string
		h    frame.Header
		pt   []byte
	}{
		{"type", frame.Header{Type: 99, Seq: 1, TransferID: 7}, nil},
		{"flag", frame.Header{Type: frame.TypeDATA, Flags: 1 << 2, Seq: 1, Offset: 0, TransferID: 7}, []byte{1, 2, 3, 4}},
		{"retx-fin", frame.Header{Type: frame.TypeFIN, Flags: frame.FlagRETX, Seq: 1, Offset: 100, TransferID: 7}, nil},
		{"wrap", frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: ^uint64(0) - 3, TransferID: 7}, bytes.Repeat([]byte{1}, 8)},
		{"past", frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 98, TransferID: 7}, bytes.Repeat([]byte{1}, 8)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr := newPair(t, bytes.Repeat([]byte{1}, 100), 100, nil)
			pr.r.Recv(0, forge(t, tc.h, tc.pt, seal.DirClient))
			if pr.r.Reason() != frame.ReasonProtocol || pr.dst.writes != 0 || pr.cleansR != 1 || pr.commits != 0 {
				t.Fatalf("reason %d writes %d clean %d commit %d", pr.r.Reason(), pr.dst.writes, pr.cleansR, pr.commits)
			}
		})
	}
}

func TestDoneMismatchAndCommit(t *testing.T) {
	pr := newPair(t, nil, 100, nil)
	wrong := bytes.Repeat([]byte{1}, 32)
	pr.s.Recv(0, forge(t, frame.Header{Type: frame.TypeDONE, Seq: 1, Offset: 0, TransferID: 7}, wrong, seal.DirAgent))
	if pr.s.OK() || pr.s.Reason() != frame.ReasonHashMismatch {
		t.Fatalf("ok %v reason %d", pr.s.OK(), pr.s.Reason())
	}

	file := bytes.Repeat([]byte{2}, 80)
	sum := sha256.Sum256(file)
	pr = newPair(t, file, 100, nil)
	pr.s.Recv(0, forge(t, frame.Header{Type: frame.TypeDONE, Seq: 1, Offset: 80, TransferID: 7}, sum[:], seal.DirAgent))
	if pr.s.OK() || pr.s.Reason() != frame.ReasonProtocol {
		t.Fatalf("early done ok %v reason %d", pr.s.OK(), pr.s.Reason())
	}

	pr = newPair(t, file, 100, func(s, r *Config) {
		r.ExpectHash[0] ^= 0xff
	})
	now, err := runUntil(pr, newPipe(), newPipe(), 3*time.Second)
	if err == nil || pr.commits != 0 || pr.cleansR != 1 || pr.r.Reason() != frame.ReasonHashMismatch {
		t.Fatalf("at %s err %v commits %d clean %d reason %d", now, err, pr.commits, pr.cleansR, pr.r.Reason())
	}

	pr = newPair(t, file, 100, nil)
	pr.r.SetHooks(Hooks{
		Commit:  func() error { pr.commits++; return io.ErrClosedPipe },
		Cleanup: func() { pr.cleansR++ },
	})
	_, err = runUntil(pr, newPipe(), newPipe(), 3*time.Second)
	if err == nil || pr.r.Reason() != frame.ReasonIO || pr.commits != 1 || pr.r.OK() {
		t.Fatalf("commit err %v reason %d commits %d", err, pr.r.Reason(), pr.commits)
	}
}

func TestAuthBudgets(t *testing.T) {
	good := forge(t, frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 0, TransferID: 7}, bytes.Repeat([]byte{1}, 20), seal.DirClient)
	pr := newPair(t, bytes.Repeat([]byte{1}, 100), 100, nil)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	for i := 0; i < 31; i++ {
		pr.r.Recv(0, bad)
		if pr.r.Err() != nil {
			t.Fatalf("died at %d", i)
		}
	}
	pr.r.Recv(0, good)
	if pr.r.Delivered() != 20 {
		t.Fatalf("delivered %d", pr.r.Delivered())
	}
	pr.r.Recv(0, bad)
	if pr.r.Reason() != frame.ReasonAuth || pr.cleansR != 1 {
		t.Fatalf("reason %d clean %d", pr.r.Reason(), pr.cleansR)
	}

	pr = newPair(t, bytes.Repeat([]byte{1}, 100), 100, nil)
	tok := append([]byte(nil), good...)
	tok[48] ^= 0xff
	for i := 0; i < 31; i++ {
		pr.r.Recv(0, tok)
		if pr.r.Err() != nil {
			t.Fatalf("token died at %d", i)
		}
	}
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeDATA, Seq: 2, Offset: 0, TransferID: 7}, bytes.Repeat([]byte{1}, 20), seal.DirClient))
	if pr.r.Delivered() != 20 || pr.r.Err() != nil {
		t.Fatalf("after 31 tokens delivered %d %v", pr.r.Delivered(), pr.r.Err())
	}
	pr.r.Recv(0, tok)
	if pr.r.Reason() != frame.ReasonAuth || pr.cleansR != 1 {
		t.Fatalf("token reason %d clean %d", pr.r.Reason(), pr.cleansR)
	}
}

func TestTransferIDIsQuiet(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{1}, 40), 100, nil)
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 0, TransferID: 99}, bytes.Repeat([]byte{1}, 40), seal.DirClient))
	if pr.r.Err() != nil || pr.r.Delivered() != 0 || pr.dst.writes != 0 {
		t.Fatalf("mismatch err %v delivered %d", pr.r.Err(), pr.r.Delivered())
	}
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeDATA, Seq: 2, Offset: 0, TransferID: 7}, bytes.Repeat([]byte{1}, 40), seal.DirClient))
	if pr.r.Delivered() != 40 || pr.r.Err() != nil {
		t.Fatalf("delivered %d %v", pr.r.Delivered(), pr.r.Err())
	}
}

func TestByteCap(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{1}, 100), 100, func(s, r *Config) {
		s.ByteCap = 99
		r.ByteCap = 99
	})
	pr.s.Pump(0)
	pr.s.Recv(2*time.Millisecond, forge(t, frame.Header{
		Type: frame.TypePONG, Seq: 1, Offset: 1, TransferID: 7,
	}, frame.EncodePong(0, 0), seal.DirAgent))
	pr.s.Pump(2 * time.Millisecond)
	if pr.s.Reason() != frame.ReasonByteCap || countType(pr.s.Take(), frame.TypeDATA) != 0 || pr.cleansS != 1 {
		t.Fatalf("sender reason %d", pr.s.Reason())
	}

	pr = newPair(t, bytes.Repeat([]byte{1}, 100), 100, func(s, r *Config) {
		r.ByteCap = 99
	})
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 0, TransferID: 7}, bytes.Repeat([]byte{1}, 100), seal.DirClient))
	if pr.r.Reason() != frame.ReasonByteCap || pr.commits != 0 || pr.cleansR != 1 || pr.r.OK() {
		t.Fatalf("receiver reason %d commits %d", pr.r.Reason(), pr.commits)
	}
}

func TestExpiredBeforeIdle(t *testing.T) {
	pr := newPair(t, []byte{1}, 100, func(s, r *Config) {
		s.Max = 5 * time.Millisecond
		s.Idle = 5 * time.Millisecond
		s.FirstPacket = time.Hour
	})
	pr.s.Pump(0)
	pr.s.Recv(0, forge(t, frame.Header{Type: frame.TypePING, Seq: 1, TransferID: 7}, nil, seal.DirAgent))
	pr.s.Pump(5 * time.Millisecond)
	if pr.s.Reason() != frame.ReasonExpired {
		t.Fatalf("reason %s", pr.s.Err())
	}

	pr = newPair(t, []byte{1}, 100, func(s, r *Config) {
		s.Max = 5 * time.Millisecond
		s.FirstPacket = 5 * time.Millisecond
		s.Idle = time.Hour
	})
	pr.s.Pump(0)
	pr.s.Pump(5 * time.Millisecond)
	if pr.s.Reason() != frame.ReasonExpired {
		t.Fatalf("unseen reason %s", pr.s.Err())
	}
}

func TestTransportGates(t *testing.T) {
	key, tok := testMaterial()
	base := Config{TransferID: 1, Size: 10, Key: key, Token: tok, LocalDir: 0, PeerDir: 1, Sender: true}
	base.Transport = TransportQUICDatagram
	base.Pacing = true
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "pacing") || containsSecret(err.Error()) {
		t.Fatal(err)
	}
	base.Pacing = false
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	base.Transport = TransportQUICStream
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatal(err)
	}
	base.Transport = "crypto=off"
	if _, err := New(base); err == nil || containsSecret(err.Error()) {
		t.Fatal(err)
	}
	base.Transport = TransportUDP
	base.Pacing = false
	base.Size = 400
	base.MSS = 100
	s, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSource(&memFile{b: bytes.Repeat([]byte{1}, 400)}); err != nil {
		t.Fatal(err)
	}
	s.Pump(0)
	s.Recv(2*time.Millisecond, forge(t, frame.Header{Type: frame.TypePONG, Seq: 1, Offset: 1, TransferID: 1}, frame.EncodePong(0, 0), seal.DirAgent))
	s.Pump(2 * time.Millisecond)
	if countType(s.Take(), frame.TypeDATA) != 1 {
		t.Fatal("first pump")
	}
	s.Pump(2 * time.Millisecond)
	if countType(s.Take(), frame.TypeDATA) != 0 {
		t.Fatal("udp paced a second DATA at the same instant")
	}
}

func TestErrorsOmitSecrets(t *testing.T) {
	key, tok := testMaterial()
	_, err := New(Config{Size: 1 << 63, Key: key, Token: tok})
	if err == nil || containsSecret(err.Error()) {
		t.Fatal(err)
	}
	cfg := Config{
		TransferID: 1, Size: 4, Key: append([]byte(nil), key...), Token: append([]byte(nil), tok...),
		Sender: true, HaveHash: true, ExpectHash: sha256.Sum256([]byte("nope")),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = p.AttachSource(&memFile{b: []byte("yes!")})
	if err == nil || err.Error() != "sahxfer: hash_mismatch" || containsSecret(err.Error()) {
		t.Fatal(err)
	}
	pr := newPair(t, []byte{1}, 100, nil)
	pr.r.Recv(0, forge(t, frame.Header{Type: 99, Seq: 1, TransferID: 7}, nil, seal.DirClient))
	if containsSecret(pr.r.Err().Error()) {
		t.Fatal(pr.r.Err())
	}
}

// A relay holds the sender's first PING until the receiver pins. Its PONG
// predates the first packet the sender heard and must not become srtt.
func TestSenderDropsHeldPingSample(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{9}, 300), 100, nil)
	pr.s.Pump(0)
	held := pr.s.Take()
	if countType(held, frame.TypePING) != 1 {
		t.Fatalf("first sender burst %d PINGs", countType(held, frame.TypePING))
	}
	pr.r.Pump(0)
	ms := time.Millisecond
	for _, d := range pr.r.Take() {
		pr.s.Recv(ms, d)
	}
	pr.s.Pump(ms)
	fresh := pr.s.Take()
	if countType(fresh, frame.TypePING) != 1 {
		t.Fatal("sender did not PING again on first hearing the receiver")
	}
	for _, d := range fresh {
		pr.r.Recv(2*ms, d)
	}
	pr.r.Pump(2 * ms)
	for _, d := range pr.r.Take() {
		pr.s.Recv(3*ms, d)
	}
	if !pr.s.haveRTT || pr.s.srtt > 10*ms {
		t.Fatalf("fresh PING srtt %v have %v", pr.s.srtt, pr.s.haveRTT)
	}
	// The held PING reaches the receiver 500 ms late.
	for _, d := range held {
		pr.r.Recv(500*ms, d)
	}
	pr.r.Pump(500 * ms)
	for _, d := range pr.r.Take() {
		pr.s.Recv(501*ms, d)
	}
	if pr.s.srtt > 10*ms {
		t.Fatalf("held PING moved srtt to %v", pr.s.srtt)
	}
}

// Every PONG but the first is dropped, and that one answers a PING sent
// before the sender heard the receiver, 20 ms late. Only the FEEDBACK
// echo can give the sender an RTT. The pipe is 1 ms each way and the
// FEEDBACK hold is at most 5 ms.
func TestFeedbackEchoGivesRTT(t *testing.T) {
	file := bytes.Repeat([]byte{6}, 5000)
	pr := newPair(t, file, 100, nil)
	ba := newPipe()
	pongs := 0
	ba.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type != frame.TypePONG {
			return false, 0
		}
		pongs++
		return pongs > 1, 20 * time.Millisecond
	}
	mustFinish(t, pr, newPipe(), ba)
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("file mismatch")
	}
	if !pr.s.haveRTT || pr.s.srtt < 2*time.Millisecond || pr.s.srtt > 7*time.Millisecond {
		t.Fatalf("srtt from FEEDBACK %v have %v", pr.s.srtt, pr.s.haveRTT)
	}
}

// A partial repair re-births the rest of a hole, so the oldest hole can sit
// above a younger one. The NACK must still list holes in offset order; an
// age-ordered list failed EncodeNACK and aborted the grant with protocol.
func TestNACKHolesInOffsetOrder(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{2}, 1000), 100, nil)
	ms := time.Millisecond
	data := func(at time.Duration, seq, off uint64) {
		pr.r.Recv(at, forge(t, frame.Header{
			Type: frame.TypeDATA, TransferID: 7, Seq: seq, Offset: off, SendTimeNS: uint64(at),
		}, bytes.Repeat([]byte{2}, 100), seal.DirClient))
	}
	data(0, 1, 0)
	data(ms, 2, 300)   // hole [100,300) born 0
	data(2*ms, 3, 600) // hole [400,600) born 1 ms
	data(3*ms, 4, 100) // repair re-births [200,300) at 3 ms
	pr.r.Pump(3 * ms)
	if err := pr.r.Err(); err != nil {
		t.Fatalf("receiver aborted: %v", err)
	}
	out := pr.r.Take()
	if countType(out, frame.TypeNACK) != 1 {
		t.Fatalf("NACKs %d", countType(out, frame.TypeNACK))
	}
	key, tok := testMaterial()
	sess, err := seal.New(key, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wipe()
	for _, d := range out {
		h, pt, err := sess.Open(d, seal.DirAgent)
		if err != nil || h.Type != frame.TypeNACK {
			continue
		}
		holes, err := frame.DecodeNACK(pt, 1000)
		if err != nil {
			t.Fatal(err)
		}
		want := []frame.Span{{Start: 200, End: 300}, {Start: 400, End: 600}}
		if len(holes) != 2 || holes[0] != want[0] || holes[1] != want[1] {
			t.Fatalf("holes %v, want %v", holes, want)
		}
	}
}

// After the last DATA, timer FEEDBACKs must not repeat an old echo into the
// sender's srtt. A repeated echo once grew srtt by 5 ms per FEEDBACK, the FIN
// retry backed off with it, and 9+ lost FINs ended in idle at 5 s.
func TestFINLossBurst(t *testing.T) {
	for n := 1; n <= 12; n++ {
		file := bytes.Repeat([]byte{8}, 3000)
		pr := newPair(t, file, 100, nil)
		ab := newPipe()
		fins := 0
		ab.filt = func(h frame.Header) (bool, time.Duration) {
			if h.Type != frame.TypeFIN {
				return false, 0
			}
			fins++
			return fins <= n, 0
		}
		now, err := runUntil(pr, ab, newPipe(), 3*time.Second)
		if err != nil {
			t.Fatalf("n=%d at %s: %v", n, now, err)
		}
		if now > 500*time.Millisecond || pr.s.srtt > 20*time.Millisecond {
			t.Fatalf("n=%d done at %s srtt %v", n, now, pr.s.srtt)
		}
		if !bytes.Equal(pr.dst.b, file) {
			t.Fatalf("n=%d file mismatch", n)
		}
	}
}

// An authenticated peer that reports more delivered bytes than were sent
// cannot raise the pacer past what left the sender.
func TestFeedbackDeliveredClamped(t *testing.T) {
	file := bytes.Repeat([]byte{1}, 100_000)
	honest := newPair(t, file, 1000, nil)
	liar := newPair(t, file, 1000, nil)
	ms := time.Millisecond
	for _, pr := range []*pair{honest, liar} {
		pr.s.Recv(0, forge(t, frame.Header{Type: frame.TypePONG, TransferID: 7, Seq: 1}, frame.EncodePong(0, 0), seal.DirAgent))
		pr.s.Pump(0)
		pr.s.Take()
	}
	fb := func(pr *pair, seq uint64, at time.Duration, delivered uint64) {
		pr.s.Recv(at, forge(t, frame.Header{Type: frame.TypeFEEDBACK, TransferID: 7, Seq: seq},
			frame.EncodeFeedback(frame.Feedback{DeliveredBytes: delivered}), seal.DirAgent))
	}
	sent := honest.s.nextNew
	if sent == 0 || sent != liar.s.nextNew {
		t.Fatalf("sent %d / %d", sent, liar.s.nextNew)
	}
	fb(honest, 2, 5*ms, 1)
	fb(liar, 2, 5*ms, 1)
	fb(honest, 3, 10*ms, sent)
	fb(liar, 3, 10*ms, 1<<62)
	if honest.s.pacer.Cap() != liar.s.pacer.Cap() {
		t.Fatalf("lying FEEDBACK moved cap: honest %d liar %d", honest.s.pacer.Cap(), liar.s.pacer.Cap())
	}
}

// 40 mature holes: the oldest 32 go out, in offset order.
func TestNACK40Holes(t *testing.T) {
	const size = 8100
	pr := newPair(t, bytes.Repeat([]byte{2}, size), 100, nil)
	ms := time.Millisecond
	seq := uint64(0)
	data := func(off uint64) {
		seq++
		at := time.Duration(seq) * ms
		pr.r.Recv(at, forge(t, frame.Header{
			Type: frame.TypeDATA, TransferID: 7, Seq: seq, Offset: off, SendTimeNS: uint64(at),
		}, bytes.Repeat([]byte{2}, 100), seal.DirClient))
	}
	// Descending offsets: each accept re-births the hole above it, so the
	// higher a hole, the older it is. Holes are [o+100, o+200) for
	// o = 0, 200, ..., 7800.
	for off := uint64(8000); ; off -= 200 {
		data(off)
		if off == 0 {
			break
		}
	}
	if got := len(pr.r.holes.Missing()); got != 40 {
		t.Fatalf("holes %d", got)
	}
	now := time.Duration(seq) * ms
	pr.r.Pump(now)
	if err := pr.r.Err(); err != nil {
		t.Fatalf("receiver aborted: %v", err)
	}
	key, tok := testMaterial()
	sess, err := seal.New(key, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wipe()
	nacks := 0
	for _, d := range pr.r.Take() {
		h, pt, err := sess.Open(d, seal.DirAgent)
		if err != nil || h.Type != frame.TypeNACK {
			continue
		}
		nacks++
		holes, err := frame.DecodeNACK(pt, size)
		if err != nil {
			t.Fatal(err)
		}
		if len(holes) != frame.MaxNACKHoles {
			t.Fatalf("holes %d", len(holes))
		}
		for i, sp := range holes {
			start := uint64(1700 + 200*i)
			if sp.Start != start || sp.End != start+100 {
				t.Fatalf("hole %d = %v, want [%d,%d)", i, sp, start, start+100)
			}
		}
	}
	if nacks != 1 {
		t.Fatalf("NACKs %d", nacks)
	}
}

// The sender's list of in-flight segments holds the window, not every
// segment ever sent: each FEEDBACK and NACK scans it, so a list that grew
// with the file made the sender's work quadratic in the file size.
func TestInflightListBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("30 MB virtual-clock transfer")
	}
	maxLen := func(size int) int {
		file := make([]byte, size)
		for i := range file {
			file[i] = byte(i*13 + i>>9)
		}
		pr := newPair(t, file, frame.InternetPlaintext, func(s, r *Config) {
			s.Max, r.Max = 60*time.Second, 60*time.Second
		})
		// Preallocate so memFile does not regrow on every in-order write.
		pr.dst.b = make([]byte, size)
		ab := newPipe()
		ab.bps = 20e6
		ba := newPipe()
		most := 0
		ba.filt = func(h frame.Header) (bool, time.Duration) {
			if h.Type == frame.TypeFEEDBACK && len(pr.s.inflight) > most {
				most = len(pr.s.inflight)
			}
			return false, 0
		}
		now, err := runUntil(pr, ab, ba, 20*time.Second)
		if err != nil {
			t.Fatalf("%d bytes at %s: %v", size, now, err)
		}
		if !bytes.Equal(pr.dst.b, file) {
			t.Fatalf("%d bytes: file mismatch", size)
		}
		t.Logf("%d bytes: %d segments sent, at most %d listed at a FEEDBACK, done at %s",
			size, pr.s.seq, most, now)
		return most
	}
	small, large := maxLen(3_000_000), maxLen(30_000_000)
	if large > 2*small+64 {
		t.Fatalf("in-flight list grew with the file: %d for 3 MB, %d for 30 MB", small, large)
	}
}

// A lost retransmission is released on a NACK once it is older than the
// repair timeout (2*srtt), re-sent, and counted as loss again; it does not
// sit in flight until contig passes it. The file is long enough that DATA
// is still flowing, so the NACK path, not the stall probe, repairs it.
func TestLostRepairReleased(t *testing.T) {
	file := bytes.Repeat([]byte{4}, 200_000)
	pr := newPair(t, file, 100, nil)
	ab := newPipe()
	sends := 0
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type != frame.TypeDATA || h.Offset != 5000 {
			return false, 0
		}
		sends++
		return sends <= 2, 0
	}
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) || sends < 3 {
		t.Fatalf("file mismatch or sends %d", sends)
	}
	if got := pr.s.pacer.Lost(); got != 200 {
		t.Fatalf("lost %d bytes, want 200: the original and its repair", got)
	}
}

// Receiver rule: a FEEDBACK echoes a send time only when DATA was accepted
// since the previous FEEDBACK, and 0 otherwise.
func TestFeedbackEchoOnlyNewData(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{2}, 1000), 100, nil)
	key, tok := testMaterial()
	sess, err := seal.New(key, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Wipe()
	echoes := func(at time.Duration) []uint64 {
		pr.r.Pump(at)
		var out []uint64
		for _, d := range pr.r.Take() {
			h, pt, err := sess.Open(d, seal.DirAgent)
			if err != nil || h.Type != frame.TypeFEEDBACK {
				continue
			}
			f, err := frame.DecodeFeedback(pt)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, f.EchoSendTimeNS)
		}
		return out
	}
	ms := time.Millisecond
	pr.r.Recv(ms, forge(t, frame.Header{Type: frame.TypeDATA, TransferID: 7, Seq: 1, SendTimeNS: 777}, bytes.Repeat([]byte{2}, 100), seal.DirClient))
	if e := echoes(ms); len(e) != 1 || e[0] != 777 {
		t.Fatalf("first FEEDBACK echoes %v, want [777]", e)
	}
	if e := echoes(10 * ms); len(e) != 1 || e[0] != 0 {
		t.Fatalf("FEEDBACK with no new DATA echoes %v, want [0]", e)
	}
	pr.r.Recv(11*ms, forge(t, frame.Header{Type: frame.TypeDATA, TransferID: 7, Seq: 2, Offset: 100, SendTimeNS: 999}, bytes.Repeat([]byte{2}, 100), seal.DirClient))
	if e := echoes(20 * ms); len(e) != 1 || e[0] != 999 {
		t.Fatalf("FEEDBACK after new DATA echoes %v, want [999]", e)
	}
}

// Sender rule: an echo not greater than the last sampled one is not an RTT
// sample, whatever the receiver sends.
func TestSenderIgnoresRepeatedEcho(t *testing.T) {
	pr := newPair(t, bytes.Repeat([]byte{2}, 1000), 100, nil)
	ms := time.Millisecond
	seq := uint64(0)
	fb := func(at time.Duration, echo uint64) {
		seq++
		pr.s.Recv(at, forge(t, frame.Header{Type: frame.TypeFEEDBACK, TransferID: 7, Seq: seq},
			frame.EncodeFeedback(frame.Feedback{EchoSendTimeNS: echo}), seal.DirAgent))
	}
	fb(2*ms, uint64(ms))
	if !pr.s.haveRTT || pr.s.srtt != ms {
		t.Fatalf("first echo: srtt %v", pr.s.srtt)
	}
	for i := 1; i <= 50; i++ {
		fb(2*ms+time.Duration(i)*5*ms, uint64(ms))
	}
	fb(400*ms, uint64(ms)/2)
	if pr.s.srtt != ms {
		t.Fatalf("repeated or older echo moved srtt to %v", pr.s.srtt)
	}
	fb(401*ms, uint64(395*ms))
	if pr.s.srtt == ms {
		t.Fatal("a newer echo was not sampled")
	}
}

// stalledSender is a sender in SENDING with srtt 10 ms, rttvar 0, and the
// given segments in flight, as if sent and never answered.
func stalledSender(t *testing.T, segs []sentSeg) *pair {
	t.Helper()
	pr := newPair(t, bytes.Repeat([]byte{5}, 10_000), 100, nil)
	pr.s.state = stSending
	pr.s.haveRTT = true
	pr.s.srtt = 10 * time.Millisecond
	pr.s.inflight = append([]sentSeg(nil), segs...)
	for _, s := range segs {
		if s.end > pr.s.nextNew {
			pr.s.nextNew = s.end
		}
	}
	return pr
}

// The first probe of a stall is the highest in-flight segment, released
// from nothing and not counted as loss.
func TestStallTailProbeFirst(t *testing.T) {
	pr := stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 200, n: 100}})
	w := pr.s.stallWait()
	if w != 20*time.Millisecond {
		t.Fatalf("W %v", w)
	}
	pr.s.maybeStall(w - time.Millisecond)
	if len(pr.s.retx) != 0 {
		t.Fatal("probe before W")
	}
	pr.s.maybeStall(w)
	if len(pr.s.retx) != 1 || pr.s.retx[0] != (frame.Span{Start: 100, End: 200}) {
		t.Fatalf("tail probe %v", pr.s.retx)
	}
	if len(pr.s.inflight) != 2 || pr.s.pacer.Lost() != 0 || pr.s.wholeProbes != 0 {
		t.Fatalf("tail probe released %d, lost %d", 2-len(pr.s.inflight), pr.s.pacer.Lost())
	}
}

// A range probe queues, releases and counts as lost every old segment;
// a later NACK of the same bytes adds no loss and no duplicate repair.
func TestStallRangeProbeCountsLoss(t *testing.T) {
	pr := stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 200, n: 100}})
	pr.s.probes = 1
	now := 2 * time.Second
	pr.s.maybeStall(now)
	if pr.s.wholeProbes != 1 || len(pr.s.inflight) != 0 || pr.s.pacer.Lost() != 200 || len(pr.s.retx) != 2 {
		t.Fatalf("range probe: whole %d inflight %d lost %d retx %v", pr.s.wholeProbes, len(pr.s.inflight), pr.s.pacer.Lost(), pr.s.retx)
	}
	pt, err := frame.EncodeNACK([]frame.Span{{Start: 0, End: 200}})
	if err != nil {
		t.Fatal(err)
	}
	pr.s.Recv(now+time.Millisecond, forge(t, frame.Header{Type: frame.TypeNACK, TransferID: 7, Seq: 1}, pt, seal.DirAgent))
	if pr.s.pacer.Lost() != 200 || len(pr.s.retx) != 2 {
		t.Fatalf("NACK after range probe: lost %d retx %v", pr.s.pacer.Lost(), pr.s.retx)
	}
}

// An old segment whose range a younger send overlaps is refused by the
// repair timeout. It must stay in flight, not be released onto a stalled
// path, and the sender must wake when the younger send ages out.
func TestStallRangeProbeReleasesOnlyQueued(t *testing.T) {
	now := 2 * time.Second
	young := now - time.Millisecond
	pr := stalledSender(t, []sentSeg{
		{start: 0, end: 100, n: 100},
		{start: 0, end: 100, n: 100, at: young, retx: true},
	})
	pr.s.probes = 1
	pr.s.progAt = 0
	pr.s.maybeStall(now)
	if len(pr.s.inflight) != 2 || len(pr.s.retx) != 0 || pr.s.pacer.Lost() != 0 || pr.s.wholeProbes != 0 {
		t.Fatalf("refused range released: inflight %d retx %v lost %d", len(pr.s.inflight), pr.s.retx, pr.s.pacer.Lost())
	}
	if want := young + pr.s.repairTimeout(); pr.s.recheckAt != want {
		t.Fatalf("recheck at %v, want %v", pr.s.recheckAt, want)
	}
}

// Progress resets the backoff: after range probes, a FEEDBACK that
// advances delivered bytes returns the next stall to the tail probe at W.
func TestStallBackoffResetsOnProgress(t *testing.T) {
	pr := stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 200, n: 100}})
	w := pr.s.stallWait()
	pr.s.probes = 3
	if got := pr.s.stallWait(); got != 4*time.Second {
		t.Fatalf("backed-off wait %v", got)
	}
	pr.s.Recv(time.Second, forge(t, frame.Header{Type: frame.TypeFEEDBACK, TransferID: 7, Seq: 1},
		frame.EncodeFeedback(frame.Feedback{DeliveredBytes: 100}), seal.DirAgent))
	if pr.s.probes != 0 || pr.s.stallWait() != w {
		t.Fatalf("after progress: probes %d wait %v, want 0 and %v", pr.s.probes, pr.s.stallWait(), w)
	}
}
