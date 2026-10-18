package engine

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

// zeroFile is size bytes, about frac of them zero, in runs of 64 KiB to
// 4 MiB between pseudo-random runs. Deterministic for a seed.
func zeroFile(size int, frac float64, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	b := make([]byte, size)
	for at := 0; at < size; {
		n := 64<<10 + rng.Intn(4<<20)
		if at+n > size {
			n = size - at
		}
		if rng.Float64() >= frac {
			rng.Read(b[at : at+n])
		}
		at += n
	}
	return b
}

func zeroFraction(b []byte) float64 {
	z := 0
	for _, c := range b {
		if c == 0 {
			z++
		}
	}
	return float64(z) / float64(len(b))
}

// wire counts datagrams and bytes through a pipe, by type.
type wire struct {
	bytes, n int
	byType   map[uint8]int
	retxZero int
}

func (w *wire) tap(p *pipe, drop func(frame.Header) bool) {
	w.byType = map[uint8]int{}
	prev := p.filt
	p.filt = func(h frame.Header) (bool, time.Duration) {
		if drop != nil && drop(h) {
			return true, 0
		}
		if prev != nil {
			if d, ex := prev(h); d {
				return true, ex
			}
		}
		w.n++
		w.bytes += frame.Overhead + int(h.PayloadLen)
		w.byType[h.Type]++
		if h.Type == frame.TypeZERO && h.Flags&frame.FlagRETX != 0 {
			w.retxZero++
		}
		return false, 0
	}
}

func TestZeroRoundTrip(t *testing.T) {
	file := zeroFile(6<<20, 0.6, 1)
	pr := newPair(t, file, frame.InternetPlaintext, nil)
	ab, ba := newPipe(), newPipe()
	var w wire
	w.tap(ab, nil)
	mustFinish(t, pr, ab, ba)
	if !bytes.Equal(pr.dst.b, file) || pr.commits != 1 {
		t.Fatal("file differs")
	}
	frames, zb := pr.s.ZeroStats()
	if frames == 0 || w.byType[frame.TypeZERO] != int(frames) {
		t.Fatalf("zero frames %d on wire %d", frames, w.byType[frame.TypeZERO])
	}
	if pr.r.Delivered() != uint64(len(file)) {
		t.Fatalf("delivered %d", pr.r.Delivered())
	}
	if w.bytes > len(file)/2 {
		t.Fatalf("wire %d bytes for %d (%.0f%% zero, %d bytes in ZERO)", w.bytes, len(file), 100*zeroFraction(file), zb)
	}
}

// A run that is only the file's short final block is DATA; a run that
// reaches the end includes it.
func TestZeroFinalPartialBlock(t *testing.T) {
	const mss = 100
	cases := []struct {
		name string
		file []byte
		zero int
	}{
		{"short-tail-alone", append(bytes.Repeat([]byte{9}, 300), make([]byte, 50)...), 0},
		{"tail-joins-run", append(bytes.Repeat([]byte{9}, 300), make([]byte, 250)...), 1},
		{"all-zero", make([]byte, 1000), 1},
		{"mss-alone", append(append(bytes.Repeat([]byte{9}, 100), make([]byte, 100)...), 9), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr := newPair(t, tc.file, mss, nil)
			ab := newPipe()
			var w wire
			w.tap(ab, nil)
			mustFinish(t, pr, ab, newPipe())
			if !bytes.Equal(pr.dst.b, tc.file) {
				t.Fatal("file differs")
			}
			if w.byType[frame.TypeZERO] != tc.zero {
				t.Fatalf("ZERO frames %d, want %d", w.byType[frame.TypeZERO], tc.zero)
			}
		})
	}
}

// A run longer than the cap is several ZEROs, each at a multiple of MSS.
func TestZeroRunCapped(t *testing.T) {
	const mss = 1000
	file := make([]byte, frame.MaxZero*2+12345)
	file[len(file)-1] = 1
	pr := newPair(t, file, mss, nil)
	ab := newPipe()
	var offs []uint64
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypeZERO {
			offs = append(offs, h.Offset)
		}
		return false, 0
	}
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("file differs")
	}
	if len(offs) != 3 {
		t.Fatalf("ZERO offsets %v", offs)
	}
	for _, o := range offs {
		if o%mss != 0 {
			t.Fatalf("unaligned ZERO at %d", o)
		}
	}
}

// Losing ZEROs, first sends and a repair, is repaired with ZERO, and a
// lost ZERO counts its 88-byte datagram as loss, not its length.
func TestZeroLossRepaired(t *testing.T) {
	file := zeroFile(4<<20, 0.6, 2)
	pr := newPair(t, file, frame.InternetPlaintext, nil)
	ab := newPipe()
	var w wire
	var first, retx int
	// Drop the 1st and 3rd ZERO first sends, and the first ZERO repair.
	w.tap(ab, func(h frame.Header) bool {
		if h.Type != frame.TypeZERO {
			return false
		}
		if h.Flags&frame.FlagRETX == 0 {
			first++
			return first == 1 || first == 3
		}
		retx++
		return retx == 1
	})
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("loss inside a zero run not repaired")
	}
	if w.retxZero == 0 {
		t.Fatal("no ZERO repair")
	}
	if lost := pr.s.pacer.Lost(); lost > 64*1152 {
		t.Fatalf("pacer counted %d bytes lost for a few lost ZEROs", lost)
	}
}

// A hole inside a zero run, on the receiver, is repaired with one ZERO.
func TestZeroHoleRepairUsesZero(t *testing.T) {
	file := make([]byte, 64*1000)
	file[0] = 1
	pr := newPair(t, file, 1000, nil)
	// Drop the first ZERO (the run [1000, 64000)) once.
	ab := newPipe()
	var w wire
	dropped := false
	w.tap(ab, func(h frame.Header) bool {
		if h.Type == frame.TypeZERO && !dropped {
			dropped = true
			return true
		}
		return false
	})
	mustFinish(t, pr, ab, newPipe())
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("file differs")
	}
	if w.byType[frame.TypeDATA] > 2 || w.retxZero != 1 {
		t.Fatalf("repair: DATA %d ZERO retx %d", w.byType[frame.TypeDATA], w.retxZero)
	}
}

func TestZeroBadFramesAbortWithoutWrite(t *testing.T) {
	cases := []struct {
		name  string
		off   uint64
		pt    []byte
		flags uint16
		alter func(s, r *Config)
	}{
		{"past-size", 50, frame.EncodeZero(51), 0, nil},
		{"wrap", ^uint64(0) - 3, frame.EncodeZero(8), 0, nil},
		{"len-zero", 0, frame.EncodeZero(0), 0, nil},
		{"above-cap", 0, frame.EncodeZero(frame.MaxZero + 1), 0, nil},
		{"long-payload", 0, make([]byte, 16), 0, nil},
		{"close-ack", 0, frame.EncodeZero(10), frame.FlagCloseAck, nil},
		{"old-receiver", 0, frame.EncodeZero(10), 0, func(s, r *Config) { r.NoZero = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size := 100
			if tc.name == "above-cap" {
				size = frame.MaxZero + 2
			}
			pr := newPair(t, make([]byte, size), 100, tc.alter)
			h := frame.Header{Type: frame.TypeZERO, Flags: tc.flags, Seq: 1, Offset: tc.off, TransferID: 7}
			pr.r.Recv(0, forge(t, h, tc.pt, seal.DirClient))
			if pr.r.Reason() != frame.ReasonProtocol || pr.dst.writes != 0 || pr.cleansR != 1 || pr.commits != 0 {
				t.Fatalf("reason %d writes %d clean %d commit %d", pr.r.Reason(), pr.dst.writes, pr.cleansR, pr.commits)
			}
		})
	}
}

// A ZERO over bytes that are not zero cannot skip the hash: the receiver
// hashes what the file holds and refuses to commit.
func TestZeroOverDataIsHashMismatch(t *testing.T) {
	file := bytes.Repeat([]byte{3}, 5000)
	pr := newPair(t, file, 1000, nil)
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeZERO, Seq: 1 << 40, Offset: 1000, TransferID: 7}, frame.EncodeZero(1000), seal.DirClient))
	_, err := runUntil(pr, newPipe(), newPipe(), 3*time.Second)
	if err == nil || pr.r.Reason() != frame.ReasonHashMismatch || pr.commits != 0 {
		t.Fatalf("err %v reason %d commits %d", err, pr.r.Reason(), pr.commits)
	}
}

// An old receiver never sets ZERO_OK, so it sees only DATA and the file
// lands the same. An old sender ignores the bit.
func TestZeroNegotiation(t *testing.T) {
	file := zeroFile(2<<20, 0.6, 3)
	for _, c := range []struct {
		name string
		old  func(s, r *Config)
	}{
		{"old-receiver", func(s, r *Config) { r.NoZero = true }},
		{"old-sender", func(s, r *Config) { s.NoZero = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr := newPair(t, file, frame.InternetPlaintext, c.old)
			ab, ba := newPipe(), newPipe()
			var w wire
			w.tap(ab, nil)
			var pingBit, pings int
			ba.filt = func(h frame.Header) (bool, time.Duration) {
				if h.Type == frame.TypePING {
					pings++
					if h.Offset&frame.ZeroOK != 0 {
						pingBit++
					}
				}
				return false, 0
			}
			mustFinish(t, pr, ab, ba)
			if !bytes.Equal(pr.dst.b, file) {
				t.Fatal("file differs")
			}
			if w.byType[frame.TypeZERO] != 0 {
				t.Fatalf("%d ZERO frames sent", w.byType[frame.TypeZERO])
			}
			wantBit := 0
			if c.name == "old-sender" {
				wantBit = pings
			}
			if pings == 0 || pingBit != wantBit {
				t.Fatalf("receiver PINGs %d with ZERO_OK %d", pings, pingBit)
			}
		})
	}
}

// The pacer measures wire bytes: a mostly-zero file does not inflate the
// bandwidth estimate past the link, so the DATA after a zero run is not
// sent at a rate the link cannot carry.
func TestZeroDoesNotInflateBandwidth(t *testing.T) {
	// Zero runs in the middle, after rounds have started.
	rng := rand.New(rand.NewSource(4))
	var file []byte
	for i := 0; i < 4; i++ {
		d := make([]byte, 1<<20)
		rng.Read(d)
		file = append(append(file, d...), make([]byte, 4<<20)...)
	}
	pr := newPair(t, file, frame.InternetPlaintext, func(s, r *Config) {
		s.Max, r.Max = 120*time.Second, 120*time.Second
	})
	const bps = 5e6
	ab := &pipe{delay: 10 * time.Millisecond, bps: bps, qcap: 40 * time.Millisecond}
	ba := &pipe{delay: 10 * time.Millisecond}
	var maxBW float64
	pr.step = func() {
		if bw := pr.s.pacer.BW(); bw > maxBW {
			maxBW = bw
		}
	}
	took, err := runUntil(pr, ab, ba, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("file differs")
	}
	t.Logf("took %v, max bandwidth estimate %.2f MB/s on a %.2f MB/s link, %d tail drops, %d bytes lost", took, maxBW/1e6, bps/1e6, ab.drops, pr.s.pacer.Lost())
	if maxBW > 2*bps {
		t.Fatalf("bandwidth estimate %.0f B/s on a %.0f B/s link", maxBW, float64(bps))
	}
}

// osStep, when set, runs after each runOSFile step.
var osStep func(s, r *Peer)

type osPair struct {
	s, r     *Peer
	commits  int
	srcF     *os.File
	dstF     *os.File
	took     time.Duration
	wire     wire
	cpu      time.Duration
	allocDst int64
}

// runOSFile moves path through the engine to a temp *os.File, so the
// receiver takes the safeio.ZeroRange path, over a 100 MB/s, 1 ms pipe.
func runOSFile(t *testing.T, path string, size int64, noZero bool) *osPair {
	t.Helper()
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	key, tok := testMaterial()
	sc := Config{TransferID: 7, Size: uint64(size), Key: key, Token: tok, LocalDir: seal.DirClient, PeerDir: seal.DirAgent,
		Sender: true, HaveHash: true, ExpectHash: sum, Idle: 5 * time.Second, Max: 600 * time.Second, FirstPacket: 2 * time.Second, NoZero: noZero}
	rc := sc
	rc.Key, rc.Token = append([]byte(nil), key...), append([]byte(nil), tok...)
	rc.LocalDir, rc.PeerDir, rc.Sender = seal.DirAgent, seal.DirClient, false
	s, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rc)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(filepath.Join(t.TempDir(), "dst"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dst.Close() })
	op := &osPair{s: s, r: r, srcF: src, dstF: dst}
	if err := s.AttachSource(src); err != nil {
		t.Fatal(err)
	}
	r.AttachDest(dst)
	r.SetHooks(Hooks{Commit: func() error { op.commits++; return dst.Sync() }})
	ab := &pipe{delay: time.Millisecond, bps: 100e6, qcap: 10 * time.Millisecond}
	ba := &pipe{delay: time.Millisecond}
	op.wire.tap(ab, nil)
	pr := &pair{s: s, r: r, src: &memFile{}, dst: &memFile{}}
	if osStep != nil {
		pr.step = func() { osStep(s, r) }
	}
	start := time.Now()
	took, err := runUntil(pr, ab, ba, 300*time.Second)
	op.cpu = time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	op.took = took
	var st syscall.Stat_t
	if err := syscall.Fstat(int(dst.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	op.allocDst = st.Blocks * 512
	return op
}

func sameFiles(t *testing.T, a, b *os.File, size int64) {
	t.Helper()
	ba, bb := make([]byte, 1<<20), make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(ba)) {
		na, _ := a.ReadAt(ba, off)
		nb, _ := b.ReadAt(bb, off)
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			t.Fatalf("files differ near %d", off)
		}
	}
	st, err := b.Stat()
	if err != nil || st.Size() != size {
		t.Fatalf("target size %v %v", st, err)
	}
}

// writeZeroFile writes a size-byte file with frac of it in zero runs of
// 64 KiB to 64 MiB (log-uniform), leaving those runs as holes.
func writeZeroFile(t *testing.T, path string, size int64, frac float64, seed int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, 1<<20)
	for at := int64(0); at < size; {
		// log-uniform 64 KiB .. 64 MiB
		n := int64(float64(64<<10) * pow1024(rng.Float64()))
		if at+n > size {
			n = size - at
		}
		if rng.Float64() >= frac {
			for left := n; left > 0; {
				k := int64(len(buf))
				if k > left {
					k = left
				}
				rng.Read(buf[:k])
				if _, err := f.WriteAt(buf[:k], at+n-left); err != nil {
					t.Fatal(err)
				}
				left -= k
			}
		}
		at += n
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func TestZeroLargeSparseFile(t *testing.T) {
	size := int64(200 << 20)
	if testing.Short() || raceEnabled {
		size = 24 << 20
	}
	dir := t.TempDir()
	zpath := filepath.Join(dir, "zero60")
	rpath := filepath.Join(dir, "random")
	writeZeroFile(t, zpath, size, 0.6, 5)
	writeZeroFile(t, rpath, size, 0, 5)
	countZero := func(path string) int64 {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var z int64
		buf := make([]byte, 1<<20)
		for off := int64(0); off < size; off += int64(len(buf)) {
			n, _ := f.ReadAt(buf, off)
			for _, c := range buf[:n] {
				if c == 0 {
					z++
				}
			}
		}
		return z
	}
	zeroBytes := countZero(zpath)

	type result struct {
		name string
		op   *osPair
	}
	var rs []result
	for _, c := range []struct {
		name   string
		path   string
		noZero bool
	}{
		{"zero60", zpath, false},
		{"zero60-as-DATA", zpath, true},
		{"random", rpath, false},
	} {
		op := runOSFile(t, c.path, size, c.noZero)
		if op.commits != 1 {
			t.Fatalf("%s: commits %d", c.name, op.commits)
		}
		sameFiles(t, op.srcF, op.dstF, size)
		rs = append(rs, result{c.name, op})
		frames, zb := op.s.ZeroStats()
		t.Logf("%-15s size %d zero %.1f%%: virtual %v (%.1f MB/s), wire %d bytes in %d datagrams (%d ZERO carrying %d bytes), wall %v, target allocated %d bytes",
			c.name, size, 100*float64(countZero(c.path))/float64(size), op.took.Round(time.Millisecond), float64(size)/op.took.Seconds()/1e6,
			op.wire.bytes, op.wire.n, frames, zb, op.cpu.Round(time.Millisecond), op.allocDst)
	}
	z, asData := rs[0].op, rs[1].op
	if z.wire.bytes >= asData.wire.bytes/2 || z.took >= asData.took {
		t.Fatalf("ZERO did not help: wire %d vs %d, time %v vs %v", z.wire.bytes, asData.wire.bytes, z.took, asData.took)
	}
	// Sparse where the filesystem keeps an extended range unallocated. A
	// filesystem without sparse files, or one that compresses, decides
	// allocation itself: log, do not fail.
	if z.allocDst >= size-zeroBytes/2 {
		t.Logf("target not sparse on this filesystem: %d bytes allocated for %d non-zero", z.allocDst, size-zeroBytes)
		return
	}
	if asData.allocDst < size*9/10 {
		t.Logf("DATA target also sparse here (compressing filesystem?): %d bytes allocated", asData.allocDst)
	}
	if z.allocDst > (size-zeroBytes)+size/50 {
		t.Errorf("target allocated %d bytes for %d non-zero bytes", z.allocDst, size-zeroBytes)
	}
}

// pow1024 is 1024^x.
func pow1024(x float64) float64 { return math.Pow(1024, x) }

// A range probe over a ZERO counts its charge as lost, and a NACK of a
// ZERO's span counts the same, not its length.
func TestZeroRangeProbeAndNACKCharge(t *testing.T) {
	zw := zeroCharge(4900)
	pr := stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 5000, n: zw, zero: true}})
	pr.s.probes = 1
	pr.s.maybeStall(2 * time.Second)
	if pr.s.wholeProbes != 1 || pr.s.pacer.Lost() != 100+zw {
		t.Fatalf("range probe lost %d", pr.s.pacer.Lost())
	}

	pr = stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 5000, n: zw, zero: true}, {start: 5000, end: 5100, n: 100}})
	pt, err := frame.EncodeNACK([]frame.Span{{Start: 100, End: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	pr.s.Recv(time.Second, forge(t, frame.Header{Type: frame.TypeNACK, TransferID: 7, Seq: 1, Offset: 100}, pt, seal.DirAgent))
	if pr.s.pacer.Lost() != zw || len(pr.s.retx) != 1 {
		t.Fatalf("NACK of a ZERO: lost %d retx %v", pr.s.pacer.Lost(), pr.s.retx)
	}
}

// delivered_bytes that includes zero runs, or lies past the file, never
// gives the pacer more than the wire bytes sent.
func TestZeroWireDelivered(t *testing.T) {
	pr := newPair(t, make([]byte, 20_000), 100, nil)
	s := pr.s
	// 10,000 of 20,000 bytes sent once.
	s.nextNew = 10_000
	s.zeroAbove = []frame.Span{{Start: 100, End: 5000}, {Start: 5100, End: 10_000}}
	zc := zeroCharge(4900)
	s.zeroAboveX = (4900 - zc) * 2
	// Nothing below contig yet; the receiver claims all of it.
	if w := s.wireDelivered(10_000); w != 200+2*zc {
		t.Fatalf("all delivered above contig: %d", w)
	}
	// Only the first DATA and the first ZERO landed, in order.
	s.noteContig(5000, time.Second)
	if s.zeroBelow != 4900-zc || s.zeroAboveX != 4900-zc {
		t.Fatalf("below %d above %d", s.zeroBelow, s.zeroAboveX)
	}
	if w := s.wireDelivered(5000); w != 100+zc {
		t.Fatalf("contig 5000: %d", w)
	}
	// Above contig, a ZERO not yet below it could account for the bytes
	// reported there, so they are not counted yet: short, never over.
	if w := s.wireDelivered(5100); w != 100+zc {
		t.Fatalf("data above contig behind a ZERO: %d", w)
	}
}

// A FEEDBACK or NACK whose contiguous offset is above the bytes sent once
// aborts, so a lying receiver cannot make the pacer count bytes that never
// left; wireDelivered clamps contig as well.
func TestContigAboveSentRefused(t *testing.T) {
	for _, typ := range []uint8{frame.TypeFEEDBACK, frame.TypeNACK} {
		pr := newPair(t, make([]byte, 10_000), 100, nil)
		pr.s.state = stSending
		pr.s.nextNew = 1000
		pt := frame.EncodeFeedback(frame.Feedback{})
		if typ == frame.TypeNACK {
			pt, _ = frame.EncodeNACK(nil)
		}
		pr.s.Recv(time.Second, forge(t, frame.Header{Type: typ, TransferID: 7, Seq: 1, Offset: 10_000}, pt, seal.DirAgent))
		if pr.s.Reason() != frame.ReasonProtocol {
			t.Fatalf("type %d: offset past sent accepted, reason %d", typ, pr.s.Reason())
		}
		if pr.s.pacer.BW() != 0 {
			t.Fatalf("type %d: pacer sampled %f", typ, pr.s.pacer.BW())
		}
	}
	pr := newPair(t, make([]byte, 10_000), 100, nil)
	pr.s.nextNew = 1000
	pr.s.contig = 10_000 // forced: belt and braces
	if w := pr.s.wireDelivered(10_000); w > 1000 {
		t.Fatalf("wireDelivered %d past 1000 sent", w)
	}
	// At the bound is legal.
	pr = newPair(t, make([]byte, 10_000), 100, nil)
	pr.s.state = stSending
	pr.s.nextNew = 1000
	pr.s.Recv(time.Second, forge(t, frame.Header{Type: frame.TypeFEEDBACK, TransferID: 7, Seq: 1, Offset: 1000}, frame.EncodeFeedback(frame.Feedback{DeliveredBytes: 1000}), seal.DirAgent))
	if pr.s.Err() != nil || pr.s.contig != 1000 {
		t.Fatalf("offset == sent refused: %v", pr.s.Err())
	}
}

// First write wins: a ZERO over bytes DATA already filled leaves them, and
// fills only what is missing, also when it overlaps them in part.
func TestZeroAfterDataFirstWriteWins(t *testing.T) {
	for _, c := range []struct {
		name     string
		off, n   uint64
		wantZero [][2]int
	}{
		{"same", 100, 100, nil},
		{"overlap", 150, 100, [][2]int{{200, 250}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr := newPair(t, make([]byte, 1000), 100, nil)
			data := bytes.Repeat([]byte{7}, 100)
			pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeDATA, Seq: 1, Offset: 100, TransferID: 7}, data, seal.DirClient))
			before := pr.r.Delivered()
			pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeZERO, Seq: 2, Offset: c.off, TransferID: 7}, frame.EncodeZero(c.n), seal.DirClient))
			if pr.r.Err() != nil {
				t.Fatal(pr.r.Err())
			}
			if !bytes.Equal(pr.dst.b[100:200], data) {
				t.Fatal("ZERO overwrote DATA")
			}
			want := before
			for _, z := range c.wantZero {
				want += uint64(z[1] - z[0])
				if len(pr.dst.b) < z[1] {
					t.Fatalf("file %d bytes, want through %d", len(pr.dst.b), z[1])
				}
				for _, b := range pr.dst.b[z[0]:z[1]] {
					if b != 0 {
						t.Fatal("missing range not zero")
					}
				}
			}
			if pr.r.Delivered() != want {
				t.Fatalf("delivered %d want %d", pr.r.Delivered(), want)
			}
		})
	}
}

// A ZERO of exactly MaxZero is accepted; MaxZero+1 is not (TestZeroBadFrames).
func TestZeroExactlyMax(t *testing.T) {
	pr := newPair(t, make([]byte, frame.MaxZero+10), 1000, nil)
	pr.r.Recv(0, forge(t, frame.Header{Type: frame.TypeZERO, Seq: 1, Offset: 0, TransferID: 7}, frame.EncodeZero(frame.MaxZero), seal.DirClient))
	if pr.r.Err() != nil || pr.r.Delivered() != frame.MaxZero || len(pr.dst.b) != frame.MaxZero {
		t.Fatalf("err %v delivered %d len %d", pr.r.Err(), pr.r.Delivered(), len(pr.dst.b))
	}
}

// Zero bytes sent as DATA before ZERO_OK arrived and lost are repaired as
// ZERO; the file lands. The controller counts those bytes as the DATA they
// were first sent as (design 4.7, bounded over-count).
func TestDataRepairedAsZero(t *testing.T) {
	file := make([]byte, 64*1000)
	file[len(file)-1] = 1
	pr := newPair(t, file, 1000, nil)
	ab, ba := newPipe(), newPipe()
	// Delay the receiver's PINGs (ZERO_OK), and drop the zero DATA at
	// offset 0 for as long as the sender does not know ZERO_OK.
	var w wire
	w.tap(ab, func(h frame.Header) bool {
		return h.Type == frame.TypeDATA && h.Offset == 0 && !pr.s.peerZero
	})
	ba.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type == frame.TypePING {
			return false, 20 * time.Millisecond
		}
		return false, 0
	}
	mustFinish(t, pr, ab, ba)
	if !bytes.Equal(pr.dst.b, file) {
		t.Fatal("file differs")
	}
	if w.retxZero == 0 {
		t.Fatalf("lost DATA of zeros not repaired as ZERO: %v", w.byType)
	}
}

// A NACK hole that covers a ZERO only in part counts at most the ZERO's
// charge as lost, not the overlap.
func TestZeroPartialNACKCharge(t *testing.T) {
	zw := zeroCharge(4900)
	pr := stalledSender(t, []sentSeg{{start: 0, end: 100, n: 100}, {start: 100, end: 5000, n: zw, zero: true}, {start: 5000, end: 5100, n: 100}})
	pt, err := frame.EncodeNACK([]frame.Span{{Start: 2000, End: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	pr.s.Recv(time.Second, forge(t, frame.Header{Type: frame.TypeNACK, TransferID: 7, Seq: 1, Offset: 100}, pt, seal.DirAgent))
	if pr.s.Err() != nil || pr.s.pacer.Lost() > zw {
		t.Fatalf("partial NACK of a ZERO: lost %d (charge %d) err %v", pr.s.pacer.Lost(), zw, pr.s.Err())
	}
}

// Hash lag on a large sparse file (review question). Set SAHXFER_BIG=1:
// it writes a 2 GB, 90%-zero file and reports the largest lag of the
// receiver's hash behind its contiguous prefix. The virtual clock does not
// charge hashing time; the wall-clock check is the loopback run in the
// report. It fails on any abort (idle included) or a missing commit.
func TestBigSparseHashLag(t *testing.T) {
	if os.Getenv("SAHXFER_BIG") == "" {
		t.Skip("set SAHXFER_BIG=1: writes a 2 GB sparse file")
	}
	size := int64(2 << 30)
	path := filepath.Join(t.TempDir(), "big")
	writeZeroFile(t, path, size, 0.9, 7)
	var maxLag uint64
	osStep = func(s, r *Peer) {
		if lag := r.holes.Contiguous() - r.hashedTo; lag > maxLag {
			maxLag = lag
		}
	}
	defer func() { osStep = nil }()
	start := time.Now()
	op := runOSFile(t, path, size, false)
	if op.commits != 1 {
		t.Fatal("no commit")
	}
	frames, zb := op.s.ZeroStats()
	t.Logf("2 GiB, %d ZERO carrying %d bytes: virtual %v, wall %v; largest hash lag %d bytes",
		frames, zb, op.took.Round(time.Millisecond), time.Since(start).Round(time.Millisecond), maxLag)
}
