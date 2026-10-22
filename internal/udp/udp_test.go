package udp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/relay"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

func testMaterial() ([]byte, []byte) {
	return bytes.Repeat([]byte("K"), seal.KeySize), bytes.Repeat([]byte("T"), seal.TokenSize)
}

type memFile struct {
	b []byte
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
	return len(p), nil
}

type ends struct {
	s, r            *engine.Peer
	dst             *memFile
	commits, cleans int
}

func newEnds(t *testing.T, file []byte, cap uint64) *ends {
	t.Helper()
	key, tok := testMaterial()
	sum := sha256.Sum256(file)
	sc := engine.Config{
		TransferID:  7,
		Size:        uint64(len(file)),
		MSS:         frame.InternetPlaintext,
		Key:         append([]byte(nil), key...),
		Token:       append([]byte(nil), tok...),
		LocalDir:    seal.DirClient,
		PeerDir:     seal.DirAgent,
		Sender:      true,
		Transport:   engine.TransportUDP,
		HaveHash:    true,
		ExpectHash:  sum,
		Idle:        5 * time.Second,
		Max:         20 * time.Second,
		FirstPacket: 2 * time.Second,
		ByteCap:     cap,
	}
	rc := sc
	rc.Key = append([]byte(nil), key...)
	rc.Token = append([]byte(nil), tok...)
	rc.LocalDir = seal.DirAgent
	rc.PeerDir = seal.DirClient
	rc.Sender = false
	s, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := engine.New(rc)
	if err != nil {
		t.Fatal(err)
	}
	e := &ends{s: s, r: r, dst: &memFile{}}
	if err := s.AttachSource(&memFile{b: append([]byte(nil), file...)}); err != nil {
		t.Fatal(err)
	}
	r.AttachDest(e.dst)
	s.SetHooks(engine.Hooks{Cleanup: func() { e.cleans++ }})
	r.SetHooks(engine.Hooks{
		Commit:  func() error { e.commits++; return nil },
		Cleanup: func() { e.cleans++ },
	})
	return e
}

func listen(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func dial(t testing.TB, addr net.Addr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func runPair(t *testing.T, rx, tx Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, rx) }()
	time.Sleep(20 * time.Millisecond)
	txErr := Run(ctx, tx)
	rxErr := <-errc
	if txErr != nil || rxErr != nil {
		t.Fatalf("tx=%v rx=%v", txErr, rxErr)
	}
}

func dropSome(d []byte) bool {
	if len(d) < frame.HeaderSize || d[5] != frame.TypeDATA {
		return false
	}
	if binary.LittleEndian.Uint16(d[6:8])&frame.FlagRETX != 0 {
		return false
	}
	off := binary.LittleEndian.Uint64(d[24:32])
	return off%(4*uint64(frame.InternetPlaintext)) == 0
}

func TestRunRejects(t *testing.T) {
	if err := Run(context.Background(), Config{}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
}

func TestDirectCopy(t *testing.T) {
	file := bytes.Repeat([]byte("abc"), 1700)
	e := newEnds(t, file, 0)
	rxc := listen(t)
	defer rxc.Close()
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	runPair(t,
		Config{Peer: e.r, Conn: rxc},
		Config{Peer: e.s, Conn: txc, Connected: true},
	)
	if e.commits != 1 || e.cleans != 0 || !bytes.Equal(e.dst.b, file) {
		t.Fatalf("commits=%d cleans=%d n=%d", e.commits, e.cleans, len(e.dst.b))
	}
}

func TestDirectEpoch(t *testing.T) {
	file := bytes.Repeat([]byte("e"), 3000)
	e := newEnds(t, file, 0)
	rxc := listen(t)
	defer rxc.Close()
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	epoch := time.Duration(time.Now().UnixNano()) - time.Second
	runPair(t,
		Config{Peer: e.r, Conn: rxc, Epoch: epoch},
		Config{Peer: e.s, Conn: txc, Connected: true, Epoch: epoch},
	)
	if e.commits != 1 || !bytes.Equal(e.dst.b, file) {
		t.Fatalf("commits=%d n=%d", e.commits, len(e.dst.b))
	}
}

func TestDirectLoss(t *testing.T) {
	file := bytes.Repeat([]byte("L"), 5000)
	e := newEnds(t, file, 0)
	rxc := listen(t)
	defer rxc.Close()
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	runPair(t,
		Config{Peer: e.r, Conn: rxc, Filter: dropSome},
		Config{Peer: e.s, Conn: txc, Connected: true},
	)
	if e.commits != 1 || e.cleans != 0 || !bytes.Equal(e.dst.b, file) {
		t.Fatalf("commits=%d cleans=%d n=%d", e.commits, e.cleans, len(e.dst.b))
	}
}

func TestEmptyFile(t *testing.T) {
	e := newEnds(t, nil, 0)
	rxc := listen(t)
	defer rxc.Close()
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	runPair(t,
		Config{Peer: e.r, Conn: rxc},
		Config{Peer: e.s, Conn: txc, Connected: true},
	)
	if e.commits != 1 || e.cleans != 0 || len(e.dst.b) != 0 {
		t.Fatalf("commits=%d cleans=%d n=%d", e.commits, e.cleans, len(e.dst.b))
	}
}

func TestCancel(t *testing.T) {
	e := newEnds(t, bytes.Repeat([]byte("c"), 100), 0)
	rxc := listen(t)
	defer rxc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, Config{Peer: e.r, Conn: rxc}) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err != context.Canceled {
			t.Fatalf("%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hung")
	}
}

func TestRelayCopy(t *testing.T) {
	for _, loss := range []bool{false, true} {
		file := bytes.Repeat([]byte("r"), 5000)
		e := newEnds(t, file, 0)
		rc := listen(t)
		key, tok := testMaterial()
		_ = key
		exp := time.Duration(time.Now().UnixNano()) + time.Minute
		cap := uint64(len(file))
		if loss {
			cap = uint64(len(file)) * 32
		}
		rel := relay.New()
		if err := rel.Admit(7, tok, cap, exp); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = rel.Serve(ctx, rc, nil) }()
		rxc := dial(t, rc.LocalAddr())
		txc := dial(t, rc.LocalAddr())
		rx := Config{Peer: e.r, Conn: rxc, Connected: true}
		tx := Config{Peer: e.s, Conn: txc, Connected: true}
		if loss {
			rx.Filter = dropSome
		}
		runPair(t, rx, tx)
		cancel()
		rxc.Close()
		txc.Close()
		rc.Close()
		if e.commits != 1 || e.cleans != 0 || !bytes.Equal(e.dst.b, file) {
			t.Fatalf("loss=%v commits=%d cleans=%d n=%d", loss, e.commits, e.cleans, len(e.dst.b))
		}
	}
}

// A listening receiver queues its first PING until the sender appears.
// That PONG must not become the receiver's srtt: FEEDBACK cadence is
// max(5 ms, srtt/4), and a 1 s stale sample once held loopback to one
// 10*MSS window per ~250 ms (2 MB hit the grant max).
func TestLateSenderLoopbackThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("realistic-size loopback transfer")
	}
	loopbackThroughput(t, 2_000_000, time.Second, 4*time.Second)
}

// FEEDBACK frees the window at most every 5 ms. A window of 10*MSS
// against that floor held loopback to about 2 MB/s (30 MB in 14.7 s).
// The cap covers max(RTprop, 5 ms) with BBR's window gain
// (docs/design.md section 6).
func TestLoopbackThroughput30MB(t *testing.T) {
	if testing.Short() {
		t.Skip("realistic-size loopback transfer")
	}
	loopbackThroughput(t, 30_000_000, 0, 6*time.Second)
}

func loopbackThroughput(t *testing.T, size int, late, bound time.Duration) {
	t.Helper()
	file := make([]byte, size)
	for i := range file {
		file[i] = byte(i*7 + i>>11)
	}
	e := newEnds(t, file, uint64(len(file)))
	// Preallocate so memFile does not regrow on every in-order write.
	e.dst.b = make([]byte, len(file))
	lc := listen(t)
	dc := dial(t, lc.LocalAddr())
	defer lc.Close()
	defer dc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), bound+late+10*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, Config{Peer: e.r, Conn: lc}) }()
	time.Sleep(late)
	began := time.Now()
	txErr := Run(ctx, Config{Peer: e.s, Conn: dc, Connected: true, Diag: func(line string) { t.Log(line) }})
	rxErr := <-errc
	took := time.Since(began)
	if txErr != nil || rxErr != nil {
		t.Fatalf("tx=%v rx=%v after %v", txErr, rxErr, took)
	}
	if !bytes.Equal(e.dst.b, file) || e.commits != 1 {
		t.Fatalf("file mismatch or commits=%d", e.commits)
	}
	if took > bound {
		t.Fatalf("%d bytes on loopback took %v, want under %v", size, took, bound)
	}
	t.Logf("%d bytes in %v (%.1f MB/s)", size, took, float64(size)/took.Seconds()/1e6)
}

// A forged datagram from another source reaches the listener first. It does
// not open, so it must not pin that source, and the real sender completes.
func TestForgedFirstDatagramDoesNotPin(t *testing.T) {
	file := bytes.Repeat([]byte("f"), 4000)
	e := newEnds(t, file, 0)
	rxc := listen(t)
	defer rxc.Close()
	forger := dial(t, rxc.LocalAddr())
	defer forger.Close()
	other, err := seal.New(bytes.Repeat([]byte("X"), seal.KeySize), bytes.Repeat([]byte("T"), seal.TokenSize))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := other.Seal(frame.Header{Type: frame.TypePING, Seq: 1, TransferID: 7}, nil, seal.DirClient)
	other.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var calls int
	errc := make(chan error, 1)
	go func() {
		errc <- Run(ctx, Config{Peer: e.r, Conn: rxc, Progress: func(uint64) { calls++ }})
	}()
	for _, d := range [][]byte{[]byte("junk"), forged} {
		if _, err := forger.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(30 * time.Millisecond)
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	txErr := Run(ctx, Config{Peer: e.s, Conn: txc, Connected: true})
	rxErr := <-errc
	if txErr != nil || rxErr != nil {
		t.Fatalf("tx=%v rx=%v", txErr, rxErr)
	}
	if e.commits != 1 || !bytes.Equal(e.dst.b, file) || calls < 1 {
		t.Fatalf("commits=%d n=%d progress=%d", e.commits, len(e.dst.b), calls)
	}
}

// A done context cancels the peer and sends one ABORT cancelled, so the
// other side stops within an RTT instead of idling out.
func TestCancelSendsAbort(t *testing.T) {
	e := newEnds(t, bytes.Repeat([]byte("a"), 50000), 0)
	var sClean, rClean int
	e.s.SetHooks(engine.Hooks{Cleanup: func() { sClean++ }})
	e.r.SetHooks(engine.Hooks{Cleanup: func() { rClean++ }})
	rxc := listen(t)
	defer rxc.Close()
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	noData := func(d []byte) bool { return len(d) >= frame.HeaderSize && d[5] == frame.TypeDATA }
	rctx, rcancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Run(rctx, Config{Peer: e.r, Conn: rxc, Filter: noData}) }()
	tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer tcancel()
	txc2 := make(chan error, 1)
	go func() { txc2 <- Run(tctx, Config{Peer: e.s, Conn: txc, Connected: true}) }()
	time.Sleep(200 * time.Millisecond)
	rcancel()
	if err := <-errc; err != context.Canceled {
		t.Fatalf("rx %v", err)
	}
	err := <-txc2
	ae, ok := err.(*engine.AbortError)
	if !ok || ae.Reason != frame.ReasonCancelled {
		t.Fatalf("tx %v", err)
	}
	if sClean != 1 || rClean != 1 {
		t.Fatalf("cleans=%d,%d", sClean, rClean)
	}
}

// 100 datagrams with a valid header and a wrong route token reach the
// listener before the real sender. Unpinned failures spend no budget, so
// the grant survives and the transfer completes.
func TestBadDatagramsBeforePinDoNotKill(t *testing.T) {
	file := bytes.Repeat([]byte("b"), 4000)
	e := newEnds(t, file, 0)
	rxc := listen(t)
	defer rxc.Close()
	forger := dial(t, rxc.LocalAddr())
	defer forger.Close()
	key, _ := testMaterial()
	other, err := seal.New(key, bytes.Repeat([]byte("W"), seal.TokenSize))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, Config{Peer: e.r, Conn: rxc}) }()
	for i := 1; i <= 100; i++ {
		d, err := other.Seal(frame.Header{Type: frame.TypeDATA, Seq: uint64(i), TransferID: 7}, []byte("x"), seal.DirClient)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forger.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	other.Wipe()
	time.Sleep(50 * time.Millisecond)
	txc := dial(t, rxc.LocalAddr())
	defer txc.Close()
	txErr := Run(ctx, Config{Peer: e.s, Conn: txc, Connected: true})
	if rxErr := <-errc; txErr != nil || rxErr != nil {
		t.Fatalf("tx=%v rx=%v", txErr, rxErr)
	}
	if e.commits != 1 || !bytes.Equal(e.dst.b, file) {
		t.Fatalf("commits=%d n=%d", e.commits, len(e.dst.b))
	}
}
