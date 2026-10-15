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

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func dial(t *testing.T, addr net.Addr) *net.UDPConn {
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
