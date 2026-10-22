package engine

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

func TestWakeOverdueFeedback(t *testing.T) {
	pr := newPair(t, []byte("abcd"), 4, nil)
	pr.r.Pump(time.Second)
	pr.r.onData(time.Second, frame.Header{Seq: 1}, []byte("ab"))
	pr.r.Pump(time.Second)
	now := time.Second + 20*time.Millisecond
	if got := pr.r.WakeAt(now); got != now {
		t.Fatalf("overdue feedback wakes at %v, want %v", got, now)
	}
	pr.r.Pump(now)
	if got := pr.r.WakeAt(now); got <= now {
		t.Fatalf("serviced feedback spins at %v", got)
	}
}

func TestWakeInactiveReceiverDoesNotSpin(t *testing.T) {
	pr := newPair(t, []byte("abcd"), 4, nil)
	pr.r.Pump(time.Second)
	now := time.Second + 20*time.Millisecond
	if got := pr.r.WakeAt(now); got <= now {
		t.Fatalf("no data: immediate wake %v", got)
	}
	pr.r.onData(now, frame.Header{Offset: 2, Seq: 2}, []byte("cd"))
	pr.r.Pump(now) // NACK the prefix.
	pr.r.onData(now, frame.Header{Seq: 1}, []byte("ab"))
	now += 20 * time.Millisecond
	pr.r.Pump(now)
	if got := pr.r.WakeAt(now); got <= now {
		t.Fatalf("filled hole: immediate wake %v", got)
	}
}

func TestWakeRepairRecheckIsLowerBound(t *testing.T) {
	pr := newPair(t, []byte("abcd"), 4, nil)
	s := pr.s
	s.tick(0)
	s.state, s.sawPeer = stSending, true
	s.ponged = true
	s.nextNew = 4
	s.inflight = []sentSeg{{start: 0, end: 4, n: 4}}
	s.probes = 1
	s.recheckAt = 4 * time.Second
	s.lastProgress = 3 * time.Second
	if got := s.WakeAt(3 * time.Second); got != 4*time.Second {
		t.Fatalf("repair retry wakes at %v", got)
	}
}

func TestCloseClearsOwnedPlaintextScratch(t *testing.T) {
	pr := newPair(t, []byte("abcd"), 4, nil)
	p := pr.s
	if _, err := p.classify(frame.Span{End: 4}, false); err != nil {
		t.Fatal(err)
	}
	scratch := p.sourceBuf
	p.Close()
	if !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("source plaintext retained on close")
	}
}

type countedFile struct {
	memFile
	reads                 int
	shortRead, shortWrite bool
}

func (f *countedFile) ReadAt(b []byte, off int64) (int, error) {
	f.reads++
	if f.shortRead {
		return 0, nil
	}
	return f.memFile.ReadAt(b, off)
}
func (f *countedFile) WriteAt(b []byte, off int64) (int, error) {
	if f.shortWrite {
		return 0, nil
	}
	return f.memFile.WriteAt(b, off)
}

func TestReceiveDirectHashAndOverlap(t *testing.T) {
	for _, reorder := range []bool{false, true} {
		pr := newPair(t, []byte("abcdefgh"), 8, nil)
		f := &countedFile{}
		pr.r.AttachDest(f)
		if reorder {
			pr.r.onData(0, frame.Header{Offset: 2, Seq: 2}, []byte("cd"))
			// Conflicting overlap must retain the already written cd.
			pr.r.onData(0, frame.Header{Seq: 3}, []byte("abXXefgh"))
		} else {
			pr.r.onData(0, frame.Header{Seq: 1}, []byte("abcd"))
			pr.r.onData(0, frame.Header{Offset: 4, Seq: 2}, []byte("efgh"))
		}
		writes := f.writes
		pr.r.onData(0, frame.Header{Seq: 4}, []byte("XXXXXXXX"))
		if f.writes != writes {
			t.Fatal("replay rewrote file")
		}
		want := sha256.Sum256([]byte("abcdefgh"))
		if !bytes.Equal(pr.r.hash.Sum(nil), want[:]) || pr.r.hashedTo != 8 {
			t.Fatal("overlap polluted hash")
		}
		if !reorder && f.reads != 0 {
			t.Fatalf("in-order receive reread %d times", f.reads)
		}
		pr.r.onFIN(0, frame.Header{Offset: 8, Seq: 5}, nil)
		pr.r.Pump(0)
		if !pr.r.Committed() {
			t.Fatalf("commit: %v", pr.r.Err())
		}
	}
}

func TestShortIOFailsClosed(t *testing.T) {
	for _, read := range []bool{false, true} {
		pr := newPair(t, []byte("abcd"), 4, nil)
		f := &countedFile{shortRead: read, shortWrite: !read}
		pr.r.AttachDest(f)
		if read {
			pr.r.onData(0, frame.Header{Offset: 2, Seq: 2}, []byte("cd"))
		}
		pr.r.onData(0, frame.Header{Seq: 1}, []byte("ab"))
		if pr.r.Reason() != frame.ReasonIO || pr.commits != 0 || pr.cleansR != 1 {
			t.Fatalf("short IO not closed: %v", pr.r.Err())
		}
	}
	pr := newPair(t, []byte("abcd"), 4, nil)
	pr.s.src = &countedFile{shortRead: true}
	if _, err := pr.s.classify(frame.Span{End: 4}, false); err != io.ErrUnexpectedEOF {
		t.Fatalf("short source: %v", err)
	}
}

func TestSourceLookaheadOwnsPendingAndRereadsRepairs(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 600<<10)
	pr := newPair(t, body, frame.InternetPlaintext, nil)
	f := &countedFile{memFile: memFile{b: body}}
	pr.s.src = f
	first, err := pr.s.classify(frame.Span{End: uint64(len(body))}, false)
	if err != nil {
		t.Fatal(err)
	}
	for off := uint64(0); off < uint64(len(body)); {
		packet, err := pr.s.classify(frame.Span{Start: off, End: uint64(len(body))}, false)
		if err != nil {
			t.Fatal(err)
		}
		off = packet.sp.End
	}
	if f.reads > 4 {
		t.Fatalf("source reads %d, want <=4", f.reads)
	}
	if !bytes.Equal(first.buf, body[:len(first.buf)]) {
		t.Fatal("pending buffer overwritten")
	}
	body[0] = 9
	repair, err := pr.s.classify(frame.Span{End: 1}, true)
	if err != nil || repair.buf[0] != 9 {
		t.Fatalf("repair did not reread: %v", err)
	}
	if first.buf[0] != 7 {
		t.Fatal("repair mutated pending frame")
	}
}
