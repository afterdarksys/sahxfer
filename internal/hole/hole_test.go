package hole

import (
	"math/rand"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

func TestMissingVisitorAndAcceptMatchBitmap(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	for trial := 0; trial < 50; trial++ {
		m, _ := New(256)
		var present [256]bool
		var delivered uint64
		for seq := uint64(1); seq <= 100; seq++ {
			start := rng.Intn(256)
			end := start + 1 + rng.Intn(256-start)
			var want uint64
			for i := start; i < end; i++ {
				if !present[i] {
					want++
				}
			}
			var visited uint64
			if err := m.VisitMissing(uint64(start), uint64(end), func(lo, hi uint64) error {
				for i := lo; i < hi; i++ {
					if present[i] {
						t.Fatal("visited filled byte")
					}
					visited++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			n, err := m.Accept(uint64(start), uint64(end), seq, time.Duration(seq)*time.Millisecond)
			if err != nil || n != want || visited != want {
				t.Fatalf("accept=%d visit=%d want=%d err=%v", n, visited, want, err)
			}
			for i := start; i < end; i++ {
				present[i] = true
			}
			delivered += want
			var prefix uint64
			for prefix < 256 && present[prefix] {
				prefix++
			}
			if m.Delivered() != delivered || m.Contiguous() != prefix {
				t.Fatal("bitmap mismatch")
			}
		}
	}
}

func TestEmptyFile(t *testing.T) {
	m, err := New(0)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Empty() || m.Contiguous() != 0 || m.Delivered() != 0 {
		t.Fatal(m)
	}
	if _, err := m.Accept(0, 1, 1, 0); err != ErrRange {
		t.Fatal(err)
	}
}

func TestSizeRejected(t *testing.T) {
	if _, err := New(1 << 63); err != ErrSize {
		t.Fatal(err)
	}
}

func TestReplayDoesNotGrow(t *testing.T) {
	m, _ := New(100)
	n, err := m.Accept(0, 40, 1, 0)
	if err != nil || n != 40 {
		t.Fatalf("n=%d %v", n, err)
	}
	n, err = m.Accept(0, 40, 2, time.Millisecond)
	if err != nil || n != 0 {
		t.Fatalf("replay n=%d %v", n, err)
	}
	if m.Delivered() != 40 {
		t.Fatal(m.Delivered())
	}
	n, err = m.Accept(20, 50, 3, time.Millisecond)
	if err != nil || n != 10 {
		t.Fatalf("partial n=%d %v", n, err)
	}
	if m.Delivered() != 50 || m.Contiguous() != 50 {
		t.Fatalf("del %d contig %d", m.Delivered(), m.Contiguous())
	}
}

func TestPastSizeDoesNotMutate(t *testing.T) {
	m, _ := New(100)
	if _, err := m.Accept(90, 101, 1, 0); err != ErrRange {
		t.Fatal(err)
	}
	if _, err := m.Accept(50, 40, 1, 0); err != ErrRange {
		t.Fatal(err)
	}
	if m.Delivered() != 0 || m.Contiguous() != 0 {
		t.Fatalf("mutated del %d contig %d", m.Delivered(), m.Contiguous())
	}
}

func TestTrailingIsNotAHoleUntilFIN(t *testing.T) {
	m, _ := New(300)
	if _, err := m.Accept(0, 100, 1, 0); err != nil {
		t.Fatal(err)
	}
	if got := m.Mature(time.Hour, time.Millisecond); len(got) != 0 {
		t.Fatalf("trailing nack before FIN: %+v", got)
	}
}

func TestInteriorMaturesImmediately(t *testing.T) {
	// Last range arrives before the first. The hole in front is interior.
	m, _ := New(200)
	if _, err := m.Accept(100, 200, 2, 0); err != nil {
		t.Fatal(err)
	}
	got := m.Mature(0, time.Millisecond)
	if len(got) != 1 || got[0] != (frame.Span{Start: 0, End: 100}) {
		t.Fatalf("mature %+v", got)
	}
	if _, err := m.Accept(0, 100, 1, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !m.Empty() || m.Delivered() != 200 || m.Contiguous() != 200 {
		t.Fatalf("del %d contig %d empty %v", m.Delivered(), m.Contiguous(), m.Empty())
	}
	if got := m.Mature(time.Second, time.Millisecond); len(got) != 0 {
		t.Fatalf("nack after fill %+v", got)
	}
}

func TestTrailingMaturesAfterFINAndAge(t *testing.T) {
	m, _ := New(300)
	// Punch the middle. Left hole is interior. Right hole is a young tail.
	now := 5 * time.Millisecond
	if _, err := m.Accept(100, 200, 4, now); err != nil {
		t.Fatal(err)
	}
	got := m.Mature(now, time.Millisecond)
	if len(got) != 1 || got[0].End != 100 {
		t.Fatalf("only the interior hole should be mature, got %+v", got)
	}
	m.NoteFIN(9, now)
	if got := m.Mature(now, time.Millisecond); len(got) != 1 {
		t.Fatalf("tail mature before age: %+v", got)
	}
	later := now + 3*time.Millisecond
	got = m.Mature(later, time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("tail should be mature, got %+v", got)
	}
	// Oldest first: the interior hole was born at 0.
	if got[0].Start != 0 || got[1].Start != 200 {
		t.Fatalf("order %+v", got)
	}
}

func TestReorderOfPrefixDoesNotNackTail(t *testing.T) {
	m, _ := New(100)
	if _, err := m.Accept(0, 40, 1, 0); err != nil {
		t.Fatal(err)
	}
	// A later seq has been accepted, and time has passed, but there is no FIN.
	got := m.Mature(time.Second, time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("tail treated as loss: %+v", got)
	}
}
