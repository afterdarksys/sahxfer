package hole

import (
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

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
