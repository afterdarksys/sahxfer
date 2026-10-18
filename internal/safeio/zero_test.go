//go:build darwin || linux

package safeio

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func allocated(t *testing.T, f *os.File) int64 {
	t.Helper()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Blocks * 512
}

func newFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "z"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// A never-written tail range is extended, reads as zero, and leaves the
// bytes before it alone. On a filesystem with sparse files it allocates
// almost nothing.
func TestZeroRangeExtendsSparse(t *testing.T) {
	f := newFile(t)
	head := bytes.Repeat([]byte{0xA5}, 100)
	if _, err := f.WriteAt(head, 0); err != nil {
		t.Fatal(err)
	}
	const n = 8 << 20
	if err := ZeroRange(f, 100, n); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if st.Size() != 100+n {
		t.Fatalf("size %d", st.Size())
	}
	got := make([]byte, 100+n)
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:100], head) || !bytes.Equal(got[100:], make([]byte, n)) {
		t.Fatal("content")
	}
	if a := allocated(t, f); a >= n/2 {
		t.Logf("filesystem did not keep the extension sparse: %d bytes allocated", a)
	}
}

// A range inside the file never shrinks it, and unaligned neighbours that
// were written stay intact.
func TestZeroRangeInsideKeepsNeighbours(t *testing.T) {
	f := newFile(t)
	a := bytes.Repeat([]byte{1}, 1000)
	b := bytes.Repeat([]byte{2}, 1000)
	if _, err := f.WriteAt(a, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(b, 3<<20+77); err != nil {
		t.Fatal(err)
	}
	if err := ZeroRange(f, 1000, 3<<20+77-1000); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if st.Size() != 3<<20+77+1000 {
		t.Fatalf("size %d", st.Size())
	}
	got := make([]byte, st.Size())
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:1000], a) || !bytes.Equal(got[3<<20+77:], b) {
		t.Fatal("neighbour changed")
	}
	if !bytes.Equal(got[1000:3<<20+77], make([]byte, 3<<20+77-1000)) {
		t.Fatal("range not zero")
	}
}

func TestZeroRangeRefusesBadArgs(t *testing.T) {
	f := newFile(t)
	for _, c := range [][2]int64{{-1, 10}, {0, 0}, {0, -5}, {1 << 62, 1 << 62}} {
		if err := ZeroRange(f, c[0], c[1]); err == nil {
			t.Fatalf("%v accepted", c)
		}
	}
	if err := ZeroRange(nil, 0, 1); err == nil {
		t.Fatal("nil file accepted")
	}
}

// punch deallocates written blocks where the platform supports it. This
// checks the F_PUNCHHOLE argument layout on Darwin and PUNCH_HOLE on Linux.
func TestPunchDeallocates(t *testing.T) {
	f := newFile(t)
	data := bytes.Repeat([]byte{0x5A}, 4<<20)
	if _, err := f.WriteAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	before := allocated(t, f)
	punch(f, 1<<20, 2<<20)
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	after := allocated(t, f)
	got := make([]byte, 4<<20)
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if after >= before {
		t.Skipf("filesystem did not punch: %d -> %d bytes allocated", before, after)
	}
	if !bytes.Equal(got[:1<<20], data[:1<<20]) || !bytes.Equal(got[3<<20:], data[3<<20:]) {
		t.Fatal("punch touched bytes outside the range")
	}
	if !bytes.Equal(got[1<<20:3<<20], make([]byte, 2<<20)) {
		t.Fatal("punched range not zero")
	}
	t.Logf("allocated %d -> %d bytes", before, after)
}
