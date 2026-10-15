//go:build unix

package secfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/code"
)

func TestOpenAndCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	f, err := CreateExcl(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	rf, _, err := OpenRead(path)
	if err != nil {
		t.Fatal(err)
	}
	rf.Close()
	if _, err := CreateExcl(path); !is(err, "exists") {
		t.Fatalf("second create: %v", err)
	}
}

func TestSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenRead(link); !is(err, "symlink_refused") {
		t.Fatalf("read link: %v", err)
	}
	if _, err := CreateExcl(link); !is(err, "symlink_refused") {
		t.Fatalf("create link: %v", err)
	}
	if _, _, err := OpenRead(filepath.Join(dir, "missing")); !is(err, "not_found") {
		t.Fatal(err)
	}
}

func TestLooseModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenRead(path); !is(err, "auth") {
		t.Fatalf("mode: %v", err)
	}
	tight := filepath.Join(dir, "tight")
	if err := os.WriteFile(tight, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := CurrentUID
	CurrentUID = func() int { return 1 }
	t.Cleanup(func() { CurrentUID = old })
	if _, _, err := OpenRead(tight); !is(err, "auth") {
		t.Fatalf("owner: %v", err)
	}
	if err := CheckDir0700(dir); !is(err, "auth") {
		t.Fatalf("dir owner: %v", err)
	}
}

func TestDirMode(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tok")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir0700(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir0700(sub); !is(err, "auth") {
		t.Fatalf("0755: %v", err)
	}
	link := filepath.Join(dir, "dlink")
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir0700(link); !is(err, "symlink_refused") {
		t.Fatalf("dir link: %v", err)
	}
}

func is(err error, c string) bool {
	e, ok := err.(*code.Error)
	return ok && e.Error() == c
}
