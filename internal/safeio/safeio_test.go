package safeio_test

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/safeio"
)

func TestOpenAndCommit(t *testing.T) {
	root := physDir(t)
	if err := os.Mkdir(filepath.Join(root, "rel"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := mustRoot(t, root)
	defer r.Close()

	tmp, err := r.CreateTemp("rel/app.bin", "xfr_abcdefgh", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.File.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	info, err := tmp.File.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := tmp.Commit(false); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Remove(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "rel", "app.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("body %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "rel", ".sahxfer-xfr_abcdefgh.part")); !os.IsNotExist(err) {
		t.Fatal("temp name still present")
	}

	f, err := r.OpenRegular("rel/app.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != "payload" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}

func TestExistsLeavesTarget(t *testing.T) {
	root := physDir(t)
	target := filepath.Join(root, "app.bin")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustRoot(t, root)
	defer r.Close()
	_, err := r.CreateTemp("app.bin", "xfr_abcdefgh", false)
	if err == nil || err.Error() != "exists" {
		t.Fatalf("got %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep" {
		t.Fatalf("target changed %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sahxfer-xfr_abcdefgh.part")); !os.IsNotExist(err) {
		t.Fatal("temp created")
	}
}

func TestSymlinkRefused(t *testing.T) {
	root := physDir(t)
	other := physDir(t)
	if err := os.WriteFile(filepath.Join(other, "secret"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "secret"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}
	r := mustRoot(t, root)
	defer r.Close()

	_, err := r.OpenRegular("escape/secret")
	if err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("dir symlink %v", err)
	}
	_, err = r.OpenRegular("filelink")
	if err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("file symlink %v", err)
	}
	_, err = r.CreateTemp("filelink", "xfr_abcdefgh", true)
	if err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("create through symlink %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, ".sahxfer-xfr_abcdefgh.part")); !os.IsNotExist(err) {
		t.Fatal("wrote through symlink")
	}

	linkRoot := filepath.Join(physDir(t), "rootlink")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := safeio.OpenRoot(linkRoot); err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("root symlink %v", err)
	}
}

func TestPathAndFifo(t *testing.T) {
	root := physDir(t)
	r := mustRoot(t, root)
	defer r.Close()

	for _, p := range []string{"../x", "a/../../etc/passwd", ".sahxfer-xfr_a.part", "dir/.sahsync-upl.part"} {
		_, err := r.OpenRegular(p)
		if err == nil {
			t.Fatalf("opened %q", p)
		}
		if p[0] == '.' || len(p) > 4 && p[len(p)-5:] == ".part" {
			if err.Error() != "reserved_name" && err.Error() != "bad_path" {
				t.Fatalf("%q %v", p, err)
			}
		}
	}
	_, err := r.OpenRegular(".sahxfer-xfr_a.part")
	if err == nil || err.Error() != "reserved_name" {
		t.Fatalf("reserved %v", err)
	}
	_, err = r.CreateTemp("ok", "not-a-grant", false)
	if err == nil || err.Error() != "bad_path" {
		t.Fatalf("grant id %v", err)
	}
	_, err = r.CreateTemp(".", "xfr_abcdefgh", false)
	if err == nil || err.Error() != "not_a_file" {
		t.Fatalf("dot %v", err)
	}

	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = r.OpenRegular("pipe")
	if err == nil || err.Error() != "not_a_file" {
		t.Fatalf("fifo %v", err)
	}
	_, err = r.CreateTemp("pipe", "xfr_abcdefgh", true)
	if err == nil || err.Error() != "not_a_file" {
		t.Fatalf("fifo create %v", err)
	}

	if err := os.Mkdir(filepath.Join(root, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = r.OpenRegular("subdir")
	if err == nil || err.Error() != "not_a_file" {
		t.Fatalf("dir %v", err)
	}
}

func TestClientFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	if err := os.WriteFile(src, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := safeio.OpenRead(src)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	link := filepath.Join(dir, "link")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := safeio.OpenRead(link); err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("open read symlink %v", err)
	}
	if _, err := safeio.CreateNew(link); err == nil || err.Error() != "symlink_refused" {
		t.Fatalf("create symlink %v", err)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatal("create followed symlink")
	}

	dst := filepath.Join(dir, "dst.bin")
	out, err := safeio.CreateNew(dst)
	if err != nil {
		t.Fatal(err)
	}
	out.Close()
	if _, err := safeio.CreateNew(dst); err == nil || err.Error() != "exists" {
		t.Fatalf("clobber %v", err)
	}

	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := safeio.OpenRead(fifo); err == nil || err.Error() != "not_a_file" {
		t.Fatalf("client fifo %v", err)
	}
}

func TestBadRoot(t *testing.T) {
	dir := physDir(t)
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := safeio.OpenRoot(file); err == nil || err.Error() != "bad_root" {
		t.Fatalf("file root %v", err)
	}
	if _, err := safeio.OpenRoot(filepath.Join(dir, "missing")); err == nil || err.Error() != "bad_root" {
		t.Fatalf("missing root %v", err)
	}
	if _, err := safeio.OpenRoot("rel"); err == nil || err.Error() != "bad_root" {
		t.Fatalf("relative root %v", err)
	}
}

// physDir is a temp directory with no symlink components. On Darwin,
// t.TempDir is under /var, and /var is a symlink. OpenRoot refuses that.
func physDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustRoot(t *testing.T, path string) *safeio.Root {
	t.Helper()
	r, err := safeio.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A target created after the temp, before the commit, is not replaced
// without overwrite: exists, and the target keeps its bytes.
func TestCommitRaceKeepsTarget(t *testing.T) {
	root := physDir(t)
	r := mustRoot(t, root)
	defer r.Close()
	tmp, err := r.CreateTemp("app.bin", "xfr_race0001", false)
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Remove()
	if _, err := tmp.File.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "app.bin")
	if err := os.WriteFile(target, []byte("racer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Commit(false); err == nil || err.Error() != "exists" {
		t.Fatalf("commit %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "racer" {
		t.Fatalf("target %q %v", got, err)
	}
}
