// Package safeio opens paths inside a grant root.
//
// Threats: a path that escapes the root, a symlink (including a final
// component), a FIFO that would block, a reserved temp name supplied by the
// caller, and a commit that replaces an existing target when overwrite is
// false. Linux uses openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|
// RESOLVE_NO_MAGICLINKS and renameat2(RENAME_NOREPLACE). Darwin walks one
// component at a time with O_NOFOLLOW. That walk is not openat2. Darwin
// commits with renameatx_np(RENAME_EXCL) when overwrite is false. A
// kernel without openat2 is agent_unsupported. There is
// no fallback. This package does not drop uid: Go cannot drop privileges on
// one goroutine. The agent must spawn the helper as pty_user.
//
// It does not defend a hard link inside the root that points outside it.
package safeio

import (
	"io"
	"os"
	"strings"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/pathx"
)

// LockExclusive takes a nonblocking advisory lock until Root.Close. All writers
// of the local stream store must participate; it is not an authorization check.
func (r *Root) LockExclusive() error {
	if r == nil || r.fd < 0 {
		return code.New("bad_root")
	}
	if r.lock >= 0 {
		return nil
	}
	// Linux roots are O_PATH descriptors. Open the same directory beneath
	// that descriptor for flock; never resolve its pathname again.
	fd, err := openDir(r.fd, ".")
	if err != nil {
		return err
	}
	if err := lockfd(fd); err != nil {
		closefd(fd)
		return err
	}
	r.lock = fd
	return nil
}

// Sync persists directory-entry changes after a rename.
func (r *Root) Sync() error {
	if r == nil || r.fd < 0 {
		return code.New("bad_root")
	}
	fd, err := openDir(r.fd, ".")
	if err != nil {
		return err
	}
	defer closefd(fd)
	return fsyncfd(fd)
}

// Empty checks initialization without following paths or enumerating an
// unbounded directory. Call only on a newly opened, exclusively locked root.
func (r *Root) Empty() (bool, error) {
	if r == nil || r.fd < 0 {
		return false, code.New("bad_root")
	}
	fd, err := openDir(r.fd, ".")
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), "root")
	defer f.Close()
	entries, err := f.ReadDir(1)
	if err != nil && err != io.EOF {
		return false, err
	}
	return len(entries) == 0, nil
}

// Root is a directory fd for one grant root.
type Root struct {
	fd   int
	path string
	lock int
}

// OpenRoot opens path as a directory without following a symlink.
func OpenRoot(path string) (*Root, error) {
	if err := pathx.CheckRoot(path); err != nil {
		return nil, err
	}
	fd, err := openRoot(path)
	if err != nil {
		return nil, err
	}
	return &Root{fd: fd, path: path, lock: -1}, nil
}

// Close releases the root fd.
func (r *Root) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	if r.lock >= 0 {
		_ = closefd(r.lock)
		r.lock = -1
	}
	err := closefd(r.fd)
	r.fd = -1
	return err
}

// OpenRegular opens a regular file read-only. A FIFO, directory, or symlink
// is refused before any byte is read.
func (r *Root) OpenRegular(rel string) (*os.File, error) {
	if r == nil || r.fd < 0 {
		return nil, code.New("bad_root")
	}
	dirs, name, err := pathx.Parent(rel)
	if err != nil {
		return nil, err
	}
	parent, err := r.walk(dirs)
	if err != nil {
		return nil, err
	}
	defer closefd(parent)
	fd, err := openReg(parent, name)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		closefd(fd)
		return nil, code.New("io")
	}
	return f, nil
}

// Temp is an uncommitted .sahxfer-<grant_id>.part file.
type Temp struct {
	File     *os.File
	parent   int
	tempName string
	final    string
}

// CreateTemp creates the temp in the target's parent. An existing target
// with overwrite false is exists, and the target is not opened for write.
func (r *Root) CreateTemp(rel, grantID string, overwrite bool) (*Temp, error) {
	if r == nil || r.fd < 0 {
		return nil, code.New("bad_root")
	}
	if !validGrantID(grantID) {
		return nil, code.New("bad_path")
	}
	dirs, name, err := pathx.Parent(rel)
	if err != nil {
		return nil, err
	}
	parent, err := r.walk(dirs)
	if err != nil {
		return nil, err
	}
	kind, err := statName(parent, name)
	if err != nil {
		closefd(parent)
		return nil, err
	}
	if kind == kindRegular && !overwrite {
		closefd(parent)
		return nil, code.New("exists")
	}
	if kind == kindOther {
		closefd(parent)
		return nil, code.New("not_a_file")
	}
	tempName := ".sahxfer-" + grantID + ".part"
	fd, err := createExcl(parent, tempName)
	if err != nil {
		closefd(parent)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), tempName)
	if f == nil {
		closefd(fd)
		closefd(parent)
		return nil, code.New("io")
	}
	return &Temp{File: f, parent: parent, tempName: tempName, final: name}, nil
}

// Commit fsyncs the temp file, fsyncs the parent directory, then renames.
func (t *Temp) Commit(overwrite bool) error {
	if t == nil || t.File == nil || t.parent < 0 {
		return code.New("io")
	}
	if err := t.File.Sync(); err != nil {
		return code.New("io")
	}
	if err := fsyncfd(t.parent); err != nil {
		return code.New("io")
	}
	return renameExclusive(t.parent, t.tempName, t.final, overwrite)
}

// Remove deletes the temp name. After a successful Commit the temp name is
// already gone; the target is left in place.
func (t *Temp) Remove() error {
	if t == nil {
		return nil
	}
	var err error
	if t.parent >= 0 && t.tempName != "" {
		if uerr := unlinkAt(t.parent, t.tempName); uerr != nil && !isAbsent(uerr) {
			err = uerr
		}
	}
	if t.File != nil {
		_ = t.File.Close()
		t.File = nil
	}
	if t.parent >= 0 {
		closefd(t.parent)
		t.parent = -1
	}
	if err != nil {
		return code.New("io")
	}
	return nil
}

// RemoveTemp deletes .sahxfer-<grant_id>.part in the parent of rel, and
// nothing else. The name is fixed by the grant id, so a sweep after a crash
// cannot be aimed at another file. An absent temp is not an error.
func (r *Root) RemoveTemp(rel, grantID string) error {
	if r == nil || r.fd < 0 {
		return code.New("bad_root")
	}
	if !validGrantID(grantID) {
		return code.New("bad_path")
	}
	dirs, _, err := pathx.Parent(rel)
	if err != nil {
		return err
	}
	parent, err := r.walk(dirs)
	if err != nil {
		if e, ok := err.(*code.Error); ok && e.C == "not_found" {
			return nil
		}
		return err
	}
	defer closefd(parent)
	if err := unlinkAt(parent, ".sahxfer-"+grantID+".part"); err != nil && !isAbsent(err) {
		return code.New("io")
	}
	return nil
}

func (r *Root) walk(dirs []string) (int, error) {
	parent, err := dupfd(r.fd)
	if err != nil {
		return -1, code.New("io")
	}
	for _, name := range dirs {
		next, err := openDir(parent, name)
		closefd(parent)
		if err != nil {
			return -1, err
		}
		parent = next
	}
	return parent, nil
}

// validGrantID is ^xfr_[A-Za-z0-9_-]{8,64}$, the grant package's rule.
func validGrantID(id string) bool {
	if len(id) < 4+8 || len(id) > 4+64 || !strings.HasPrefix(id, "xfr_") {
		return false
	}
	for i := 4; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// OpenRead opens path as a regular file without following a final symlink.
// Used for the client source, which is not inside a grant root.
func OpenRead(path string) (*os.File, error) {
	if path == "" || strings.Contains(path, "\x00") {
		return nil, code.New("bad_path")
	}
	return openRead(path)
}

// CreateNew creates path mode 0600 and refuses to clobber or follow a final symlink.
func CreateNew(path string) (*os.File, error) {
	if path == "" || strings.Contains(path, "\x00") {
		return nil, code.New("bad_path")
	}
	return createNew(path)
}
