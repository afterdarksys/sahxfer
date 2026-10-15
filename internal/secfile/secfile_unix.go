//go:build unix

// Package secfile opens a secret file without following a symlink.
//
// Threats: a symlink swapped in for a token or grant file, a file owned by
// another user, or a mode that lets the group or other users read it.
// Errors are codes and do not include the path. It does not encrypt the
// file and does not stop the account's own user.
package secfile

import (
	"errors"
	"os"
	"syscall"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// CurrentUID is the owner a secret file must have. Tests replace it.
var CurrentUID = os.Getuid

// OpenRead opens path with O_NOFOLLOW and checks the open descriptor.
func OpenRead(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, openErr(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, code.New("io")
	}
	if err := checkOwned(fi); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// CheckDir0700 requires a real directory owned by the user, mode 0700.
func CheckDir0700(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return code.New("not_found")
		}
		return code.New("io")
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return code.New("symlink_refused")
	}
	if !fi.IsDir() {
		return code.New("auth")
	}
	uid, ok := owner(fi)
	if !ok || uid != CurrentUID() {
		return code.New("auth")
	}
	if fi.Mode().Perm() != 0o700 {
		return code.New("auth")
	}
	return nil
}

// CreateExcl creates path mode 0600 and refuses to clobber or follow a symlink.
func CreateExcl(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, code.New("symlink_refused")
		}
		return nil, code.New("exists")
	}
	if !os.IsNotExist(err) {
		return nil, code.New("io")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, openErr(err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, code.New("io")
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, code.New("io")
	}
	if err := checkOwned(st); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}

func checkOwned(fi os.FileInfo) error {
	if fi == nil || !fi.Mode().IsRegular() {
		return code.New("auth")
	}
	uid, ok := owner(fi)
	if !ok || uid != CurrentUID() {
		return code.New("auth")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return code.New("auth")
	}
	return nil
}

func owner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return int(st.Uid), true
}

func openErr(err error) error {
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return code.New("not_found")
	}
	if errors.Is(err, syscall.ELOOP) {
		return code.New("symlink_refused")
	}
	if os.IsExist(err) {
		return code.New("exists")
	}
	return code.New("io")
}
