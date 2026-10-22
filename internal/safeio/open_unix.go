//go:build darwin || linux

package safeio

import (
	"errors"
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
	"golang.org/x/sys/unix"
)

func closefd(fd int) error {
	if fd < 0 {
		return nil
	}
	if err := unix.Close(fd); err != nil {
		return code.New("io")
	}
	return nil
}

func fsyncfd(fd int) error {
	if err := unix.Fsync(fd); err != nil {
		return code.New("io")
	}
	return nil
}

func lockfd(fd int) error {
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return code.New("busy")
		}
		return code.New("io")
	}
	return nil
}

func unlinkAt(dirfd int, name string) error {
	return unix.Unlinkat(dirfd, name, 0)
}

func isAbsent(err error) bool {
	return errors.Is(err, unix.ENOENT)
}

// symlinkErr reports a final component that is a symlink. Darwin returns
// ENOTDIR (not ELOOP) when O_DIRECTORY is combined with O_NOFOLLOW.
func symlinkErr(dirfd int, name string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) || (errors.Is(err, unix.ENOTDIR) && isSymlink(dirfd, name)) {
		return code.New("symlink_refused")
	}
	return nil
}

func isSymlink(dirfd int, name string) bool {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK
}

func statName(dirfd int, name string) (int, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return kindAbsent, nil
		}
		return 0, mapOpenErr(err, false)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return kindRegular, nil
	case unix.S_IFLNK:
		return 0, code.New("symlink_refused")
	default:
		return kindOther, nil
	}
}

func openRead(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, mapOpenErr(err, false)
	}
	if err := requireRegular(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return fileFrom(fd, path)
}

func createNew(path string) (*os.File, error) {
	if err := refuseSymlink(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, mapOpenErr(err, false)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return nil, code.New("io")
	}
	return fileFrom(fd, path)
}

// refuseSymlink stats the final name without following it. A name that is
// absent is fine. This catches a symlink before O_CREAT.
func refuseSymlink(path string) error {
	var st unix.Stat_t
	err := unix.Fstatat(unix.AT_FDCWD, path, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return mapOpenErr(err, false)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return code.New("symlink_refused")
	}
	return nil
}

func requireRegular(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return code.New("io")
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return nil
	case unix.S_IFLNK:
		return code.New("symlink_refused")
	default:
		return code.New("not_a_file")
	}
}

func fileFrom(fd int, name string) (*os.File, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		unix.Close(fd)
		return nil, code.New("io")
	}
	return f, nil
}

func mapOpenErr(err error, root bool) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ELOOP):
		return code.New("symlink_refused")
	case errors.Is(err, unix.ENOENT):
		if root {
			return code.New("bad_root")
		}
		return code.New("not_found")
	case errors.Is(err, unix.ENOTDIR):
		if root {
			return code.New("bad_root")
		}
		return code.New("bad_path")
	case errors.Is(err, unix.EEXIST):
		return code.New("exists")
	case errors.Is(err, unix.EXDEV), errors.Is(err, unix.ENAMETOOLONG):
		return code.New("bad_path")
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		return code.New("agent_unsupported")
	default:
		return code.New("io")
	}
}
