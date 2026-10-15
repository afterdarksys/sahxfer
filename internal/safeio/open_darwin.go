//go:build darwin

package safeio

import (
	"strings"

	"github.com/afterdarksys/sahxfer/internal/code"
	"golang.org/x/sys/unix"
)

const (
	dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	regFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	// O_RDWR because the helper re-reads the temp to fold the hash.
	exclFlags = unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

// openRoot walks each component with O_NOFOLLOW. This is not openat2.
// A symlink anywhere in the root path is symlink_refused.
func openRoot(path string) (int, error) {
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, mapOpenErr(err, true)
	}
	if path == "/" {
		return fd, nil
	}
	for _, name := range strings.Split(path, "/")[1:] {
		next, err := unix.Openat(fd, name, dirFlags, 0)
		if err != nil {
			mapped := mapOpenErr(err, true)
			if s := symlinkErr(fd, name, err); s != nil {
				mapped = s
			}
			unix.Close(fd)
			return -1, mapped
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func openDir(dirfd int, name string) (int, error) {
	fd, err := unix.Openat(dirfd, name, dirFlags, 0)
	if err != nil {
		if s := symlinkErr(dirfd, name, err); s != nil {
			return -1, s
		}
		return -1, mapOpenErr(err, false)
	}
	return fd, nil
}

func openReg(dirfd int, name string) (int, error) {
	fd, err := unix.Openat(dirfd, name, regFlags, 0)
	if err != nil {
		if s := symlinkErr(dirfd, name, err); s != nil {
			return -1, s
		}
		return -1, mapOpenErr(err, false)
	}
	if err := requireRegular(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func createExcl(dirfd int, name string) (int, error) {
	fd, err := unix.Openat(dirfd, name, exclFlags, 0o600)
	if err != nil {
		return -1, mapOpenErr(err, false)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return -1, code.New("io")
	}
	return fd, nil
}

func dupfd(fd int) (int, error) {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, code.New("io")
	}
	return n, nil
}

// renameExclusive checks the target, then calls Renameat.
// Darwin has no renameat2, so a file created after the check and before
// the rename can be replaced. Linux uses RENAME_NOREPLACE.
func renameExclusive(dirfd int, tempName, final string, overwrite bool) error {
	kind, err := statName(dirfd, final)
	if err != nil {
		return err
	}
	if !overwrite && kind != kindAbsent {
		return code.New("exists")
	}
	if overwrite && kind == kindOther {
		return code.New("not_a_file")
	}
	if err := unix.Renameat(dirfd, tempName, dirfd, final); err != nil {
		return mapOpenErr(err, false)
	}
	return nil
}
