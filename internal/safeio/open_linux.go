//go:build linux

package safeio

import (
	"errors"

	"github.com/afterdarksys/sahxfer/internal/code"
	"golang.org/x/sys/unix"
)

// fileResolve is every open beneath the grant root. A kernel that rejects
// these flags is agent_unsupported. There is no openat fallback.
const fileResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

func openRoot(path string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return -1, mapLinux(err, true)
	}
	return fd, nil
}

func openDir(dirfd int, name string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: fileResolve,
	}
	fd, err := unix.Openat2(dirfd, name, how)
	if err != nil {
		if s := symlinkErr(dirfd, name, err); s != nil {
			return -1, s
		}
		return -1, mapLinux(err, false)
	}
	return fd, nil
}

func openReg(dirfd int, name string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: fileResolve,
	}
	fd, err := unix.Openat2(dirfd, name, how)
	if err != nil {
		if s := symlinkErr(dirfd, name, err); s != nil {
			return -1, s
		}
		return -1, mapLinux(err, false)
	}
	if err := requireRegular(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func createExcl(dirfd int, name string) (int, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Mode:    0o600,
		Resolve: fileResolve,
	}
	fd, err := unix.Openat2(dirfd, name, how)
	if err != nil {
		return -1, mapLinux(err, false)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return -1, code.New("io")
	}
	return fd, nil
}

// dupfd of an O_PATH root reopens "." as a real directory so the parent
// can be fsynced. The root fd itself stays O_PATH.
func dupfd(fd int) (int, error) {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return -1, code.New("io")
	}
	if flags&unix.O_PATH != 0 {
		how := &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: fileResolve,
		}
		n, err := unix.Openat2(fd, ".", how)
		if err != nil {
			return -1, mapLinux(err, false)
		}
		return n, nil
	}
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, code.New("io")
	}
	return n, nil
}

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
	flags := uint(0)
	if !overwrite {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(dirfd, tempName, dirfd, final, flags); err != nil {
		return mapLinux(err, false)
	}
	return nil
}

// mapLinux turns a missing openat2 into agent_unsupported. EINVAL from
// openat2 is the same stop: the flags are not available. There is no
// openat fallback.
func mapLinux(err error, root bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return code.New("agent_unsupported")
	}
	return mapOpenErr(err, root)
}
