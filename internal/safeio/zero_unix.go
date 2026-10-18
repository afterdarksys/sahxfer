//go:build darwin || linux

package safeio

import (
	"errors"
	"os"
	"syscall"

	"github.com/afterdarksys/sahxfer/internal/code"
	"golang.org/x/sys/unix"
)

func blockSize(st os.FileInfo) int64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Blksize > 0 {
		return int64(s.Blksize)
	}
	return 4096
}

func extendErr(err error) error {
	if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EFBIG) || errors.Is(err, unix.EDQUOT) {
		return code.New("no_space")
	}
	return code.New("io")
}
