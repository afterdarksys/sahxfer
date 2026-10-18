package safeio

import (
	"os"

	"golang.org/x/sys/unix"
)

// punch deallocates [off, off+n) and keeps the file size. Errors are
// ignored: a filesystem without PUNCH_HOLE leaves the range as it is,
// which already reads as zero.
func punch(f *os.File, off, n int64) {
	_ = unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, n)
}
