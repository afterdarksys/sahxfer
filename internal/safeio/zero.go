package safeio

import (
	"os"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// ZeroRange makes [off, off+n) of f read as zero bytes. The caller
// guarantees the range was never written (the engine's hole map lacks it),
// so it already reads as zero once the file covers it. The file is
// extended with ftruncate when it is shorter than off+n and is never
// shrunk. Then the filesystem-block-aligned inside of the range is
// deallocated where the platform can (Linux fallocate PUNCH_HOLE|KEEP_SIZE,
// Darwin F_PUNCHHOLE); a filesystem that cannot is not an error, and
// rounding inward never touches a byte outside the range. An extend that
// fails is no_space or io. docs/design.md section 4.7.
func ZeroRange(f *os.File, off, n int64) error {
	if f == nil || off < 0 || n <= 0 || off+n < off {
		return code.New("io")
	}
	st, err := f.Stat()
	if err != nil {
		return code.New("io")
	}
	if st.Size() < off+n {
		if err := f.Truncate(off + n); err != nil {
			return extendErr(err)
		}
	}
	bs := blockSize(st)
	start := (off + bs - 1) / bs * bs
	end := (off + n) / bs * bs
	if end > start {
		punch(f, start, end-start)
	}
	return nil
}
