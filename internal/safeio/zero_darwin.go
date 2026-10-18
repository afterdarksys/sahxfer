package safeio

import (
	"os"

	"golang.org/x/sys/unix"
)

// punch deallocates [off, off+n) with F_PUNCHHOLE. x/sys has no
// fpunchhole_t; its layout {u32 fp_flags, u32 reserved, off_t fp_offset,
// off_t fp_length} is the first 24 bytes of fstore_t {u32 fst_flags,
// i32 fst_posmode, off_t fst_offset, off_t fst_length, ...}, so a
// zeroed Fstore_t with Offset and Length set is a valid argument. Errors
// are ignored: HFS+ and others without the call leave the range as it is,
// which already reads as zero.
func punch(f *os.File, off, n int64) {
	_ = unix.FcntlFstore(f.Fd(), unix.F_PUNCHHOLE, &unix.Fstore_t{Offset: off, Length: n})
}
