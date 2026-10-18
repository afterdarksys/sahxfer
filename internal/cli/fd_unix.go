//go:build unix

package cli

import (
	"os"
	"syscall"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// inheritedFD wraps an fd the agent passed in. It must be a pipe (FIFO) or
// a socket, never a regular file, tty, or directory. It is made
// non-blocking so that reads honour a deadline and Close interrupts them.
func inheritedFD(fd int, name string) (*os.File, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, code.New("bad_args")
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK:
	default:
		return nil, code.New("bad_args")
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, code.New("io")
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, code.New("bad_args")
	}
	return f, nil
}
