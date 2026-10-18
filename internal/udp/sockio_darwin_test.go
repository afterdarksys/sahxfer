package udp

import (
	"testing"
	"unsafe"
)

// TestMsghdrXLayout pins the hand-declared struct msghdr_x to the XNU ABI.
// recvmsg_x/sendmsg_x read and write these fields by offset, so a wrong
// offset corrupts the batch with no error. The want values are from
// bsd/sys/socket.h on LP64 (confirmed against the MacOSX SDK).
func TestMsghdrXLayout(t *testing.T) {
	if got := unsafe.Sizeof(msghdrX{}); got != 56 {
		t.Fatalf("sizeof(msghdr_x) = %d, want 56", got)
	}
	var m msghdrX
	checks := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"Name", unsafe.Offsetof(m.Name), 0},
		{"Namelen", unsafe.Offsetof(m.Namelen), 8},
		{"Iov", unsafe.Offsetof(m.Iov), 16},
		{"Iovlen", unsafe.Offsetof(m.Iovlen), 24},
		{"Control", unsafe.Offsetof(m.Control), 32},
		{"Controllen", unsafe.Offsetof(m.Controllen), 40},
		{"Flags", unsafe.Offsetof(m.Flags), 44},
		{"Datalen", unsafe.Offsetof(m.Datalen), 48},
	}
	for _, c := range checks {
		if c.off != c.want {
			t.Errorf("offsetof %s = %d, want %d", c.name, c.off, c.want)
		}
	}
}

// TestSysNumbers documents the syscall numbers the batch path depends on.
func TestSysNumbers(t *testing.T) {
	if sysRecvmsgX != 480 || sysSendmsgX != 481 {
		t.Fatalf("recvmsg_x=%d sendmsg_x=%d, want 480/481", sysRecvmsgX, sysSendmsgX)
	}
}
