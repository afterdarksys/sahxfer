package udp

import (
	"net"
	"testing"
)

func TestPeerAddressIdentity(t *testing.T) {
	a := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 9999}
	b := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	if !sameAddr(a, b) {
		t.Fatal("mapped IPv4 differs")
	}
	b.Port++
	if sameAddr(a, b) {
		t.Fatal("second port accepted")
	}
	b.Port = a.Port
	b.IP = net.ParseIP("127.0.0.2")
	if sameAddr(a, b) {
		t.Fatal("second host accepted")
	}
	a = &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 9999, Zone: "en0"}
	b = copyAddr(a)
	b.Zone = "en1"
	if sameAddr(a, b) {
		t.Fatal("second IPv6 zone accepted")
	}
	if sameAddr(nil, a) || sameAddr(a, nil) {
		t.Fatal("nil peer accepted")
	}
	b = copyAddr(a)
	if n := testing.AllocsPerRun(1000, func() {
		if !sameAddr(a, b) {
			panic("identity")
		}
	}); n != 0 {
		t.Fatalf("address comparison allocates %v", n)
	}
}
