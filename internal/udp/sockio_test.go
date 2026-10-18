package udp

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTuneBuffersReadsBack(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rcv, snd := TuneBuffers(c, WantBuffer)
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if rcv <= 0 || snd <= 0 {
			t.Fatalf("rcvbuf %d sndbuf %d", rcv, snd)
		}
	}
	t.Logf("asked %d, granted rcvbuf %d sndbuf %d", WantBuffer, rcv, snd)
}

func TestRcvBufWarn(t *testing.T) {
	// 50 MB/s for 5 ms is 250 kB: a 1 MiB usable buffer is enough, a
	// 64 KiB one is not. The RTT floor is 5 ms.
	big := 2 << 20
	if _, short := rcvBufWarn(big, 50e6, time.Millisecond); short {
		t.Fatal("2 MiB reported short for 250 kB")
	}
	line, short := rcvBufWarn(64<<10, 50e6, time.Millisecond)
	if !short || !strings.HasPrefix(line, fmt.Sprintf("diag warn rcvbuf=65536 usable=%d need=250000 ", usableRcv(64<<10))) {
		t.Fatalf("%v %q", short, line)
	}
	if _, short := rcvBufWarn(big, 50e6, 100*time.Millisecond); !short {
		t.Fatal("5 MB need not reported")
	}
	if _, short := rcvBufWarn(64<<10, 0, time.Second); short {
		t.Fatal("no rate reported short")
	}
}

// Datagrams go both ways between a listener and a connected socket through
// sockIO: sources are reported on the listener, bytes are intact, and on
// Linux one read takes several datagrams.
func TestSockIORoundTrip(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cl, err := net.DialUDP("udp", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	TuneBuffers(ln, WantBuffer)
	TuneBuffers(cl, WantBuffer)
	lio, cio := newSockIO(ln, false), newSockIO(cl, true)
	const n = 100
	pkts := make([][]byte, n)
	for i := range pkts {
		pkts[i] = []byte(fmt.Sprintf("datagram-%03d-%s", i, strings.Repeat("x", i)))
	}
	if err := cio.write(pkts, nil); err != nil {
		t.Fatal(err)
	}
	got, maxBatch := 0, 0
	var from *net.UDPAddr
	for got < n {
		ps, err := lio.read(time.Second)
		if err != nil {
			t.Fatalf("after %d: %v", got, err)
		}
		if len(ps) > maxBatch {
			maxBatch = len(ps)
		}
		for _, p := range ps {
			if !bytes.Equal(p.b, pkts[got]) {
				t.Fatalf("datagram %d: %q", got, p.b)
			}
			if p.addr == nil || p.addr.String() != cl.LocalAddr().String() {
				t.Fatalf("source %v, want %v", p.addr, cl.LocalAddr())
			}
			from = p.addr
			got++
		}
	}
	if runtime.GOOS == "linux" && maxBatch < 2 {
		t.Fatalf("recvmmsg never took more than %d", maxBatch)
	}
	if err := lio.write(pkts, from); err != nil {
		t.Fatal(err)
	}
	for got = 0; got < n; {
		ps, err := cio.read(time.Second)
		if err != nil {
			t.Fatalf("back %d: %v", got, err)
		}
		for _, p := range ps {
			if !bytes.Equal(p.b, pkts[got]) {
				t.Fatalf("back %d: %q", got, p.b)
			}
			got++
		}
	}
	// A read with nothing queued times out without error mapping here.
	if ps, err := cio.read(10 * time.Millisecond); err == nil && len(ps) > 0 {
		t.Fatalf("read %d from an idle socket", len(ps))
	}
	t.Logf("largest batch %d", maxBatch)
}

// A wait of 0 still reads what is queued. Go returns a timeout without
// reading when the deadline has passed, which left a busy peer deaf.
func TestSockIOZeroWaitReads(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cl, err := net.DialUDP("udp", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	lio := newSockIO(ln, false)
	if ps, err := lio.read(0); err != nil || len(ps) != 0 {
		t.Fatalf("idle zero-wait read: %d %v", len(ps), err)
	}
	if _, err := cl.Write([]byte("queued")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		ps, err := lio.read(0)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) == 1 && string(ps[0].b) == "queued" && ps[0].addr.String() == cl.LocalAddr().String() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("zero-wait read never returned the queued datagram")
		}
	}
}
