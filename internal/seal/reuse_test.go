package seal

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestSealIntoWireCompatibility(t *testing.T) {
	s := testSession(t)
	defer s.Wipe()
	a, _ := chacha20poly1305.New(bytes.Repeat([]byte{0x11}, KeySize))
	buf := make([]byte, 0, frame.MaxDatagram)
	for _, dir := range []byte{DirClient, DirAgent} {
		for _, seq := range []uint64{1, 256, 1<<32 + 7, ^uint64(0) - 1} {
			h := dataHeader(seq)
			pt := []byte("independent nonce and wire reference")
			d, err := s.SealInto(buf, h, pt, dir)
			if err != nil {
				t.Fatal(err)
			}
			h.Version, h.PayloadLen = frame.Version, uint64(len(pt))
			copy(h.RouteToken[:], bytes.Repeat([]byte{0x22}, TokenSize))
			header := make([]byte, frame.HeaderSize)
			frame.Put(header, h)
			var nonce [12]byte
			nonce[0] = dir
			binary.LittleEndian.PutUint64(nonce[4:], seq)
			want := append(header, a.Seal(nil, nonce[:], pt, header)...)
			if !bytes.Equal(d, want) || &d[0] != &buf[:cap(buf)][0] {
				t.Fatal("wire changed or buffer not reused")
			}
			d[len(d)-1] ^= 1
			if _, opened, err := s.OpenInto(make([]byte, 0, 128), d, dir, true); err == nil || opened != nil {
				t.Fatal("tampered reused buffer opened")
			}
		}
	}
}

func TestSealIntoAndOpenIntoNoSteadyStateAllocations(t *testing.T) {
	s := testSession(t)
	defer s.Wipe()
	dst := make([]byte, 0, frame.MaxDatagram)
	plain := bytes.Repeat([]byte{7}, frame.InternetPlaintext)
	opened := make([]byte, 0, len(plain))
	h := dataHeader(1)
	allocs := testing.AllocsPerRun(1000, func() {
		h.Seq++
		d, err := s.SealInto(dst, h, plain, DirClient)
		if err != nil {
			panic(err)
		}
		_, got, err := s.OpenInto(opened, d, DirClient, true)
		if err != nil || !bytes.Equal(got, plain) {
			panic("round trip")
		}
	})
	if allocs != 0 {
		t.Fatalf("seal/open scratch allocates %.1f times per round trip", allocs)
	}
}
