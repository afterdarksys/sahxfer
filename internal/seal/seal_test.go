package seal

import (
	"bytes"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

func testSession(t *testing.T) *Session {
	t.Helper()
	key := bytes.Repeat([]byte{0x11}, KeySize)
	token := bytes.Repeat([]byte{0x22}, TokenSize)
	s, err := New(key, token)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dataHeader(seq uint64) frame.Header {
	return frame.Header{
		Type:       frame.TypeDATA,
		TransferID: 7,
		Seq:        seq,
		Offset:     0,
		SendTimeNS: 5,
	}
}

func TestRoundTrip(t *testing.T) {
	s := testSession(t)
	pt := []byte("hello sahxfer")
	d, err := s.Seal(dataHeader(1), pt, DirClient)
	if err != nil {
		t.Fatal(err)
	}
	h, got, err := s.Open(d, DirClient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext %q", got)
	}
	if h.TransferID != 7 || h.Seq != 1 || h.PayloadLen != uint64(len(pt)) {
		t.Fatalf("header %+v", h)
	}
	if !TokenEqual(h.RouteToken[:], bytes.Repeat([]byte{0x22}, TokenSize)) {
		t.Fatal("token")
	}
}

func TestOpenIntoReuseAndFailure(t *testing.T) {
	s := testSession(t)
	defer s.Wipe()
	scratch := make([]byte, 0, 2048)
	for seq := uint64(1); seq <= 3; seq++ {
		plain := bytes.Repeat([]byte{byte(seq)}, int(seq)*100)
		d, err := s.Seal(dataHeader(seq), plain, DirClient)
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte(nil), d...)
		_, pt, err := s.OpenInto(scratch, d, DirClient, true)
		if err != nil || !bytes.Equal(pt, plain) {
			t.Fatalf("open: %v", err)
		}
		if &pt[0] != &scratch[:cap(scratch)][0] {
			t.Fatal("scratch not reused")
		}
		if !bytes.Equal(d, original) {
			t.Fatal("ciphertext mutated")
		}
		d[len(d)-1] ^= 1
		_, pt, err = s.OpenInto(scratch, d, DirClient, true)
		if err != ErrDrop || pt != nil {
			t.Fatal("tampered tag exposed plaintext")
		}
	}
}

func TestRejectsBeforeAEAD(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}

	short := d[:len(d)-1]
	if _, _, err := s.Open(short, DirClient); err != ErrDrop {
		t.Fatalf("truncated: %v", err)
	}

	bad := append([]byte(nil), d...)
	bad[0] = 0
	if _, _, err := s.Open(bad, DirClient); err != ErrDrop {
		t.Fatalf("magic: %v", err)
	}

	ver := append([]byte(nil), d...)
	ver[4] = 2
	if _, _, err := s.Open(ver, DirClient); err != ErrDrop {
		t.Fatalf("version: %v", err)
	}
	if s.aeadFails != 0 || s.tokenFails != 0 {
		t.Fatalf("budget spent on a pre-AEAD drop: aead %d token %d", s.aeadFails, s.tokenFails)
	}
	if _, _, err := s.Open(d, DirClient); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedTagDoesNotOpen(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	d[len(d)-1] ^= 0xff
	h, pt, err := s.Open(d, DirClient)
	if err != ErrDrop {
		t.Fatalf("tag: %v", err)
	}
	if pt != nil || h.Type != 0 {
		t.Fatal("tampered packet returned plaintext")
	}
	if s.aeadFails != 1 || s.tokenFails != 0 {
		t.Fatalf("fails aead=%d token=%d", s.aeadFails, s.tokenFails)
	}
}

func TestHeaderIsAAD(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the file offset. The tag was bound to the original header.
	d[24] ^= 0x01
	if _, _, err := s.Open(d, DirClient); err != ErrDrop {
		t.Fatalf("offset swap: %v", err)
	}
}

func TestDirectionSeparatesNonce(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(d, DirAgent); err != ErrDrop {
		t.Fatalf("cross direction: %v", err)
	}
	if _, _, err := s.Open(d, DirClient); err != nil {
		t.Fatal(err)
	}
}

func TestSeqZeroAndWrapRejected(t *testing.T) {
	s := testSession(t)
	if _, err := s.Seal(dataHeader(0), []byte{1}, DirClient); err != ErrArgs {
		t.Fatalf("seq 0: %v", err)
	}
	if _, err := s.Seal(dataHeader(^uint64(0)), []byte{1}, DirClient); err != ErrArgs {
		t.Fatalf("seq max: %v", err)
	}
}

func TestTokenMismatchSkipsAEAD(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the tag as well. A double count would spend an AEAD failure.
	for i := 0; i < AuthBudget-1; i++ {
		bad := append([]byte(nil), d...)
		bad[48] ^= 0xff
		bad[len(bad)-1] ^= 0xff
		h, pt, err := s.Open(bad, DirClient)
		if err != ErrDrop || pt != nil || h.PayloadLen != 0 {
			t.Fatalf("mismatch %d: %v", i, err)
		}
	}
	if s.tokenFails != AuthBudget-1 || s.aeadFails != 0 {
		t.Fatalf("counted twice or wrong counter: token %d aead %d", s.tokenFails, s.aeadFails)
	}
	if _, _, err := s.Open(d, DirClient); err != nil {
		t.Fatal("valid packet rejected before the budget")
	}
	bad := append([]byte(nil), d...)
	bad[48] ^= 0xff
	if _, _, err := s.Open(bad, DirClient); err != ErrBudget {
		t.Fatalf("32nd mismatch: %v", err)
	}
	if _, err := s.Seal(dataHeader(2), []byte{1}, DirClient); err != ErrWiped {
		t.Fatalf("seal after wipe: %v", err)
	}
	if _, _, err := s.Open(d, DirClient); err != ErrBudget {
		t.Fatalf("open after wipe: %v", err)
	}
}

func TestAEADBudget(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < AuthBudget-1; i++ {
		bad := append([]byte(nil), d...)
		bad[len(bad)-1] ^= 0xff
		if _, _, err := s.Open(bad, DirClient); err != ErrDrop {
			t.Fatalf("tag %d: %v", i, err)
		}
	}
	if _, _, err := s.Open(d, DirClient); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), d...)
	bad[len(bad)-1] ^= 0xff
	if _, _, err := s.Open(bad, DirClient); err != ErrBudget {
		t.Fatalf("32nd tag: %v", err)
	}
}

func TestBudgetsAreSeparate(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < AuthBudget-1; i++ {
		tok := append([]byte(nil), d...)
		tok[48] ^= 0xff
		if _, _, err := s.Open(tok, DirClient); err != ErrDrop {
			t.Fatal(err)
		}
		tag := append([]byte(nil), d...)
		tag[len(tag)-1] ^= byte(i + 1)
		if _, _, err := s.Open(tag, DirClient); err != ErrDrop {
			t.Fatal(err)
		}
	}
	if s.tokenFails != 31 || s.aeadFails != 31 {
		t.Fatalf("token %d aead %d", s.tokenFails, s.aeadFails)
	}
	if _, _, err := s.Open(d, DirClient); err != nil {
		t.Fatal("31+31 killed the grant")
	}
}

func TestUnknownTypeStillSeals(t *testing.T) {
	s := testSession(t)
	h := dataHeader(1)
	h.Type = 99
	d, err := s.Seal(h, []byte{1, 2, 3}, DirClient)
	if err != nil {
		t.Fatal(err)
	}
	got, pt, err := s.Open(d, DirClient)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != 99 || !bytes.Equal(pt, []byte{1, 2, 3}) {
		t.Fatalf("type %d pt %x", got.Type, pt)
	}
}

func TestTokenEqual(t *testing.T) {
	a := bytes.Repeat([]byte{1}, TokenSize)
	b := append([]byte(nil), a...)
	if !TokenEqual(a, b) {
		t.Fatal("equal")
	}
	b[0] ^= 1
	if TokenEqual(a, b) {
		t.Fatal("unequal")
	}
	if TokenEqual(a, a[:15]) {
		t.Fatal("short")
	}
}

func TestBadKeyLen(t *testing.T) {
	if _, err := New([]byte{1}, bytes.Repeat([]byte{2}, TokenSize)); err != ErrArgs {
		t.Fatal(err)
	}
}

// Before a source is pinned, token and tag failures are dropped without
// spending either budget. Counted opens still spend it afterwards.
func TestOpenUncountedSpendsNothing(t *testing.T) {
	s := testSession(t)
	d, err := s.Seal(dataHeader(1), []byte("abc"), DirClient)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3*AuthBudget; i++ {
		tok := append([]byte(nil), d...)
		tok[48] ^= 0xff
		tag := append([]byte(nil), d...)
		tag[len(tag)-1] ^= 0xff
		for _, bad := range [][]byte{tok, tag} {
			if _, _, err := s.OpenUncounted(bad, DirClient); err != ErrDrop {
				t.Fatalf("%d: %v", i, err)
			}
		}
	}
	if s.tokenFails != 0 || s.aeadFails != 0 || s.wiped {
		t.Fatalf("token %d aead %d", s.tokenFails, s.aeadFails)
	}
	if _, _, err := s.OpenUncounted(d, DirClient); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), d...)
	bad[len(bad)-1] ^= 0xff
	if _, _, err := s.Open(bad, DirClient); err != ErrDrop || s.aeadFails != 1 {
		t.Fatalf("counted open: %v %d", err, s.aeadFails)
	}
}
