package frame

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{
		Version:    Version,
		Type:       TypeDATA,
		Flags:      FlagRETX,
		TransferID: 0x1122334455667788,
		Seq:        7,
		Offset:     4096,
		PayloadLen: 100,
		SendTimeNS: 99,
	}
	copy(h.RouteToken[:], []byte("0123456789abcdef"))
	buf := make([]byte, HeaderSize)
	Put(buf, h)
	if buf[0] != 'S' || buf[1] != 'A' || buf[2] != 'H' || buf[3] != 'X' {
		t.Fatalf("magic %x", buf[:4])
	}
	got, err := Peek(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v", got)
	}
	// The token's wire image is the raw bytes, not a swapped integer.
	if !bytes.Equal(buf[48:64], h.RouteToken[:]) {
		t.Fatal("token bytes moved")
	}
}

func TestPeekRejects(t *testing.T) {
	if _, err := Peek(make([]byte, 63)); err != ErrShort {
		t.Fatalf("short: %v", err)
	}
	buf := make([]byte, HeaderSize)
	Put(buf, Header{Version: Version, Type: TypePING})
	buf[0] = 0
	if _, err := Peek(buf); err != ErrMagic {
		t.Fatalf("magic: %v", err)
	}
}

func TestVersionIsVisible(t *testing.T) {
	buf := make([]byte, HeaderSize)
	Put(buf, Header{Version: 2, Type: TypeDATA})
	h, err := Peek(buf)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 2 {
		t.Fatalf("version %d", h.Version)
	}
}

func TestLengthOK(t *testing.T) {
	h := Header{PayloadLen: 10}
	if LengthOK(make([]byte, 80), h) {
		t.Fatal("short datagram accepted")
	}
	if !LengthOK(make([]byte, 90), h) {
		t.Fatal("exact datagram rejected")
	}
	h.PayloadLen = MaxPlaintext + 1
	if LengthOK(make([]byte, 100), h) {
		t.Fatal("oversize payload accepted")
	}
}

func TestFlags(t *testing.T) {
	if !FlagsOK(TypeDATA, FlagRETX) || !FlagsOK(TypeDATA, 0) {
		t.Fatal("data retx")
	}
	if FlagsOK(TypeDATA, FlagCloseAck) || FlagsOK(TypeDATA, 1<<2) {
		t.Fatal("data accepted a bad flag")
	}
	if !FlagsOK(TypeFIN, FlagCloseAck) || FlagsOK(TypeFIN, FlagRETX) {
		t.Fatal("fin flags")
	}
	if FlagsOK(TypeNACK, FlagRETX) || !FlagsOK(TypePING, 0) {
		t.Fatal("control flags")
	}
	if KnownType(0) || KnownType(9) || !KnownType(TypePONG) {
		t.Fatal("types")
	}
}

func TestNACKCodec(t *testing.T) {
	holes := []Span{{0, 10}, {20, 30}}
	buf, err := EncodeNACK(holes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNACK(buf, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Start != 20 {
		t.Fatalf("%+v", got)
	}
	if _, err := DecodeNACK(buf, 25); err != ErrPayload {
		t.Fatalf("past size: %v", err)
	}
	// overlap
	bad, _ := EncodeNACK([]Span{{0, 10}, {10, 12}})
	// 10 >= prev end 10 is allowed (they touch). Force overlap by editing.
	binary.LittleEndian.PutUint64(bad[8+16:], 9)
	if _, err := DecodeNACK(bad, 100); err != ErrPayload {
		t.Fatalf("overlap: %v", err)
	}
	too := make([]Span, MaxNACKHoles+1)
	for i := range too {
		too[i] = Span{uint64(i) * 2, uint64(i)*2 + 1}
	}
	if _, err := EncodeNACK(too); err != ErrPayload {
		t.Fatal("33 holes encoded")
	}
}

func TestFeedbackAndAbort(t *testing.T) {
	f := Feedback{EchoSendTimeNS: 5, DeliveredBytes: 9, NewlyLostBytes: 3, HighestSeq: 4, RecvRateBps: 100}
	got, err := DecodeFeedback(EncodeFeedback(f))
	if err != nil || got != f {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeFeedback(make([]byte, 47)); err != ErrPayload {
		t.Fatal("short feedback")
	}
	r, err := DecodeAbort(EncodeAbort(ReasonAuth))
	if err != nil || r != ReasonAuth {
		t.Fatal(r, err)
	}
	echo, delay, err := DecodePong(EncodePong(8, 2))
	if err != nil || echo != 8 || delay != 2 {
		t.Fatal(echo, delay, err)
	}
}

func TestReasonName(t *testing.T) {
	if ReasonName(ReasonIdle) != "idle" || ReasonName(99) != "abort" {
		t.Fatal(ReasonName(99))
	}
}
