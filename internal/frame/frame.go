// Package frame is the sahxfer datagram header and the control payloads.
//
// Threats: a short, mis-sized, or wrong-magic datagram is rejected before
// any caller treats it as authentic. This package does not check the AEAD
// tag. It does not defend a peer who ignores a decode error.
package frame

import (
	"encoding/binary"
	"errors"
)

const (
	Magic0 byte = 0x53
	Magic1 byte = 0x41
	Magic2 byte = 0x48
	Magic3 byte = 0x58

	Version    uint8 = 1
	HeaderSize       = 64
	TagSize          = 16
	Overhead         = HeaderSize + TagSize // 80

	MaxPlaintext      = 8112
	MaxDatagram       = Overhead + MaxPlaintext // 8192
	InternetPlaintext = 1152
	InternetDatagram  = 1232
	DCPlaintext       = 8112
	DCDatagram        = 8192

	MaxNACKHoles = 32
	FeedbackLen  = 48
	HashLen      = 32
	PongLen      = 16
	AbortLen     = 8
	ZeroLen      = 8

	// MaxZero is the largest span one ZERO may name (1 MiB). Each side
	// hashes a ZERO's bytes, so this bounds the work one datagram costs.
	MaxZero = 1 << 20
	// ZeroOK is bit 62 of a receiver's PING offset: it accepts ZERO.
	ZeroOK uint64 = 1 << 62
	// ZeroWire is a ZERO datagram's length, which is what it is charged.
	ZeroWire = Overhead + ZeroLen
)

const (
	TypeDATA     uint8 = 1
	TypeNACK     uint8 = 2
	TypeFEEDBACK uint8 = 3
	TypeFIN      uint8 = 4
	TypeDONE     uint8 = 5
	TypeABORT    uint8 = 6
	TypePING     uint8 = 7
	TypePONG     uint8 = 8
	TypeZERO     uint8 = 9
)

const (
	FlagRETX     uint16 = 1 << 0
	FlagCloseAck uint16 = 1 << 1
)

const (
	ReasonSizeMismatch uint64 = 1
	ReasonHashMismatch uint64 = 2
	ReasonExpired      uint64 = 3
	ReasonPolicy       uint64 = 4
	ReasonIO           uint64 = 5
	ReasonProtocol     uint64 = 6
	ReasonAuth         uint64 = 7
	ReasonCancelled    uint64 = 8
	ReasonByteCap      uint64 = 9
	ReasonIdle         uint64 = 10
	ReasonNoSpace      uint64 = 11
)

// EmptySHA256 is SHA-256 of the empty input.
const EmptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

var (
	ErrShort    = errors.New("sahxfer: short datagram")
	ErrMagic    = errors.New("sahxfer: bad magic")
	ErrLength   = errors.New("sahxfer: length mismatch")
	ErrPayload  = errors.New("sahxfer: bad payload")
	ErrProtocol = errors.New("sahxfer: protocol")
)

// Header is the 64-byte cleartext prefix. RouteToken is the raw 16 bytes.
// On the wire those bytes are two little-endian u64 slots, which is the same
// byte order as the token itself.
type Header struct {
	Version    uint8
	Type       uint8
	Flags      uint16
	TransferID uint64
	Seq        uint64
	Offset     uint64
	PayloadLen uint64
	SendTimeNS uint64
	RouteToken [16]byte
}

// Span is a half-open file range [Start, End).
type Span struct {
	Start uint64
	End   uint64
}

// Feedback is the 48-byte congestion sample.
type Feedback struct {
	EchoSendTimeNS uint64
	DeliveredBytes uint64
	NewlyLostBytes uint64
	HighestSeq     uint64
	ECNCECount     uint64
	RecvRateBps    uint64
}

// Put encodes h into dst, which must be at least HeaderSize bytes.
func Put(dst []byte, h Header) {
	dst[0] = Magic0
	dst[1] = Magic1
	dst[2] = Magic2
	dst[3] = Magic3
	dst[4] = h.Version
	dst[5] = h.Type
	binary.LittleEndian.PutUint16(dst[6:8], h.Flags)
	binary.LittleEndian.PutUint64(dst[8:16], h.TransferID)
	binary.LittleEndian.PutUint64(dst[16:24], h.Seq)
	binary.LittleEndian.PutUint64(dst[24:32], h.Offset)
	binary.LittleEndian.PutUint64(dst[32:40], h.PayloadLen)
	binary.LittleEndian.PutUint64(dst[40:48], h.SendTimeNS)
	copy(dst[48:64], h.RouteToken[:])
}

// Peek reads a header. It checks the magic and that b holds a header.
// It does not check the version. Callers drop an unknown version before AEAD.
func Peek(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShort
	}
	if b[0] != Magic0 || b[1] != Magic1 || b[2] != Magic2 || b[3] != Magic3 {
		return Header{}, ErrMagic
	}
	var h Header
	h.Version = b[4]
	h.Type = b[5]
	h.Flags = binary.LittleEndian.Uint16(b[6:8])
	h.TransferID = binary.LittleEndian.Uint64(b[8:16])
	h.Seq = binary.LittleEndian.Uint64(b[16:24])
	h.Offset = binary.LittleEndian.Uint64(b[24:32])
	h.PayloadLen = binary.LittleEndian.Uint64(b[32:40])
	h.SendTimeNS = binary.LittleEndian.Uint64(b[40:48])
	copy(h.RouteToken[:], b[48:64])
	return h, nil
}

// DatagramLen reports the only legal UDP length for a header.
// ok is false when payload_len is above the v1 maximum.
func DatagramLen(h Header) (int, bool) {
	if h.PayloadLen > MaxPlaintext {
		return 0, false
	}
	return Overhead + int(h.PayloadLen), true
}

// LengthOK reports whether len(b) equals 80+payload_len and the payload cap holds.
func LengthOK(b []byte, h Header) bool {
	n, ok := DatagramLen(h)
	return ok && len(b) == n
}

// KnownType reports whether t is a v1 type. ZERO is known here; a
// receiver that did not set ZeroOK refuses it as protocol.
func KnownType(t uint8) bool {
	return t >= TypeDATA && t <= TypeZERO
}

// FlagsOK reports whether flags are legal on typ.
func FlagsOK(typ uint8, flags uint16) bool {
	switch typ {
	case TypeDATA, TypeZERO:
		return flags&^FlagRETX == 0
	case TypeFIN:
		return flags&^FlagCloseAck == 0
	default:
		return flags == 0
	}
}

// ReasonName is the stable name for an ABORT code. Unknown codes return "abort".
func ReasonName(r uint64) string {
	switch r {
	case ReasonSizeMismatch:
		return "size_mismatch"
	case ReasonHashMismatch:
		return "hash_mismatch"
	case ReasonExpired:
		return "expired"
	case ReasonPolicy:
		return "policy"
	case ReasonIO:
		return "io"
	case ReasonProtocol:
		return "protocol"
	case ReasonAuth:
		return "auth"
	case ReasonCancelled:
		return "cancelled"
	case ReasonByteCap:
		return "byte_cap"
	case ReasonIdle:
		return "idle"
	case ReasonNoSpace:
		return "no_space"
	default:
		return "abort"
	}
}

// EncodeNACK encodes hole_count and the half-open ranges.
func EncodeNACK(holes []Span) ([]byte, error) {
	if len(holes) > MaxNACKHoles {
		return nil, ErrPayload
	}
	buf := make([]byte, 8+len(holes)*16)
	binary.LittleEndian.PutUint64(buf[:8], uint64(len(holes)))
	var prev uint64
	for i, h := range holes {
		if h.Start >= h.End || (i > 0 && h.Start < prev) {
			return nil, ErrPayload
		}
		prev = h.End
		off := 8 + i*16
		binary.LittleEndian.PutUint64(buf[off:], h.Start)
		binary.LittleEndian.PutUint64(buf[off+8:], h.End)
	}
	return buf, nil
}

// DecodeNACK checks order, overlap, and the file size. size bounds each end.
func DecodeNACK(pt []byte, size uint64) ([]Span, error) {
	if len(pt) < 8 {
		return nil, ErrPayload
	}
	n := binary.LittleEndian.Uint64(pt[:8])
	if n > MaxNACKHoles {
		return nil, ErrPayload
	}
	if uint64(len(pt)) != 8+n*16 {
		return nil, ErrPayload
	}
	out := make([]Span, 0, n)
	var prev uint64
	for i := uint64(0); i < n; i++ {
		off := 8 + int(i)*16
		start := binary.LittleEndian.Uint64(pt[off:])
		end := binary.LittleEndian.Uint64(pt[off+8:])
		if start >= end || end > size || (i > 0 && start < prev) {
			return nil, ErrPayload
		}
		prev = end
		out = append(out, Span{Start: start, End: end})
	}
	return out, nil
}

// EncodeFeedback encodes the fixed 48-byte sample.
func EncodeFeedback(f Feedback) []byte {
	buf := make([]byte, FeedbackLen)
	binary.LittleEndian.PutUint64(buf[0:8], f.EchoSendTimeNS)
	binary.LittleEndian.PutUint64(buf[8:16], f.DeliveredBytes)
	binary.LittleEndian.PutUint64(buf[16:24], f.NewlyLostBytes)
	binary.LittleEndian.PutUint64(buf[24:32], f.HighestSeq)
	binary.LittleEndian.PutUint64(buf[32:40], f.ECNCECount)
	binary.LittleEndian.PutUint64(buf[40:48], f.RecvRateBps)
	return buf
}

// DecodeFeedback rejects any length other than 48.
func DecodeFeedback(pt []byte) (Feedback, error) {
	if len(pt) != FeedbackLen {
		return Feedback{}, ErrPayload
	}
	return Feedback{
		EchoSendTimeNS: binary.LittleEndian.Uint64(pt[0:8]),
		DeliveredBytes: binary.LittleEndian.Uint64(pt[8:16]),
		NewlyLostBytes: binary.LittleEndian.Uint64(pt[16:24]),
		HighestSeq:     binary.LittleEndian.Uint64(pt[24:32]),
		ECNCECount:     binary.LittleEndian.Uint64(pt[32:40]),
		RecvRateBps:    binary.LittleEndian.Uint64(pt[40:48]),
	}, nil
}

// EncodePong encodes the two u64 fields.
func EncodePong(echoSendTimeNS, receiverDelayNS uint64) []byte {
	buf := make([]byte, PongLen)
	binary.LittleEndian.PutUint64(buf[0:8], echoSendTimeNS)
	binary.LittleEndian.PutUint64(buf[8:16], receiverDelayNS)
	return buf
}

// DecodePong rejects any length other than 16.
func DecodePong(pt []byte) (echo, delay uint64, err error) {
	if len(pt) != PongLen {
		return 0, 0, ErrPayload
	}
	return binary.LittleEndian.Uint64(pt[0:8]), binary.LittleEndian.Uint64(pt[8:16]), nil
}

// EncodeZero encodes the ZERO length.
func EncodeZero(length uint64) []byte {
	buf := make([]byte, ZeroLen)
	binary.LittleEndian.PutUint64(buf, length)
	return buf
}

// DecodeZero rejects any payload other than 8 bytes and a length of 0 or
// above MaxZero. The caller checks offset+length against the file size.
func DecodeZero(pt []byte) (uint64, error) {
	if len(pt) != ZeroLen {
		return 0, ErrPayload
	}
	n := binary.LittleEndian.Uint64(pt)
	if n == 0 || n > MaxZero {
		return 0, ErrPayload
	}
	return n, nil
}

// EncodeAbort encodes one reason.
func EncodeAbort(reason uint64) []byte {
	buf := make([]byte, AbortLen)
	binary.LittleEndian.PutUint64(buf, reason)
	return buf
}

// DecodeAbort rejects any length other than 8.
func DecodeAbort(pt []byte) (uint64, error) {
	if len(pt) != AbortLen {
		return 0, ErrPayload
	}
	return binary.LittleEndian.Uint64(pt), nil
}
