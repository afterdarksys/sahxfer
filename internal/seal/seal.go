// Package seal is the sahxfer ChaCha20-Poly1305 session.
//
// Threats: an off-path sender who has the transfer id but not the route
// token or the grant key; a ciphertext moved under a different header
// (the 64-byte header is AAD); a tag flip; a version or length lie before
// decryption. It does not defend an on-path dropper, a stolen key, or a
// caller who ignores an error and writes the buffer anyway.
//
// The route token is compared by SHA-256 of both sides, then
// subtle.ConstantTimeCompare. A mismatch is counted once and is not also
// opened. The 32nd mismatch, or the 32nd failed open, wipes the key.
package seal

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"github.com/afterdarksys/sahxfer/internal/frame"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// DirClient is nonce byte 0 for a packet the client sends.
	DirClient byte = 0
	// DirAgent is nonce byte 0 for a packet the agent sends.
	DirAgent byte = 1

	// AuthBudget is the number of route-token mismatches, or failed opens,
	// that kills the grant. The two counters are separate.
	AuthBudget = 32

	KeySize   = 32
	TokenSize = 16
)

var (
	// ErrDrop is a packet the peer must ignore. It is not an abort by itself.
	ErrDrop = errors.New("sahxfer: drop")
	// ErrBudget is the 32nd token mismatch or the 32nd failed open.
	// The session key is wiped.
	ErrBudget = errors.New("sahxfer: auth")
	// ErrWiped is Seal after Wipe or after the budget tripped.
	ErrWiped = errors.New("sahxfer: wiped")
	// ErrArgs is a bad key, token, direction, or sequence.
	ErrArgs = errors.New("sahxfer: args")
)

// Session holds one direction-pair of sequence spaces under one key.
// Seq 0 and seq MaxUint64 are rejected so a counter cannot wrap to 0.
type Session struct {
	aead       aeadIface
	key        [KeySize]byte
	token      [TokenSize]byte
	aeadFails  int
	tokenFails int
	wiped      bool
}

type aeadIface interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Overhead() int
}

// New copies key and token. The caller wipes its own copies.
// key is 32 bytes. token is 16 bytes. Both come from crypto/rand.
func New(key, token []byte) (*Session, error) {
	if len(key) != KeySize || len(token) != TokenSize {
		return nil, ErrArgs
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrArgs
	}
	s := &Session{aead: a}
	copy(s.key[:], key)
	copy(s.token[:], token)
	return s, nil
}

// Wipe zeros the key and token copies this session holds and drops the
// cipher. The library may retain its own key copy until GC.
func (s *Session) Wipe() {
	if s == nil {
		return
	}
	for i := range s.key {
		s.key[i] = 0
	}
	for i := range s.token {
		s.token[i] = 0
	}
	s.aead = nil
	s.wiped = true
}

// TokenEqual reports whether a and b are the same 16-byte route token.
// It hashes both sides and compares the digests in constant time.
func TokenEqual(a, b []byte) bool {
	if len(a) != TokenSize || len(b) != TokenSize {
		return false
	}
	da := sha256.Sum256(a)
	db := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// Seal appends one datagram. h.Type, flags, transfer id, seq, offset, and
// send time are the caller's. Version, payload length, and route token are
// overwritten. Unknown types are sealed so a test can craft one; Open does
// not accept or reject them.
func (s *Session) Seal(h frame.Header, pt []byte, dir byte) ([]byte, error) {
	if s == nil || s.wiped || s.aead == nil {
		return nil, ErrWiped
	}
	if dir != DirClient && dir != DirAgent {
		return nil, ErrArgs
	}
	if h.Seq == 0 || h.Seq == ^uint64(0) {
		return nil, ErrArgs
	}
	if uint64(len(pt)) > frame.MaxPlaintext {
		return nil, ErrArgs
	}
	h.Version = frame.Version
	h.PayloadLen = uint64(len(pt))
	h.RouteToken = s.token
	var aad [frame.HeaderSize]byte
	frame.Put(aad[:], h)
	buf := make([]byte, frame.HeaderSize, frame.HeaderSize+len(pt)+s.aead.Overhead())
	copy(buf, aad[:])
	buf = s.aead.Seal(buf, nonce(dir, h.Seq), pt, aad[:])
	return buf, nil
}

// Open authenticates one datagram.
//
// Magic, version other than 1, and a length that is not 80+payload_len are
// dropped before AEAD and do not spend the budget. A route-token mismatch
// spends one token failure and skips AEAD. A bad tag spends one AEAD failure.
// The 32nd of either wipes the session and returns ErrBudget.
//
// peerDir is who the peer is (the side that sent this packet). It is not
// read from the datagram.
func (s *Session) Open(dgram []byte, peerDir byte) (frame.Header, []byte, error) {
	return s.open(dgram, peerDir, true)
}

// OpenUncounted is Open for a datagram from a source that is not yet
// pinned. A token or tag failure is ErrDrop and does not spend the budget,
// so datagrams from anyone who can reach an open listen port cannot use up
// the 32 failures before the real peer arrives.
func (s *Session) OpenUncounted(dgram []byte, peerDir byte) (frame.Header, []byte, error) {
	return s.open(dgram, peerDir, false)
}

func (s *Session) open(dgram []byte, peerDir byte, count bool) (frame.Header, []byte, error) {
	if s == nil || s.wiped || s.aead == nil {
		return frame.Header{}, nil, ErrBudget
	}
	if peerDir != DirClient && peerDir != DirAgent {
		return frame.Header{}, nil, ErrArgs
	}
	h, err := frame.Peek(dgram)
	if err != nil {
		return frame.Header{}, nil, ErrDrop
	}
	if h.Version != frame.Version || !frame.LengthOK(dgram, h) {
		return frame.Header{}, nil, ErrDrop
	}
	if !TokenEqual(h.RouteToken[:], s.token[:]) {
		return frame.Header{}, nil, s.failIf(count, true)
	}
	pt, err := s.aead.Open(nil, nonce(peerDir, h.Seq), dgram[frame.HeaderSize:], dgram[:frame.HeaderSize])
	if err != nil {
		return frame.Header{}, nil, s.failIf(count, false)
	}
	if uint64(len(pt)) != h.PayloadLen {
		return frame.Header{}, nil, s.failIf(count, false)
	}
	return h, pt, nil
}

func (s *Session) failIf(count, token bool) error {
	if !count {
		return ErrDrop
	}
	return s.fail(token)
}

func (s *Session) fail(token bool) error {
	if token {
		s.tokenFails++
		if s.tokenFails >= AuthBudget {
			s.Wipe()
			return ErrBudget
		}
		return ErrDrop
	}
	s.aeadFails++
	if s.aeadFails >= AuthBudget {
		s.Wipe()
		return ErrBudget
	}
	return ErrDrop
}

func nonce(dir byte, seq uint64) []byte {
	var n [12]byte
	n[0] = dir
	n[4] = byte(seq)
	n[5] = byte(seq >> 8)
	n[6] = byte(seq >> 16)
	n[7] = byte(seq >> 24)
	n[8] = byte(seq >> 32)
	n[9] = byte(seq >> 40)
	n[10] = byte(seq >> 48)
	n[11] = byte(seq >> 56)
	return n[:]
}
