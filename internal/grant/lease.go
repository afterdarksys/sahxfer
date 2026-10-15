package grant

// Threats: a helper that keeps writing after the control plane has
// withdrawn the grant, a put lease presented to a get, and a signature
// from a key the agent does not pin. The signature is checked before any
// field in the payload is trusted. Deadline equality is expired.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
)

const (
	// LeaseTTL is the signature lifetime. Renew uses the same window.
	LeaseTTL = 60 * time.Second
	// LeaseRenew is how often the caller asks for a new signature.
	LeaseRenew = 30 * time.Second
)

// Sign builds an 8-line payload and signs it with the control-plane key.
// Deadline is now plus LeaseTTL for both start and renew.
func Sign(priv ed25519.PrivateKey, g *Grant, kind string, now time.Time) (msg, sig []byte, deadline time.Time, err error) {
	if g == nil || len(priv) != ed25519.PrivateKeySize {
		return nil, nil, time.Time{}, code.New("auth")
	}
	if kind != "start" && kind != "renew" {
		return nil, nil, time.Time{}, code.New("auth")
	}
	if now.IsZero() {
		now = time.Now()
	}
	deadline = now.Add(LeaseTTL)
	msg = payload(g.GrantID, deadline.Unix(), kind, g.Dir, g.Root, g.Path, g.Size, g.Hash)
	return msg, ed25519.Sign(priv, msg), deadline, nil
}

// Verify checks the signature, then the deadline, then that the payload
// names this grant. A mismatch other than the deadline is auth.
func Verify(pub ed25519.PublicKey, g *Grant, msg, sig []byte, now time.Time) error {
	if g == nil || len(pub) != ed25519.PublicKeySize {
		return code.New("auth")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return code.New("auth")
	}
	if now.IsZero() {
		now = time.Now()
	}
	id, dl, kind, dir, root, path, size, sum, err := parseLease(msg)
	if err != nil {
		return err
	}
	if now.Unix() >= dl {
		return code.New("expired")
	}
	if kind != "start" && kind != "renew" {
		return code.New("auth")
	}
	want, err := leaseDir(g)
	if err != nil {
		return err
	}
	if id != g.GrantID || dir != want || dir != g.Dir || root != g.Root || path != g.Path || size != g.Size || !SameHash(sum, g.Hash) {
		return code.New("auth")
	}
	return nil
}

func leaseDir(g *Grant) (string, error) {
	switch g.Purpose {
	case PurposePut:
		if g.Dir != "put" {
			return "", code.New("auth")
		}
	case PurposeGet:
		if g.Dir != "get" {
			return "", code.New("auth")
		}
	case PurposeRoot:
		if g.Dir != "put" && g.Dir != "get" {
			return "", code.New("auth")
		}
	default:
		return "", code.New("auth")
	}
	return g.Dir, nil
}

func payload(id string, deadline int64, kind, dir, root, path string, size uint64, sum [32]byte) []byte {
	s := fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%s\n%d\n%s",
		id, deadline, kind, dir, root, path, size, hex.EncodeToString(sum[:]))
	return []byte(s)
}

func parseLease(msg []byte) (id string, deadline int64, kind, dir, root, path string, size uint64, sum [32]byte, err error) {
	n := 0
	for _, c := range msg {
		if c == '\n' {
			n++
		}
	}
	if n != 7 {
		return "", 0, "", "", "", "", 0, sum, code.New("auth")
	}
	lines := split8(msg)
	if lines == nil {
		return "", 0, "", "", "", "", 0, sum, code.New("auth")
	}
	dl, perr := strconv.ParseInt(lines[1], 10, 64)
	if perr != nil {
		return "", 0, "", "", "", "", 0, sum, code.New("auth")
	}
	sz, perr := ParseUint(lines[6])
	if perr != nil {
		return "", 0, "", "", "", "", 0, sum, code.New("auth")
	}
	sum, perr = ParseHash(lines[7])
	if perr != nil {
		return "", 0, "", "", "", "", 0, sum, code.New("auth")
	}
	return lines[0], dl, lines[2], lines[3], lines[4], lines[5], sz, sum, nil
}

func split8(msg []byte) []string {
	out := make([]string, 0, 8)
	start := 0
	for i, c := range msg {
		if c == '\n' {
			out = append(out, string(msg[start:i]))
			start = i + 1
		}
	}
	out = append(out, string(msg[start:]))
	if len(out) != 8 {
		return nil
	}
	return out
}
