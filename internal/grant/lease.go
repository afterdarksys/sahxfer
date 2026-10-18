package grant

// Threats: a lease payload that two builders (Go here and in the agent,
// Node in the server) encode differently, so a field the signer did not
// mean to bind passes; a field that smuggles a newline and shifts every
// later line; and the key material reaching the signer. The payload binds
// every field the agent or recv acts on, and the key only as a hash.
// The lease envelope (systemapi-lease-v1) is verified by the agent, not
// here. docs/golden-xfer-lease-v2.txt is the shared vector.

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

const materialLabel = "sahxfer-material-v1\n"

// Material is hex(sha256("sahxfer-material-v1\n" || key || token)) over the
// raw 32-byte key and 16-byte route token.
func Material(key, token []byte) (string, error) {
	if len(key) != seal.KeySize || len(token) != seal.TokenSize {
		return "", code.New("auth")
	}
	h := sha256.New()
	h.Write([]byte(materialLabel))
	h.Write(key)
	h.Write(token)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Payload is the 18-line xfer lease payload: lines joined by "\n", no
// trailing newline. phase is start or renew. peer is listen or
// dial:<host:port>. material is the 64-hex Material value. The expiry
// line is FirstBy. A control byte or newline in any field is bad_grant.
func Payload(g *Grant, deadline time.Time, phase, peer, material string) (string, error) {
	if g == nil {
		return "", code.New("internal")
	}
	if phase != "start" && phase != "renew" {
		return "", code.New("bad_grant")
	}
	if g.Dir != "put" && g.Dir != "get" {
		return "", code.New("bad_purpose")
	}
	if peer != "listen" {
		if !strings.HasPrefix(peer, "dial:") || checkAddr(peer[len("dial:"):]) != nil {
			return "", code.New("bad_grant")
		}
	}
	if len(material) != 64 {
		return "", code.New("bad_grant")
	}
	if _, err := ParseHash(material); err != nil {
		return "", err
	}
	if !grantID.MatchString(g.GrantID) || g.TransferID == 0 || !g.HaveHash {
		return "", code.New("bad_grant")
	}
	if g.Idle <= 0 || g.Max <= 0 || g.Idle > g.Max || g.Max > 3600*time.Second || g.ByteCap < g.Size {
		return "", code.New("mismatch")
	}
	ow := "0"
	if g.Overwrite {
		ow = "1"
	}
	lines := []string{
		g.GrantID,
		strconv.FormatInt(deadline.Unix(), 10),
		phase,
		g.Dir,
		g.Root,
		g.Path,
		strconv.FormatUint(g.Size, 10),
		hex.EncodeToString(g.Hash[:]),
		ow,
		TransferHex(g.TransferID),
		strconv.FormatInt(g.FirstBy.Unix(), 10),
		strconv.FormatInt(int64(g.Idle/time.Second), 10),
		strconv.FormatInt(int64(g.Max/time.Second), 10),
		strconv.FormatUint(g.ByteCap, 10),
		g.Profile,
		g.Transport,
		peer,
		material,
	}
	for _, l := range lines {
		if l == "" {
			return "", code.New("bad_grant")
		}
		for i := 0; i < len(l); i++ {
			if l[i] < 0x20 || l[i] == 0x7f {
				return "", code.New("bad_grant")
			}
		}
	}
	return strings.Join(lines, "\n"), nil
}

// TransferHex is the 16 lowercase hex digit form of a transfer id.
func TransferHex(id uint64) string {
	s := strconv.FormatUint(id, 16)
	return strings.Repeat("0", 16-len(s)) + s
}
