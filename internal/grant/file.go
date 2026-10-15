package grant

// Threats: a bootstrap file the group can read, a symlink swapped in for
// that file, a second writer clobbering the key, and a decode error that
// quotes the key. The raw buffer is wiped. Go strings the decoder copies
// cannot be wiped. This is the only on-disk copy of the key.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/secfile"
)

const maxGrantFile = 1 << 20

// fileKeep is the Read error set. auth from a loose mode becomes bad_grant.
var fileKeep = map[string]bool{
	"not_found": true, "symlink_refused": true, "exists": true, "io": true,
	"too_large": true, "expired": true, "mismatch": true, "bad_purpose": true,
	"bad_root": true, "bad_path": true, "bad_grant": true, "internal": true,
	"not_a_file": true, "reserved_name": true,
}

type fileDoc struct {
	V          int     `json:"v"`
	GrantID    string  `json:"grant_id"`
	TransferID string  `json:"transfer_id"`
	HostID     string  `json:"host_id"`
	Purpose    string  `json:"purpose"`
	Dir        string  `json:"dir"`
	Root       string  `json:"root"`
	Path       string  `json:"path"`
	Size       Uint64  `json:"size"`
	SHA256     string  `json:"sha256"`
	Overwrite  bool    `json:"overwrite"`
	Profile    string  `json:"profile"`
	Transport  string  `json:"transport"`
	Peer       peerDoc `json:"peer"`
	AEAD       string  `json:"aead"`
	Key        string  `json:"key"`
	RouteToken string  `json:"route_token"`
	ExpiresAt  string  `json:"expires_at"`
	Idle       int64   `json:"idle_seconds"`
	Max        int64   `json:"max_seconds"`
	ByteCap    Uint64  `json:"byte_cap"`
}

type peerDoc struct {
	UDP  *string `json:"udp"`
	QUIC *string `json:"quic"`
}

// Write creates path mode 0600. A failed write removes the partial file.
// The caller's grant is not wiped.
func Write(path string, g *Grant) error {
	if g == nil {
		return code.New("internal")
	}
	doc := fileDoc{
		V:          g.V,
		GrantID:    g.GrantID,
		TransferID: fmt.Sprintf("%016x", g.TransferID),
		HostID:     g.HostID,
		Purpose:    g.Purpose,
		Dir:        g.Dir,
		Root:       g.Root,
		Path:       g.Path,
		Size:       Uint64(g.Size),
		SHA256:     fmt.Sprintf("%x", g.Hash[:]),
		Overwrite:  g.Overwrite,
		Profile:    g.Profile,
		Transport:  g.Transport,
		Peer:       peerDoc{UDP: strPtr(g.PeerUDP), QUIC: strPtr(g.PeerQUIC)},
		AEAD:       g.AEAD,
		Key:        base64.StdEncoding.EncodeToString(g.Key),
		RouteToken: base64.StdEncoding.EncodeToString(g.Token),
		ExpiresAt:  g.Expires.UTC().Format(time.RFC3339Nano),
		Idle:       int64(g.Idle / time.Second),
		Max:        int64(g.Max / time.Second),
		ByteCap:    Uint64(g.ByteCap),
	}
	var buf bytes.Buffer
	defer func() {
		b := buf.Bytes()
		if cap(b) > 0 {
			wipe(b[:cap(b)])
		}
	}()
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&doc); err != nil {
		return code.New("internal")
	}
	f, err := secfile.CreateExcl(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return dropFile(f, path)
	}
	if err := f.Sync(); err != nil {
		return dropFile(f, path)
	}
	if err := f.Close(); err != nil {
		if rm := os.Remove(path); rm != nil && !os.IsNotExist(rm) {
			return code.New("io")
		}
		return code.New("io")
	}
	return nil
}

func dropFile(f *os.File, path string) error {
	_ = f.Close()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return code.New("io")
	}
	return code.New("io")
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Read loads one grant. Defaults for an empty profile, transport, idle,
// byte cap, or expiry are applied, then Check runs. The raw buffer is wiped.
func Read(path string, now time.Time) (g *Grant, err error) {
	f, _, err := secfile.OpenRead(path)
	if err != nil {
		return nil, mapFile(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxGrantFile+1))
	if err != nil {
		return nil, code.New("io")
	}
	defer wipe(raw)
	if len(raw) > maxGrantFile {
		return nil, code.New("too_large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc fileDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, code.New("bad_grant")
	}
	if dec.More() {
		return nil, code.New("bad_grant")
	}
	g, err = doc.grant(now)
	if err != nil {
		if g != nil {
			g.Wipe()
		}
		return nil, mapFile(err)
	}
	return g, nil
}

func (d fileDoc) grant(now time.Time) (*Grant, error) {
	if now.IsZero() {
		now = time.Now()
	}
	g := &Grant{
		V:         d.V,
		GrantID:   d.GrantID,
		HostID:    d.HostID,
		Purpose:   d.Purpose,
		Dir:       d.Dir,
		Root:      d.Root,
		Path:      d.Path,
		Size:      uint64(d.Size),
		Overwrite: d.Overwrite,
		Profile:   d.Profile,
		Transport: d.Transport,
		AEAD:      d.AEAD,
		PeerUDP:   deref(d.Peer.UDP),
		PeerQUIC:  deref(d.Peer.QUIC),
		ByteCap:   uint64(d.ByteCap),
	}
	id, err := parseTransfer(d.TransferID)
	if err != nil {
		return nil, err
	}
	g.TransferID = id
	sum, err := ParseHash(d.SHA256)
	if err != nil {
		return nil, err
	}
	g.Hash = sum
	g.HaveHash = true
	key, err := decodeCanon(d.Key, 32)
	if err != nil {
		return nil, err
	}
	tok, err := decodeCanon(d.RouteToken, 16)
	if err != nil {
		wipe(key)
		return nil, err
	}
	g.Key = key
	g.Token = tok
	if d.Idle < 0 || d.Max < 0 {
		g.Wipe()
		return nil, code.New("mismatch")
	}
	g.Idle = time.Duration(d.Idle) * time.Second
	g.Max = time.Duration(d.Max) * time.Second
	if g.Profile == "" {
		g.Profile = "internet"
	}
	if g.Transport == "" {
		g.Transport = "udp"
	}
	if g.Idle == 0 {
		g.Idle = 30 * time.Second
	}
	if g.Max == 0 {
		g.Max = 3600 * time.Second
	}
	if g.ByteCap == 0 {
		g.ByteCap = g.Size
	}
	if d.ExpiresAt == "" {
		g.Expires = now.Add(g.Max)
	} else {
		t, perr := time.Parse(time.RFC3339Nano, d.ExpiresAt)
		if perr != nil {
			g.Wipe()
			return nil, code.New("bad_grant")
		}
		g.Expires = t
	}
	if err := g.Check(now); err != nil {
		g.Wipe()
		return nil, err
	}
	return g, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func parseTransfer(s string) (uint64, error) {
	if len(s) != 16 {
		return 0, code.New("bad_grant")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return 0, code.New("bad_grant")
		}
	}
	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil || n == 0 {
		return 0, code.New("bad_grant")
	}
	return n, nil
}

func decodeCanon(s string, n int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, code.New("bad_grant")
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		wipe(b)
		return nil, code.New("bad_grant")
	}
	if len(b) != n {
		wipe(b)
		return nil, code.New("auth")
	}
	return b, nil
}

func mapFile(err error) error {
	var ce *code.Error
	if errors.As(err, &ce) && fileKeep[ce.C] {
		return err
	}
	return code.New("bad_grant")
}
