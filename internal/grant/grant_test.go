package grant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

func putReq() Request {
	return Request{
		Purpose:  PurposePut,
		Dir:      "put",
		Root:     "/srv/app",
		Path:     "releases/app.tar.gz",
		Size:     4,
		Hash:     [32]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		HaveHash: true,
		PeerUDP:  "127.0.0.1:9",
		Scopes:   Scopes{Read: true, Write: true},
		Now:      time.Unix(1_700_000_000, 0).UTC(),
	}
}

func mustIssue(t *testing.T, in Request) *Grant {
	t.Helper()
	g, err := Issue(in)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if g == nil || len(g.Key) != seal.KeySize || len(g.Token) != seal.TokenSize {
		t.Fatalf("grant material")
	}
	return g
}

func codeIs(err error, want string) bool {
	return err != nil && err.Error() == want
}

func TestScopeMatrix(t *testing.T) {
	base := putReq()
	cases := []struct {
		name string
		edit func(*Request)
		want string
	}{
		{"put ok", func(*Request) {}, ""},
		{"put dir", func(r *Request) { r.Dir = "get" }, "bad_purpose"},
		{"put scope", func(r *Request) { r.Scopes.Write = false }, "scope_denied"},
		{"get ok", func(r *Request) {
			r.Purpose, r.Dir, r.Scopes = PurposeGet, "get", Scopes{Read: true}
		}, ""},
		{"get scope", func(r *Request) {
			r.Purpose, r.Dir, r.Scopes = PurposeGet, "get", Scopes{}
		}, "scope_denied"},
		{"get dir", func(r *Request) {
			r.Purpose, r.Dir = PurposeGet, "put"
			r.Scopes = Scopes{Read: true}
		}, "bad_purpose"},
		{"root ok", func(r *Request) {
			r.Purpose = PurposeRoot
			r.Scopes = Scopes{Root: true}
		}, ""},
		{"root get", func(r *Request) {
			r.Purpose, r.Dir = PurposeRoot, "get"
			r.Scopes = Scopes{Root: true}
		}, ""},
		{"root denied", func(r *Request) {
			r.Purpose = PurposeRoot
			r.Scopes = Scopes{Read: true, Write: true}
		}, "root_denied"},
		{"root dir", func(r *Request) {
			r.Purpose, r.Dir = PurposeRoot, "side"
			r.Scopes = Scopes{Root: true}
		}, "bad_purpose"},
		{"unknown", func(r *Request) { r.Purpose = "xfer:nope" }, "bad_purpose"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.edit(&in)
			g, err := Issue(in)
			if tc.want == "" {
				if err != nil || g == nil {
					t.Fatalf("got %v", err)
				}
				g.Wipe()
				return
			}
			if g != nil || !codeIs(err, tc.want) {
				t.Fatalf("got grant=%v err=%v want %s", g != nil, err, tc.want)
			}
		})
	}
}

func TestIssueRejects(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
		want string
	}{
		{"dot", func(r *Request) { r.Path = "." }, "not_a_file"},
		{"dotdot", func(r *Request) { r.Path = ".." }, "bad_path"},
		{"rel root", func(r *Request) { r.Root = "srv" }, "bad_root"},
		{"size", func(r *Request) { r.Size = 1 << 63 }, "too_large"},
		{"cap small", func(r *Request) { r.ByteCap = 1 }, "mismatch"},
		{"cap huge", func(r *Request) { r.ByteCap = 1 << 63 }, "too_large"},
		{"idle max", func(r *Request) {
			r.Idle = 60 * time.Second
			r.Max = 30 * time.Second
		}, "mismatch"},
		{"fraction", func(r *Request) { r.Idle = 1500 * time.Millisecond }, "mismatch"},
		{"past", func(r *Request) { r.Expires = r.Now.Add(-time.Second) }, "expired"},
		{"crypto off", func(r *Request) { r.Transport = "crypto=off" }, "mismatch"},
		{"dc transport", func(r *Request) { r.Transport = "dc" }, "mismatch"},
		{"no hash", func(r *Request) { r.HaveHash = false }, "bad_grant"},
		{"bad host", func(r *Request) { r.HostID = "nope host" }, "mismatch"},
		{"port 0", func(r *Request) { r.PeerUDP = "127.0.0.1:0" }, "mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := putReq()
			tc.edit(&in)
			g, err := Issue(in)
			if g != nil || !codeIs(err, tc.want) {
				t.Fatalf("got grant=%v err=%v want %s", g != nil, err, tc.want)
			}
		})
	}
}

func TestIssueDefaults(t *testing.T) {
	in := putReq()
	g := mustIssue(t, in)
	defer g.Wipe()
	if g.Profile != "internet" || g.Transport != engine.TransportUDP {
		t.Fatalf("defaults %s %s", g.Profile, g.Transport)
	}
	if g.Idle != 30*time.Second || g.Max != 3600*time.Second || g.ByteCap != g.Size {
		t.Fatalf("limits")
	}
	if !g.Expires.Equal(in.Now.Add(g.Max)) {
		t.Fatalf("expires %s", g.Expires)
	}
	in.PeerUDP = "[::1]:9"
	g2 := mustIssue(t, in)
	g2.Wipe()
}

func TestPeerConfigIndependentOfWipe(t *testing.T) {
	g := mustIssue(t, putReq())
	cfg, err := g.PeerConfig("client")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sender || cfg.LocalDir != seal.DirClient || cfg.PeerDir != seal.DirAgent {
		t.Fatalf("put client %+v", cfg)
	}
	if cfg.HaveHash != true || !SameHash(cfg.ExpectHash, g.Hash) {
		t.Fatal("hash")
	}
	key0 := cfg.Key[0]
	tok0 := cfg.Token[0]
	g.Wipe()
	if cfg.Key[0] != key0 || cfg.Token[0] != tok0 {
		t.Fatal("aliased")
	}
	for i := range cfg.Key {
		cfg.Key[i] = 0
	}
	for i := range cfg.Token {
		cfg.Token[i] = 0
	}

	in := putReq()
	in.Purpose, in.Dir, in.Scopes = PurposeGet, "get", Scopes{Read: true}
	g = mustIssue(t, in)
	defer g.Wipe()
	c, err := g.PeerConfig("client")
	if err != nil || c.Sender || c.LocalDir != seal.DirClient {
		t.Fatalf("get client %+v %v", c, err)
	}
	a, err := g.PeerConfig("agent")
	if err != nil || !a.Sender || a.LocalDir != seal.DirAgent || a.PeerDir != seal.DirClient {
		t.Fatalf("get agent %+v %v", a, err)
	}
	wipeCfg(c)
	wipeCfg(a)
	if _, err := g.PeerConfig("nope"); !codeIs(err, "internal") {
		t.Fatal(err)
	}
}

func wipeCfg(c engine.Config) {
	for i := range c.Key {
		c.Key[i] = 0
	}
	for i := range c.Token {
		c.Token[i] = 0
	}
}

func TestRunnableAndLimits(t *testing.T) {
	in := putReq()
	in.Transport = engine.TransportQUICDatagram
	in.PeerQUIC = "127.0.0.1:9"
	in.PeerUDP = ""
	g := mustIssue(t, in)
	defer g.Wipe()
	if err := g.Runnable(); !codeIs(err, "agent_unsupported") {
		t.Fatal(err)
	}
	cfg, err := g.PeerConfig("client")
	if err != nil || cfg.Pacing {
		t.Fatalf("pacing %v %+v", err, cfg)
	}
	wipeCfg(cfg)

	in = putReq()
	in.Expires = in.Now.Add(10 * time.Second)
	g = mustIssue(t, in)
	defer g.Wipe()
	idle, max, err := g.RunLimits(in.Now)
	if err != nil || idle != 30*time.Second || max != 10*time.Second {
		t.Fatalf("%s %s %v", idle, max, err)
	}
	_, _, err = g.RunLimits(g.Expires)
	if !codeIs(err, "expired") {
		t.Fatal(err)
	}
}

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "g.json")
	in := putReq()
	in.Size = 0
	in.Hash = [32]byte{}
	g := mustIssue(t, in)
	defer g.Wipe()
	if err := Write(path, g); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"size":0`)) {
		t.Fatalf("size field: %s", body)
	}
	if bytes.Contains(body, []byte("expires_in")) {
		t.Fatal("expires_in")
	}
	got, err := Read(path, in.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	if got.GrantID != g.GrantID || got.TransferID != g.TransferID || got.Size != 0 || !SameHash(got.Hash, g.Hash) {
		t.Fatal("round trip fields")
	}
	if !bytes.Equal(got.Key, g.Key) || !bytes.Equal(got.Token, g.Token) {
		t.Fatal("material")
	}
	if err := Write(path, g); !codeIs(err, "exists") {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, in.Now); !codeIs(err, "symlink_refused") {
		t.Fatal(err)
	}
	if _, _, err := g.RunLimits(g.Expires); !codeIs(err, "expired") {
		t.Fatal(err)
	}
	if _, err := Read(path, g.Expires); !codeIs(err, "expired") {
		t.Fatal(err)
	}
}

func TestFileRejects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "g.json")
	secret := "planted-key-material-0123456789abcdef"
	body := []byte(`{"v":1,"grant_id":"xfr_abcdefgh","transfer_id":"0000000000000001","sha256":"ABCDEF","key":"` + secret + `","expires_in":1}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path, time.Unix(1_700_000_000, 0))
	if !codeIs(err, "bad_grant") || strings.Contains(err.Error(), secret) {
		t.Fatalf("%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Read(path, time.Unix(1_700_000_000, 0))
	if !codeIs(err, "bad_grant") || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "ABCDEF") {
		t.Fatalf("%v", err)
	}

	g := mustIssue(t, putReq())
	defer g.Wipe()
	good := filepath.Join(dir, "good.json")
	if err := Write(good, g); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"profile":"internet"`), []byte(`"profile":""`), 1)
	raw = bytes.Replace(raw, []byte(`"transport":"udp"`), []byte(`"transport":""`), 1)
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(empty, putReq().Now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != "internet" || got.Transport != "udp" {
		t.Fatalf("defaults %s %s", got.Profile, got.Transport)
	}
	got.Wipe()

	upper := bytes.Replace(raw, []byte(`"sha256":"`+g.shaHex()+`"`), []byte(`"sha256":"`+strings.ToUpper(g.shaHex())+`"`), 1)
	up := filepath.Join(dir, "upper.json")
	if err := os.WriteFile(up, upper, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(up, putReq().Now); !codeIs(err, "bad_grant") {
		t.Fatal(err)
	}
}

func (g *Grant) shaHex() string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range g.Hash {
		b[i*2] = hexdigits[c>>4]
		b[i*2+1] = hexdigits[c&0x0f]
	}
	return string(b)
}

func TestParseUint(t *testing.T) {
	n, err := ParseUint("0")
	if err != nil || n != 0 {
		t.Fatal(err)
	}
	for _, s := range []string{"01", "1.0", "1e2", "-1", "+1", " 1", "", "18446744073709551616"} {
		if _, err := ParseUint(s); !codeIs(err, "bad_grant") {
			t.Fatalf("%q %v", s, err)
		}
	}
}

func TestCheckShortKey(t *testing.T) {
	g := mustIssue(t, putReq())
	defer g.Wipe()
	g.Key = g.Key[:16]
	if err := g.Check(putReq().Now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
}

func TestLease(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	g := mustIssue(t, putReq())
	defer g.Wipe()
	msg, sig, dl, err := Sign(priv, g, "start", now)
	if err != nil {
		t.Fatal(err)
	}
	if !dl.Equal(now.Add(LeaseTTL)) {
		t.Fatal(dl)
	}
	if err := Verify(pub, g, msg, sig, now); err != nil {
		t.Fatal(err)
	}
	_, sig2, _, err := Sign(priv, g, "renew", now)
	if err != nil {
		t.Fatal(err)
	}
	renew := payload(g.GrantID, dl.Unix(), "renew", g.Dir, g.Root, g.Path, g.Size, g.Hash)
	if err := Verify(pub, g, renew, sig2, now); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if err := Verify(pub, g, msg, bad, now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	if err := Verify(pub, g, msg, sig, dl); !codeIs(err, "expired") {
		t.Fatal(err)
	}
	if err := Verify(pub, g, msg, sig, dl.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub[:16], g, msg, sig, now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	if _, _, _, err := Sign(priv[:32], g, "start", now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	if err := Verify(pub, nil, msg, sig, now); !codeIs(err, "auth") {
		t.Fatal(err)
	}

	in := putReq()
	in.Purpose, in.Dir, in.Scopes = PurposeGet, "get", Scopes{Read: true}
	getg := mustIssue(t, in)
	defer getg.Wipe()
	putMsg := payload(getg.GrantID, now.Add(LeaseTTL).Unix(), "start", "put", getg.Root, getg.Path, getg.Size, getg.Hash)
	if err := Verify(pub, getg, putMsg, ed25519.Sign(priv, putMsg), now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	kind := payload(g.GrantID, now.Add(LeaseTTL).Unix(), "nope", g.Dir, g.Root, g.Path, g.Size, g.Hash)
	if err := Verify(pub, g, kind, ed25519.Sign(priv, kind), now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	upper := payload(g.GrantID, now.Add(LeaseTTL).Unix(), "start", g.Dir, g.Root, g.Path, g.Size, g.Hash)
	lines := strings.Split(string(upper), "\n")
	lines[7] = strings.ToUpper(lines[7])
	upper = []byte(strings.Join(lines, "\n"))
	if err := Verify(pub, g, upper, ed25519.Sign(priv, upper), now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	moved := append(append([]byte(nil), msg...), '\n')
	if err := Verify(pub, g, moved, ed25519.Sign(priv, moved), now); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	late := payload(g.GrantID, now.Unix(), "start", g.Dir, g.Root, g.Path, g.Size, g.Hash)
	if err := Verify(pub, g, late, ed25519.Sign(priv, late), now); !codeIs(err, "expired") {
		t.Fatal(err)
	}
}

func TestCanonicalKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, 32)
	s := base64.StdEncoding.EncodeToString(raw)
	broken := s[:10] + "\n" + s[10:]
	b, err := decodeCanon(broken, 32)
	if b != nil || !codeIs(err, "bad_grant") {
		t.Fatal(err)
	}
}
