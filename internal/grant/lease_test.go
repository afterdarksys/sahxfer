package grant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The golden vector is docs/golden-xfer-lease-v2.txt, copied byte for byte
// into systemapi tests/xfer.test.js and the agent's lease test. A change
// here without the other copies breaks the suite.
const (
	goldenContentSHA = "fce1b8bb923aa974c6756658f3e59e5dedfe1ad2f3082a484cd7a2fe593c29e5"
	goldenMaterial   = "b23ea5d376d27f2cc2bb3d42be53bb07c06da9693649646bbe64dfd4b087802c"
	goldenPayload    = "xfr_GoldenVectorAAAAAAAAAA\n" +
		"1760745600\n" +
		"start\n" +
		"put\n" +
		"/srv/app\n" +
		"releases/app.tar.gz\n" +
		"1048576\n" +
		goldenContentSHA + "\n" +
		"0\n" +
		"0123456789abcdef\n" +
		"1760745600\n" +
		"30\n" +
		"3600\n" +
		"1048576\n" +
		"internet\n" +
		"udp\n" +
		"listen\n" +
		goldenMaterial
	goldenMsgSHA = "234e6abdf170097f94d2c8e3f6dafb006e5d1cf761159b6a4a226f3f6ca32380"
)

func goldenGrant(t *testing.T) *Grant {
	t.Helper()
	sum := sha256.Sum256([]byte("sahxfer golden vector contents.."))
	if hex.EncodeToString(sum[:]) != goldenContentSHA {
		t.Fatalf("content sha %x", sum)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	tok := make([]byte, 16)
	for i := range tok {
		tok[i] = byte(0xa1 + i)
	}
	exp := time.Unix(1760745600, 0)
	return &Grant{
		V: 1, GrantID: "xfr_GoldenVectorAAAAAAAAAA", TransferID: 0x0123456789abcdef,
		Purpose: PurposePut, Dir: "put", Root: "/srv/app", Path: "releases/app.tar.gz",
		Size: 1048576, Hash: sum, HaveHash: true, Overwrite: false,
		Profile: "internet", Transport: "udp", PeerUDP: "127.0.0.1:9", AEAD: AEAD,
		Key: key, Token: tok, FirstBy: exp, HardStop: exp.Add(3540 * time.Second),
		Idle: 30 * time.Second, Max: 3600 * time.Second, ByteCap: 1048576,
	}
}

func TestLeaseGoldenVector(t *testing.T) {
	g := goldenGrant(t)
	mat, err := Material(g.Key, g.Token)
	if err != nil || mat != goldenMaterial {
		t.Fatalf("material %s %v", mat, err)
	}
	p, err := Payload(g, time.Unix(1760745600, 0), "start", "listen", mat)
	if err != nil {
		t.Fatal(err)
	}
	if p != goldenPayload {
		t.Fatalf("payload diverged:\n%q\n%q", p, goldenPayload)
	}
	if n := strings.Count(p, "\n"); n != 17 || strings.HasSuffix(p, "\n") {
		t.Fatalf("lines %d", n)
	}
	msg := sha256.Sum256([]byte("xfer\n" + p))
	if hex.EncodeToString(msg[:]) != goldenMsgSHA {
		t.Fatalf("message hash %x", msg)
	}
}

// Every field of the grant that the payload binds moves exactly its line.
func TestLeaseFieldsBind(t *testing.T) {
	g := goldenGrant(t)
	dl := time.Unix(1760745600, 0)
	base, err := Payload(g, dl, "start", "listen", goldenMaterial)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		line int
		mut  func(g *Grant) (time.Time, string, string, string)
	}{
		{0, func(g *Grant) (time.Time, string, string, string) {
			g.GrantID = "xfr_GoldenVectorAAAAAAAAAB"
			return dl, "start", "listen", goldenMaterial
		}},
		{1, func(g *Grant) (time.Time, string, string, string) {
			return dl.Add(time.Second), "start", "listen", goldenMaterial
		}},
		{2, func(g *Grant) (time.Time, string, string, string) { return dl, "renew", "listen", goldenMaterial }},
		{3, func(g *Grant) (time.Time, string, string, string) {
			g.Dir = "get"
			return dl, "start", "listen", goldenMaterial
		}},
		{4, func(g *Grant) (time.Time, string, string, string) {
			g.Root = "/srv/other"
			return dl, "start", "listen", goldenMaterial
		}},
		{5, func(g *Grant) (time.Time, string, string, string) {
			g.Path = "releases/b.tar.gz"
			return dl, "start", "listen", goldenMaterial
		}},
		{6, func(g *Grant) (time.Time, string, string, string) {
			g.Size--
			return dl, "start", "listen", goldenMaterial
		}},
		{7, func(g *Grant) (time.Time, string, string, string) {
			g.Hash[0] ^= 1
			return dl, "start", "listen", goldenMaterial
		}},
		{8, func(g *Grant) (time.Time, string, string, string) {
			g.Overwrite = true
			return dl, "start", "listen", goldenMaterial
		}},
		{9, func(g *Grant) (time.Time, string, string, string) {
			g.TransferID++
			return dl, "start", "listen", goldenMaterial
		}},
		{10, func(g *Grant) (time.Time, string, string, string) {
			g.FirstBy = g.FirstBy.Add(time.Second)
			return dl, "start", "listen", goldenMaterial
		}},
		{11, func(g *Grant) (time.Time, string, string, string) {
			g.Idle = 31 * time.Second
			return dl, "start", "listen", goldenMaterial
		}},
		{12, func(g *Grant) (time.Time, string, string, string) {
			g.Max = 3599 * time.Second
			return dl, "start", "listen", goldenMaterial
		}},
		{13, func(g *Grant) (time.Time, string, string, string) {
			g.ByteCap++
			return dl, "start", "listen", goldenMaterial
		}},
		{14, func(g *Grant) (time.Time, string, string, string) {
			g.Profile = "dc"
			return dl, "start", "listen", goldenMaterial
		}},
		{15, func(g *Grant) (time.Time, string, string, string) {
			g.Transport = "quic-datagram"
			return dl, "start", "listen", goldenMaterial
		}},
		{16, func(g *Grant) (time.Time, string, string, string) {
			return dl, "start", "dial:192.0.2.1:4700", goldenMaterial
		}},
		{17, func(g *Grant) (time.Time, string, string, string) {
			m, _ := Material(append([]byte{0}, g.Key[1:]...), g.Token)
			return dl, "start", "listen", m
		}},
	}
	want := strings.Split(base, "\n")
	for _, c := range cases {
		g2 := goldenGrant(t)
		d, ph, peer, m := c.mut(g2)
		p, err := Payload(g2, d, ph, peer, m)
		if err != nil {
			t.Fatalf("line %d: %v", c.line, err)
		}
		got := strings.Split(p, "\n")
		for i := range want {
			if (got[i] != want[i]) != (i == c.line) {
				t.Fatalf("line %d moved line %d: %q", c.line, i, got[i])
			}
		}
	}
}

func TestLeasePayloadRefuses(t *testing.T) {
	dl := time.Unix(1760745600, 0)
	bad := []struct {
		name string
		mut  func(g *Grant)
		ph   string
		peer string
		mat  string
	}{
		{"phase", nil, "prepare", "listen", goldenMaterial},
		{"peer", nil, "start", "direct", goldenMaterial},
		{"dial no port", nil, "start", "dial:relay", goldenMaterial},
		{"dial newline", nil, "start", "dial:relay\n:1", goldenMaterial},
		{"material short", nil, "start", "listen", goldenMaterial[:63]},
		{"material upper", nil, "start", "listen", strings.ToUpper(goldenMaterial)},
		{"root newline", func(g *Grant) { g.Root = "/srv/app\nx" }, "start", "listen", goldenMaterial},
		{"path control", func(g *Grant) { g.Path = "a\x01b" }, "start", "listen", goldenMaterial},
		{"profile newline", func(g *Grant) { g.Profile = "internet\n" }, "start", "listen", goldenMaterial},
		{"transport empty", func(g *Grant) { g.Transport = "" }, "start", "listen", goldenMaterial},
		{"dir", func(g *Grant) { g.Dir = "both" }, "start", "listen", goldenMaterial},
		{"grant id", func(g *Grant) { g.GrantID = "xfr_a\nb" }, "start", "listen", goldenMaterial},
		{"transfer zero", func(g *Grant) { g.TransferID = 0 }, "start", "listen", goldenMaterial},
		{"idle over max", func(g *Grant) { g.Idle = 2 * g.Max }, "start", "listen", goldenMaterial},
		{"cap under size", func(g *Grant) { g.ByteCap = g.Size - 1 }, "start", "listen", goldenMaterial},
	}
	for _, c := range bad {
		g := goldenGrant(t)
		if c.mut != nil {
			c.mut(g)
		}
		if p, err := Payload(g, dl, c.ph, c.peer, c.mat); err == nil {
			t.Fatalf("%s: accepted %q", c.name, p)
		}
	}
	if _, err := Payload(nil, dl, "start", "listen", goldenMaterial); err == nil {
		t.Fatal("nil grant")
	}
	if _, err := Material(make([]byte, 31), make([]byte, 16)); !codeIs(err, "auth") {
		t.Fatal(err)
	}
	if _, err := Material(make([]byte, 32), make([]byte, 15)); !codeIs(err, "auth") {
		t.Fatal(err)
	}
}

// An HTTP grant: expires_at is the first-packet deadline 60 s after issue,
// and the hard stop is issue plus max_seconds, not expires_at.
func TestRunLimitsFirstByHardStop(t *testing.T) {
	g := goldenGrant(t)
	issue := g.FirstBy.Add(-60 * time.Second)
	idle, max, first, err := g.RunLimits(issue)
	if err != nil || idle != 30*time.Second || max != 3600*time.Second || first != 60*time.Second {
		t.Fatalf("%s %s %s %v", idle, max, first, err)
	}
	// Past the first-packet deadline a fresh start is expired.
	if _, _, _, err := g.RunLimits(g.FirstBy); !codeIs(err, "expired") {
		t.Fatal(err)
	}
}

// The shared vector file and the constants above must not drift apart.
func TestLeaseGoldenFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "golden-xfer-lease-v2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	const begin, end = "-----BEGIN PAYLOAD-----\n", "\n-----END PAYLOAD-----"
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i || s[i+len(begin):j] != goldenPayload {
		t.Fatal("payload in docs/golden-xfer-lease-v2.txt diverged")
	}
	for _, want := range []string{goldenMsgSHA, goldenMaterial, goldenContentSHA} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
}

// The agent's grant line: the hard stop is the start lease's issue time
// (deadline minus 60 s) plus max_s, and port 0 is a valid listen address.
func TestDecodeAgent(t *testing.T) {
	g := goldenGrant(t)
	now := time.Unix(1760745600-50, 0)
	line := func(mut func(m map[string]any)) []byte {
		m := map[string]any{
			"v": 1, "grant_id": g.GrantID, "transfer_id": "0123456789abcdef",
			"purpose": "xfer:put", "dir": "put", "root": "/srv/app", "path": "releases/app.tar.gz",
			"size": 1048576, "sha256": goldenContentSHA, "overwrite": false,
			"profile": "internet", "transport": "udp", "aead": AEAD,
			"key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "route_token": "oaKjpKWmp6ipqqusra6vsA==",
			"expires_unix": 1760745600, "deadline_unix": 1760745600,
			"idle_s": 30, "max_s": 3600, "byte_cap": 1048576, "peer": "listen:0.0.0.0:0",
		}
		if mut != nil {
			mut(m)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, err := DecodeAgent(line(nil), now)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Grant.Wipe()
	if a.Listen != "0.0.0.0:0" || a.Dial != "" || a.Grant.PeerUDP != "" {
		t.Fatalf("peer %q %q %q", a.Listen, a.Dial, a.Grant.PeerUDP)
	}
	if !a.Grant.HardStop.Equal(time.Unix(1760745600-60+3600, 0)) || !a.Grant.FirstBy.Equal(time.Unix(1760745600, 0)) {
		t.Fatalf("hard %s first %s", a.Grant.HardStop, a.Grant.FirstBy)
	}
	mat, _ := Material(a.Grant.Key, a.Grant.Token)
	if mat != goldenMaterial {
		t.Fatal(mat)
	}
	d, err := DecodeAgent(line(func(m map[string]any) { m["peer"] = "dial:192.0.2.1:4700" }), now)
	if err != nil || d.Dial != "192.0.2.1:4700" {
		t.Fatal(d, err)
	}
	d.Grant.Wipe()
	bad := map[string]func(m map[string]any){
		"too_large": nil,
		"bad_grant": func(m map[string]any) { m["v"] = 2 },
		"expired":   func(m map[string]any) { m["deadline_unix"] = now.Unix() },
		"mismatch":  func(m map[string]any) { m["idle_s"] = 3601 },
	}
	for want, mut := range bad {
		raw := line(mut)
		if want == "too_large" {
			raw = bytes.Repeat([]byte(" "), MaxAgentLine+1)
		}
		if _, err := DecodeAgent(raw, now); !codeIs(err, want) {
			t.Fatalf("%s: %v", want, err)
		}
	}
	for _, peer := range []string{"listen:host:1", "listen:127.0.0.1:65536", "listen:127.0.0.1:01", "dial:192.0.2.1:0", "relay:1.2.3.4:5"} {
		if _, err := DecodeAgent(line(func(m map[string]any) { m["peer"] = peer }), now); !codeIs(err, "bad_grant") && !codeIs(err, "mismatch") {
			t.Fatalf("%s: %v", peer, err)
		}
	}
}
