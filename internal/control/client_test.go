package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/token"
)

const (
	testBearer = "bearer-token-ok!!"
	testAPIKey = "api-key-value-ok!"
)

var testHash = [32]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func codeIs(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("got %v want %s", err, want)
	}
	if strings.Contains(err.Error(), "http") || strings.Contains(err.Error(), testBearer) {
		t.Fatalf("error leaked: %s", err.Error())
	}
}

func tlsRoots(srv *httptest.Server) *x509.CertPool {
	return srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func originOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return token.Origin(u)
}

func newTestClient(t *testing.T, srv *httptest.Server, bearer, apiKey string) *Client {
	t.Helper()
	c, err := New(srv.URL, bearer, originOf(t, srv.URL), apiKey, tlsRoots(srv))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func b64n(n int, b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n))
}

type gbody struct {
	GrantID    string          `json:"grant_id"`
	HostID     string          `json:"host_id"`
	TransferID string          `json:"transfer_id"`
	ExpiresAt  string          `json:"expires_at"`
	ExpiresIn  json.RawMessage `json:"expires_in,omitempty"`
	Idle       int64           `json:"idle_seconds"`
	Max        int64           `json:"max_seconds"`
	ByteCap    grant.Uint64    `json:"byte_cap"`
	Purpose    string          `json:"purpose"`
	Root       string          `json:"root"`
	Path       string          `json:"path"`
	Size       grant.Uint64    `json:"size"`
	SHA256     string          `json:"sha256"`
	Overwrite  bool            `json:"overwrite"`
	Profile    string          `json:"profile"`
	Transport  string          `json:"transport"`
	Peer       struct {
		UDP  *string `json:"udp"`
		QUIC *string `json:"quic"`
	} `json:"peer"`
	AEAD  string `json:"aead"`
	Key   string `json:"key"`
	Token string `json:"route_token"`
}

func goodBody(now time.Time) gbody {
	udp := "127.0.0.1:9"
	var b gbody
	b.GrantID = "xfr_0123456789abcdef"
	b.HostID = "web1"
	b.TransferID = "0000000000000001"
	b.ExpiresAt = now.Add(time.Hour).UTC().Format(time.RFC3339Nano)
	b.Idle = 30
	b.Max = 3600
	b.ByteCap = 4
	b.Purpose = grant.PurposePut
	b.Root = "/srv/app"
	b.Path = "releases/app.tar.gz"
	b.Size = 4
	b.SHA256 = hexHash(testHash)
	b.Profile = "internet"
	b.Transport = "udp"
	b.Peer.UDP = &udp
	b.AEAD = grant.AEAD
	b.Key = b64n(32, 0x11)
	b.Token = b64n(16, 0x22)
	return b
}

func goodReq(now time.Time) GrantRequest {
	return GrantRequest{
		HostID: "web1", Purpose: grant.PurposePut, Dir: "put",
		Root: "/srv/app", Path: "releases/app.tar.gz",
		Size: 4, Hash: testHash, HaveHash: true, Transport: "udp", Now: now,
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDialGuard(t *testing.T) {
	refuse := []string{
		"169.254.169.254:443",
		"[fe80::1]:443",
		"[fd00:ec2::254]:443",
		"0.0.0.0:443",
		"224.0.0.1:443",
		"[::ffff:169.254.169.254]:443",
		"[::]:443",
		"example.com:443",
		"not-an-ip",
	}
	for _, a := range refuse {
		if err := DialGuard("udp", a, nil); err == nil || err.Error() != "dial_refused" {
			t.Fatalf("%s: %v", a, err)
		}
	}
	allow := []string{"127.0.0.1:9", "[::1]:9", "1.2.3.4:443"}
	for _, a := range allow {
		if err := DialGuard("udp", a, nil); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	wrapped := &url.Error{Op: "dial", URL: "https://169.254.169.254/secret", Err: code.New("dial_refused")}
	if got := mapDo(wrapped); got.Error() != "dial_refused" || strings.Contains(got.Error(), "169") {
		t.Fatal(got)
	}
}

func TestNewRefuses(t *testing.T) {
	roots := x509.NewCertPool()
	cases := []struct {
		base, bearer, origin, key, want string
	}{
		{"https://127.0.0.1:9", testBearer, "https://127.0.0.1:9", testAPIKey, "auth"},
		{"http://127.0.0.1:9", testBearer, "http://127.0.0.1:9", "", "auth"},
		{"https://metadata.google.internal", testBearer, "x", "", "auth"},
		{"https://metadata.goog", testBearer, "x", "", "auth"},
		{"https://169.254.169.254", testBearer, "x", "", "auth"},
		{"https://[fd00:ec2::254]", testBearer, "x", "", "auth"},
		{"https://user:pass@example.com", testBearer, "x", "", "bad_args"},
		{"https://" + strings.Repeat("a", 200), testBearer, "x", "", "bad_args"},
		{"", testBearer, "x", "", "bad_args"},
		{"https://127.0.0.1:9", "short", "x", "", "auth"},
		{"https://127.0.0.1:9", "", "x", "", "auth"},
		{"https://127.0.0.1:9", "", "x", "short-key", "auth"},
	}
	for _, tc := range cases {
		_, err := New(tc.base, tc.bearer, tc.origin, tc.key, roots)
		codeIs(t, err, tc.want)
	}
}

func TestResolve(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testBearer {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth"}`))
			return
		}
		if r.Header.Get("X-API-Key") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth"}`))
			return
		}
		name := r.URL.Query().Get("name")
		switch name {
		case "web1":
			_, _ = w.Write([]byte(`{"host_id":"h1","hostname":"web1","tenant":"t","status":"online"}`))
		case "down":
			_, _ = w.Write([]byte(`{"host_id":"h2","hostname":"down","tenant":"","status":"offline"}`))
		case "other":
			_, _ = w.Write([]byte(`{"host_id":"h1","hostname":"nope","status":"online"}`))
		case "weird":
			_, _ = w.Write([]byte(`{"host_id":"h1","hostname":"weird","status":"booting"}`))
		case "missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","key":"SECRETKEY"}`))
		case "many":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"ambiguous","matches":3}`))
		case "bad":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_name"}`))
		case "html":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`<html>SECRETKEY</html>`))
		case "nope":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"nope","key":"SECRETKEY"}`))
		case "page":
			_, _ = w.Write([]byte(`<html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found"}`))
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testBearer, "")
	ctx := context.Background()

	h, err := c.Resolve(ctx, "web1")
	if err != nil || h.HostID != "h1" || h.Hostname != "web1" || h.Status != "online" || h.Tenant != "t" {
		t.Fatalf("%+v %v", h, err)
	}
	h, err = c.Resolve(ctx, "down")
	if err != nil || h.Status != "offline" || h.Tenant != "" {
		t.Fatalf("%+v %v", h, err)
	}
	_, err = c.Resolve(ctx, "other")
	codeIs(t, err, "mismatch")
	_, err = c.Resolve(ctx, "weird")
	codeIs(t, err, "mismatch")
	_, err = c.Resolve(ctx, "missing")
	codeIs(t, err, "not_found")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
	_, err = c.Resolve(ctx, "many")
	codeIs(t, err, "ambiguous")
	_, err = c.Resolve(ctx, "bad")
	codeIs(t, err, "invalid_name")
	_, err = c.Resolve(ctx, "html")
	codeIs(t, err, "request_failed")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
	_, err = c.Resolve(ctx, "nope")
	codeIs(t, err, "request_failed")
	_, err = c.Resolve(ctx, "page")
	codeIs(t, err, "bad_grant")
	before := hits.Load()
	_, err = c.Resolve(ctx, "bad name")
	codeIs(t, err, "invalid_name")
	_, err = c.Resolve(ctx, "")
	codeIs(t, err, "invalid_name")
	if hits.Load() != before {
		t.Fatal("invalid name was sent")
	}

	c.APIKey = testAPIKey
	_, err = c.Resolve(ctx, "web1")
	codeIs(t, err, "auth")
}

func TestAPIKeyHeader(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != testAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"auth"}`))
			return
		}
		_, _ = w.Write([]byte(`{"host_id":"h1","hostname":"web1","status":"online"}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, "", testAPIKey)
	h, err := c.Resolve(context.Background(), "web1")
	if err != nil || h.HostID != "h1" {
		t.Fatal(err, h)
	}
	c.BearerOrigin = "https://evil.example"
	c.Bearer = testBearer
	c.APIKey = ""
	_, err = c.Resolve(context.Background(), "web1")
	codeIs(t, err, "auth")
}

func TestGrantRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	var body []byte
	var ctype string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/xfer/grant" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		body = append([]byte(nil), raw...)
		doc := goodBody(now)
		out, err := json.Marshal(doc)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		out = bytes.Replace(out, []byte("{"), []byte(`{"dir":"get","note":"extra",`), 1)
		_, _ = w.Write(out)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testBearer, "")
	g, err := c.Grant(context.Background(), goodReq(now))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Wipe()
	if g.Dir != "put" || g.TransferID != 1 || g.Size != 4 || g.HostID != "web1" {
		t.Fatalf("%+v", g)
	}
	if !grant.SameHash(g.Hash, testHash) || g.PeerUDP != "127.0.0.1:9" || g.PeerQUIC != "" {
		t.Fatalf("%+v", g)
	}
	wantKey, _ := base64.StdEncoding.DecodeString(b64n(32, 0x11))
	wantTok, _ := base64.StdEncoding.DecodeString(b64n(16, 0x22))
	if !bytes.Equal(g.Key, wantKey) || !bytes.Equal(g.Token, wantTok) {
		t.Fatal("key round trip")
	}
	if !bytes.Contains(body, []byte(`"size":4`)) || bytes.Contains(body, []byte(`"size":"`)) {
		t.Fatalf("size encoding %s", body)
	}
	if !bytes.Contains(body, []byte(`"sha256":"`+hexHash(testHash)+`"`)) {
		t.Fatalf("hash missing %s", body)
	}
	if ctype != "application/json" {
		t.Fatalf("content-type %s", ctype)
	}
}

func TestGrantAdoptAndReject(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	type tweak struct {
		name string
		edit func(*gbody) []byte
		req  func(*GrantRequest)
		want string
	}
	other := [32]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10}
	cases := []tweak{
		{name: "hash", edit: func(b *gbody) []byte {
			b.SHA256 = hexHash(other)
			return nil
		}, want: "mismatch"},
		{name: "upper", edit: func(b *gbody) []byte {
			b.SHA256 = strings.ToUpper(b.SHA256)
			return nil
		}, want: "bad_grant"},
		{name: "purpose", edit: func(b *gbody) []byte {
			b.Purpose = grant.PurposeGet
			return nil
		}, want: "bad_purpose"},
		{name: "root", edit: func(b *gbody) []byte {
			b.Root = "/srv/other"
			return nil
		}, want: "bad_root"},
		{name: "path", edit: func(b *gbody) []byte {
			b.Path = "other.bin"
			return nil
		}, want: "bad_path"},
		{name: "past", edit: func(b *gbody) []byte {
			b.ExpiresAt = now.UTC().Format(time.RFC3339Nano)
			return nil
		}, want: "expired"},
		{name: "aead", edit: func(b *gbody) []byte {
			b.AEAD = "AES-256-GCM"
			return nil
		}, want: "auth"},
		{name: "idle0", edit: func(b *gbody) []byte {
			b.Idle = 0
			return nil
		}, want: "mismatch"},
		{name: "cap0", edit: func(b *gbody) []byte {
			b.ByteCap = 0
			return nil
		}, want: "mismatch"},
		{name: "profile", edit: func(b *gbody) []byte {
			b.Profile = ""
			return nil
		}, want: "mismatch"},
		{name: "transport", edit: func(b *gbody) []byte {
			b.Transport = ""
			return nil
		}, want: "mismatch"},
		{name: "expnull", edit: func(b *gbody) []byte {
			b.ExpiresIn = json.RawMessage("null")
			return nil
		}, want: "bad_grant"},
		{name: "exp0", edit: func(b *gbody) []byte {
			b.ExpiresIn = json.RawMessage("0")
			return nil
		}, want: "mismatch"},
		{name: "expbig", edit: func(b *gbody) []byte {
			b.ExpiresIn = json.RawMessage("3601")
			return nil
		}, want: "mismatch"},
		{name: "expstr", edit: func(b *gbody) []byte {
			b.ExpiresIn = json.RawMessage(`"60"`)
			return nil
		}, want: "bad_grant"},
		{name: "sizestr", edit: func(b *gbody) []byte {
			raw, err := json.Marshal(b)
			if err != nil {
				return []byte("{")
			}
			return bytes.Replace(raw, []byte(`"size":4`), []byte(`"size":"4"`), 1)
		}, want: "bad_grant"},
		{name: "newlinekey", edit: func(b *gbody) []byte {
			b.Key = b.Key[:8] + "\n" + b.Key[8:]
			return nil
		}, want: "bad_grant"},
		{name: "shortkey", edit: func(b *gbody) []byte {
			b.Key = b64n(16, 0x11)
			return nil
		}, want: "auth"},
		{name: "two", edit: func(b *gbody) []byte {
			raw, err := json.Marshal(b)
			if err != nil {
				return []byte("{")
			}
			return append(raw, '{', '}')
		}, want: "bad_grant"},
		{name: "badid", edit: func(b *gbody) []byte {
			b.GrantID = "nope"
			return nil
		}, want: "bad_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				doc := goodBody(now)
				if raw := tc.edit(&doc); raw != nil {
					_, _ = w.Write(raw)
					return
				}
				_, _ = w.Write(mustJSON(t, doc))
			}))
			defer srv.Close()
			c := newTestClient(t, srv, testBearer, "")
			req := goodReq(now)
			if tc.req != nil {
				tc.req(&req)
			}
			g, err := c.Grant(context.Background(), req)
			if g != nil {
				g.Wipe()
			}
			codeIs(t, err, tc.want)
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), b64n(4, 0x11)) {
				t.Fatal(err)
			}
		})
	}
}

func TestGrantAdoptMeta(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	srvHash := [32]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10}
	var reqBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		reqBody = append([]byte(nil), buf.Bytes()...)
		doc := goodBody(now)
		doc.Purpose = grant.PurposeGet
		doc.Size = 9
		doc.ByteCap = 9
		doc.SHA256 = hexHash(srvHash)
		_, _ = w.Write(mustJSON(t, doc))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testBearer, "")
	req := goodReq(now)
	req.Purpose = grant.PurposeGet
	req.Dir = "get"
	req.Size = 0
	req.HaveHash = false
	req.AdoptMeta = true
	g, err := c.Grant(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Wipe()
	if g.Dir != "get" || g.Size != 9 || !grant.SameHash(g.Hash, srvHash) || !g.HaveHash {
		t.Fatalf("%+v", g)
	}
	if bytes.Contains(reqBody, []byte(`"sha256"`)) {
		t.Fatalf("get request carried a hash: %s", reqBody)
	}
}

func TestGrantPreCheck(t *testing.T) {
	now := time.Now()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testBearer, "")
	req := goodReq(now)
	req.Transport = "crypto=off"
	_, err := c.Grant(context.Background(), req)
	codeIs(t, err, "mismatch")
	req = goodReq(now)
	req.HaveHash = false
	_, err = c.Grant(context.Background(), req)
	codeIs(t, err, "bad_grant")
	req = goodReq(now)
	req.Path = "."
	_, err = c.Grant(context.Background(), req)
	codeIs(t, err, "not_a_file")
	req = goodReq(now)
	req.Purpose = grant.PurposePut
	req.Dir = "get"
	_, err = c.Grant(context.Background(), req)
	codeIs(t, err, "bad_purpose")
	if hits.Load() != 0 {
		t.Fatal("pre-check reached the server")
	}
}

func TestHTTPEdges(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/xfer/grant":
			switch r.Header.Get("X-Case") {
			case "scope":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"scope_denied","key":"SECRETKEY"}`))
			case "root":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"root_denied"}`))
			case "big":
				_, _ = w.Write(bytes.Repeat([]byte("a"), maxBody+1))
			case "redir":
				http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
			case "quic":
				doc := goodBody(now)
				q := "127.0.0.1:443"
				doc.Transport = "quic-datagram"
				doc.Peer.UDP = nil
				doc.Peer.QUIC = &q
				_, _ = w.Write(mustJSON(t, doc))
			case "expok":
				doc := goodBody(now)
				doc.ExpiresIn = json.RawMessage("60")
				_, _ = w.Write(mustJSON(t, doc))
			default:
				_, _ = w.Write(mustJSON(t, goodBody(now)))
			}
		default:
			if r.URL.Path == "/hang" {
				<-r.Context().Done()
				return
			}
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, testBearer, "")
	ctx := context.Background()

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "scope")
		return srv.Client().Transport.RoundTrip(r)
	})
	_, err := c.Grant(ctx, goodReq(now))
	codeIs(t, err, "scope_denied")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "root")
		return srv.Client().Transport.RoundTrip(r)
	})
	_, err = c.Grant(ctx, goodReq(now))
	codeIs(t, err, "root_denied")

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "big")
		return srv.Client().Transport.RoundTrip(r)
	})
	_, err = c.Grant(ctx, goodReq(now))
	codeIs(t, err, "response_too_large")

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "redir")
		return srv.Client().Transport.RoundTrip(r)
	})
	_, err = c.Grant(ctx, goodReq(now))
	codeIs(t, err, "redirect_denied")
	if strings.Contains(err.Error(), "evil") {
		t.Fatal(err)
	}

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "quic")
		return srv.Client().Transport.RoundTrip(r)
	})
	g, err := c.Grant(ctx, goodReq(now))
	if err != nil {
		t.Fatal(err)
	}
	if g.Transport != "quic-datagram" || g.PeerQUIC != "127.0.0.1:443" || g.Runnable() == nil || g.Runnable().Error() != "agent_unsupported" {
		t.Fatalf("%+v %v", g, g.Runnable())
	}
	g.Wipe()

	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		r.Header.Set("X-Case", "expok")
		return srv.Client().Transport.RoundTrip(r)
	})
	g, err = c.Grant(ctx, goodReq(now))
	if err != nil {
		t.Fatal(err)
	}
	g.Wipe()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c.HTTP = newHTTP(tlsRoots(srv))
	_, err = c.Resolve(cancelCtx, "web1")
	codeIs(t, err, "cancelled")
}

type roundFunc func(*http.Request) (*http.Response, error)

func (f roundFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func roundTrip(f func(*http.Request) (*http.Response, error)) http.RoundTripper {
	return roundFunc(f)
}
