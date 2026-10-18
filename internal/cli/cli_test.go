package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/grant"
)

const (
	apiKey = "api-key-value-ok!"
	bearer = "bearer-token-ok!!"
)

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func phys(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runCmd(ctx context.Context, args ...string) (int, string, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	var out, errb bytes.Buffer
	c := RunContext(ctx, args, &out, &errb)
	return c, out.String(), errb.String()
}

func assertFail(t *testing.T, want string, args ...string) {
	t.Helper()
	c, out, err := runCmd(context.Background(), args...)
	if c != 1 || out != "" || err != want+"\n" {
		t.Fatalf("%v code=%d out=%q err=%q want %s", args, c, out, err, want)
	}
	if strings.Contains(err, "usage") || strings.Contains(err, "flag") {
		t.Fatalf("usage text: %q", err)
	}
}

type cmdResult struct {
	code     int
	out, err string
}

func goCmd(ctx context.Context, args ...string) <-chan cmdResult {
	ch := make(chan cmdResult, 1)
	go func() {
		c, o, e := runCmd(ctx, args...)
		ch <- cmdResult{c, o, e}
	}()
	return ch
}

func await(t *testing.T, ch <-chan cmdResult) cmdResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(35 * time.Second):
		t.Fatal("timeout")
		return cmdResult{}
	}
}

func freeUDP(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

func grabUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func silent(t *testing.T, c *net.UDPConn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var buf [2048]byte
	n, _, err := c.ReadFromUDP(buf[:])
	if err == nil || n > 0 {
		t.Fatalf("packet %d", n)
	}
}

func writeBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func makeGrant(t *testing.T, dir, root, rel string, body []byte, extra func(*grant.Request)) (*grant.Grant, string) {
	t.Helper()
	sum := sha256.Sum256(body)
	in := grant.Request{
		Root: root, Path: rel, Size: uint64(len(body)), Hash: sum, HaveHash: true,
		HostID: "h1", PeerUDP: "127.0.0.1:9",
		Idle: 5 * time.Second, Max: 20 * time.Second,
		Expires: time.Now().Add(2 * time.Minute),
	}
	if dir == "get" {
		in.Purpose, in.Dir = grant.PurposeGet, "get"
		in.Scopes = grant.Scopes{Read: true}
	} else {
		in.Purpose, in.Dir = grant.PurposePut, "put"
		in.Scopes = grant.Scopes{Read: true, Write: true}
	}
	if extra != nil {
		extra(&in)
	}
	g, err := grant.Issue(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Wipe)
	path := filepath.Join(t.TempDir(), "g.json")
	if err := grant.Write(path, g); err != nil {
		t.Fatal(err)
	}
	return g, path
}

func assertOK(t *testing.T, r cmdResult, g *grant.Grant) {
	t.Helper()
	if r.code != 0 || r.err != "" {
		t.Fatalf("code=%d out=%q err=%q", r.code, r.out, r.err)
	}
	want := fmt.Sprintf("%s\n%016x\nok\n", g.GrantID, g.TransferID)
	if r.out != want {
		t.Fatalf("stdout %q want %q", r.out, want)
	}
	key := base64.StdEncoding.EncodeToString(g.Key)
	tok := base64.StdEncoding.EncodeToString(g.Token)
	if strings.Contains(r.out+r.err, key) || strings.Contains(r.out+r.err, tok) {
		t.Fatal("secret")
	}
}

func noPart(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".part") {
			t.Fatalf("temp %s", e.Name())
		}
	}
}

func TestRejects(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "g.json")
	assertFail(t, "bad_args")
	assertFail(t, "bad_args", "-h")
	assertFail(t, "bad_args", "nope")
	assertFail(t, "bad_args", "grant", "-h")
	assertFail(t, "bad_args", "grant", "--url", "https://127.0.0.1:9")
	assertFail(t, "bad_args", "put", "--grant", "f", "--url", "https://127.0.0.1:9", "a", "b")
	assertFail(t, "bad_args", "get", "--grant", "f", "--listen", "127.0.0.1:9", "--to", "127.0.0.1:9", "--out", "x")
	assertFail(t, "bad_args", "get", "--grant", "f", "--out", "x")
	assertFail(t, "bad_args", "put", "--root", "/srv/app", "a", "web1:/srv/app/a")
	assertFail(t, "bad_root", "put", "./app.tar.gz", "web1:/srv/app/releases/app.tar.gz")
	assertFail(t, "bad_root", "get", "web1:/srv/app/releases/app.tar.gz", "./")
	assertFail(t, "bad_args", "put", "--grant", out, "--root", "/srv/app", "a")
	assertFail(t, "bad_args", "recv")
	assertFail(t, "bad_args", "relay")
	assertFail(t, "bad_args", "relay", "--listen", "127.0.0.1:9")
	assertFail(t, "bad_purpose", "grant")
	assertFail(t, "bad_purpose", "grant", "--purpose", "nope")
	assertFail(t, "root_denied", "grant", "--purpose", grant.PurposeRoot)
	assertFail(t, "root_denied", "grant", "--purpose", grant.PurposeRoot, "--out", out)
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	assertFail(t, "bad_args", "grant", "--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "a.bin", "--sha256", frame.EmptySHA256Hex)
	assertFail(t, "bad_args", "grant",
		"--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "a.bin",
		"--size", "01", "--sha256", frame.EmptySHA256Hex, "--peer-udp", "127.0.0.1:9")
	assertFail(t, "mismatch", "grant",
		"--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "a.bin",
		"--size", "0", "--sha256", frame.EmptySHA256Hex, "--transport", "crypto=off", "--peer-udp", "127.0.0.1:9")
	assertFail(t, "mismatch", "grant",
		"--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "a.bin",
		"--size", "0", "--sha256", frame.EmptySHA256Hex, "--transport", "dc", "--peer-udp", "127.0.0.1:9")
	assertFail(t, "mismatch", "grant",
		"--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "a.bin",
		"--size", "0", "--sha256", frame.EmptySHA256Hex, "--idle", "40", "--max", "20", "--peer-udp", "127.0.0.1:9")
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestIssueOK(t *testing.T) {
	isolate(t)
	out := filepath.Join(t.TempDir(), "g.json")
	c, stdout, stderr := runCmd(nil, "grant",
		"--purpose", grant.PurposePut, "--out", out, "--root", "/srv/app", "--path", "releases/app.bin",
		"--size", "0", "--sha256", frame.EmptySHA256Hex, "--peer-udp", "127.0.0.1:9", "--host-id", "h1")
	g, err := grant.Read(out, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Wipe)
	assertOK(t, cmdResult{c, stdout, stderr}, g)
	fi, err := os.Lstat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	if g.Dir != "put" || g.Size != 0 || g.PeerUDP != "127.0.0.1:9" || g.HostID != "h1" {
		t.Fatalf("%+v", g.Dir)
	}
}

func TestRelUnder(t *testing.T) {
	ok, err := relUnder("/srv/app", "/srv/app/releases/app.bin")
	if err != nil || ok != "releases/app.bin" {
		t.Fatalf("%q %v", ok, err)
	}
	if _, err := relUnder("/srv/app", "/srv/app"); err == nil || err.Error() != "not_a_file" {
		t.Fatal(err)
	}
	if _, err := relUnder("/srv/app", "/srv/app-extra/a"); err == nil || err.Error() != "bad_path" {
		t.Fatal(err)
	}
	if _, err := relUnder("/", "/"); err == nil || err.Error() != "not_a_file" {
		t.Fatal(err)
	}
	got, err := relUnder("/", "/etc/passwd")
	if err != nil || got != "etc/passwd" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := relUnder("/srv/app", "/srv/app/../x"); err == nil || err.Error() != "bad_path" {
		t.Fatal(err)
	}
	if _, err := relUnder("/srv/app", "/srv/app/foo/../../etc/passwd"); err == nil || err.Error() != "bad_path" {
		t.Fatal(err)
	}
	if _, err := relUnder("srv", "/srv/a"); err == nil || err.Error() != "bad_root" {
		t.Fatal(err)
	}
}

func TestDestFile(t *testing.T) {
	dir := phys(t)
	missing := filepath.Join(dir, "new.bin")
	got, err := destFile(missing, "releases/app.bin", false)
	if err != nil || got != missing {
		t.Fatalf("%q %v", got, err)
	}
	got, err = destFile(dir, "releases/app.bin", false)
	if err != nil || got != filepath.Join(dir, "app.bin") {
		t.Fatalf("dir %q %v", got, err)
	}
	writeBytes(t, filepath.Join(dir, "app.bin"), []byte("keep"))
	if _, err := destFile(dir, "releases/app.bin", false); err == nil || err.Error() != "exists" {
		t.Fatal(err)
	}
	got, err = destFile(dir, "releases/app.bin", true)
	if err != nil || got != filepath.Join(dir, "app.bin") {
		t.Fatalf("overwrite %q %v", got, err)
	}
	file := filepath.Join(dir, "plain")
	writeBytes(t, file, []byte("x"))
	if _, err := destFile(file, "a.bin", false); err == nil || err.Error() != "exists" {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := destFile(link, "a.bin", false); err == nil || err.Error() != "symlink_refused" {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := destFile(fifo, "a.bin", false); err == nil || err.Error() != "not_a_file" {
		t.Fatal(err)
	}
}

func TestPurposeAndRoot(t *testing.T) {
	isolate(t)
	root := phys(t)
	body := []byte("abcd")
	_, getPath := makeGrant(t, "get", root, "inbox/a.bin", body, nil)
	_, putPath := makeGrant(t, "put", root, "inbox/a.bin", body, nil)
	assertFail(t, "bad_purpose", "put", "--grant", getPath, "--to", "127.0.0.1:9", filepath.Join(root, "src"))
	assertFail(t, "bad_purpose", "get", "--grant", putPath, "--listen", "127.0.0.1:9", "--out", filepath.Join(root, "out"))
	assertFail(t, "bad_root", "recv", "--grant", putPath, "--listen", "127.0.0.1:9", "--root", root+"-extra")
	assertFail(t, "bad_root", "recv", "--grant", putPath, "--listen", "127.0.0.1:9", "--root", "/srv/app")
}

func TestExpiredSilent(t *testing.T) {
	isolate(t)
	root := phys(t)
	body := []byte("abcd")
	src := filepath.Join(root, "src")
	writeBytes(t, src, body)
	_, path := makeGrant(t, "put", root, "inbox/a.bin", body, func(in *grant.Request) {
		in.Expires = time.Now().Add(250 * time.Millisecond)
	})
	time.Sleep(400 * time.Millisecond)
	ln := grabUDP(t)
	assertFail(t, "expired", "put", "--grant", path, "--to", ln.LocalAddr().String(), src)
	silent(t, ln)
}

func TestChangedAndMismatch(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeBytes(t, filepath.Join(root, "inbox", "a.bin"), []byte("aaaa"))
	_, path := makeGrant(t, "get", root, "inbox/a.bin", []byte("bbbb"), nil)
	ln := grabUDP(t)
	assertFail(t, "changed", "recv", "--grant", path, "--to", ln.LocalAddr().String(), "--root", root)
	silent(t, ln)

	writeBytes(t, filepath.Join(root, "inbox", "b.bin"), []byte("12345"))
	_, sp := makeGrant(t, "get", root, "inbox/b.bin", []byte("1234"), nil)
	assertFail(t, "mismatch", "recv", "--grant", sp, "--to", ln.LocalAddr().String(), "--root", root)
	silent(t, ln)

	src := filepath.Join(root, "src")
	writeBytes(t, src, []byte("aaaa"))
	_, pp := makeGrant(t, "put", root, "inbox/c.bin", []byte("bbbb"), nil)
	assertFail(t, "hash_mismatch", "put", "--grant", pp, "--to", ln.LocalAddr().String(), src)
	silent(t, ln)
}

func TestExists(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "inbox", "a.bin")
	writeBytes(t, target, []byte("keep"))
	_, path := makeGrant(t, "put", root, "inbox/a.bin", []byte("keep"), nil)
	held := grabUDP(t)
	assertFail(t, "exists", "recv", "--grant", path, "--listen", held.LocalAddr().String(), "--root", root)
	if b, err := os.ReadFile(target); err != nil || string(b) != "keep" {
		t.Fatalf("%q %v", b, err)
	}

	dest := filepath.Join(root, "got.bin")
	writeBytes(t, dest, []byte("keep"))
	_, gp := makeGrant(t, "get", root, "inbox/a.bin", []byte("keep"), nil)
	held2 := grabUDP(t)
	assertFail(t, "exists", "get", "--grant", gp, "--listen", held2.LocalAddr().String(), "--out", dest)
	if b, err := os.ReadFile(dest); err != nil || string(b) != "keep" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestSymlinkAndFIFO(t *testing.T) {
	isolate(t)
	root := phys(t)
	real := filepath.Join(root, "real")
	writeBytes(t, real, []byte("abcd"))
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, path := makeGrant(t, "put", root, "inbox/a.bin", []byte("abcd"), nil)
	ln := grabUDP(t)
	assertFail(t, "symlink_refused", "put", "--grant", path, "--to", ln.LocalAddr().String(), link)
	silent(t, ln)

	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	assertFail(t, "not_a_file", "put", "--grant", path, "--to", ln.LocalAddr().String(), fifo)
	silent(t, ln)

	_, gp := makeGrant(t, "get", root, "inbox/a.bin", []byte("abcd"), nil)
	outLink := filepath.Join(root, "out-link")
	if err := os.Symlink(real, outLink); err != nil {
		t.Fatal(err)
	}
	assertFail(t, "symlink_refused", "get", "--grant", gp, "--listen", ln.LocalAddr().String(), "--out", outLink)
	outFIFO := filepath.Join(root, "out-pipe")
	if err := syscall.Mkfifo(outFIFO, 0o644); err != nil {
		t.Fatal(err)
	}
	assertFail(t, "not_a_file", "get", "--grant", gp, "--listen", ln.LocalAddr().String(), "--out", outFIFO)
}

func copyDirect(t *testing.T, dir string, body []byte) {
	t.Helper()
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	addr := freeUDP(t)
	if dir == "put" {
		src := filepath.Join(root, "src.bin")
		writeBytes(t, src, body)
		g, path := makeGrant(t, "put", root, "inbox/app.bin", body, nil)
		rx := goCmd(ctx, "recv", "--grant", path, "--listen", addr, "--root", root)
		time.Sleep(100 * time.Millisecond)
		tx := await(t, goCmd(ctx, "put", "--grant", path, "--to", addr, src))
		assertOK(t, tx, g)
		assertOK(t, await(t, rx), g)
		got, err := os.ReadFile(filepath.Join(root, "inbox", "app.bin"))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("n=%d err=%v", len(got), err)
		}
		noPart(t, filepath.Join(root, "inbox"))
		return
	}
	writeBytes(t, filepath.Join(root, "inbox", "app.bin"), body)
	dest := filepath.Join(root, "got.bin")
	g, path := makeGrant(t, "get", root, "inbox/app.bin", body, nil)
	rx := goCmd(ctx, "get", "--grant", path, "--listen", addr, "--out", dest)
	time.Sleep(100 * time.Millisecond)
	tx := await(t, goCmd(ctx, "recv", "--grant", path, "--to", addr, "--root", root))
	assertOK(t, tx, g)
	assertOK(t, await(t, rx), g)
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
	noPart(t, root)
}

func TestDirectPut(t *testing.T) {
	copyDirect(t, "put", bytes.Repeat([]byte("abc"), 1700))
}

func TestDirectGet(t *testing.T) {
	copyDirect(t, "get", bytes.Repeat([]byte("xyz"), 1700))
}

// --diag adds only "diag " lines on stderr: the granted buffers on each
// side. Without it stderr stays empty on success (assertOK).
func TestDiagPut(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := bytes.Repeat([]byte("diag"), 5000)
	src := filepath.Join(root, "src.bin")
	writeBytes(t, src, body)
	g, path := makeGrant(t, "put", root, "inbox/app.bin", body, nil)
	addr := freeUDP(t)
	rx := goCmd(ctx, "recv", "--diag", "--grant", path, "--listen", addr, "--root", root)
	time.Sleep(100 * time.Millisecond)
	tx := await(t, goCmd(ctx, "put", "--diag", "--grant", path, "--to", addr, src))
	rr := await(t, rx)
	for _, r := range []cmdResult{tx, rr} {
		lines := strings.Split(strings.TrimSpace(r.err), "\n")
		var rcv, snd int
		if _, err := fmt.Sscanf(lines[0], "diag rcvbuf=%d sndbuf=%d", &rcv, &snd); err != nil || rcv <= 0 || snd <= 0 {
			t.Fatalf("stderr %q", r.err)
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "diag ") {
				t.Fatalf("non-diag stderr line %q", l)
			}
		}
		r.err = ""
		assertOK(t, r, g)
	}
}

func TestEmptyPut(t *testing.T) {
	copyDirect(t, "put", nil)
}

func TestRelayCopy(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("R"), 5000)
	src := filepath.Join(root, "src.bin")
	writeBytes(t, src, body)
	addr := freeUDP(t)
	g, path := makeGrant(t, "put", root, "inbox/app.bin", body, func(in *grant.Request) {
		in.ByteCap = uint64(len(body)) * 32
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rel := goCmd(ctx, "relay", "--listen", addr, "--grant", path)
	time.Sleep(100 * time.Millisecond)
	rx := goCmd(ctx, "recv", "--grant", path, "--to", addr, "--root", root)
	time.Sleep(100 * time.Millisecond)
	tx := await(t, goCmd(ctx, "put", "--grant", path, "--to", addr, src))
	assertOK(t, tx, g)
	assertOK(t, await(t, rx), g)
	cancel()
	rr := await(t, rel)
	if rr.code != 0 || rr.out != "" {
		t.Fatalf("relay %d %q %q", rr.code, rr.out, rr.err)
	}
	tok := base64.StdEncoding.EncodeToString(g.Token)
	if strings.Contains(rr.err, tok) || strings.Contains(rr.out, tok) {
		t.Fatal("token")
	}
	got, err := os.ReadFile(filepath.Join(root, "inbox", "app.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
}

func TestRelayCancel(t *testing.T) {
	isolate(t)
	root := phys(t)
	g, path := makeGrant(t, "put", root, "inbox/a.bin", []byte("abcd"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	addr := freeUDP(t)
	ch := goCmd(ctx, "relay", "--listen", addr, "--grant", path)
	time.Sleep(100 * time.Millisecond)
	cancel()
	r := await(t, ch)
	if r.code != 0 || r.out != "" {
		t.Fatalf("%d %q %q", r.code, r.out, r.err)
	}
	tok := base64.StdEncoding.EncodeToString(g.Token)
	key := base64.StdEncoding.EncodeToString(g.Key)
	if strings.Contains(r.err, tok) || strings.Contains(r.err, key) {
		t.Fatal("secret")
	}
}

func TestRelayDuplicateAndQUIC(t *testing.T) {
	isolate(t)
	root := phys(t)
	_, path := makeGrant(t, "put", root, "inbox/a.bin", []byte("abcd"), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	held := grabUDP(t)
	c, out, err := runCmd(ctx, "relay", "--listen", held.LocalAddr().String(), "--grant", path, "--grant", path)
	if c != 1 || out != "" || err != "exists\n" {
		t.Fatalf("%d %q %q", c, out, err)
	}
	_, qp := makeGrant(t, "put", root, "inbox/b.bin", []byte("abcd"), func(in *grant.Request) {
		in.Transport = engine.TransportQUICDatagram
		in.PeerUDP = ""
		in.PeerQUIC = "127.0.0.1:9"
	})
	c, out, err = runCmd(ctx, "relay", "--listen", held.LocalAddr().String(), "--grant", qp)
	if c != 1 || out != "" || err != "agent_unsupported\n" {
		t.Fatalf("quic %d %q %q", c, out, err)
	}
}

func TestQUICBeforeOpen(t *testing.T) {
	isolate(t)
	root := phys(t)
	_, path := makeGrant(t, "put", root, "inbox/a.bin", []byte("abcd"), func(in *grant.Request) {
		in.Transport = engine.TransportQUICDatagram
		in.PeerUDP = ""
		in.PeerQUIC = "127.0.0.1:9"
	})
	ln := grabUDP(t)
	missing := filepath.Join(root, "missing")
	assertFail(t, "agent_unsupported", "put", "--grant", path, "--to", ln.LocalAddr().String(), missing)
	silent(t, ln)
}

type hitAPI struct {
	mu      sync.Mutex
	resolve int
	grant   int
	body    []byte
	status  string
	doc     []byte
}

func (a *hitAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/hosts/resolve":
		a.resolve++
		name := r.URL.Query().Get("name")
		st := a.status
		if st == "" {
			st = "online"
		}
		fmt.Fprintf(w, `{"host_id":"h1","hostname":"%s","tenant":"t","status":"%s"}`, name, st)
	case "/api/v1/xfer/grant":
		a.grant++
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		a.body = append([]byte(nil), b...)
		if a.doc == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(a.doc)
	default:
		http.NotFound(w, r)
	}
}

func (a *hitAPI) counts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resolve, a.grant
}

func (a *hitAPI) posted() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.body...)
}

func testAPI(t *testing.T, h *hitAPI) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	testRootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	t.Cleanup(func() { testRootCAs = nil })
	return srv
}

func grantJSON(t *testing.T, g *grant.Grant, peer, sum string) []byte {
	t.Helper()
	udp := peer
	if sum == "" {
		sum = hex.EncodeToString(g.Hash[:])
	}
	doc := struct {
		GrantID    string `json:"grant_id"`
		HostID     string `json:"host_id"`
		TransferID string `json:"transfer_id"`
		ExpiresAt  string `json:"expires_at"`
		Idle       int64  `json:"idle_seconds"`
		Max        int64  `json:"max_seconds"`
		ByteCap    uint64 `json:"byte_cap"`
		Purpose    string `json:"purpose"`
		Root       string `json:"root"`
		Path       string `json:"path"`
		Size       uint64 `json:"size"`
		SHA256     string `json:"sha256"`
		Overwrite  bool   `json:"overwrite"`
		Profile    string `json:"profile"`
		Transport  string `json:"transport"`
		Peer       struct {
			UDP  *string `json:"udp"`
			QUIC *string `json:"quic"`
		} `json:"peer"`
		AEAD  string `json:"aead"`
		Key   string `json:"key"`
		Token string `json:"route_token"`
	}{
		GrantID: g.GrantID, HostID: g.HostID,
		TransferID: fmt.Sprintf("%016x", g.TransferID),
		ExpiresAt:  g.FirstBy.UTC().Format(time.RFC3339Nano),
		Idle:       int64(g.Idle / time.Second), Max: int64(g.Max / time.Second),
		ByteCap: g.ByteCap, Purpose: g.Purpose, Root: g.Root, Path: g.Path,
		Size: g.Size, SHA256: sum, Overwrite: g.Overwrite,
		Profile: g.Profile, Transport: g.Transport, AEAD: g.AEAD,
		Key:   base64.StdEncoding.EncodeToString(g.Key),
		Token: base64.StdEncoding.EncodeToString(g.Token),
	}
	doc.Peer.UDP = &udp
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestURLPathAndAuth(t *testing.T) {
	isolate(t)
	api := &hitAPI{}
	srv := testAPI(t, api)
	missing := filepath.Join(t.TempDir(), "nope")
	cases := []struct {
		want string
		args []string
	}{
		{"bad_path", []string{"put", "--url", srv.URL, "--root", "/srv/app", "--api-key", apiKey, missing, "web1:/srv/app/../../etc/passwd"}},
		{"bad_path", []string{"put", "--url", srv.URL, "--root", "/srv/app", "--api-key", apiKey, missing, "web1:/srv/app-extra/a"}},
		{"not_a_file", []string{"put", "--url", srv.URL, "--root", "/srv/app", "--api-key", apiKey, missing, "web1:/srv/app"}},
		{"not_a_file", []string{"put", "--url", srv.URL, "--root", "/", "--api-key", apiKey, missing, "web1:/"}},
		{"bad_path", []string{"get", "--url", srv.URL, "--root", "/srv/app", "--api-key", apiKey, "web1:/srv/app/foo/../../etc/passwd", missing}},
		{"auth", []string{"put", "--url", srv.URL, "--root", "/srv/app", "--token", bearer, "--api-key", apiKey, missing, "web1:/srv/app/../../etc/passwd"}},
		{"bad_root", []string{"put", "--url", srv.URL, "--token", bearer, "--api-key", apiKey, missing, "web1:/srv/app/a"}},
	}
	for _, tc := range cases {
		assertFail(t, tc.want, tc.args...)
	}
	if res, gr := api.counts(); res != 0 || gr != 0 {
		t.Fatalf("hits resolve=%d grant=%d", res, gr)
	}
}

func TestURLOffline(t *testing.T) {
	isolate(t)
	root := phys(t)
	body := []byte("abcd")
	src := filepath.Join(root, "src.bin")
	writeBytes(t, src, body)
	api := &hitAPI{status: "offline"}
	srv := testAPI(t, api)
	assertFail(t, "agent_offline", "put", "--url", srv.URL, "--root", root, "--api-key", apiKey, src, "web1:"+root+"/src.bin")
	res, gr := api.counts()
	if res != 1 || gr != 0 {
		t.Fatalf("resolve=%d grant=%d", res, gr)
	}
}

func TestURLHashMismatch(t *testing.T) {
	isolate(t)
	root := phys(t)
	body := []byte("abcd")
	src := filepath.Join(root, "src.bin")
	writeBytes(t, src, body)
	ln := grabUDP(t)
	g, _ := makeGrant(t, "put", root, "src.bin", body, func(in *grant.Request) {
		in.PeerUDP = ln.LocalAddr().String()
	})
	api := &hitAPI{doc: grantJSON(t, g, ln.LocalAddr().String(), strings.Repeat("ab", 32))}
	srv := testAPI(t, api)
	assertFail(t, "mismatch", "put", "--url", srv.URL, "--root", root, "--api-key", apiKey, src, "web1:"+root+"/src.bin")
	silent(t, ln)
	if _, gr := api.counts(); gr != 1 {
		t.Fatalf("grant %d", gr)
	}
}

func TestURLPut(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("U"), 5000)
	src := filepath.Join(root, "src.bin")
	writeBytes(t, src, body)
	addr := freeUDP(t)
	g, path := makeGrant(t, "put", root, "releases/app.bin", body, func(in *grant.Request) {
		in.PeerUDP = addr
	})
	api := &hitAPI{doc: grantJSON(t, g, addr, "")}
	srv := testAPI(t, api)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rx := goCmd(ctx, "recv", "--grant", path, "--listen", addr, "--root", root)
	time.Sleep(100 * time.Millisecond)
	tx := await(t, goCmd(ctx, "put", "--url", srv.URL, "--root", root, "--api-key", apiKey, src, "web1:"+root+"/releases/app.bin"))
	assertOK(t, tx, g)
	assertOK(t, await(t, rx), g)
	got, err := os.ReadFile(filepath.Join(root, "releases", "app.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
	var posted struct {
		HostID string `json:"host_id"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(api.posted(), &posted); err != nil {
		t.Fatal(err)
	}
	if posted.HostID != "h1" || posted.Path != "releases/app.bin" {
		t.Fatalf("%+v", posted)
	}
	noPart(t, filepath.Join(root, "releases"))
}

func TestURLGet(t *testing.T) {
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("G"), 4000)
	writeBytes(t, filepath.Join(root, "releases", "app.bin"), body)
	addr := freeUDP(t)
	dest := filepath.Join(root, "got.bin")
	g, path := makeGrant(t, "get", root, "releases/app.bin", body, func(in *grant.Request) {
		in.PeerUDP = addr
	})
	api := &hitAPI{doc: grantJSON(t, g, addr, "")}
	srv := testAPI(t, api)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx := goCmd(ctx, "recv", "--grant", path, "--listen", addr, "--root", root)
	time.Sleep(100 * time.Millisecond)
	rx := await(t, goCmd(ctx, "get", "--url", srv.URL, "--root", root, "--api-key", apiKey, "web1:"+root+"/releases/app.bin", dest))
	assertOK(t, rx, g)
	assertOK(t, await(t, tx), g)
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
	var posted struct {
		HostID string `json:"host_id"`
	}
	if err := json.Unmarshal(api.posted(), &posted); err != nil || posted.HostID != "h1" {
		t.Fatalf("%v %s", err, posted.HostID)
	}
}
