//go:build unix

package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/udp"
)

// fakeAgent is the agent side of recv's fd 3 and fd 4 pipes.
type fakeAgent struct {
	ctl     *os.File // write end of fd 3
	events  chan map[string]any
	run     <-chan cmdResult
	refused []map[string]any
}

// startAgentRecv starts `recv --ctl-fd N --event-fd M` in process. recv owns
// dups of the pipe ends it reads and writes, as it would after a spawn.
func startAgentRecv(t *testing.T, ctx context.Context, extra ...string) *fakeAgent {
	t.Helper()
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	evR, evW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cfd, err := syscall.Dup(int(ctlR.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	efd, err := syscall.Dup(int(evW.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	ctlR.Close()
	evW.Close()
	a := &fakeAgent{ctl: ctlW, events: make(chan map[string]any, 64)}
	t.Cleanup(func() { ctlW.Close(); evR.Close() })
	go func() {
		defer close(a.events)
		sc := bufio.NewScanner(evR)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				m = map[string]any{"ev": "unparsable", "raw": sc.Text()}
			}
			a.events <- m
		}
	}()
	args := append([]string{"recv", "--ctl-fd", fmt.Sprint(cfd), "--event-fd", fmt.Sprint(efd)}, extra...)
	a.run = goCmd(ctx, args...)
	return a
}

func (a *fakeAgent) send(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ctl.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

func (a *fakeAgent) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m, ok := <-a.events:
		if !ok {
			t.Fatal("event pipe closed")
		}
		return m
	case <-time.After(20 * time.Second):
		t.Fatal("no event")
		return nil
	}
}

// until skips active events, records refused ones, and returns the next
// other one.
func (a *fakeAgent) until(t *testing.T, ev string) map[string]any {
	t.Helper()
	for {
		m := a.next(t)
		if m["ev"] == ev {
			return m
		}
		if m["ev"] == "refused" {
			a.refused = append(a.refused, m)
			continue
		}
		if m["ev"] != "active" {
			t.Fatalf("want %s got %v", ev, m)
		}
	}
}

// grantLine is the agent's fd 3 grant for g.
func grantLine(g *grant.Grant, peer string, deadline time.Time) map[string]any {
	return map[string]any{
		"v": 1, "grant_id": g.GrantID, "transfer_id": grant.TransferHex(g.TransferID),
		"purpose": g.Purpose, "dir": g.Dir, "root": g.Root, "path": g.Path,
		"size": g.Size, "sha256": hex.EncodeToString(g.Hash[:]), "overwrite": g.Overwrite,
		"profile": g.Profile, "transport": g.Transport, "aead": g.AEAD,
		"key": base64.StdEncoding.EncodeToString(g.Key), "route_token": base64.StdEncoding.EncodeToString(g.Token),
		"expires_unix": time.Now().Add(60 * time.Second).Unix(), "deadline_unix": deadline.Unix(),
		"idle_s": int64(g.Idle / time.Second), "max_s": int64(g.Max / time.Second),
		"byte_cap": g.ByteCap, "peer": peer,
	}
}

// sendFrom runs the client sender for g against addr. stall drops every
// FEEDBACK and NACK the sender would see, so it never finishes on its own.
func sendFrom(t *testing.T, ctx context.Context, g *grant.Grant, body []byte, addr string, stall bool) <-chan error {
	t.Helper()
	cfg, err := g.PeerConfig("client")
	if err != nil {
		t.Fatal(err)
	}
	p, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AttachSource(bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	conn, err := dialUDP(addr)
	if err != nil {
		t.Fatal(err)
	}
	var filt func([]byte) bool
	if stall {
		filt = func(d []byte) bool {
			return len(d) >= frame.HeaderSize && (d[5] == frame.TypeFEEDBACK || d[5] == frame.TypeNACK)
		}
	}
	ch := make(chan error, 1)
	go func() {
		defer conn.Close()
		ch <- udp.Run(ctx, udp.Config{Peer: p, Conn: conn, Connected: true, Filter: filt})
	}()
	return ch
}

func agentRoot(t *testing.T, body []byte) (string, *grant.Grant) {
	t.Helper()
	isolate(t)
	root := phys(t)
	if err := os.Mkdir(filepath.Join(root, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Max 3600 as the server issues: the hard stop is the start lease's
	// issue time (deadline minus 60 s) plus max, so a short test deadline
	// still leaves a hard stop in the future.
	g, _ := makeGrant(t, "put", root, "inbox/app.bin", body, func(in *grant.Request) {
		in.Max = 3600 * time.Second
	})
	return root, g
}

func noSecret(t *testing.T, g *grant.Grant, s string) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(g.Key)
	tok := base64.StdEncoding.EncodeToString(g.Token)
	if strings.Contains(s, key) || strings.Contains(s, tok) {
		t.Fatal("secret leaked")
	}
}

func eventsText(ms ...map[string]any) string {
	b, _ := json.Marshal(ms)
	return string(b)
}

func TestRecvAgentPut(t *testing.T) {
	body := bytes.Repeat([]byte("agent put "), 30000)
	root, g := agentRoot(t, body)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a := startAgentRecv(t, ctx)
	a.send(t, grantLine(g, "listen:127.0.0.1:0", time.Now().Add(60*time.Second)))
	ready := a.next(t)
	addr, _ := ready["udp"].(string)
	if ready["ev"] != "ready" || !strings.HasPrefix(addr, "127.0.0.1:") || strings.HasSuffix(addr, ":0") {
		t.Fatalf("ready %v", ready)
	}
	if rb, _ := ready["rcvbuf"].(float64); rb <= 0 {
		t.Fatalf("ready without rcvbuf: %v", ready)
	}
	tx := sendFrom(t, ctx, g, body, addr, false)
	active := a.next(t)
	if active["ev"] != "active" {
		t.Fatalf("active %v", active)
	}
	res := a.until(t, "result")
	if err := <-tx; err != nil {
		t.Fatalf("sender %v", err)
	}
	sum := sha256.Sum256(body)
	if res["committed"] != true || res["status"] != "ok" || res["grant_id"] != g.GrantID ||
		res["transfer_id"] != fmt.Sprintf("%016x", g.TransferID) ||
		res["bytes"] != float64(len(body)) || res["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("result %v", res)
	}
	if _, ok := res["reason"]; ok {
		t.Fatalf("reason on ok %v", res)
	}
	r := await(t, a.run)
	assertOK(t, r, g)
	noSecret(t, g, eventsText(ready, active, res))
	got, err := os.ReadFile(filepath.Join(root, "inbox", "app.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
	noPart(t, filepath.Join(root, "inbox"))
	if _, ok := <-a.events; ok {
		t.Fatal("event after result")
	}
}

// stopMidTransfer starts a stalled transfer, waits for active, runs stop,
// and checks the receiver sent ABORT cancelled and kept no temp.
func stopMidTransfer(t *testing.T, deadline time.Duration, stop func(a *fakeAgent)) (map[string]any, cmdResult, *fakeAgent) {
	t.Helper()
	body := bytes.Repeat([]byte("s"), 2<<20)
	root, g := agentRoot(t, body)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a := startAgentRecv(t, ctx)
	a.send(t, grantLine(g, "listen:127.0.0.1:0", time.Now().Add(deadline)))
	ready := a.until(t, "ready")
	tx := sendFrom(t, ctx, g, body, ready["udp"].(string), true)
	if m := a.next(t); m["ev"] != "active" {
		t.Fatalf("active %v", m)
	}
	stop(a)
	res := a.until(t, "result")
	err := <-tx
	var ae *engine.AbortError
	if !errors.As(err, &ae) || ae.Reason != frame.ReasonCancelled {
		t.Fatalf("sender %v", err)
	}
	r := await(t, a.run)
	if res["committed"] != false || res["sha256"] != nil || res["grant_id"] != g.GrantID {
		t.Fatalf("result %v", res)
	}
	noSecret(t, g, eventsText(res)+r.out+r.err)
	noPart(t, filepath.Join(root, "inbox"))
	if _, err := os.Stat(filepath.Join(root, "inbox", "app.bin")); !os.IsNotExist(err) {
		t.Fatalf("target written %v", err)
	}
	return res, r, a
}

func TestRecvAgentCancel(t *testing.T) {
	res, r, _ := stopMidTransfer(t, 60*time.Second, func(a *fakeAgent) {
		a.send(t, map[string]any{"op": "cancel", "reason": "cancelled"})
	})
	if res["status"] != "aborted" || res["reason"] != "cancelled" || r.code != 1 || r.out != "" || r.err != "cancelled\n" {
		t.Fatalf("result %v run %+v", res, r)
	}
}

func TestRecvAgentEOF(t *testing.T) {
	res, r, _ := stopMidTransfer(t, 60*time.Second, func(a *fakeAgent) { a.ctl.Close() })
	if res["status"] != "aborted" || res["reason"] != "stopped" || r.code != 1 || r.err != "stopped\n" {
		t.Fatalf("result %v run %+v", res, r)
	}
}

// The lease deadline lapses with no renew: recv stops itself. A renew that
// would move the deadline back is ignored.
func TestRecvAgentDeadline(t *testing.T) {
	start := time.Now()
	res, r, a := stopMidTransfer(t, 3*time.Second, func(a *fakeAgent) {
		a.send(t, map[string]any{"op": "renew", "deadline_unix": time.Now().Add(-time.Hour).Unix()})
	})
	if res["status"] != "expired" || res["reason"] != "expired" || r.code != 1 || r.err != "expired\n" {
		t.Fatalf("result %v run %+v", res, r)
	}
	if len(a.refused) != 1 || a.refused[0]["op"] != "renew" || a.refused[0]["reason"] != "deadline_not_forward" {
		t.Fatalf("refused %v", a.refused)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %s", d)
	}
}

// A renew moves the deadline forward, so the transfer outlives the first one.
func TestRecvAgentRenew(t *testing.T) {
	start := time.Now()
	res, _, _ := stopMidTransfer(t, 3*time.Second, func(a *fakeAgent) {
		a.send(t, map[string]any{"op": "renew", "deadline_unix": time.Now().Add(60 * time.Second).Unix()})
		time.Sleep(4 * time.Second)
		a.send(t, map[string]any{"op": "cancel", "reason": "stopped"})
	})
	if res["reason"] != "stopped" || time.Since(start) < 4*time.Second {
		t.Fatalf("result %v after %s", res, time.Since(start))
	}
}

func TestRecvAgentOversizeGrant(t *testing.T) {
	isolate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := startAgentRecv(t, ctx)
	big := append(bytes.Repeat([]byte("x"), grant.MaxAgentLine+10), '\n')
	go func() { _, _ = a.ctl.Write(big) }()
	r := await(t, a.run)
	if r.code != 1 || r.out != "" || r.err != "too_large\n" {
		t.Fatalf("%+v", r)
	}
	decodeFailure(t, a, "too_large")
}

// decodeFailure is the one result a grant that never decoded produces:
// no grant id, no transfer id, committed false.
func decodeFailure(t *testing.T, a *fakeAgent, reason string) {
	t.Helper()
	m := a.next(t)
	want := map[string]any{"ev": "result", "status": "aborted", "reason": reason, "committed": false}
	if len(m) != len(want) {
		t.Fatalf("result %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("result %v", m)
		}
	}
	if m, ok := <-a.events; ok {
		t.Fatalf("event after result %v", m)
	}
}

// The agent never writes the grant: recv gives up after grantWait.
func TestRecvAgentNoGrantLine(t *testing.T) {
	isolate(t)
	old := grantWait
	grantWait = 300 * time.Millisecond
	t.Cleanup(func() { grantWait = old })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := startAgentRecv(t, ctx)
	r := await(t, a.run)
	if r.code != 1 || r.err != "bad_grant\n" {
		t.Fatalf("%+v", r)
	}
	decodeFailure(t, a, "bad_grant")
}

// A signal (ctx done) while recv waits for the grant ends the wait at once.
func TestRecvAgentSignalBeforeGrant(t *testing.T) {
	isolate(t)
	ctx, cancel := context.WithCancel(context.Background())
	a := startAgentRecv(t, ctx)
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancel()
	r := await(t, a.run)
	if r.code != 1 || r.err != "cancelled\n" || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %s", r, time.Since(start))
	}
	decodeFailure(t, a, "cancelled")
}

// Fds that are not a pipe or a socket are refused.
func TestRecvAgentFDKinds(t *testing.T) {
	isolate(t)
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	efd, err := syscall.Dup(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	assertFail(t, "bad_args", "recv", "--ctl-fd", fmt.Sprint(fd), "--event-fd", fmt.Sprint(efd))
	syscall.Close(fd)
}

// Control lines carry exactly the keys of their op.
func TestParseCtl(t *testing.T) {
	good := map[string]ctlMsg{
		`{"op":"renew","deadline_unix":5}`:        {Op: "renew", Deadline: 5},
		`{"op":"cancel","reason":"stopped"}`:      {Op: "cancel", Reason: "stopped"},
		`{"op":"cancel"}`:                         {Op: "cancel"},
		`{"deadline_unix":7,"op":"renew"}` + "\n": {Op: "renew", Deadline: 7},
	}
	for in, want := range good {
		if got := parseCtl([]byte(in)); got != want {
			t.Fatalf("%s: %+v", in, got)
		}
	}
	for _, in := range []string{
		`{"op":"renew","deadline_unix":5,"reason":"x"}`,
		`{"op":"renew"}`,
		`{"op":"renew","deadline_unix":0}`,
		`{"op":"renew","deadline_unix":"5"}`,
		`{"op":"cancel","deadline_unix":5}`,
		`{"op":"cancel","reason":"x","extra":1}`,
		`{"op":"cancel","reason":3}`,
		`{"op":"pause"}`,
		`{}`,
		`[]`,
		`{"op":"cancel"} {"op":"cancel"}`,
	} {
		if got := parseCtl([]byte(in)); got.Op != "bad" {
			t.Fatalf("%s: %+v", in, got)
		}
	}
}

func TestRecvAgentRefusals(t *testing.T) {
	body := []byte("abcd")
	root, g := agentRoot(t, body)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cases := []struct {
		name string
		mut  func(m map[string]any)
		want string
	}{
		{"unknown field", func(m map[string]any) { m["extra"] = 1 }, "bad_grant"},
		{"short key", func(m map[string]any) { m["key"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) }, "auth"},
		{"bad peer", func(m map[string]any) { m["peer"] = "direct" }, "bad_grant"},
		{"listen name", func(m map[string]any) { m["peer"] = "listen:localhost:0" }, "bad_grant"},
		{"lease lapsed", func(m map[string]any) { m["deadline_unix"] = time.Now().Add(-time.Second).Unix() }, "expired"},
		{"first packet lapsed", func(m map[string]any) { m["expires_unix"] = time.Now().Add(-time.Second).Unix() }, "expired"},
		{"max over 3600", func(m map[string]any) { m["max_s"] = 3601 }, "mismatch"},
		{"path escape", func(m map[string]any) { m["path"] = "../x" }, "bad_path"},
	}
	for _, c := range cases {
		a := startAgentRecv(t, ctx)
		m := grantLine(g, "listen:127.0.0.1:0", time.Now().Add(time.Minute))
		c.mut(m)
		a.send(t, m)
		r := await(t, a.run)
		if r.code != 1 || r.err != c.want+"\n" {
			t.Fatalf("%s: %+v", c.name, r)
		}
		decodeFailure(t, a, c.want)
	}
	// A target that exists without overwrite is a result before ready.
	writeBytes(t, filepath.Join(root, "inbox", "app.bin"), []byte("keep"))
	a := startAgentRecv(t, ctx)
	a.send(t, grantLine(g, "listen:127.0.0.1:0", time.Now().Add(time.Minute)))
	res := a.next(t)
	if res["ev"] != "result" || res["committed"] != false || res["reason"] != "exists" {
		t.Fatalf("result %v", res)
	}
	if r := await(t, a.run); r.code != 1 || r.err != "exists\n" {
		t.Fatalf("%+v", r)
	}
	got, _ := os.ReadFile(filepath.Join(root, "inbox", "app.bin"))
	if string(got) != "keep" {
		t.Fatalf("target %q", got)
	}
}

// A forged datagram reaches the listening recv before the real sender. It
// does not pin that source, and the real transfer completes.
func TestRecvAgentForgedFirstDatagram(t *testing.T) {
	body := bytes.Repeat([]byte("forged "), 5000)
	root, g := agentRoot(t, body)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a := startAgentRecv(t, ctx)
	a.send(t, grantLine(g, "listen:127.0.0.1:0", time.Now().Add(60*time.Second)))
	addr := a.until(t, "ready")["udp"].(string)
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	forger, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	defer forger.Close()
	junk := make([]byte, frame.HeaderSize+32)
	copy(junk, []byte("sahxfer forged first datagram"))
	if _, err := forger.Write(junk); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := <-sendFrom(t, ctx, g, body, addr, false); err != nil {
		t.Fatalf("sender %v", err)
	}
	res := a.until(t, "result")
	if res["committed"] != true || res["status"] != "ok" {
		t.Fatalf("result %v", res)
	}
	assertOK(t, await(t, a.run), g)
	got, err := os.ReadFile(filepath.Join(root, "inbox", "app.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("n=%d err=%v", len(got), err)
	}
}

func TestRecvAgentSweep(t *testing.T) {
	isolate(t)
	root := phys(t)
	temp := filepath.Join(root, "inbox", ".sahxfer-xfr_sweep0001.part")
	other := filepath.Join(root, "inbox", ".sahxfer-xfr_other0001.part")
	target := filepath.Join(root, "inbox", "app.bin")
	writeBytes(t, temp, []byte("t"))
	writeBytes(t, other, []byte("o"))
	writeBytes(t, target, []byte("keep"))
	sweep := func(doc map[string]any) cmdResult {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		fd, err := syscall.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		b, _ := json.Marshal(doc)
		if _, err := w.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		w.Close()
		c, o, e := runCmd(context.Background(), "recv", "--sweep", "--ctl-fd", fmt.Sprint(fd))
		return cmdResult{c, o, e}
	}
	r := sweep(map[string]any{"root": root, "path": "inbox/app.bin", "grant_id": "xfr_sweep0001"})
	if r.code != 0 || r.out != "" || r.err != "" {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("temp kept")
	}
	for _, p := range []string{other, target} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed", p)
		}
	}
	if r := sweep(map[string]any{"root": root, "path": "inbox/app.bin", "grant_id": "xfr_sweep0001"}); r.code != 0 {
		t.Fatalf("absent %+v", r)
	}
	if r := sweep(map[string]any{"root": root, "path": "inbox/app.bin", "grant_id": "../app.bin"}); r.code != 1 || r.err != "bad_path\n" {
		t.Fatalf("bad id %+v", r)
	}
	if r := sweep(map[string]any{"root": root, "path": "inbox/app.bin", "grant_id": "xfr_short"}); r.code != 1 || r.err != "bad_path\n" {
		t.Fatalf("short id %+v", r)
	}
	if r := sweep(map[string]any{"root": root, "path": "../x", "grant_id": "xfr_sweep0001"}); r.code != 1 {
		t.Fatalf("escape %+v", r)
	}
}

func TestRecvAgentSweepReport(t *testing.T) {
	isolate(t)
	root := phys(t)
	body := []byte("committed before the restart")
	writeBytes(t, filepath.Join(root, "inbox", "app.bin"), body)
	writeBytes(t, filepath.Join(root, "inbox", ".sahxfer-xfr_report001.part"), []byte("t"))
	pipe := func() (*os.File, *os.File) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		return r, w
	}
	report := func(path string) (cmdResult, string) {
		cr, cw := pipe()
		ctl, err := syscall.Dup(int(cr.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		cr.Close()
		b, _ := json.Marshal(map[string]any{"root": root, "path": path, "grant_id": "xfr_report001"})
		if _, err := cw.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		cw.Close()
		er, ew := pipe()
		ev, err := syscall.Dup(int(ew.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		ew.Close()
		// recv takes ownership of both fds and closes them.
		c, o, e := runCmd(context.Background(), "recv", "--sweep", "--report", "--ctl-fd", fmt.Sprint(ctl), "--event-fd", fmt.Sprint(ev))
		out, _ := io.ReadAll(er)
		er.Close()
		return cmdResult{c, o, e}, string(out)
	}
	r, ev := report("inbox/app.bin")
	sum := sha256.Sum256(body)
	want := fmt.Sprintf(`{"ev":"target","bytes":%d,"sha256":"%s"}`+"\n", len(body), hex.EncodeToString(sum[:]))
	if r.code != 0 || r.out != "" || ev != want {
		t.Fatalf("%+v %q", r, ev)
	}
	if _, err := os.Stat(filepath.Join(root, "inbox", ".sahxfer-xfr_report001.part")); !os.IsNotExist(err) {
		t.Fatal("temp kept")
	}
	if r, ev := report("inbox/absent.bin"); r.code != 0 || ev != "" {
		t.Fatalf("absent %+v %q", r, ev)
	}
	if r, ev := report("missing/absent.bin"); r.code != 0 || ev != "" {
		t.Fatalf("absent dir %+v %q", r, ev)
	}
	if err := os.Symlink(filepath.Join(root, "inbox", "app.bin"), filepath.Join(root, "inbox", "link.bin")); err != nil {
		t.Fatal(err)
	}
	if r, ev := report("inbox/link.bin"); r.code == 0 || ev != "" {
		t.Fatalf("symlink %+v %q", r, ev)
	}
	for _, args := range [][]string{
		{"recv", "--sweep", "--report", "--ctl-fd", "3"},
		{"recv", "--sweep", "--report", "--ctl-fd", "3", "--event-fd", "3"},
		{"recv", "--report", "--ctl-fd", "3", "--event-fd", "4"},
		{"recv", "--sweep", "--report=false", "--ctl-fd", "3", "--event-fd", "4"},
	} {
		assertFail(t, "bad_args", args...)
	}
}

func TestRecvAgentFlags(t *testing.T) {
	isolate(t)
	for _, args := range [][]string{
		{"recv", "--ctl-fd", "3"},
		{"recv", "--event-fd", "4"},
		{"recv", "--ctl-fd", "3", "--event-fd", "3"},
		{"recv", "--ctl-fd", "1", "--event-fd", "4"},
		{"recv", "--ctl-fd", "3", "--event-fd", "4", "--grant", "x"},
		{"recv", "--ctl-fd", "3", "--event-fd", "4", "--listen", "127.0.0.1:0"},
		{"recv", "--ctl-fd", "3", "--event-fd", "4", "--to", "127.0.0.1:9"},
		{"recv", "--ctl-fd", "3", "--event-fd", "4", "--root", "/srv"},
		{"recv", "--sweep"},
		{"recv", "--sweep", "--ctl-fd", "3", "--event-fd", "4"},
		{"recv", "--sweep", "--ctl-fd", "3", "--root", "/srv"},
	} {
		assertFail(t, "bad_args", args...)
	}
}
