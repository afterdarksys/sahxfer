package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/control"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/pathx"
	"github.com/afterdarksys/sahxfer/internal/safeio"
	"github.com/afterdarksys/sahxfer/internal/udp"
)

type side struct {
	g         *grant.Grant
	role      string
	sender    bool
	src       io.ReaderAt
	dest      engine.File
	commit    func() error
	cleanup   func()
	conn      *net.UDPConn
	connected bool
	// progress is udp.Config.Progress. done sees the peer after the run,
	// for Committed and Delivered. Both may be nil.
	progress func(uint64)
	done     func(*engine.Peer)
	// rcvbuf and sndbuf are the granted socket buffers when the caller
	// already tuned conn (agent mode reports rcvbuf in ready); 0 and 0
	// means transfer tunes it.
	rcvbuf, sndbuf int
}

type diagKey struct{}
type sourcePipelineKey struct{}

// withDiag carries the --diag stderr writer to transfer. Without --diag
// stderr stays a code (docs/design.md section 7.4).
func withDiag(ctx context.Context, on bool, w io.Writer) context.Context {
	if !on || w == nil {
		return ctx
	}
	return context.WithValue(ctx, diagKey{}, w)
}

func diagFrom(ctx context.Context) io.Writer {
	w, _ := ctx.Value(diagKey{}).(io.Writer)
	return w
}

func cmdPut(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	c := newCmd()
	pipeline := c.set.Bool("pipeline-source", false, "experimental bounded source read-ahead")
	diag := c.set.Bool("diag", false, "")
	gpath := c.set.String("grant", "", "")
	base := c.set.String("url", "", "")
	root := c.set.String("root", "", "")
	to := c.set.String("to", "", "")
	tok := c.set.String("token", "", "")
	apiKey := c.set.String("api-key", "", "")
	overwrite := c.set.Bool("overwrite", false, "")
	if err := c.parse(args); err != nil {
		return err
	}
	ctx = withDiag(ctx, *diag, stderr)
	ctx = context.WithValue(ctx, sourcePipelineKey{}, *pipeline)
	if c.saw("grant") && c.saw("url") {
		return code.New("bad_args")
	}
	if c.saw("url") {
		if c.saw("to") || c.saw("grant") {
			return code.New("bad_args")
		}
		if *root == "" {
			return code.New("bad_root")
		}
		if c.narg() != 2 {
			return code.New("bad_args")
		}
		return urlPut(ctx, urlOpts{
			base: *base, root: *root, token: *tok, apiKey: *apiKey,
			sawTok: c.saw("token"), sawKey: c.saw("api-key"),
			overwrite: *overwrite, local: c.arg(0), remote: c.arg(1),
		}, stdout)
	}
	if c.saw("grant") {
		if c.saw("root") || c.saw("token") || c.saw("api-key") || c.saw("overwrite") {
			return code.New("bad_args")
		}
		if *gpath == "" || c.narg() != 1 {
			return code.New("bad_args")
		}
		return grantPut(ctx, *gpath, *to, c.saw("to"), c.arg(0), stdout)
	}
	if *root == "" {
		return code.New("bad_root")
	}
	return code.New("bad_args")
}

func cmdGet(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	c := newCmd()
	diag := c.set.Bool("diag", false, "")
	gpath := c.set.String("grant", "", "")
	base := c.set.String("url", "", "")
	root := c.set.String("root", "", "")
	to := c.set.String("to", "", "")
	listen := c.set.String("listen", "", "")
	out := c.set.String("out", "", "")
	tok := c.set.String("token", "", "")
	apiKey := c.set.String("api-key", "", "")
	overwrite := c.set.Bool("overwrite", false, "")
	if err := c.parse(args); err != nil {
		return err
	}
	ctx = withDiag(ctx, *diag, stderr)
	if c.saw("grant") && c.saw("url") {
		return code.New("bad_args")
	}
	if c.saw("url") {
		if c.saw("listen") || c.saw("to") || c.saw("out") || c.saw("grant") {
			return code.New("bad_args")
		}
		if *root == "" {
			return code.New("bad_root")
		}
		if c.narg() != 2 {
			return code.New("bad_args")
		}
		return urlGet(ctx, urlOpts{
			base: *base, root: *root, token: *tok, apiKey: *apiKey,
			sawTok: c.saw("token"), sawKey: c.saw("api-key"),
			overwrite: *overwrite, local: c.arg(1), remote: c.arg(0),
		}, stdout)
	}
	if c.saw("grant") {
		if c.saw("root") || c.saw("token") || c.saw("api-key") || c.saw("overwrite") || c.saw("url") {
			return code.New("bad_args")
		}
		if *gpath == "" || c.narg() != 0 || c.saw("listen") == c.saw("to") {
			return code.New("bad_args")
		}
		if !c.saw("out") || *out == "" {
			return code.New("bad_args")
		}
		return grantGet(ctx, *gpath, *listen, *to, c.saw("listen"), *out, stdout)
	}
	if *root == "" {
		return code.New("bad_root")
	}
	return code.New("bad_args")
}

func cmdRecv(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	c := newCmd()
	diag := c.set.Bool("diag", false, "")
	gpath := c.set.String("grant", "", "")
	listen := c.set.String("listen", "", "")
	to := c.set.String("to", "", "")
	root := c.set.String("root", "", "")
	ctlFD := c.set.Int("ctl-fd", -1, "")
	evFD := c.set.Int("event-fd", -1, "")
	sweep := c.set.Bool("sweep", false, "")
	report := c.set.Bool("report", false, "")
	if err := c.parse(args); err != nil {
		return err
	}
	ctx = withDiag(ctx, *diag, stderr)
	fileMode := c.saw("grant") || c.saw("listen") || c.saw("to") || c.saw("root")
	if c.saw("sweep") {
		// --report, and only --report, takes an event fd.
		if !*sweep || fileMode || !c.saw("ctl-fd") || *ctlFD < 3 || c.narg() != 0 ||
			c.saw("report") != c.saw("event-fd") || (c.saw("report") && (!*report || *evFD < 3 || *evFD == *ctlFD)) {
			return code.New("bad_args")
		}
		if !c.saw("report") {
			*evFD = -1
		}
		return recvSweep(ctx, *ctlFD, *evFD)
	}
	if c.saw("report") {
		return code.New("bad_args")
	}
	if c.saw("ctl-fd") || c.saw("event-fd") {
		if fileMode || !c.saw("ctl-fd") || !c.saw("event-fd") || c.narg() != 0 ||
			*ctlFD < 3 || *evFD < 3 || *ctlFD == *evFD {
			return code.New("bad_args")
		}
		return recvAgent(ctx, *ctlFD, *evFD, stdout)
	}
	if c.narg() != 0 || !c.saw("grant") || *gpath == "" || c.saw("listen") == c.saw("to") {
		return code.New("bad_args")
	}
	g, err := grant.Read(*gpath, time.Now())
	if err != nil {
		return err
	}
	defer g.Wipe()
	if err := allowAgent(g); err != nil {
		return err
	}
	if *root != g.Root {
		return code.New("bad_root")
	}
	if err := ready(g); err != nil {
		return err
	}
	// The agent starts this process as pty_user. Go cannot drop uid on one
	// goroutine, so recv itself does not change credentials.
	sender := g.Dir == "get"
	rootH, err := safeio.OpenRoot(g.Root)
	if err != nil {
		return err
	}
	defer rootH.Close()
	var src *os.File
	var temp *safeio.Temp
	if sender {
		src, err = rootH.OpenRegular(g.Path)
		if err != nil {
			return err
		}
		defer src.Close()
		n, err := fileSize(src)
		if err != nil {
			return err
		}
		if n != g.Size {
			return code.New("mismatch")
		}
		sum, err := hashFile(src, n)
		if err != nil {
			return err
		}
		if !grant.SameHash(sum, g.Hash) {
			return code.New("changed")
		}
	} else {
		temp, err = rootH.CreateTemp(g.Path, g.GrantID, g.Overwrite)
		if err != nil {
			return err
		}
		defer temp.Remove()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, connected, err := bind(*listen, *to, c.saw("listen"))
	if err != nil {
		return err
	}
	defer conn.Close()
	s := side{
		g: g, role: "agent", sender: sender,
		conn: conn, connected: connected,
	}
	if sender {
		s.src = src
	} else {
		s.dest = temp.File
		s.commit = func() error { return temp.Commit(g.Overwrite) }
		s.cleanup = func() { _ = temp.Remove() }
	}
	if err := transfer(ctx, s); err != nil {
		return err
	}
	return printOK(stdout, g)
}

type urlOpts struct {
	base, root, token, apiKey string
	sawTok, sawKey            bool
	overwrite                 bool
	local, remote             string
}

func urlPut(ctx context.Context, o urlOpts, stdout io.Writer) error {
	if o.sawTok && o.sawKey {
		return code.New("auth")
	}
	host, abs, err := splitRemote(o.remote)
	if err != nil {
		return err
	}
	rel, err := relUnder(o.root, abs)
	if err != nil {
		return err
	}
	if o.local == "" {
		return code.New("bad_args")
	}
	f, err := safeio.OpenRead(o.local)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := fileSize(f)
	if err != nil {
		return err
	}
	sum, err := hashFile(f, n)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g, err := fetchGrant(ctx, o, control.GrantRequest{
		Purpose:   grant.PurposePut,
		Dir:       "put",
		Root:      o.root,
		Path:      rel,
		Size:      n,
		Hash:      sum,
		HaveHash:  true,
		Overwrite: o.overwrite,
		Transport: engine.TransportUDP,
	}, host)
	if err != nil {
		return err
	}
	defer g.Wipe()
	if err := ready(g); err != nil {
		return err
	}
	if g.PeerUDP == "" {
		return code.New("bad_args")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := dialUDP(g.PeerUDP)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := transfer(ctx, side{
		g: g, role: "client", sender: true, src: f,
		conn: conn, connected: true,
	}); err != nil {
		return err
	}
	return printOK(stdout, g)
}

func urlGet(ctx context.Context, o urlOpts, stdout io.Writer) error {
	if o.sawTok && o.sawKey {
		return code.New("auth")
	}
	host, abs, err := splitRemote(o.remote)
	if err != nil {
		return err
	}
	rel, err := relUnder(o.root, abs)
	if err != nil {
		return err
	}
	if o.local == "" {
		return code.New("bad_args")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g, err := fetchGrant(ctx, o, control.GrantRequest{
		Purpose:   grant.PurposeGet,
		Dir:       "get",
		Root:      o.root,
		Path:      rel,
		AdoptMeta: true,
		Overwrite: o.overwrite,
		Transport: engine.TransportUDP,
	}, host)
	if err != nil {
		return err
	}
	defer g.Wipe()
	if err := ready(g); err != nil {
		return err
	}
	if g.PeerUDP == "" {
		return code.New("bad_args")
	}
	dest, err := destFile(o.local, rel, g.Overwrite)
	if err != nil {
		return err
	}
	lt, err := newLocal(dest, g.GrantID, g.Overwrite)
	if err != nil {
		return err
	}
	defer lt.drop()
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := dialUDP(g.PeerUDP)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := transfer(ctx, side{
		g: g, role: "client", sender: false, dest: lt.f,
		commit: lt.commit, cleanup: lt.drop,
		conn: conn, connected: true,
	}); err != nil {
		return err
	}
	return printOK(stdout, g)
}

func fetchGrant(ctx context.Context, o urlOpts, req control.GrantRequest, host string) (*grant.Grant, error) {
	cl, err := openClient(o.base, o.token, o.apiKey, o.sawTok, o.sawKey)
	if err != nil {
		return nil, err
	}
	h, err := cl.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if h.Status != "online" {
		return nil, code.New("agent_offline")
	}
	req.HostID = h.HostID
	return cl.Grant(ctx, req)
}

func grantPut(ctx context.Context, path, to string, sawTo bool, local string, stdout io.Writer) error {
	g, err := grant.Read(path, time.Now())
	if err != nil {
		return err
	}
	defer g.Wipe()
	if err := allowClient(g, "put"); err != nil {
		return err
	}
	if err := ready(g); err != nil {
		return err
	}
	f, err := safeio.OpenRead(local)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := fileSize(f)
	if err != nil {
		return err
	}
	if n != g.Size {
		return code.New("mismatch")
	}
	addr, err := dialAddr(g.PeerUDP, to, sawTo)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := dialUDP(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := transfer(ctx, side{
		g: g, role: "client", sender: true, src: f,
		conn: conn, connected: true,
	}); err != nil {
		return err
	}
	return printOK(stdout, g)
}

func grantGet(ctx context.Context, path, listen, to string, sawListen bool, out string, stdout io.Writer) error {
	g, err := grant.Read(path, time.Now())
	if err != nil {
		return err
	}
	defer g.Wipe()
	if err := allowClient(g, "get"); err != nil {
		return err
	}
	if err := ready(g); err != nil {
		return err
	}
	dest, err := destFile(out, g.Path, g.Overwrite)
	if err != nil {
		return err
	}
	lt, err := newLocal(dest, g.GrantID, g.Overwrite)
	if err != nil {
		return err
	}
	defer lt.drop()
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, connected, err := bind(listen, to, sawListen)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := transfer(ctx, side{
		g: g, role: "client", sender: false, dest: lt.f,
		commit: lt.commit, cleanup: lt.drop,
		conn: conn, connected: connected,
	}); err != nil {
		return err
	}
	return printOK(stdout, g)
}

func transfer(ctx context.Context, s side) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	idle, max, first, err := s.g.RunLimits(time.Now())
	if err != nil {
		return err
	}
	cfg, err := s.g.PeerConfig(s.role)
	if err != nil {
		return err
	}
	cfg.Idle, cfg.Max, cfg.FirstPacket = idle, max, first
	cfg.SourcePipeline, _ = ctx.Value(sourcePipelineKey{}).(bool)
	if cfg.Idle > cfg.Max {
		cfg.Idle = cfg.Max
	}
	if err := ctx.Err(); err != nil {
		wipeCfg(&cfg)
		s.g.Wipe()
		return err
	}
	p, nerr := engine.New(cfg)
	wipeCfg(&cfg)
	s.g.Wipe()
	if nerr != nil {
		return nerr
	}
	ran := false
	defer func() {
		if !ran {
			p.Close()
		}
	}()
	p.SetHooks(engine.Hooks{Commit: s.commit, Cleanup: s.cleanup})
	if s.sender {
		if err := p.AttachSource(s.src); err != nil {
			return err
		}
	} else {
		p.AttachDest(s.dest)
	}
	ran = true
	rcv, snd := s.rcvbuf, s.sndbuf
	if rcv == 0 && snd == 0 {
		rcv, snd = udp.TuneBuffers(s.conn, udp.WantBuffer)
	}
	var diag func(string)
	if w := diagFrom(ctx); w != nil {
		fmt.Fprintf(w, "diag rcvbuf=%d sndbuf=%d\n", rcv, snd)
		diag = func(line string) { fmt.Fprintln(w, line) }
	}
	err = udp.Run(ctx, udp.Config{Peer: p, Conn: s.conn, Connected: s.connected, Epoch: 0, Progress: s.progress, RcvBuf: rcv, Diag: diag})
	if s.done != nil {
		s.done(p)
	}
	return err
}

func wipeCfg(cfg *engine.Config) {
	wipe(cfg.Key)
	wipe(cfg.Token)
	cfg.Key = nil
	cfg.Token = nil
}

func ready(g *grant.Grant) error {
	if err := g.Runnable(); err != nil {
		return err
	}
	_, _, _, err := g.RunLimits(time.Now())
	return err
}

func allowClient(g *grant.Grant, dir string) error {
	if g == nil || g.Dir != dir {
		return code.New("bad_purpose")
	}
	return purposeDir(g.Purpose, g.Dir)
}

func allowAgent(g *grant.Grant) error {
	if g == nil {
		return code.New("bad_purpose")
	}
	return purposeDir(g.Purpose, g.Dir)
}

func purposeDir(purpose, dir string) error {
	switch dir {
	case "put":
		if purpose == grant.PurposePut || purpose == grant.PurposeRoot {
			return nil
		}
	case "get":
		if purpose == grant.PurposeGet || purpose == grant.PurposeRoot {
			return nil
		}
	}
	return code.New("bad_purpose")
}

func splitRemote(s string) (host, abs string, err error) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", code.New("bad_args")
	}
	host, abs = s[:i], s[i+1:]
	if !grant.HostName(host) {
		return "", "", code.New("invalid_name")
	}
	if !strings.HasPrefix(abs, "/") {
		return "", "", code.New("bad_args")
	}
	return host, abs, nil
}

func relUnder(root, abs string) (string, error) {
	if err := pathx.CheckRoot(root); err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, "/") {
		return "", code.New("bad_args")
	}
	var rel string
	if root == "/" {
		if abs == "/" {
			return "", code.New("not_a_file")
		}
		rel = abs[1:]
	} else if abs == root {
		return "", code.New("not_a_file")
	} else if !strings.HasPrefix(abs, root+"/") {
		return "", code.New("bad_path")
	} else {
		rel = abs[len(root)+1:]
	}
	if err := pathx.CheckPath(rel); err != nil {
		return "", err
	}
	if _, _, err := pathx.Parent(rel); err != nil {
		return "", err
	}
	return rel, nil
}

func destFile(out, rel string, overwrite bool) (string, error) {
	_, name, err := pathx.Parent(rel)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(out)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return "", code.New("io")
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", code.New("symlink_refused")
	}
	if fi.IsDir() {
		child := filepath.Join(out, name)
		cfi, err := os.Lstat(child)
		if err != nil {
			if os.IsNotExist(err) {
				return child, nil
			}
			return "", code.New("io")
		}
		if cfi.Mode()&os.ModeSymlink != 0 {
			return "", code.New("symlink_refused")
		}
		if !cfi.Mode().IsRegular() {
			return "", code.New("not_a_file")
		}
		if !overwrite {
			return "", code.New("exists")
		}
		return child, nil
	}
	if fi.Mode().IsRegular() {
		if !overwrite {
			return "", code.New("exists")
		}
		return out, nil
	}
	return "", code.New("not_a_file")
}

type localTemp struct {
	f         *os.File
	temp      string
	dest      string
	overwrite bool
}

func newLocal(dest, grantID string, overwrite bool) (*localTemp, error) {
	if strings.Contains(dest, "\x00") || strings.Contains(grantID, "/") || grantID == "" {
		return nil, code.New("bad_path")
	}
	temp := filepath.Join(filepath.Dir(dest), ".sahxfer-"+grantID+".part")
	f, err := safeio.CreateNew(temp)
	if err != nil {
		return nil, err
	}
	return &localTemp{f: f, temp: temp, dest: dest, overwrite: overwrite}, nil
}

func (t *localTemp) commit() error {
	if t == nil || t.f == nil {
		return code.New("io")
	}
	if err := t.f.Sync(); err != nil {
		return code.New("io")
	}
	parent, err := os.Open(filepath.Dir(t.dest))
	if err != nil {
		return code.New("io")
	}
	serr := parent.Sync()
	cerr := parent.Close()
	if serr != nil || cerr != nil {
		return code.New("io")
	}
	if !t.overwrite {
		if _, err := os.Lstat(t.dest); err == nil {
			return code.New("exists")
		} else if !os.IsNotExist(err) {
			return code.New("io")
		}
	}
	if err := os.Rename(t.temp, t.dest); err != nil {
		return code.New("io")
	}
	t.temp = ""
	return nil
}

func (t *localTemp) drop() {
	if t == nil {
		return
	}
	if t.temp != "" {
		_ = os.Remove(t.temp)
		t.temp = ""
	}
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}

func fileSize(f *os.File) (uint64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, code.New("io")
	}
	if !fi.Mode().IsRegular() {
		return 0, code.New("not_a_file")
	}
	if fi.Size() < 0 || uint64(fi.Size()) >= 1<<63 {
		return 0, code.New("too_large")
	}
	return uint64(fi.Size()), nil
}

func hashFile(f *os.File, size uint64) ([32]byte, error) {
	h := sha256.New()
	if size > 0 {
		if _, err := io.Copy(h, io.NewSectionReader(f, 0, int64(size))); err != nil {
			return [32]byte{}, code.New("io")
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func dialAddr(peer, to string, sawTo bool) (string, error) {
	addr := peer
	if sawTo {
		addr = to
	}
	if addr == "" {
		return "", code.New("bad_args")
	}
	return addr, nil
}

func bind(listen, to string, sawListen bool) (*net.UDPConn, bool, error) {
	if sawListen {
		if listen == "" {
			return nil, false, code.New("bad_args")
		}
		c, err := listenUDP(listen)
		return c, false, err
	}
	if to == "" {
		return nil, false, code.New("bad_args")
	}
	c, err := dialUDP(to)
	return c, true, err
}

func listenUDP(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, code.New("bad_args")
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, code.New("io")
	}
	return c, nil
}

func dialUDP(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, code.New("bad_args")
	}
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return nil, code.New("io")
	}
	return c, nil
}
