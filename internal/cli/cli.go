// Package cli is the sahxfer command.
//
// Threats: a bearer, a grant key, or a route token on stdout or stderr; a
// root compared as a prefix; a put grant used to get; a temp left after
// cancel. This process does not drop uid. The agent must spawn recv with
// SysProcAttr.Credential set to the host pty_user. The host commit is
// RENAME_NOREPLACE on Linux and renameatx_np(RENAME_EXCL) on Darwin.
// Stdout is the grant id, the transfer id, and ok. Stderr is a code.
package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/control"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/relay"
	"github.com/afterdarksys/sahxfer/internal/token"
)

// testRootCAs is nil outside tests. Tests in this package install the
// httptest certificate pool here. Production keeps the system pool.
var testRootCAs *x509.CertPool

// Run runs one command. Interrupt and SIGTERM cancel it.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunContext(ctx, args, stdout, stderr)
}

// RunContext is Run with a caller-owned context.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	err := dispatch(ctx, args, stdout, stderr)
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, mapErr(err).Error())
	return 1
}

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return code.New("bad_args")
	}
	switch args[0] {
	case "grant":
		return cmdGrant(args[1:], stdout)
	case "put":
		return cmdPut(ctx, args[1:], stdout)
	case "get":
		return cmdGet(ctx, args[1:], stdout)
	case "recv":
		return cmdRecv(ctx, args[1:], stdout)
	case "relay":
		return cmdRelay(ctx, args[1:], stderr)
	default:
		return code.New("bad_args")
	}
}

type cmdFlags struct {
	set  *flag.FlagSet
	seen map[string]bool
}

func newCmd() *cmdFlags {
	set := flag.NewFlagSet("sahxfer", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Usage = func() {}
	return &cmdFlags{set: set, seen: map[string]bool{}}
}

func (c *cmdFlags) parse(args []string) error {
	if err := c.set.Parse(args); err != nil {
		return code.New("bad_args")
	}
	c.set.Visit(func(f *flag.Flag) { c.seen[f.Name] = true })
	return nil
}

func (c *cmdFlags) saw(name string) bool { return c.seen[name] }

func (c *cmdFlags) narg() int { return c.set.NArg() }

func (c *cmdFlags) arg(i int) string { return c.set.Arg(i) }

func cmdGrant(args []string, stdout io.Writer) error {
	c := newCmd()
	out := c.set.String("out", "", "")
	purpose := c.set.String("purpose", "", "")
	root := c.set.String("root", "", "")
	path := c.set.String("path", "", "")
	sizeS := c.set.String("size", "", "")
	hashS := c.set.String("sha256", "", "")
	profile := c.set.String("profile", "", "")
	transport := c.set.String("transport", "", "")
	hostID := c.set.String("host-id", "", "")
	peerUDP := c.set.String("peer-udp", "", "")
	peerQUIC := c.set.String("peer-quic", "", "")
	expiresS := c.set.String("expires", "", "")
	idleS := c.set.String("idle", "", "")
	maxS := c.set.String("max", "", "")
	capS := c.set.String("byte-cap", "", "")
	overwrite := c.set.Bool("overwrite", false, "")
	if err := c.parse(args); err != nil {
		return err
	}
	var dir string
	var scopes grant.Scopes
	switch *purpose {
	case grant.PurposeRoot:
		return code.New("root_denied")
	case grant.PurposePut:
		dir = "put"
		scopes = grant.Scopes{Read: true, Write: true}
	case grant.PurposeGet:
		dir = "get"
		scopes = grant.Scopes{Read: true}
	default:
		return code.New("bad_purpose")
	}
	if !c.saw("out") || *out == "" || c.narg() != 0 {
		return code.New("bad_args")
	}
	if !c.saw("size") {
		return code.New("bad_args")
	}
	size, err := parseU(*sizeS)
	if err != nil {
		return err
	}
	hash, err := parseHashFlag(*hashS)
	if err != nil {
		return err
	}
	idle, err := parseSeconds(*idleS)
	if err != nil {
		return err
	}
	max, err := parseSeconds(*maxS)
	if err != nil {
		return err
	}
	var byteCap uint64
	if c.saw("byte-cap") && *capS != "" {
		byteCap, err = parseU(*capS)
		if err != nil {
			return err
		}
	}
	expires, err := parseExpires(*expiresS)
	if err != nil {
		return err
	}
	g, err := grant.Issue(grant.Request{
		Purpose:   *purpose,
		Dir:       dir,
		Root:      *root,
		Path:      *path,
		Size:      size,
		Hash:      hash,
		HaveHash:  true,
		Overwrite: *overwrite,
		Profile:   *profile,
		Transport: *transport,
		HostID:    *hostID,
		PeerUDP:   *peerUDP,
		PeerQUIC:  *peerQUIC,
		Expires:   expires,
		Idle:      idle,
		Max:       max,
		ByteCap:   byteCap,
		Scopes:    scopes,
	})
	if err != nil {
		return err
	}
	werr := grant.Write(*out, g)
	g.Wipe()
	if werr != nil {
		return werr
	}
	return printOK(stdout, g)
}

func cmdRelay(ctx context.Context, args []string, stderr io.Writer) error {
	c := newCmd()
	listen := c.set.String("listen", "", "")
	var paths []string
	c.set.Func("grant", "", func(s string) error {
		if s == "" {
			return code.New("bad_args")
		}
		paths = append(paths, s)
		return nil
	})
	if err := c.parse(args); err != nil {
		return err
	}
	if c.narg() != 0 || !c.saw("listen") || *listen == "" || len(paths) == 0 {
		return code.New("bad_args")
	}
	now := time.Now()
	gs := make([]*grant.Grant, 0, len(paths))
	defer func() {
		for _, g := range gs {
			g.Wipe()
		}
	}()
	for _, p := range paths {
		g, err := grant.Read(p, now)
		if err != nil {
			return err
		}
		gs = append(gs, g)
	}
	for _, g := range gs {
		if err := g.Runnable(); err != nil {
			return err
		}
		if _, _, _, err := g.RunLimits(time.Now()); err != nil {
			return err
		}
	}
	r := relay.New()
	for _, g := range gs {
		exp := time.Duration(g.HardStop.UnixNano())
		if err := r.Admit(g.TransferID, g.Token, g.ByteCap, exp); err != nil {
			return err
		}
		g.Wipe()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	conn, err := listenUDP(*listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = r.Serve(ctx, conn, func(id uint64, rep string) {
		if rep == "" {
			return
		}
		fmt.Fprintf(stderr, "%016x %s\n", id, rep)
	})
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func openClient(base, tok, apiKey string, sawTok, sawKey bool) (*control.Client, error) {
	if sawTok && sawKey {
		return nil, code.New("auth")
	}
	u, _ := url.Parse(base)
	origin := token.Origin(u)
	if sawKey {
		return control.New(base, "", "", apiKey, testRootCAs)
	}
	if sawTok {
		if !token.Valid(tok) {
			return nil, code.New("auth")
		}
		return control.New(base, tok, origin, "", testRootCAs)
	}
	tf, err := token.Read(token.DefaultPath())
	if err != nil {
		return nil, err
	}
	if tf.Origin != origin {
		return nil, code.New("auth")
	}
	return control.New(base, tf.Token, origin, "", testRootCAs)
}

func parseU(s string) (uint64, error) {
	n, err := grant.ParseUint(s)
	if err != nil {
		return 0, code.New("bad_args")
	}
	return n, nil
}

func parseHashFlag(s string) ([32]byte, error) {
	if s == "" {
		return [32]byte{}, code.New("bad_args")
	}
	sum, err := grant.ParseHash(s)
	if err != nil {
		return [32]byte{}, code.New("bad_args")
	}
	return sum, nil
}

func parseSeconds(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	n, err := parseU(s)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	const limit = uint64((1<<63 - 1) / int64(time.Second))
	if n > limit {
		return 0, code.New("mismatch")
	}
	return time.Duration(n) * time.Second, nil
}

func parseExpires(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, code.New("bad_args")
	}
	return t, nil
}

func printOK(w io.Writer, g *grant.Grant) error {
	if g == nil {
		return code.New("internal")
	}
	_, err := fmt.Fprintf(w, "%s\n%016x\nok\n", g.GrantID, g.TransferID)
	if err != nil {
		return code.New("io")
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return code.New("cancelled")
	}
	var ae *engine.AbortError
	if errors.As(err, &ae) {
		return code.New(ae.Error())
	}
	var ce *code.Error
	if errors.As(err, &ce) {
		return ce
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "sahxfer: ") {
		return code.New(strings.TrimPrefix(msg, "sahxfer: "))
	}
	return code.New("io")
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
