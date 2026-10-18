package grant

// Threats: a grant line from the agent that names fields this helper does
// not know, a line large enough to exhaust memory, a peer that points the
// helper at a third party, and a hard stop later than the server allows.
// The agent has already verified the lease envelope; this is the shape
// check. Unknown fields are refused. The caller wipes the raw line.
// json.Decoder copies the line into its own internal buffer, and the
// decoded key and token are Go strings; neither can be wiped, and both are
// left to the garbage collector.

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// MaxAgentLine is the cap on one fd 3 line, the grant included.
const MaxAgentLine = 64 << 10

// AgentGrant is the grant line the agent writes to recv on fd 3.
// Peer is listen:<bind addr> or dial:<host:port>. Deadline is the lease
// deadline; only a renew moves it.
type AgentGrant struct {
	Grant    *Grant
	Listen   string
	Dial     string
	Deadline time.Time
}

type agentDoc struct {
	V          int    `json:"v"`
	GrantID    string `json:"grant_id"`
	TransferID string `json:"transfer_id"`
	Purpose    string `json:"purpose"`
	Dir        string `json:"dir"`
	Root       string `json:"root"`
	Path       string `json:"path"`
	Size       Uint64 `json:"size"`
	SHA256     string `json:"sha256"`
	Overwrite  bool   `json:"overwrite"`
	Profile    string `json:"profile"`
	Transport  string `json:"transport"`
	AEAD       string `json:"aead"`
	Key        string `json:"key"`
	RouteToken string `json:"route_token"`
	Expires    int64  `json:"expires_unix"`
	Deadline   int64  `json:"deadline_unix"`
	Idle       int64  `json:"idle_s"`
	Max        int64  `json:"max_s"`
	ByteCap    Uint64 `json:"byte_cap"`
	Peer       string `json:"peer"`
}

// DecodeAgent decodes one grant line (without its newline) and runs Check.
// No defaults are applied: every field is required. The hard stop is the
// earlier of now plus max_s and the issue time (deadline_unix minus the
// 60 s start lease) plus max_s.
func DecodeAgent(raw []byte, now time.Time) (*AgentGrant, error) {
	if len(raw) > MaxAgentLine {
		return nil, code.New("too_large")
	}
	if now.IsZero() {
		now = time.Now()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d agentDoc
	if err := dec.Decode(&d); err != nil || dec.More() {
		return nil, code.New("bad_grant")
	}
	if d.V != 1 {
		return nil, code.New("bad_grant")
	}
	a := &AgentGrant{}
	switch {
	case strings.HasPrefix(d.Peer, "listen:"):
		a.Listen = d.Peer[len("listen:"):]
		if err := checkBind(a.Listen); err != nil {
			return nil, err
		}
	case strings.HasPrefix(d.Peer, "dial:"):
		a.Dial = d.Peer[len("dial:"):]
		if err := checkAddr(a.Dial); err != nil {
			return nil, err
		}
	default:
		return nil, code.New("bad_grant")
	}
	if d.Idle <= 0 || d.Max <= 0 || d.Max > 3600 || d.Idle > d.Max {
		return nil, code.New("mismatch")
	}
	if d.Deadline <= 0 || d.Expires <= 0 {
		return nil, code.New("bad_grant")
	}
	a.Deadline = time.Unix(d.Deadline, 0)
	if !a.Deadline.After(now) {
		return nil, code.New("expired")
	}
	g := &Grant{
		V:         d.V,
		GrantID:   d.GrantID,
		Purpose:   d.Purpose,
		Dir:       d.Dir,
		Root:      d.Root,
		Path:      d.Path,
		Size:      uint64(d.Size),
		Overwrite: d.Overwrite,
		Profile:   d.Profile,
		Transport: d.Transport,
		AEAD:      d.AEAD,
		ByteCap:   uint64(d.ByteCap),
		Idle:      time.Duration(d.Idle) * time.Second,
		Max:       time.Duration(d.Max) * time.Second,
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
	g.Key, g.Token = key, tok
	g.HardStop = now.Add(g.Max)
	if h := a.Deadline.Add(-60 * time.Second).Add(g.Max); h.Before(g.HardStop) {
		g.HardStop = h
	}
	g.FirstBy = time.Unix(d.Expires, 0)
	if g.FirstBy.After(g.HardStop) {
		g.FirstBy = g.HardStop
	}
	// Check needs a send address for udp. In listen mode the client's
	// address is learned from its first authentic packet; the bind address
	// stands in, with port 0 (ephemeral) shown as 1 for the shape check only.
	g.PeerUDP = a.Dial
	if a.Listen != "" {
		h, p, _ := net.SplitHostPort(a.Listen)
		if p == "0" {
			p = "1"
		}
		g.PeerUDP = net.JoinHostPort(h, p)
	}
	if err := g.Check(now); err != nil {
		g.Wipe()
		return nil, err
	}
	g.PeerUDP = ""
	a.Grant = g
	return a, nil
}

// checkBind is an IP literal and a port 0 to 65535.
func checkBind(s string) error {
	if len(s) == 0 || len(s) > 64 {
		return code.New("bad_grant")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || net.ParseIP(host) == nil || port == "" || (len(port) > 1 && port[0] == '0') {
		return code.New("bad_grant")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
		return code.New("bad_grant")
	}
	return nil
}
