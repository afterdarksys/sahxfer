package grant

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/pathx"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

const (
	// AEAD is the only v1 cipher. There is no negotiation and no crypto=off.
	AEAD = "ChaCha20-Poly1305"

	PurposePut  = "xfer:put"
	PurposeGet  = "xfer:get"
	PurposeRoot = "xfer:root"
)

var (
	hostName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	grantID  = regexp.MustCompile(`^xfr_[A-Za-z0-9_-]{8,64}$`)
)

// Scopes is the operator's file-scope set. The HTTP client does not invent
// this list; SystemAPI does. The local issuer does, because there is no server.
type Scopes struct {
	Read  bool
	Write bool
	Root  bool
}

// Request is the local issuer's input. Rand runs only after this validates.
type Request struct {
	Purpose   string
	Dir       string
	Root      string
	Path      string
	Size      uint64
	Hash      [32]byte
	HaveHash  bool
	Overwrite bool
	Profile   string
	Transport string
	HostID    string
	PeerUDP   string
	PeerQUIC  string
	Expires   time.Time
	Idle      time.Duration
	Max       time.Duration
	ByteCap   uint64
	Now       time.Time
	Scopes    Scopes
}

// Grant is one file, one direction. Key and Token are memory copies.
type Grant struct {
	V          int
	GrantID    string
	TransferID uint64
	HostID     string
	Purpose    string
	Dir        string
	Root       string
	Path       string
	Size       uint64
	Hash       [32]byte
	HaveHash   bool
	Overwrite  bool
	Profile    string
	Transport  string
	PeerUDP    string
	PeerQUIC   string
	AEAD       string
	Key        []byte
	Token      []byte
	Expires    time.Time
	Idle       time.Duration
	Max        time.Duration
	ByteCap    uint64
}

// CheckScopes is the purpose, direction, and scope matrix.
func CheckScopes(purpose, dir string, s Scopes) error {
	switch purpose {
	case PurposePut:
		if dir != "put" {
			return code.New("bad_purpose")
		}
		if !s.Read || !s.Write {
			return code.New("scope_denied")
		}
	case PurposeGet:
		if dir != "get" {
			return code.New("bad_purpose")
		}
		if !s.Read {
			return code.New("scope_denied")
		}
	case PurposeRoot:
		if dir != "put" && dir != "get" {
			return code.New("bad_purpose")
		}
		if !s.Root {
			return code.New("root_denied")
		}
	default:
		return code.New("bad_purpose")
	}
	return nil
}

// Issue builds a grant. A failed issue returns no key material.
func Issue(in Request) (*Grant, error) {
	if err := CheckScopes(in.Purpose, in.Dir, in.Scopes); err != nil {
		return nil, err
	}
	if err := pathx.CheckRoot(in.Root); err != nil {
		return nil, err
	}
	if err := pathx.CheckPath(in.Path); err != nil {
		return nil, err
	}
	if _, _, err := pathx.Parent(in.Path); err != nil {
		return nil, err
	}
	if in.Size >= 1<<63 {
		return nil, code.New("too_large")
	}
	if !in.HaveHash {
		return nil, code.New("bad_grant")
	}
	profile := in.Profile
	if profile == "" {
		profile = "internet"
	}
	if profile != "internet" && profile != "dc" {
		return nil, code.New("mismatch")
	}
	transport := in.Transport
	if transport == "" {
		transport = engine.TransportUDP
	}
	switch transport {
	case engine.TransportUDP, engine.TransportQUICDatagram, engine.TransportQUICStream, engine.TransportQUICBridge:
	default:
		return nil, code.New("mismatch")
	}
	g := &Grant{
		V:         1,
		Purpose:   in.Purpose,
		Dir:       in.Dir,
		Root:      in.Root,
		Path:      in.Path,
		Size:      in.Size,
		Hash:      in.Hash,
		HaveHash:  true,
		Overwrite: in.Overwrite,
		Profile:   profile,
		Transport: transport,
		HostID:    in.HostID,
		PeerUDP:   in.PeerUDP,
		PeerQUIC:  in.PeerQUIC,
		AEAD:      AEAD,
		ByteCap:   in.ByteCap,
	}
	if err := g.checkPeers(); err != nil {
		return nil, err
	}
	if g.HostID != "" && !hostName.MatchString(g.HostID) {
		return nil, code.New("mismatch")
	}
	idle, max, err := normLimits(in.Idle, in.Max)
	if err != nil {
		return nil, err
	}
	g.Idle = idle
	g.Max = max
	if g.ByteCap >= 1<<63 {
		return nil, code.New("too_large")
	}
	if g.ByteCap == 0 {
		g.ByteCap = g.Size
	}
	if g.ByteCap < g.Size {
		return nil, code.New("mismatch")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if in.Expires.IsZero() {
		g.Expires = now.Add(g.Max)
	} else {
		g.Expires = in.Expires
	}
	if !g.Expires.After(now) {
		return nil, code.New("expired")
	}
	if err := g.fillRand(); err != nil {
		g.Wipe()
		return nil, err
	}
	if err := g.Check(now); err != nil {
		g.Wipe()
		return nil, err
	}
	return g, nil
}

func (g *Grant) fillRand() error {
	id, err := randBytes(8)
	if err != nil {
		return err
	}
	g.GrantID = "xfr_" + hex.EncodeToString(id)
	wipe(id)
	var xfer uint64
	for i := 0; i < 8; i++ {
		b, err := randBytes(8)
		if err != nil {
			return err
		}
		xfer = binary.LittleEndian.Uint64(b)
		wipe(b)
		if xfer != 0 {
			break
		}
	}
	if xfer == 0 {
		return code.New("internal")
	}
	g.TransferID = xfer
	key, err := randBytes(seal.KeySize)
	if err != nil {
		return err
	}
	tok, err := randBytes(seal.TokenSize)
	if err != nil {
		wipe(key)
		return err
	}
	g.Key = key
	g.Token = tok
	return nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		wipe(b)
		return nil, code.New("internal")
	}
	return b, nil
}

func normLimits(idle, max time.Duration) (time.Duration, time.Duration, error) {
	if idle < 0 || max < 0 || idle%time.Second != 0 || max%time.Second != 0 {
		return 0, 0, code.New("mismatch")
	}
	if idle == 0 {
		idle = 30 * time.Second
	}
	if max == 0 {
		max = 3600 * time.Second
	}
	if idle > max || max > 3600*time.Second {
		return 0, 0, code.New("mismatch")
	}
	return idle, max, nil
}

// Check is the shared shape check. It does not apply local defaults.
// An empty profile, transport, or idle is mismatch. A bad cipher or key is auth.
func (g *Grant) Check(now time.Time) error {
	if g == nil || g.V != 1 || !grantID.MatchString(g.GrantID) || g.TransferID == 0 {
		return code.New("bad_grant")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if g.HostID != "" && !hostName.MatchString(g.HostID) {
		return code.New("mismatch")
	}
	switch g.Purpose {
	case PurposePut:
		if g.Dir != "put" {
			return code.New("bad_purpose")
		}
	case PurposeGet:
		if g.Dir != "get" {
			return code.New("bad_purpose")
		}
	case PurposeRoot:
		if g.Dir != "put" && g.Dir != "get" {
			return code.New("bad_purpose")
		}
	default:
		return code.New("bad_purpose")
	}
	if err := pathx.CheckRoot(g.Root); err != nil {
		return err
	}
	if err := pathx.CheckPath(g.Path); err != nil {
		return err
	}
	if _, _, err := pathx.Parent(g.Path); err != nil {
		return err
	}
	if g.Size >= 1<<63 {
		return code.New("too_large")
	}
	if !g.HaveHash {
		return code.New("bad_grant")
	}
	if g.Profile != "internet" && g.Profile != "dc" {
		return code.New("mismatch")
	}
	switch g.Transport {
	case engine.TransportUDP, engine.TransportQUICDatagram, engine.TransportQUICStream, engine.TransportQUICBridge:
	default:
		return code.New("mismatch")
	}
	if err := g.checkPeers(); err != nil {
		return err
	}
	if g.AEAD != AEAD || len(g.Key) != seal.KeySize || len(g.Token) != seal.TokenSize {
		return code.New("auth")
	}
	if g.Idle <= 0 || g.Max <= 0 || g.Idle%time.Second != 0 || g.Max%time.Second != 0 || g.Idle > g.Max || g.Max > 3600*time.Second {
		return code.New("mismatch")
	}
	if g.ByteCap >= 1<<63 {
		return code.New("too_large")
	}
	if g.ByteCap < g.Size {
		return code.New("mismatch")
	}
	if !g.Expires.After(now) {
		return code.New("expired")
	}
	return nil
}

func (g *Grant) checkPeers() error {
	var needUDP, needQUIC bool
	switch g.Transport {
	case engine.TransportUDP:
		needUDP = true
	case engine.TransportQUICDatagram, engine.TransportQUICStream:
		needQUIC = true
	case engine.TransportQUICBridge:
		needUDP, needQUIC = true, true
	default:
		return code.New("mismatch")
	}
	if needUDP || g.PeerUDP != "" {
		if err := checkAddr(g.PeerUDP); err != nil {
			return err
		}
	}
	if needQUIC || g.PeerQUIC != "" {
		if err := checkAddr(g.PeerQUIC); err != nil {
			return err
		}
	}
	return nil
}

func checkAddr(s string) error {
	if len(s) == 0 || len(s) > 256 {
		return code.New("mismatch")
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return code.New("mismatch")
		}
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" || (len(port) > 1 && port[0] == '0') {
		return code.New("mismatch")
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return code.New("mismatch")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return code.New("mismatch")
	}
	return nil
}

// PeerConfig is the engine config for role "client" or "agent".
// Key and Token are fresh copies. Wiping the grant does not wipe them.
// quic-stream is not started here. The caller checks Runnable before New.
func (g *Grant) PeerConfig(role string) (engine.Config, error) {
	if g == nil {
		return engine.Config{}, code.New("internal")
	}
	var local, peer byte
	var sender bool
	switch role {
	case "client":
		local, peer = seal.DirClient, seal.DirAgent
		sender = g.Dir == "put"
	case "agent":
		local, peer = seal.DirAgent, seal.DirClient
		sender = g.Dir == "get"
	default:
		return engine.Config{}, code.New("internal")
	}
	cfg := engine.Config{
		TransferID:  g.TransferID,
		Size:        g.Size,
		Key:         append([]byte(nil), g.Key...),
		Token:       append([]byte(nil), g.Token...),
		LocalDir:    local,
		PeerDir:     peer,
		Sender:      sender,
		Transport:   g.Transport,
		Profile:     g.Profile,
		Idle:        g.Idle,
		Max:         g.Max,
		FirstPacket: 60 * time.Second,
		ByteCap:     g.ByteCap,
		HaveHash:    true,
		ExpectHash:  g.Hash,
	}
	if g.Transport == engine.TransportQUICDatagram || g.Transport == engine.TransportQUICBridge {
		cfg.Pacing = false
	}
	return cfg, nil
}

// Runnable is nil for UDP. QUIC transports are refused until that path exists.
func (g *Grant) Runnable() error {
	if g == nil {
		return code.New("internal")
	}
	switch g.Transport {
	case "", engine.TransportUDP:
		return nil
	default:
		return code.New("agent_unsupported")
	}
}

// RunLimits shortens the hard stop to the grant expiry.
// max <= 0 is expired. The caller shrinks Idle when it is longer than max.
func (g *Grant) RunLimits(now time.Time) (idle, max time.Duration, err error) {
	if g == nil {
		return 0, 0, code.New("internal")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !g.Expires.After(now) {
		return 0, 0, code.New("expired")
	}
	until := g.Expires.Sub(now)
	max = g.Max
	if until < max {
		max = until
	}
	if max <= 0 {
		return 0, 0, code.New("expired")
	}
	return g.Idle, max, nil
}

// Wipe zeros the key and the route token. It does not wipe copies the
// caller already made, and it cannot wipe a Go string.
func (g *Grant) Wipe() {
	if g == nil {
		return
	}
	wipe(g.Key)
	wipe(g.Token)
	g.Key = nil
	g.Token = nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SameHash compares two SHA-256 digests in constant time.
func SameHash(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// ParseHash accepts 64 lowercase hex characters.
func ParseHash(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, code.New("bad_grant")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return out, code.New("bad_grant")
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, code.New("bad_grant")
	}
	copy(out[:], b)
	return out, nil
}

// HostName reports whether s is a host label this client will resolve.
func HostName(s string) bool {
	return hostName.MatchString(s)
}
