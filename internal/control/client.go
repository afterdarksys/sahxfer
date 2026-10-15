// Package control is the SAH HTTPS client for one host resolve and one grant.
//
// Threats: a bearer sent to the wrong origin, a redirect that carries the
// bearer off the API, a grant whose host, root, path, size, or hash does
// not match the request, a metadata address, and an error string that
// quotes the bearer or the key. Both credentials set is refused. The raw
// response is wiped. Go strings the decoder copies cannot be wiped.
// This package does not implement the SystemAPI grant server.
package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/pathx"
	"github.com/afterdarksys/sahxfer/internal/token"
)

const maxBody = 1 << 20

// errRedirect is the CheckRedirect sentinel. Callers see redirect_denied.
var errRedirect = errors.New("sahxfer: redirect")

// Host is a resolved agent name.
type Host struct {
	HostID   string
	Hostname string
	Tenant   string
	Status   string
}

// GrantRequest is the client view of POST /api/v1/xfer/grant.
// AdoptMeta, set only for a URL get, takes the server size and hash.
// The request has no profile and no scope list.
type GrantRequest struct {
	HostID    string
	Purpose   string
	Dir       string
	Root      string
	Path      string
	Size      uint64
	Hash      [32]byte
	HaveHash  bool
	Overwrite bool
	Transport string
	AdoptMeta bool
	Now       time.Time
}

// Client talks to one HTTPS origin. HTTP is nil until New fills it.
type Client struct {
	Base         string
	Bearer       string
	BearerOrigin string
	APIKey       string
	HTTP         *http.Client
}

// New checks the origin and builds a TLS 1.3 client with no proxy.
// roots nil uses the system pool. Both credentials set is auth.
func New(base, bearer, origin, apiKey string, roots *x509.CertPool) (*Client, error) {
	if bearer != "" && apiKey != "" {
		return nil, code.New("auth")
	}
	if _, err := parseBase(base); err != nil {
		return nil, err
	}
	switch {
	case bearer != "":
		if !token.Valid(bearer) {
			return nil, code.New("auth")
		}
	case apiKey != "":
		if !token.Valid(apiKey) {
			return nil, code.New("auth")
		}
	default:
		return nil, code.New("auth")
	}
	return &Client{
		Base:         base,
		Bearer:       bearer,
		BearerOrigin: origin,
		APIKey:       apiKey,
		HTTP:         newHTTP(roots),
	}, nil
}

func newHTTP(roots *x509.CertPool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: DialGuard}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
			},
		},
	}
}

// DialGuard refuses a resolved address that is not an IP, or that is
// link-local, multicast, unspecified, or the EC2 metadata address.
// Loopback is allowed.
func DialGuard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return code.New("dial_refused")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return code.New("dial_refused")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return code.New("dial_refused")
	}
	return nil
}

func badName(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch h {
	case "metadata.google.internal", "metadata.goog":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return false
	}
	if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	return false
}

func parseBase(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 200 {
		return nil, code.New("bad_args")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, code.New("bad_args")
	}
	if u.User != nil {
		return nil, code.New("bad_args")
	}
	if !strings.EqualFold(u.Scheme, "https") || badName(u.Hostname()) {
		return nil, code.New("auth")
	}
	return u, nil
}

// Resolve is GET /api/v1/hosts/resolve. The name must match the host label
// regex or the client does not send the request.
func (c *Client) Resolve(ctx context.Context, name string) (Host, error) {
	if !grant.HostName(name) {
		return Host{}, code.New("invalid_name")
	}
	q := url.Values{}
	q.Set("name", name)
	raw, err := c.do(ctx, http.MethodGet, "/api/v1/hosts/resolve?"+q.Encode(), nil)
	if err != nil {
		return Host{}, err
	}
	defer wipe(raw)
	var doc struct {
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
		Tenant   string `json:"tenant"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Host{}, code.New("bad_grant")
	}
	if doc.HostID == "" || doc.Hostname == "" || doc.Hostname != name {
		return Host{}, code.New("mismatch")
	}
	if doc.Status != "online" && doc.Status != "offline" {
		return Host{}, code.New("mismatch")
	}
	return Host{HostID: doc.HostID, Hostname: doc.Hostname, Tenant: doc.Tenant, Status: doc.Status}, nil
}

// Grant is POST /api/v1/xfer/grant. The response is checked against the
// request before it is returned. A non-200 is never a grant.
func (c *Client) Grant(ctx context.Context, req GrantRequest) (*grant.Grant, error) {
	if err := preGrant(req); err != nil {
		return nil, err
	}
	body, err := encodeReq(req)
	if err != nil {
		return nil, err
	}
	defer wipe(body)
	raw, err := c.do(ctx, http.MethodPost, "/api/v1/xfer/grant", body)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	return decodeGrant(raw, req)
}

func preGrant(req GrantRequest) error {
	if req.HostID == "" || !grant.HostName(req.HostID) {
		return code.New("mismatch")
	}
	switch req.Purpose {
	case grant.PurposePut:
		if req.Dir != "put" {
			return code.New("bad_purpose")
		}
	case grant.PurposeGet:
		if req.Dir != "get" {
			return code.New("bad_purpose")
		}
	case grant.PurposeRoot:
		if req.Dir != "put" && req.Dir != "get" {
			return code.New("bad_purpose")
		}
	default:
		return code.New("bad_purpose")
	}
	if err := pathx.CheckRoot(req.Root); err != nil {
		return err
	}
	if err := pathx.CheckPath(req.Path); err != nil {
		return err
	}
	if _, _, err := pathx.Parent(req.Path); err != nil {
		return err
	}
	if req.Size >= 1<<63 {
		return code.New("too_large")
	}
	if !req.AdoptMeta && !req.HaveHash {
		return code.New("bad_grant")
	}
	switch req.Transport {
	case "", engine.TransportUDP, engine.TransportQUICDatagram, engine.TransportQUICStream, engine.TransportQUICBridge:
	default:
		return code.New("mismatch")
	}
	return nil
}

func encodeReq(req GrantRequest) ([]byte, error) {
	doc := struct {
		HostID    string       `json:"host_id"`
		Purpose   string       `json:"purpose"`
		Dir       string       `json:"dir"`
		Root      string       `json:"root"`
		Path      string       `json:"path"`
		Size      grant.Uint64 `json:"size"`
		SHA256    string       `json:"sha256,omitempty"`
		Overwrite bool         `json:"overwrite"`
		Transport string       `json:"transport,omitempty"`
	}{
		HostID: req.HostID, Purpose: req.Purpose, Dir: req.Dir, Root: req.Root,
		Path: req.Path, Size: grant.Uint64(req.Size), Overwrite: req.Overwrite,
		Transport: req.Transport,
	}
	if req.HaveHash {
		doc.SHA256 = hexHash(req.Hash)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&doc); err != nil {
		return nil, code.New("internal")
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if c == nil || c.HTTP == nil {
		return nil, code.New("internal")
	}
	if c.Bearer != "" && c.APIKey != "" {
		return nil, code.New("auth")
	}
	u, err := parseBase(c.Base)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, code.New("auth")
	}
	ref, err := u.Parse(path)
	if err != nil {
		return nil, code.New("bad_args")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	rq, err := http.NewRequestWithContext(ctx, method, ref.String(), rdr)
	if err != nil {
		return nil, code.New("bad_args")
	}
	if body != nil {
		rq.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.APIKey != "":
		if !token.Valid(c.APIKey) {
			return nil, code.New("auth")
		}
		rq.Header.Set("X-API-Key", c.APIKey)
	case c.Bearer != "":
		if !token.Valid(c.Bearer) || c.BearerOrigin != token.Origin(u) {
			return nil, code.New("auth")
		}
		rq.Header.Set("Authorization", "Bearer "+c.Bearer)
	default:
		return nil, code.New("auth")
	}
	resp, err := c.HTTP.Do(rq)
	if err != nil {
		return nil, mapDo(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		wipe(raw)
		return nil, code.New("io")
	}
	if len(raw) > maxBody {
		wipe(raw)
		return nil, code.New("response_too_large")
	}
	if resp.StatusCode != http.StatusOK {
		err := errorCode(raw)
		wipe(raw)
		return nil, err
	}
	return raw, nil
}

func mapDo(err error) error {
	if errors.Is(err, errRedirect) {
		return code.New("redirect_denied")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return code.New("cancelled")
	}
	var ce *code.Error
	if errors.As(err, &ce) {
		return ce
	}
	return code.New("request_failed")
}

var allowErr = map[string]bool{
	"bad_purpose": true, "bad_root": true, "bad_path": true, "scope_denied": true,
	"root_denied": true, "not_found": true, "exists": true, "too_large": true,
	"rate_limited": true, "agent_offline": true, "agent_unsupported": true,
	"cap_reached": true, "internal": true, "changed": true, "symlink_refused": true,
	"reserved_name": true, "not_a_file": true, "ambiguous": true, "invalid_name": true,
	"auth": true, "expired": true, "mismatch": true, "bad_grant": true,
}

func errorCode(raw []byte) error {
	var doc struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &doc) != nil || !allowErr[doc.Error] {
		return code.New("request_failed")
	}
	return code.New(doc.Error)
}

type grantDoc struct {
	GrantID    string          `json:"grant_id"`
	HostID     string          `json:"host_id"`
	TransferID string          `json:"transfer_id"`
	ExpiresAt  string          `json:"expires_at"`
	ExpiresIn  json.RawMessage `json:"expires_in"`
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

func decodeGrant(raw []byte, req GrantRequest) (*grant.Grant, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var doc grantDoc
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return nil, code.New("bad_grant")
	}
	if err := expiresIn(doc.ExpiresIn); err != nil {
		return nil, err
	}
	if uint64(doc.Size) >= 1<<63 || uint64(doc.ByteCap) >= 1<<63 {
		return nil, code.New("too_large")
	}
	if doc.Purpose != req.Purpose {
		return nil, code.New("bad_purpose")
	}
	if doc.Root != req.Root {
		return nil, code.New("bad_root")
	}
	if doc.Path != req.Path {
		return nil, code.New("bad_path")
	}
	if doc.HostID != req.HostID || doc.Overwrite != req.Overwrite {
		return nil, code.New("mismatch")
	}
	sum, err := grant.ParseHash(doc.SHA256)
	if err != nil {
		return nil, err
	}
	size := uint64(doc.Size)
	if req.AdoptMeta {
		req.Size = size
		req.Hash = sum
		req.HaveHash = true
	} else if size != req.Size || !grant.SameHash(sum, req.Hash) {
		return nil, code.New("mismatch")
	}
	if doc.Profile != "internet" && doc.Profile != "dc" {
		return nil, code.New("mismatch")
	}
	switch doc.Transport {
	case engine.TransportUDP, engine.TransportQUICDatagram, engine.TransportQUICStream, engine.TransportQUICBridge:
	default:
		return nil, code.New("mismatch")
	}
	if doc.AEAD != grant.AEAD {
		return nil, code.New("auth")
	}
	if doc.Idle <= 0 || doc.Max <= 0 || doc.Idle > doc.Max || doc.Max > 3600 {
		return nil, code.New("mismatch")
	}
	capn := uint64(doc.ByteCap)
	if capn == 0 && size != 0 || capn < size {
		return nil, code.New("mismatch")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	exp, err := time.Parse(time.RFC3339Nano, doc.ExpiresAt)
	if err != nil {
		return nil, code.New("bad_grant")
	}
	if !exp.After(now) {
		return nil, code.New("expired")
	}
	id, err := parseTransfer(doc.TransferID)
	if err != nil {
		return nil, err
	}
	key, err := decodeCanon(doc.Key, 32)
	if err != nil {
		return nil, err
	}
	tok, err := decodeCanon(doc.Token, 16)
	if err != nil {
		wipe(key)
		return nil, err
	}
	g := &grant.Grant{
		V: 1, GrantID: doc.GrantID, TransferID: id, HostID: doc.HostID,
		Purpose: doc.Purpose, Dir: req.Dir, Root: doc.Root, Path: doc.Path,
		Size: size, Hash: sum, HaveHash: true, Overwrite: doc.Overwrite,
		Profile: doc.Profile, Transport: doc.Transport,
		PeerUDP: deref(doc.Peer.UDP), PeerQUIC: deref(doc.Peer.QUIC),
		AEAD: doc.AEAD, Key: key, Token: tok, Expires: exp,
		Idle:    time.Duration(doc.Idle) * time.Second,
		Max:     time.Duration(doc.Max) * time.Second,
		ByteCap: capn,
	}
	if err := g.Check(now); err != nil {
		g.Wipe()
		return nil, err
	}
	return g, nil
}

func expiresIn(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if string(raw) == "null" {
		return code.New("bad_grant")
	}
	n, err := grant.ParseUint(string(raw))
	if err != nil {
		return code.New("bad_grant")
	}
	if n < 1 || n > 3600 {
		return code.New("mismatch")
	}
	return nil
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
		wipe(b)
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func hexHash(sum [32]byte) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range sum {
		b[i*2] = hexdigits[c>>4]
		b[i*2+1] = hexdigits[c&0x0f]
	}
	return string(b)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
