// Package token reads the sahconnect device-login file.
//
// Threats: a bearer sent to the wrong origin, a symlink planted at the
// token path, a directory other users can read, and an error string that
// contains the token or the path. The file must be a regular file owned by
// the user with no group or other bits, in a directory that is exactly
// mode 0700. This package does not write the file and does not print the
// token. A Go string cannot be wiped; the raw file buffer is zeroed after
// parse.
package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/secfile"
)

const maxFile = 2048

// MaxLen is the longest accepted bearer.
const MaxLen = 512

// File is the stored credential. Token is a Go string and cannot be wiped.
type File struct {
	Origin string
	Token  string
}

type fileJSON struct {
	V      int    `json:"v"`
	Origin string `json:"origin"`
	Token  string `json:"token"`
}

// Valid reports a bearer of 16 to 512 printable ASCII bytes with no whitespace.
func Valid(s string) bool {
	if len(s) < 16 || len(s) > MaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Fingerprint is the first 16 hex characters of SHA-256(token).
func Fingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:16]
}

// Origin is scheme://host[:port] with a default port dropped.
func Origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]"
	}
	return scheme + "://" + host
}

// DefaultPath is $XDG_CONFIG_HOME/sahconnect/token, or ~/.config/sahconnect/token.
func DefaultPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "sahconnect", "token")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "sahconnect", "token")
}

// Read opens path. A missing file is not_found. Anything else wrong is
// symlink_refused, bad_token, or io. The error does not contain the token.
func Read(path string) (*File, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, code.New("not_found")
		}
		return nil, code.New("io")
	}
	if err := secfile.CheckDir0700(filepath.Dir(path)); err != nil {
		return nil, mapErr(err)
	}
	f, fi, err := secfile.OpenRead(path)
	if err != nil {
		return nil, mapErr(err)
	}
	defer f.Close()
	if fi.Size() < 0 || fi.Size() > maxFile {
		return nil, code.New("bad_token")
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, code.New("io")
	}
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	if len(buf) > maxFile {
		return nil, code.New("bad_token")
	}
	tf, err := parse(buf)
	if err != nil {
		return nil, code.New("bad_token")
	}
	return tf, nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	switch err.Error() {
	case "not_found", "symlink_refused", "io":
		return err
	default:
		return code.New("bad_token")
	}
}

func parse(b []byte) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j fileJSON
	if err := dec.Decode(&j); err != nil || dec.More() {
		return nil, code.New("bad_token")
	}
	if j.V != 1 || !validOrigin(j.Origin) || !Valid(j.Token) {
		return nil, code.New("bad_token")
	}
	return &File{Origin: j.Origin, Token: j.Token}, nil
}

func validOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return Origin(u) == o
}
