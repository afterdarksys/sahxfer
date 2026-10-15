// Package pathx is the sah-file-protocol path rules plus the sahxfer
// reserved temp name.
//
// Threats: a path that leaves the root by "..", an absolute path, a NUL or
// control byte, a backslash, or a reserved temp component. Nothing is
// percent-decoded and nothing is Unicode-normalized. This package does not
// open files and does not stop a symlink that the opener follows.
package pathx

import (
	"strings"
	"unicode/utf8"

	"github.com/afterdarksys/sahxfer/internal/code"
)

const (
	maxBytes     = 4096
	maxComponent = 255
)

// CheckPath applies the file-protocol rules to a path relative to a root.
// "." alone is the root. A reserved temp component is reserved_name.
func CheckPath(p string) error {
	if p == "." {
		return nil
	}
	if len(p) < 1 || len(p) > maxBytes || !utf8.ValidString(p) {
		return code.New("bad_path")
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, "//") {
		return code.New("bad_path")
	}
	if dirty(p) {
		return code.New("bad_path")
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || len(c) > maxComponent {
			return code.New("bad_path")
		}
		if Reserved(c) {
			return code.New("reserved_name")
		}
	}
	return nil
}

// CheckRoot applies the same byte rules to an absolute root.
// "/" is the filesystem root. A trailing slash on any other root is refused.
func CheckRoot(p string) error {
	if p == "/" {
		return nil
	}
	if len(p) < 1 || len(p) > maxBytes || !utf8.ValidString(p) || !strings.HasPrefix(p, "/") {
		return code.New("bad_root")
	}
	if strings.HasSuffix(p, "/") || strings.Contains(p, "//") || dirty(p) {
		return code.New("bad_root")
	}
	parts := strings.Split(p, "/")
	// Split("/srv/app") is ["", "srv", "app"].
	for i, c := range parts {
		if i == 0 {
			if c != "" {
				return code.New("bad_root")
			}
			continue
		}
		if c == "" || c == "." || c == ".." || len(c) > maxComponent || Reserved(c) {
			return code.New("bad_root")
		}
	}
	return nil
}

// Reserved reports a component the helper owns: .sahsync-*.part or .sahxfer-*.part.
func Reserved(name string) bool {
	return reserved(name, ".sahsync-") || reserved(name, ".sahxfer-")
}

func reserved(name, prefix string) bool {
	const suf = ".part"
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suf) && len(name) >= len(prefix)+len(suf)
}

func dirty(p string) bool {
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b == '\\' || b == 0 || b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

// Parent splits a file path into directory components and a final name.
// "." is not a file.
func Parent(p string) (dirs []string, name string, err error) {
	if err = CheckPath(p); err != nil {
		return nil, "", err
	}
	if p == "." {
		return nil, "", code.New("not_a_file")
	}
	parts := strings.Split(p, "/")
	return parts[:len(parts)-1], parts[len(parts)-1], nil
}
