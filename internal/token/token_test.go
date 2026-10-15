package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/secfile"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sahconnect")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "token")
	const tok = "abcdefghijklmnop"
	body := []byte(`{"v":1,"origin":"https://sah.example","token":"` + tok + `"}`)
	f, err := secfile.CreateExcl(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != tok || got.Origin != "https://sah.example" {
		t.Fatalf("origin %s", got.Origin)
	}
	if _, err := Read(filepath.Join(sub, "nope")); !isCode(err, "not_found") {
		t.Fatal(err)
	}
}

func TestRefuse(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "token")
	if err := os.WriteFile(path, []byte(`{"v":1,"origin":"https://sah.example","token":"abcdefghijklmnop"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := mustErr(t, path)
	if !isCode(err, "bad_token") || strings.Contains(err.Error(), "abcdefghijklmnop") || strings.Contains(err.Error(), path) {
		t.Fatalf("dir mode: %v", err)
	}
	if err := os.Chmod(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mustErr(t, path); !isCode(err, "bad_token") {
		t.Fatal(err)
	}
	link := filepath.Join(sub, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := mustErr(t, link); !isCode(err, "symlink_refused") {
		t.Fatal(err)
	}
	bare := filepath.Join(sub, "bare")
	if err := os.WriteFile(bare, []byte("abcdefghijklmnop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mustErr(t, bare); !isCode(err, "bad_token") {
		t.Fatal(err)
	}
}

func TestValid(t *testing.T) {
	if Valid("short") || Valid("has space in token!!") || !Valid("abcdefghijklmnop") {
		t.Fatal("valid")
	}
	if len(Fingerprint("abcdefghijklmnop")) != 16 {
		t.Fatal("fingerprint")
	}
}

func mustErr(t *testing.T, path string) error {
	t.Helper()
	_, err := Read(path)
	if err == nil {
		t.Fatal("expected error")
	}
	return err
}

func isCode(err error, c string) bool {
	return err != nil && err.Error() == c
}
