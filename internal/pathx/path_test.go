package pathx

import "testing"

func TestCheckPath(t *testing.T) {
	ok := []string{".", "a", "releases/app.tar.gz", "a b", "%2e%2e", "é"}
	for _, p := range ok {
		if err := CheckPath(p); err != nil {
			t.Fatalf("%q: %v", p, err)
		}
	}
	bad := []string{"", "/a", "a/", "a//b", "..", "a/../b", "a/./b", "a\\b", "a\x00b", "a\nb", "a\x7fb", string([]byte{0xff}), string(make([]byte, 4097))}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	bad = append(bad, string(long))
	for _, p := range bad {
		if err := CheckPath(p); err == nil || err.Error() != "bad_path" {
			t.Fatalf("%q err %v", p, err)
		}
	}
	for _, p := range []string{".sahsync-upl.part", ".sahxfer-xfr_a.part", "dir/.sahxfer-1.part"} {
		if err := CheckPath(p); err == nil || err.Error() != "reserved_name" {
			t.Fatalf("%q err %v", p, err)
		}
	}
	// No normalization: NFD and NFC are different paths, both accepted.
	nfd := "e\u0301"
	nfc := "é"
	if nfd == nfc {
		t.Fatal("fixture collapsed")
	}
	if err := CheckPath(nfd); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath("%2e%2e"); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRoot(t *testing.T) {
	for _, p := range []string{"/", "/srv", "/srv/app"} {
		if err := CheckRoot(p); err != nil {
			t.Fatalf("%q %v", p, err)
		}
	}
	for _, p := range []string{"", "srv", "/srv/", "/srv//a", "/srv/../a", "/srv/./a", "/.", "/.."} {
		if err := CheckRoot(p); err == nil || err.Error() != "bad_root" {
			t.Fatalf("%q %v", p, err)
		}
	}
	if err := CheckRoot("/srv/.sahxfer-x.part"); err == nil || err.Error() != "bad_root" {
		t.Fatal(err)
	}
}
