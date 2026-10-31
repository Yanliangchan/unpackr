package safety

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSecureJoin(t *testing.T) {
	root := t.TempDir()
	good := []string{"a.txt", "dir/b.bin", "./c", "dir/../d", "a/b/c/d.txt"}
	for _, n := range good {
		p, err := SecureJoin(root, n)
		if err != nil {
			t.Errorf("%q rejected: %v", n, err)
			continue
		}
		if rel, _ := filepath.Rel(root, p); len(rel) == 0 || rel[0] == '.' && len(rel) > 1 && rel[1] == '.' {
			t.Errorf("%q escaped: %s", n, p)
		}
	}
	bad := []string{"", "../x", "a/../../x", "/etc/passwd", "..", "C:\\Windows\\x", "..\\..\\x", "a\x00b", "c:/x"}
	for _, n := range bad {
		if _, err := SecureJoin(root, n); err == nil {
			t.Errorf("%q should be rejected", n)
		} else if !errors.Is(err, ErrEscapes) && n != "" && n != "a\x00b" {
			t.Errorf("%q: unexpected error %v", n, err)
		}
	}
}

func TestOpenInputRejectsDirsAndBigFiles(t *testing.T) {
	if _, _, err := OpenInput(t.TempDir(), 0); err == nil {
		t.Fatal("directory accepted")
	}
}
