package textutil

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	out := Sanitize("a\x1b[2J\x1b]0;x\x07b\u202ec\x00\xff")
	for _, r := range out {
		if r < 0x20 || r == 0x7f || r == 0x202e {
			t.Fatalf("unsafe rune %U in %q", r, out)
		}
	}
	if !strings.Contains(out, `\x1b`) || Sanitize("héllo ✓") != "héllo ✓" {
		t.Fatalf("%q", out)
	}
}
