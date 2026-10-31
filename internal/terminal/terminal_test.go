package terminal

import (
	"strings"
	"testing"
)

func TestSanitizeNeutralisesHostileStrings(t *testing.T) {
	in := "a\x1b[2J\x1b]0;owned\x07b\rc‮evil\x00\xff"
	out := Sanitize(in)
	for _, r := range out {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
			t.Fatalf("unsafe rune %U in %q", r, out)
		}
	}
	if !strings.Contains(out, `\x1b`) || !strings.Contains(out, "\\u202e") || !strings.Contains(out, `\xff`) {
		t.Fatalf("escapes not visible: %q", out)
	}
	if Sanitize("héllo wörld ✓") != "héllo wörld ✓" {
		t.Fatal("legitimate unicode was altered")
	}
}

func TestStyleOff(t *testing.T) {
	if (Style{}).Bold("x") != "x" {
		t.Fatal("style leaked when disabled")
	}
}
