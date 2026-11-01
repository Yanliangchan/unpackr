package artvault

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/assets"
)

func builtin(t *testing.T) *Vault {
	v, warns, err := Load(assets.ArtVault, "artvault", "")
	if err != nil || len(warns) > 0 {
		t.Fatal(err, warns)
	}
	return v
}

func TestBuiltInArtworkIsValidAndDistinct(t *testing.T) {
	v := builtin(t)
	if len(v.All()) < 16 {
		t.Fatalf("only %d banners", len(v.All()))
	}
	titles, bodies := map[string]bool{}, map[string]bool{}
	for _, b := range v.All() {
		if b.Title == "" || b.Category == "custom" {
			t.Errorf("%s lacks metadata", b.ID)
		}
		if titles[b.Title] || bodies[b.Text()] {
			t.Errorf("%s duplicates another banner", b.ID)
		}
		titles[b.Title], bodies[b.Text()] = true, true
		if strings.Contains(strings.ToLower(b.Text()), "metasploit") {
			t.Errorf("%s mentions a third-party brand", b.ID)
		}
	}
}

func TestValidateRejectsControlSequences(t *testing.T) {
	cases := map[string]string{
		"esc":  "ok\x1b[31mred",
		"tab":  "a\tb",
		"nul":  "a\x00b",
		"utf8": "café",
		"wide": strings.Repeat("x", MaxCols+1),
	}
	for name, line := range cases {
		if err := Validate(Banner{ID: "x", Lines: []string{line}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := Validate(Banner{ID: "x", Lines: make([]string, MaxRows+1)}); err == nil {
		t.Error("too many rows accepted")
	}
}

func TestPickAvoidsLastAndHonoursSelectors(t *testing.T) {
	v := builtin(t)
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		b, err := v.Pick("random", "007", rnd)
		if err != nil || b.ID == "007" {
			t.Fatalf("repeated last banner: %v %v", b.ID, err)
		}
	}
	if b, _ := v.Pick("999", "", rnd); b.ID == "999" {
		t.Fatal("id 999 does not exist")
	}
	if b, err := v.Pick("003", "", rnd); err != nil || b.ID != "003" {
		t.Fatal(err)
	}
	b, err := v.Pick("humour", "", rnd)
	if err != nil || b.Category != "humour" {
		t.Fatal(err, b)
	}
	if _, err := v.Pick("nonsense", "", rnd); err == nil {
		t.Fatal("unknown selector accepted")
	}
}

func TestCustomArtworkIsValidatedNotTrusted(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "good.txt"), []byte("---\nid: c1\ncategory: mine\ntitle: T\n---\nhello\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("plain art\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "evil.txt"), []byte("\x1b]0;pwned\x07\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "dup.txt"), []byte("---\nid: 001\n---\nx\n"), 0o600)
	v, warns, err := Load(assets.ArtVault, "artvault", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 2 {
		t.Fatalf("expected evil and dup rejected, got %v", warns)
	}
	if _, ok := v.Get("c1"); !ok {
		t.Fatal("valid custom missing")
	}
	if _, ok := v.Get("plain"); !ok {
		t.Fatal("plain custom missing")
	}
}

func TestFavouritesAndLast(t *testing.T) {
	d := t.TempDir()
	_ = AddFavourite(d, "007")
	_ = AddFavourite(d, "003")
	_ = AddFavourite(d, "007")
	if f := Favourites(d); len(f) != 2 || f[0] != "003" {
		t.Fatal(f)
	}
	RememberShown(d, "005")
	if LastShown(d) != "005" {
		t.Fatal("last")
	}
}

// The library promises at least sixty original banners.
func TestAtLeastSixtyBuiltInBanners(t *testing.T) {
	if n := len(builtin(t).All()); n < 60 {
		t.Fatalf("%d built-in banners, want at least 60", n)
	}
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func TestPaintKeepsTheArtworkIntactAtEveryDepth(t *testing.T) {
	v := builtin(t)
	for _, b := range v.All() {
		if b.Text() != Paint(b, "", DepthNone) {
			t.Fatalf("%s changed without colour", b.ID)
		}
		for _, d := range []Depth{DepthBasic, Depth256, DepthTrue} {
			p := Paint(b, "", d)
			if stripANSI(p) != b.Text() {
				t.Fatalf("%s depth %d: colour changed the artwork", b.ID, d)
			}
			if !strings.Contains(p, "\x1b[") {
				t.Fatalf("%s depth %d: nothing was coloured", b.ID, d)
			}
			for _, l := range strings.Split(p, "\n") {
				if strings.Contains(l, "\x1b[") && !strings.HasSuffix(l, "\x1b[0m") {
					t.Fatalf("%s: a line leaves colour switched on: %q", b.ID, l)
				}
			}
		}
	}
}

func TestEveryStyleWorksAndUnknownOnesFallBack(t *testing.T) {
	b := Banner{ID: "x", Category: "picture", Lines: []string{"ab", "cd", "ef"}}
	for _, name := range StyleNames() {
		if p := Paint(b, name, DepthTrue); stripANSI(p) != b.Text() || !strings.Contains(p, "38;2;") {
			t.Errorf("%s: %q", name, p)
		}
	}
	if b.EffectiveStyle() != "rainbow" {
		t.Fatalf("category default: %s", b.EffectiveStyle())
	}
	b.Style = "nonsense"
	if b.EffectiveStyle() != "rainbow" {
		t.Fatal("an unknown style must fall back, not break")
	}
	b.Custom = true
	if b.EffectiveStyle() != "cyan" {
		t.Fatal("custom artwork keeps its plain colour unless it names a style")
	}
}

func TestDetectDepth(t *testing.T) {
	t.Setenv("COLORTERM", "truecolor")
	if DetectDepth() != DepthTrue {
		t.Fatal("truecolor")
	}
	t.Setenv("COLORTERM", "")
	t.Setenv("TERM", "xterm-256color")
	if DetectDepth() != Depth256 {
		t.Fatal("256")
	}
	t.Setenv("TERM", "vt100")
	if DetectDepth() != DepthBasic {
		t.Fatal("basic")
	}
}
