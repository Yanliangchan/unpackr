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
