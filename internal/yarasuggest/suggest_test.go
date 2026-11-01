package yarasuggest

import (
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

func report() *models.Report {
	return &models.Report{
		File:   models.FileInfo{Size: 40000, Hashes: models.Hashes{SHA256: strings.Repeat("ab", 32)}},
		Binary: &models.Binary{Format: "PE32+", ImportHash: "ABCDEF0123456789"},
		Analysis: &models.Analysis{
			Decoded: []models.DecodedString{{Method: "xor", Key: "0x5a", Text: "http://c2.evil.example.net/gate.php", Evidence: "x4"}},
			Indicators: []models.Indicator{
				{Type: "domain", Value: "backup.evil-update.example.org", Encoding: "ascii"},
				{Type: "ipv4", Value: "10.1.2.3", Encoding: "ascii", Note: "private range"},
				{Type: "url", Value: "http://c2.evil.example.net/gate.php", Encoding: "decoded:xor 0x5a"},
			},
			Strings: models.StringsInfo{Shown: []models.StringHit{
				{Text: "Global\\UnpackrTestMutex_8f3a21", Encoding: "ascii"},
				{Text: "runtime.goexit", Encoding: "ascii"},
				{Text: "GCC: (Ubuntu 13.2.0)", Encoding: "ascii"},
				{Text: "C:\\Users\\dev\\Desktop\\loader\\Release\\core.pdb", Encoding: "ascii"},
				{Text: "short", Encoding: "ascii"},
				{Text: "this is a long sentence of prose that clean programs also contain", Encoding: "ascii"},
			}},
		},
	}
}

func TestDraftPrefersHiddenStringsAndIndicators(t *testing.T) {
	s, err := Build(report(), Options{Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Rule, `$x1 = "http://c2.evil.example.net/gate.php" xor`) {
		t.Errorf("hidden string missing:\n%s", s.Rule)
	}
	for _, want := range []string{"rule unpackr_abababababab {", "uint16(0) == 0x5A4D", "filesize < 81920", `sha256 = "`, `status = "experimental"`, "backup.evil-update.example.org"} {
		if !strings.Contains(s.Rule, want) {
			t.Errorf("missing %q in\n%s", want, s.Rule)
		}
	}
	for _, bad := range []string{"runtime.goexit", "GCC:", "10.1.2.3", "short", "prose", "UnpackrTestMutex", "core.pdb"} {
		if strings.Contains(s.Rule, bad) {
			t.Errorf("boilerplate or weak feature %q used:\n%s", bad, s.Rule)
		}
	}
	// The recovered URL is also an indicator, but must appear once.
	if strings.Count(s.Rule, "gate.php") != 1 {
		t.Errorf("duplicate feature:\n%s", s.Rule)
	}
	if len(s.Dropped) == 0 {
		t.Error("dropped candidates should be explained")
	}
}

// A draft padded with ordinary strings matched clean files built with the same
// compiler (found by testing a real draft against a directory of clean files).
func TestSpecificFeaturesAreNotPaddedWithOrdinaryStrings(t *testing.T) {
	r := report()
	for _, s := range []string{"_ITM_deregisterTMCloneTable", "__do_global_dtors_aux", "_GLOBAL_OFFSET_TABLE_", "deregister_tm_clones", ".note.ABI-tag", "Global\\SomeUniqueName_11"} {
		r.Analysis.Strings.Shown = append(r.Analysis.Strings.Shown, models.StringHit{Text: s, Encoding: "ascii"})
	}
	s, err := Build(r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"_ITM_", "do_global", "GLOBAL_OFFSET", "tm_clones", "ABI-tag", "SomeUniqueName"} {
		if strings.Contains(s.Rule, bad) {
			t.Errorf("ordinary string %q used alongside specific features:\n%s", bad, s.Rule)
		}
	}
	if len(s.Features) != 2 || s.Required != 2 {
		t.Errorf("want the two specific features and 2 required, got %d features, %d required", len(s.Features), s.Required)
	}
}

func TestOrdinaryStringsAloneNeedAtLeastThreeAndCarryAWarning(t *testing.T) {
	r := report()
	r.Analysis.Decoded, r.Analysis.Indicators = nil, nil
	r.Analysis.Strings.Shown = []models.StringHit{{Text: "Global\\UnpackrTestMutex_8f3a21"}, {Text: "C:\\Users\\dev\\Desktop\\loader\\Release\\core.pdb"}}
	if _, err := Build(r, Options{}); err == nil {
		t.Fatal("two ordinary strings are not enough")
	}
	r.Analysis.Strings.Shown = append(r.Analysis.Strings.Shown, models.StringHit{Text: "UnpackrConfigKey_77aa9"})
	s, err := Build(r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Warnings) == 0 || s.Required < 2 {
		t.Errorf("%+v", s)
	}
}

func TestRefusesWhenThereIsLittleToGoOn(t *testing.T) {
	r := report()
	r.Analysis.Decoded = nil
	r.Analysis.Indicators = nil
	r.Analysis.Strings.Shown = r.Analysis.Strings.Shown[:2] // boilerplate only
	_, err := Build(r, Options{})
	var ne *ErrNotEnough
	if err == nil || !asNotEnough(err, &ne) {
		t.Fatalf("want ErrNotEnough, got %v", err)
	}
	if _, err := Build(&models.Report{}, Options{}); err == nil {
		t.Error("a report without analysis must be refused")
	}
}

func asNotEnough(err error, target **ErrNotEnough) bool {
	if e, ok := err.(*ErrNotEnough); ok {
		*target = e
		return true
	}
	return false
}

// unquote reverses quote for the escapes it produces.
func unquote(t *testing.T, lit string) string {
	t.Helper()
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		t.Fatalf("not a quoted literal: %s", lit)
	}
	in, out := lit[1:len(lit)-1], []byte{}
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' {
			if in[i] == '"' {
				t.Fatalf("unescaped quote inside literal: %s", lit)
			}
			out = append(out, in[i])
			continue
		}
		i++
		switch in[i] {
		case '\\', '"':
			out = append(out, in[i])
		case 'x':
			var v byte
			for _, c := range []byte(in[i+1 : i+3]) {
				v = v<<4 | map[bool]byte{true: c - '0', false: c - 'a' + 10}[c <= '9']
			}
			out = append(out, v)
			i += 2
		default:
			t.Fatalf("unexpected escape in %s", lit)
		}
	}
	return string(out)
}

func TestHostileStringsCannotInjectRuleSyntax(t *testing.T) {
	hostile := `http://x.test/" } rule evil { condition: true } //`
	r := report()
	r.Analysis.Decoded = nil
	r.Analysis.Strings.Shown = nil
	r.Analysis.Indicators = []models.Indicator{{Type: "url", Value: hostile, Encoding: "ascii"}, {Type: "domain", Value: "second.indicator.example.net", Encoding: "ascii"}}
	s, err := Build(r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(s.Rule, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "$s") {
			continue
		}
		lit := strings.TrimSuffix(line[strings.Index(line, "= ")+2:], " ascii")
		if unquote(t, lit) == hostile {
			found = true
		}
	}
	if !found {
		t.Fatalf("the hostile string should round-trip through the quoting:\n%s", s.Rule)
	}
	if q := quote("a\"b\\c\x00\x7f\n"); q != `"a\"b\\c\x00\x7f\x0a"` {
		t.Errorf("quote = %s", q)
	}
}

func TestNonASCIIAndOverlongStringsAreRejected(t *testing.T) {
	if reject("héllo-world-long", true) == "" || reject(strings.Repeat("a", 201), true) == "" || reject("abc", true) == "" {
		t.Error("weak features accepted")
	}
	if reject("Global\\UnpackrTestMutex_8f3a21", false) != "" {
		t.Error("a specific string was rejected")
	}
}

func TestRuleNameIsValidated(t *testing.T) {
	for _, bad := range []string{"1abc", "has space", "x;y", "", strings.Repeat("a", 200)} {
		if bad == "" {
			continue // empty means "derive it"
		}
		if _, err := Build(report(), Options{Name: bad}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	s, err := Build(report(), Options{Name: "My_Family_2"})
	if err != nil || !strings.Contains(s.Rule, "rule My_Family_2 {") {
		t.Fatalf("%v", err)
	}
}

func TestImphashAlternativeAndWarnings(t *testing.T) {
	s, err := Build(report(), Options{Imphash: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Rule, `import "pe"`) || !strings.Contains(s.Rule, `pe.imphash() == "abcdef0123456789"`) {
		t.Errorf("imphash alternative missing:\n%s", s.Rule)
	}
	if len(s.Warnings) == 0 {
		t.Error("the imphash alternative must carry a warning about breadth")
	}
}

func TestIndicatorsOnlyDraftsCarryAWarning(t *testing.T) {
	r := report()
	r.Analysis.Decoded = nil
	s, err := Build(r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, w := range s.Warnings {
		warned = warned || strings.Contains(w, "identifies a project or vendor")
	}
	if !warned || !strings.Contains(s.Rule, "// NOTE:") {
		t.Errorf("warnings: %v\n%s", s.Warnings, s.Rule)
	}
	// With a recovered hidden string the warning does not apply.
	if s2, _ := Build(report(), Options{}); s2 != nil {
		for _, w := range s2.Warnings {
			if strings.Contains(w, "identifies a project or vendor") {
				t.Error("unexpected warning when a hidden string is present")
			}
		}
	}
}
