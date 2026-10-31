package yara

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/assets/rules"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func TestMain(m *testing.M) {
	if worker.IsWorker() {
		worker.Serve()
	}
	os.Exit(m.Run())
}

func scanner(t *testing.T) func(data []byte, userDir string) []models.YaraMatch {
	t.Helper()
	tool, err := Locate(context.Background(), "yr", 2<<30)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("yr (YARA-X) not installed")
		}
		if errors.Is(err, worker.ErrExecSandbox) {
			t.Skipf("no full sandbox here: %v", err)
		}
		t.Fatal(err)
	}
	return func(data []byte, userDir string) []models.YaraMatch {
		t.Helper()
		res, err := Scan(context.Background(), tool, bytes.NewReader(data), Options{
			Builtin: rules.FS, BuiltinDir: ".", UserRuleDir: userDir, Timeout: 30 * time.Second, MemoryBytes: 2 << 30,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Matches
	}
}

func has(ms []models.YaraMatch, rule string) bool {
	for _, m := range ms {
		if m.Rule == rule {
			return true
		}
	}
	return false
}

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every built-in rule must compile: Scan runs with --ignore-invalid-rules so
// a typo would otherwise silently disable a rule.
func TestBuiltInRulesCompile(t *testing.T) {
	yr, err := exec.LookPath("yr")
	if err != nil {
		t.Skip("yr not installed")
	}
	out, err := exec.Command(yr, "compile", "-o", filepath.Join(t.TempDir(), "r.yarc"), "../../assets/rules").CombinedOutput() //nolint:gosec // fixed test tool
	if err != nil {
		t.Fatalf("built-in rules do not compile:\n%s", out)
	}
}

var reRule = regexp.MustCompile(`(?s)rule\s+(\w+)\s*(?::\s*\w+)?\s*\{(.*?)\n\}`)

// Every rule must carry the metadata the engine relies on, and a rule may only
// claim status "tested" if this file has fixtures for it (checked below).
func TestRuleMetadataContract(t *testing.T) {
	var tested []string
	for _, f := range []string{"languages.yar", "packers.yar"} {
		src := string(read(t, "../../assets/rules/"+f))
		for _, m := range reRule.FindAllStringSubmatch(src, -1) {
			name, body := m[1], m[2]
			for _, key := range []string{"name", "strength", "status", "description"} {
				if !regexp.MustCompile(`\b` + key + `\s*=\s*"`).MatchString(body) {
					t.Errorf("%s: missing meta %q", name, key)
				}
			}
			if regexp.MustCompile(`status\s*=\s*"tested"`).MatchString(body) {
				tested = append(tested, name)
			}
		}
	}
	for _, r := range tested {
		if _, ok := fixtureCoverage[r]; !ok {
			t.Errorf("rule %s claims status \"tested\" but has no positive/negative fixture in yara_test.go", r)
		}
	}
	for r := range fixtureCoverage {
		found := false
		for _, x := range tested {
			found = found || x == r
		}
		if !found {
			t.Errorf("fixtureCoverage lists %s which is not a tested built-in rule", r)
		}
	}
}

type coverage struct {
	positive func(t *testing.T) []byte
	negative func(t *testing.T) []byte
}

func goBin(os_, arch string) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return read(t, fixtures.GoBinary(t, os_, arch)) }
}

func upxPE(t *testing.T) []byte {
	return read(t, fixtures.PackWithUPX(t, fixtures.GoBinary(t, "windows", "amd64")))
}
func upxELF(t *testing.T) []byte {
	return read(t, fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64")))
}

var fixtureCoverage = map[string]coverage{
	"go_buildinfo":  {goBin("linux", "amd64"), upxPE},
	"go_pclntab":    {goBin("windows", "amd64"), upxPE},
	"rust_std_path": {func(t *testing.T) []byte { return read(t, fixtures.RustBinary(t)) }, goBin("linux", "amd64")},
	"pyinstaller_archive": {func(t *testing.T) []byte {
		return append(bytes.Repeat([]byte{0}, 100), []byte("MEI\x0c\x0b\x0a\x0b\x0e")...)
	}, goBin("linux", "amd64")},
	"upx_magic":       {upxPE, goBin("windows", "amd64")},
	"upx_stub_banner": {upxELF, goBin("linux", "amd64")},
	"upx_pe_layout_without_magic": {
		func(t *testing.T) []byte { return bytes.ReplaceAll(upxPE(t), []byte("UPX!"), []byte("UXP!")) },
		upxPE, // genuine UPX has the magic, so the "stripped" rule must stay silent
	},
}

func TestEveryTestedRuleMatchesItsPositiveAndNotItsNegative(t *testing.T) {
	run := scanner(t)
	for rule, c := range fixtureCoverage {
		pos := run(c.positive(t), "")
		if !has(pos, rule) {
			t.Errorf("%s did not match its positive fixture", rule)
		}
		neg := run(c.negative(t), "")
		if has(neg, rule) {
			t.Errorf("%s matched its negative fixture (false positive)", rule)
		}
		for _, m := range pos {
			if m.Rule == rule && m.Status != "tested" {
				t.Errorf("%s: status %q", rule, m.Status)
			}
		}
	}
}

func TestExperimentalRulesAreLabelled(t *testing.T) {
	run := scanner(t)
	ms := run([]byte("....Nullsoft Install System...."), "")
	if !has(ms, "nsis_installer") {
		t.Fatalf("%+v", ms)
	}
	for _, m := range ms {
		if m.Rule == "nsis_installer" && m.Status != "experimental" {
			t.Fatalf("untested rule presented as %q", m.Status)
		}
	}
}

func TestUserRulesAreUsedButNeverEvidence(t *testing.T) {
	run := scanner(t)
	dir := t.TempDir()
	mustWrite := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("mine.yar", `rule mine : packer { meta: name="UPX" strength="strong" status="tested" family="sig:UPX" strings: $a = "FINDME" condition: $a }`)
	mustWrite("broken.yar", `rule broken { condition: nope }`)
	mustWrite("big.yar", strings.Repeat("// padding\n", MaxUserRuleBytes/10+10))
	mustWrite("ignored.txt", `rule txt { condition: true }`)
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "link.yar")); err != nil {
		t.Fatal(err)
	}
	ms := run([]byte("xxFINDMExx"), dir)
	var mine *models.YaraMatch
	for i := range ms {
		if ms[i].Rule == "mine" {
			mine = &ms[i]
		}
		if ms[i].Rule == "txt" || ms[i].Rule == "broken" {
			t.Fatalf("%s should not match", ms[i].Rule)
		}
	}
	if mine == nil {
		t.Fatalf("analyst rule did not run: %+v", ms)
	}
	// The rule claims to be tested, strong and in the UPX family. None of
	// that is honoured for analyst rules.
	if mine.Status != "user" || mine.Namespace != "user" || mine.Strength != "" || mine.Family != "" {
		t.Fatalf("analyst rule must not borrow built-in trust: %+v", mine)
	}
}

func TestParseIsStrictAndBounded(t *testing.T) {
	good := `{"path":"x","rules":[{"identifier":"r\u001b[2J","namespace":"builtin","meta":[["name","N\u001b]0;x"],["strength","strong"],["status","tested"],["n",5]],"tags":["packer"],"strings":[{"identifier":"$a","offset":7,"match":"abc"}]}]}`
	ms, err := Parse(good)
	if err != nil || len(ms) != 1 {
		t.Fatal(err, ms)
	}
	for _, s := range []string{ms[0].Rule, ms[0].Name} {
		if strings.ContainsRune(s, 0x1b) {
			t.Fatalf("control byte survived: %q", s)
		}
	}
	if ms[0].Status != "tested" || ms[0].Category != "packer" || ms[0].Matches[0].Offset != 7 {
		t.Fatalf("%+v", ms[0])
	}
	if _, err := Parse("not json"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := Parse(strings.Repeat(`{"rules":[]}`+"\n", MaxOutputLines+1)); err == nil {
		t.Fatal("excess output lines accepted")
	}
	// A hostile process cannot inflate the result.
	var b strings.Builder
	b.WriteString(`{"rules":[`)
	for i := 0; i < MaxMatches*2; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"identifier":"r","namespace":"builtin"}`)
	}
	b.WriteString("]}")
	ms, err = Parse(b.String())
	if err != nil || len(ms) != MaxMatches {
		t.Fatalf("%v %d", err, len(ms))
	}
	// Built-in rules without a status are experimental, never tested.
	ms, _ = Parse(`{"rules":[{"identifier":"x","namespace":"builtin","meta":[["strength","strong"]]}]}`)
	if ms[0].Status != "experimental" {
		t.Fatalf("%+v", ms[0])
	}
}
