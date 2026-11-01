// Package integration exercises the built binary exactly as a user would.
package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "unpackr-it")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "unpackr")
	root, _ := filepath.Abs("../..")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/unpackr")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

var (
	dataMu   sync.Mutex
	dataDirs = map[string]string{}
)

// dataDir gives each test its own database location, shared by the several
// runs inside that test, so tests never touch the real ~/.local/share.
func dataDir(t *testing.T) string {
	dataMu.Lock()
	defer dataMu.Unlock()
	d, ok := dataDirs[t.Name()]
	if !ok {
		d = t.TempDir()
		dataDirs[t.Name()] = d
	}
	return d
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir(), "XDG_DATA_HOME="+dataDir(t))
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{o.String(), e.String(), code}
}

func samplePE() []byte {
	b := make([]byte, 0x400)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0xaa64)
	binary.LittleEndian.PutUint16(b[0x84+16:], 0xf0)
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	return b
}

func write(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJSONOutputIsPureAndHasNoBanner(t *testing.T) {
	p := write(t, t.TempDir(), "s.dat", samplePE(), 0o600)
	r := run(t, "-i", p, "--format", "json")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%.200s", err, r.stdout)
	}
	if strings.Contains(r.stdout, "ArtVault") || strings.Contains(r.stdout, "\x1b[") {
		t.Fatal("artwork or ANSI leaked into JSON")
	}
	if rep["binary"] == nil {
		t.Fatalf("structure stage missing from JSON: %v", rep)
	}
	if rep["schema_version"] == nil || rep["not_run"] == nil {
		t.Fatalf("missing fields: %v", rep)
	}
}

func TestBannerSuppressedWhenPiped(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600)
	r := run(t, "-i", p) // stdout/stderr are pipes here
	if strings.Contains(r.stderr, "ArtVault") || strings.Contains(r.stdout, "ArtVault") {
		t.Fatal("banner shown without a terminal")
	}
}

func TestMisleadingExtensionAndTruncatedFiles(t *testing.T) {
	d := t.TempDir()
	good := samplePE()
	a := write(t, d, "photo.jpg", good, 0o600)
	b := write(t, d, "cut.exe", good[:100], 0o600)
	r := run(t, "-i", a, "--format", "json")
	if !strings.Contains(r.stdout, `"primary": "PE32+"`) {
		t.Fatalf("extension should be irrelevant: %s", r.stdout)
	}
	r = run(t, "-i", b, "--format", "json")
	if r.code != 0 || strings.Contains(r.stdout, `"primary": "PE32+"`) {
		t.Fatalf("truncated PE misreported: %d %s", r.code, r.stdout)
	}
	r = run(t, "-i", write(t, d, "empty.dll", nil, 0o600), "--format", "json")
	if r.code != 0 || !strings.Contains(r.stdout, `"primary": "unknown"`) {
		t.Fatalf("empty file: %d %s", r.code, r.stdout)
	}
}

func TestSampleIsNeverExecuted(t *testing.T) {
	d := t.TempDir()
	marker := filepath.Join(d, "EXECUTED")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	p := write(t, d, "canary", []byte(script), 0o755)
	r := run(t, "-i", p)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the analysed file was executed")
	}
	if !strings.Contains(r.stdout, "Script with interpreter line") {
		t.Fatalf("script not identified: %s", r.stdout)
	}
}

func TestOriginalPreserved(t *testing.T) {
	d := t.TempDir()
	data := samplePE()
	p := write(t, d, "s.exe", data, 0o444)
	before, _ := os.Stat(p)
	run(t, "-i", p, "-o", filepath.Join(d, "report.json"))
	after, _ := os.Stat(p)
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("sample modified")
	}
	if _, err := os.Stat(filepath.Join(d, "report.json")); err != nil {
		t.Fatal("report not written")
	}
}

func TestHostileFilenameCannotInjectTerminalSequences(t *testing.T) {
	d := t.TempDir()
	p := write(t, d, "evil\x1b]0;PWNED\x07name", samplePE(), 0o600)
	r := run(t, "-i", p, "-v")
	if strings.ContainsRune(r.stdout, 0x1b) || strings.ContainsRune(r.stdout, 7) {
		t.Fatalf("raw control bytes reached the terminal: %q", r.stdout)
	}
	r = run(t, "-q", d)
	if strings.ContainsRune(r.stdout, 0x1b) {
		t.Fatalf("control bytes in batch table: %q", r.stdout)
	}
}

func TestUnicodeFilenames(t *testing.T) {
	d := t.TempDir()
	p := write(t, d, "образец-样本-🧪.exe", samplePE(), 0o600)
	r := run(t, "-i", p, "--no-banner")
	if r.code != 0 || !strings.Contains(r.stdout, "образец-样本-🧪.exe") {
		t.Fatalf("%d %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestBatchDirectoryAndOutputDir(t *testing.T) {
	d := t.TempDir()
	for i, name := range []string{"a", "b", "c"} {
		data := samplePE()
		data[0x200] = byte(i)
		write(t, d, name, data, 0o600)
	}
	out := filepath.Join(t.TempDir(), "results")
	r := run(t, "-q", d, "--output-dir", out, "--threads", "2")
	if r.code != 0 || !strings.Contains(r.stdout, "3 analysed, 0 failed") {
		t.Fatalf("%d %s %s", r.code, r.stdout, r.stderr)
	}
	ents, _ := os.ReadDir(out)
	if len(ents) != 3 {
		t.Fatalf("expected 3 reports, got %d", len(ents))
	}
	for _, e := range ents {
		if len(e.Name()) != 64+5 {
			t.Fatalf("report names must be sha256-based, got %s", e.Name())
		}
	}
}

// -r needs radare2. Without it the run still succeeds and says plainly that the
// stage did not run, instead of looking clean.
func TestReverseWithoutRadare2SaysSoAndIsNotFaked(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600)
	t.Setenv("PATH", t.TempDir())
	r := run(t, "-r", p)
	if r.code != 0 || !strings.Contains(r.stdout, "skipped:") {
		t.Errorf("code %d\n%s", r.code, r.stdout)
	}
}

// -d is implemented for x86 and x86-64; on anything else it must say what it
// skipped instead of producing a quiet, clean-looking result.
func TestDeepSaysWhatItSkipped(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600) // an ARM64 image
	r := run(t, "-d", p)
	if r.code != 0 || !strings.Contains(r.stdout, "pattern analysis skipped") || !strings.Contains(r.stdout, "code-pattern-analysis: skipped") {
		t.Errorf("code %d\n%s", r.code, r.stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"-i"}, {"-i", "-q", "x"}, {"--bogus"}, {"-c", "a"}} {
		if r := run(t, args...); r.code != 2 {
			t.Errorf("%v: code %d", args, r.code)
		}
	}
	if r := run(t, "-i", "/definitely/not/here"); r.code != 1 {
		t.Errorf("missing file: code %d", r.code)
	}
}

func TestVersionAndDoctor(t *testing.T) {
	if r := run(t, "--version"); r.code != 0 || !strings.Contains(r.stdout, "UNPACKR") {
		t.Fatalf("%v", r)
	}
	r := run(t, "doctor")
	if r.code != 0 || !strings.Contains(r.stdout, "Confinement") {
		t.Fatalf("%v", r)
	}
	if strings.Contains(r.stdout, "ALLOWED") {
		t.Fatalf("sandbox allowed a forbidden action:\n%s", r.stdout)
	}
}

func TestRequireSandboxIsHonoured(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600)
	r := run(t, "-i", p, "--require-sandbox", "--format", "json")
	// On a capable kernel this succeeds; otherwise it must fail closed.
	if r.code != 0 && !strings.Contains(r.stderr, "sandbox") {
		t.Fatalf("unexpected failure: %d %s", r.code, r.stderr)
	}
}

func TestArtCommands(t *testing.T) {
	if r := run(t, "art", "list"); r.code != 0 || !strings.Contains(r.stdout, "Stack frame") {
		t.Fatalf("%v", r)
	}
	if r := run(t, "art", "show", "001"); r.code != 0 || !strings.Contains(r.stdout, "rbp") {
		t.Fatalf("%v", r)
	}
	if r := run(t, "art", "show", "nope"); r.code != 2 {
		t.Fatalf("%v", r)
	}
}

func TestModulesSelection(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600)
	r := run(t, "-i", p, "--format", "json", "--modules", "identification")
	if r.code != 0 || strings.Contains(r.stdout, `"binary"`) {
		t.Fatalf("structure ran although not selected: %d", r.code)
	}
	r = run(t, "-i", p, "--format", "json", "--modules", "identification,structure")
	if r.code != 0 || strings.Contains(r.stdout, `"analysis"`) {
		t.Fatalf("analysis ran although not selected: %d", r.code)
	}
	if r := run(t, "-i", p, "--modules", "nonsense"); r.code != 2 {
		t.Fatalf("code %d", r.code)
	}
}

func TestAnalysisAppearsInTerminalAndJSON(t *testing.T) {
	data := samplePE()
	data = append(data, []byte("see https://c2.badhost.xyz/beacon now")...)
	p := write(t, t.TempDir(), "s.exe", data, 0o600)
	r := run(t, "-i", p)
	for _, want := range []string{"Technical fingerprint", "Packing and obfuscation", "Static intelligence", "c2.badhost.xyz"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("terminal output lacks %q", want)
		}
	}
	if !strings.Contains(r.stdout, "do not show that the sample uses or contacts them") {
		t.Error("indicator disclaimer missing")
	}
	r = run(t, "-i", p, "--format", "json")
	var rep struct {
		Analysis struct {
			Packing struct {
				State string `json:"state"`
			} `json:"packing"`
			Indicators []struct{ Type, Value string } `json:"indicators"`
		} `json:"analysis"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Analysis.Packing.State == "" || len(rep.Analysis.Indicators) == 0 {
		t.Fatalf("%+v", rep)
	}
}

func packedUPX(t *testing.T) string {
	t.Helper()
	return fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
}

func TestUnpackThroughTheCLI(t *testing.T) {
	packed := packedUPX(t)
	out := t.TempDir()
	r := run(t, "-i", packed, "-u", "--output-dir", out, "--format", "json")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	var rep struct {
		Unpack struct {
			Status string `json:"status"`
		} `json:"unpack"`
		Artifacts []struct {
			Path   string `json:"path"`
			Report struct {
				Analysis struct {
					Packing struct {
						State string `json:"state"`
					} `json:"packing"`
				} `json:"analysis"`
			} `json:"report"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Unpack.Status == "unavailable" {
		t.Skipf("unpacking unavailable here")
	}
	if rep.Unpack.Status != "unpacked" || len(rep.Artifacts) != 1 {
		t.Fatalf("%+v", rep)
	}
	if rep.Artifacts[0].Report.Analysis.Packing.State != "unpacked" {
		t.Fatalf("the unpacked layer must be analysed: %+v", rep.Artifacts[0])
	}
	st, err := os.Stat(rep.Artifacts[0].Path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("artifact: %v %v", st, err)
	}
	if !strings.HasPrefix(rep.Artifacts[0].Path, out) {
		t.Fatalf("artifact not under --output-dir: %s", rep.Artifacts[0].Path)
	}
	// Terminal output mentions the comparison.
	r = run(t, "-i", packed, "-u", "--output-dir", out)
	for _, want := range []string{"Unpacking", "unpacked", "Differences (packed -> unpacked)", "Analysis of the unpacked layer"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("terminal output lacks %q", want)
		}
	}
}

func TestCompareThroughTheCLI(t *testing.T) {
	packed := packedUPX(t)
	plain := fixtures.GoBinary(t, "linux", "amd64")
	r := run(t, "-c", packed, plain)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	for _, want := range []string{"Comparison", "packing state", "confirmed-packed (UPX)", "only in"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("lacks %q:\n%s", want, r.stdout)
		}
	}
	r = run(t, "-c", plain, plain, "--format", "json")
	var cmp struct {
		Comparison struct {
			Identical bool `json:"identical"`
		} `json:"comparison"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &cmp); err != nil || !cmp.Comparison.Identical {
		t.Fatalf("%v %s", err, r.stdout)
	}
	if r := run(t, "-c", plain, t.TempDir()); r.code != 2 {
		t.Fatalf("directory argument: code %d", r.code)
	}
}

func TestUnpackNotApplicableMessage(t *testing.T) {
	r := run(t, "-i", fixtures.GoBinary(t, "linux", "amd64"), "-u", "--no-banner")
	if r.code != 0 || !strings.Contains(r.stdout, "not-applicable") {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
}

func TestYaraEngineInTerminalAndJSON(t *testing.T) {
	if _, err := exec.LookPath("yr"); err != nil {
		t.Skip("yr not installed")
	}
	plain := fixtures.GoBinary(t, "linux", "amd64")
	r := run(t, "-i", plain, "--no-banner")
	for _, want := range []string{"YARA-X", "go_buildinfo", "tested"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("terminal output lacks %q", want)
		}
	}
	r = run(t, "-i", plain, "--format", "json", "--modules", "identification,structure,analysis")
	if strings.Contains(r.stdout, `"rule": "go_buildinfo"`) {
		t.Fatal("signatures ran although not selected")
	}
	// An analyst rules directory is honoured but never trusted as evidence.
	cfg := t.TempDir()
	rules := filepath.Join(cfg, "unpackr", "rules")
	if err := os.MkdirAll(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "mine.yar"), []byte(`rule goish { strings: $a = "Go buildinf" condition: $a }`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-i", plain, "--format", "json")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+cfg, "XDG_STATE_HOME="+t.TempDir())
	var o bytes.Buffer
	cmd.Stdout = &o
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.String(), `"rule": "goish"`) || !strings.Contains(o.String(), `"status": "user"`) {
		t.Fatal("analyst rule did not run or was mislabelled")
	}
}

func TestExtractThroughTheCLI(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"K.dll": {"a"}},
		Overlay: fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: 311, Entries: []fixtures.PYIEntry{
			{Name: "main", Type: 's', Data: []byte("CODE"), Compress: true},
			{Name: "../../etc/cron.d/evil", Type: 'x', Data: []byte("x")},
		}}),
	})
	p := write(t, t.TempDir(), "frozen.exe", data, 0o600)
	out := t.TempDir()
	r := run(t, "-x", "-i", p, "--output-dir", out, "--format", "json")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	var rep struct {
		Extraction struct {
			Status string `json:"status"`
			Dir    string `json:"dir"`
		} `json:"extraction"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || rep.Extraction.Status != "extracted" {
		t.Fatalf("%v %s", err, r.stdout)
	}
	if !strings.HasPrefix(rep.Extraction.Dir, out) {
		t.Fatalf("output outside --output-dir: %s", rep.Extraction.Dir)
	}
	if _, err := os.Stat(filepath.Join(rep.Extraction.Dir, "main.pyc")); err != nil {
		t.Fatal(err)
	}
	r = run(t, "-x", "-i", p, "--output-dir", out)
	for _, want := range []string{"Extraction", "PyInstaller", "main", "Skipped entries", "traversal", "never executed"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("terminal output lacks %q", want)
		}
	}
	if r := run(t, "-x", "-i", fixtures.GoBinary(t, "linux", "amd64"), "--no-banner"); r.code != 0 || !strings.Contains(r.stdout, "not-applicable") {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
}

func TestReportFormatsThroughTheCLI(t *testing.T) {
	data := samplePE()
	data = append(data, []byte("beacon http://203.0.113.9/gate.php and C:\\Users\\Public\\x.exe")...)
	d := t.TempDir()
	p := write(t, d, "s.exe", data, 0o600)
	for _, tc := range []struct{ file, want string }{
		{"report.html", "<!doctype html>"}, {"report.md", "# UNPACKR report"}, {"report.csv", "file_sha256,file_name,type,value"}, {"report.json", `"schema_version"`},
	} {
		out := filepath.Join(d, tc.file)
		r := run(t, "-i", p, "-o", out)
		if r.code != 0 {
			t.Fatalf("%s: %d %s", tc.file, r.code, r.stderr)
		}
		b, err := os.ReadFile(out)
		if err != nil || !strings.Contains(string(b), tc.want) {
			t.Fatalf("%s: %v %.200s", tc.file, err, b)
		}
		if strings.ContainsRune(string(b), 0x1b) || strings.Contains(string(b), "ArtVault") {
			t.Errorf("%s contains terminal artwork or escape codes", tc.file)
		}
		if tc.file != "report.csv" && tc.file != "report.json" && strings.Contains(string(b), "203.0.113.9") {
			t.Errorf("%s contains an un-defanged indicator", tc.file)
		}
	}
	// stdout formats are pure: no banner, no progress, nothing before the document.
	r := run(t, "-i", p, "--format", "html")
	if !strings.HasPrefix(r.stdout, "<!doctype html>") || r.stderr != "" {
		t.Fatalf("html on stdout not pure: %.80q / %q", r.stdout, r.stderr)
	}
	if r := run(t, "-i", p, "--format", "markdown"); !strings.HasPrefix(r.stdout, "# UNPACKR report") {
		t.Fatalf("%.80q", r.stdout)
	}
	// The report is never written over the input, whatever the extension.
	if r := run(t, "-i", p, "-o", p); r.code != 2 {
		t.Fatalf("overwrite of the input allowed: %d", r.code)
	}
}

func TestBatchAndCompareReports(t *testing.T) {
	d := t.TempDir()
	write(t, d, "a.exe", samplePE(), 0o600)
	b := samplePE()
	b[0x200] = 7
	write(t, d, "b.exe", b, 0o600)
	out := filepath.Join(t.TempDir(), "batch.html")
	if r := run(t, "-q", d, "-o", out); r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	h, _ := os.ReadFile(out)
	if !strings.Contains(string(h), "UNPACKR batch report") || !strings.Contains(string(h), "a.exe") || !strings.Contains(string(h), "b.exe") {
		t.Fatalf("%.300s", h)
	}
	cmp := filepath.Join(t.TempDir(), "cmp.html")
	if r := run(t, "-c", filepath.Join(d, "a.exe"), filepath.Join(d, "b.exe"), "-o", cmp); r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	if h, _ := os.ReadFile(cmp); !strings.Contains(string(h), "UNPACKR comparison") {
		t.Fatalf("%.200s", h)
	}
	r := run(t, "-q", d, "--format", "csv")
	if !strings.HasPrefix(r.stdout, "name,sha256,format") {
		t.Fatalf("%.100s", r.stdout)
	}
}

func TestSampleMemoryAndCasesThroughTheCLI(t *testing.T) {
	d := t.TempDir()
	a := write(t, d, "a.exe", append(samplePE(), []byte("beacon http://c2.shared.example.xyz/x")...), 0o600)
	b := write(t, d, "b.exe", append(samplePE(), []byte("other http://c2.shared.example.xyz/y more")...), 0o600)

	// First analysis: nothing is known yet.
	r := run(t, "-i", a, "--no-banner")
	if r.code != 0 || strings.Contains(r.stdout, "Seen before") {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	// Second: the file is remembered.
	r = run(t, "-i", a, "--no-banner")
	if !strings.Contains(r.stdout, "Seen before") || !strings.Contains(r.stdout, "analysed 1 time(s) before") {
		t.Fatalf("memory not shown:\n%.600s", r.stdout)
	}
	// The renamed copy is the same sample.
	renamed := write(t, d, "totally-different-name.bin", append(samplePE(), []byte("beacon http://c2.shared.example.xyz/x")...), 0o600)
	if r := run(t, "-i", renamed, "--no-banner"); !strings.Contains(r.stdout, "Seen before") {
		t.Fatal("identity must be the SHA-256, not the name")
	}
	if r := run(t, "-i", a, "--format", "json"); !strings.Contains(r.stdout, `"known_sample"`) {
		t.Fatal("known_sample missing from JSON")
	}

	// Database file permissions and stats.
	db := filepath.Join(dataDir(t), "unpackr", "db.json")
	if st, err := os.Stat(db); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("database file: %v %v", st, err)
	}
	if r := run(t, "db", "stats"); !strings.Contains(r.stdout, "Samples    1") {
		t.Fatalf("%s", r.stdout)
	}

	// Cases.
	for _, args := range [][]string{
		{"case", "new", "op-test", "a", "test", "case"},
		{"case", "add", "op-test", a, b},
		{"case", "note", "op-test", "both", "beacon", "to", "the", "same", "host"},
	} {
		if r := run(t, args...); r.code != 0 {
			t.Fatalf("%v: %d %s %s", args, r.code, r.stdout, r.stderr)
		}
	}
	if r := run(t, "case", "search", "same host"); !strings.Contains(r.stdout, "op-test") {
		t.Fatalf("%s", r.stdout)
	}
	r = run(t, "case", "report", "op-test")
	for _, want := range []string{"# Case op-test", "Samples (2)", "c2[.]shared[.]example[.]xyz", "Timeline", "sample-added"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("case report lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "c2.shared.example.xyz") {
		t.Error("un-defanged indicator in the case report")
	}
	out := filepath.Join(t.TempDir(), "case.html")
	if r := run(t, "case", "report", "op-test", "-o", out); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	if h, _ := os.ReadFile(out); !strings.Contains(string(h), "<!doctype html>") || strings.Contains(string(h), "<script") {
		t.Fatal("case HTML report wrong")
	}
	if r := run(t, "db", "find", "c2.shared.example.xyz"); strings.Count(r.stdout, "\n") != 2 {
		t.Fatalf("pivot on the shared indicator should find both samples:\n%s", r.stdout)
	}
	if r := run(t, "case", "add", "nope", a); r.code != 2 {
		t.Fatalf("unknown case: %d", r.code)
	}
	if r := run(t, "case", "new", "bad name"); r.code != 2 {
		t.Fatalf("invalid case name: %d", r.code)
	}
}

func TestNoDBLeavesNothingBehind(t *testing.T) {
	p := write(t, t.TempDir(), "s.exe", samplePE(), 0o600)
	if r := run(t, "-i", p, "--no-db", "--no-banner"); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	if _, err := os.Stat(filepath.Join(dataDir(t), "unpackr")); err == nil {
		t.Fatal("--no-db still created a database")
	}
	if r := run(t, "-i", p, "--no-banner"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	if _, err := os.Stat(filepath.Join(dataDir(t), "unpackr", "db.json")); err != nil {
		t.Fatal("the database should be created by default")
	}
}

func TestDatabaseFailureNeverBlocksAnalysis(t *testing.T) {
	p := write(t, t.TempDir(), "s.exe", samplePE(), 0o600)
	cfg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cfg, "unpackr"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A database path that cannot be created (its parent is a file).
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(cfg, "unpackr", "config.yaml"), []byte("database_path: "+filepath.Join(blocker, "db.json")+"\n"), 0o600)
	cmd := exec.Command(bin, "-i", p, "--no-banner")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+cfg, "XDG_STATE_HOME="+t.TempDir())
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		t.Fatalf("analysis failed because of the database: %v", err)
	}
	if !strings.Contains(o.String(), "File identification") || !strings.Contains(e.String(), "warning: local database unavailable") {
		t.Fatalf("stdout %.100s stderr %s", o.String(), e.String())
	}
}

func TestSimilarCommandAndComparisonSimilarity(t *testing.T) {
	plain := fixtures.GoBinary(t, "linux", "amd64")
	data, _ := os.ReadFile(plain)
	variant := append([]byte(nil), data...)
	for i := len(variant) / 3; i < len(variant)/3+60000; i++ {
		variant[i] ^= 0x5a
	}
	d := t.TempDir()
	vp := write(t, d, "variant", variant, 0o600)
	if r := run(t, "-i", plain, "--no-banner"); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	r := run(t, "similar", vp)
	if r.code != 0 || !strings.Contains(r.stdout, "TLSH") || strings.Contains(r.stdout, "no stored sample resembles") {
		t.Fatalf("%d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "None is a probability") {
		t.Error("the caveat must be printed with similarity results")
	}
	// An empty database says so instead of inventing a match.
	if r := run(t, "similar", write(t, d, "lonely", samplePE(), 0o600)); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	c := run(t, "-c", plain, vp)
	if c.code != 0 || !strings.Contains(c.stdout, "similarity") || !strings.Contains(c.stdout, "not probabilities") {
		t.Fatalf("%s", c.stdout)
	}
	if r := run(t, "similar", "zz"); r.code != 2 {
		t.Fatalf("bad prefix: %d", r.code)
	}
}
