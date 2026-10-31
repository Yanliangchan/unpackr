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

func run(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
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

func TestUnimplementedFeaturesAreRefusedNotFaked(t *testing.T) {
	p := write(t, t.TempDir(), "s", samplePE(), 0o600)
	for _, flag := range []string{"-d", "-x", "-r"} {
		r := run(t, "-i", p, flag)
		if r.code != 4 || r.stdout != "" {
			t.Errorf("%s: code %d stdout %q", flag, r.code, r.stdout)
		}
	}
	if r := run(t, "-i", p, "-o", filepath.Join(t.TempDir(), "r.html")); r.code != 4 {
		t.Errorf("html: code %d", r.code)
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
