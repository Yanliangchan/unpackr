package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func needYR(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("yr"); err != nil {
		t.Skip("yr (YARA-X) not installed")
	}
}

func TestYaraSuggestEndToEnd(t *testing.T) {
	needYR(t)
	sample := fixtures.EncodedStaticStrings(t, "xor", 0x5a)
	clean := t.TempDir()
	for _, n := range []string{"clean1", "clean2"} {
		data, err := os.ReadFile(fixtures.CleanProgram(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(clean, n), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "draft.yar")
	r := run(t, "--no-banner", "yara", "suggest", sample, "--against", clean, "-o", out)
	if r.code != 0 {
		t.Fatalf("code %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{`$x1 = "http://evil.example.net/payload" xor`, "compiles with YARA-X", "matches the sample", "matches none of 2 clean file(s)", "Written to"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in\n%s", want, r.stdout)
		}
	}
	rule, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(rule), "rule unpackr_") {
		t.Fatalf("rule file: %v", err)
	}
	// The written draft passes the standalone test as well, and an existing
	// output file is never overwritten.
	if r := run(t, "--no-banner", "yara", "test", out, "--sample", sample, "--against", clean); r.code != 0 {
		t.Errorf("yara test: code %d\n%s", r.code, r.stdout)
	}
	if r := run(t, "--no-banner", "yara", "suggest", sample, "-o", out); r.code == 0 || !strings.Contains(r.stderr, "not overwriting") {
		t.Errorf("overwrote an existing file: %d %s", r.code, r.stderr)
	}
}

func TestYaraTestFailsWhenARuleIsTooBroad(t *testing.T) {
	needYR(t)
	dir := t.TempDir()
	rule := filepath.Join(dir, "broad.yar")
	if err := os.WriteFile(rule, []byte(`rule broad { strings: $a = "ELF" condition: $a }`), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "elfy"), []byte("\x7fELF clean enough"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "--no-banner", "yara", "test", rule, "--against", clean)
	if r.code == 0 || !strings.Contains(r.stdout, "too broad") || !strings.Contains(r.stdout, "elfy") {
		t.Errorf("code %d\n%s", r.code, r.stdout)
	}
}

func TestYaraTestReportsCompileErrorsAndFails(t *testing.T) {
	needYR(t)
	rule := filepath.Join(t.TempDir(), "bad.yar")
	if err := os.WriteFile(rule, []byte(`rule bad { condition: $nope }`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "--no-banner", "yara", "test", rule)
	if r.code == 0 || !strings.Contains(r.stdout, "does not compile") {
		t.Errorf("code %d\n%s", r.code, r.stdout)
	}
}

func TestYaraWithoutYRSaysNothingWasTested(t *testing.T) {
	rule := filepath.Join(t.TempDir(), "r.yar")
	if err := os.WriteFile(rule, []byte(`rule r { condition: true }`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()) // no yr anywhere
	r := run(t, "--no-banner", "yara", "test", rule)
	if !strings.Contains(r.stdout, "NOT compiled or tested") {
		t.Errorf("must say plainly that nothing was tested:\n%s", r.stdout)
	}
}

func TestYaraSuggestRefusesWhenThereIsNothingSpecific(t *testing.T) {
	p := write(t, t.TempDir(), "tiny", samplePE(), 0o600)
	r := run(t, "--no-banner", "yara", "suggest", p)
	if r.code == 0 || !strings.Contains(r.stderr, "No rule drafted") {
		t.Errorf("code %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
}
