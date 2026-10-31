package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/config"
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

func minimalPE() []byte {
	b := make([]byte, 0x400)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x84+2:], 3)
	binary.LittleEndian.PutUint16(b[0x84+16:], 0xf0)
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	return b
}

func write(t *testing.T, name string, data []byte) string {
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o444); err != nil {
		t.Fatal(err)
	}
	return p
}

func opts() Options { return Options{Config: config.Default(), Profile: ProfileInfo} }

func TestAnalyzePE(t *testing.T) {
	data := minimalPE()
	p := write(t, "sample.bin", data) // wrong extension on purpose
	rep, err := Analyze(context.Background(), p, opts())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if rep.File.Hashes.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("hash mismatch")
	}
	if rep.Identification == nil || rep.Identification.Primary != "PE32+" {
		t.Fatalf("%+v", rep.Identification)
	}
	if len(rep.Findings) == 0 || rep.Findings[0].ID != "ident.format" {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.Class != "observation" || len(f.EvidenceID) == 0 || f.Rationale == "" {
		t.Fatalf("finding lacks evidence or rationale: %+v", f)
	}
	if len(rep.NotRun) == 0 {
		t.Fatal("unimplemented stages must be listed")
	}
	if rep.Modules[0].Sandbox == nil || rep.Modules[0].Sandbox.Level == "" {
		t.Fatal("sandbox status missing")
	}
}

func TestOriginalIsUntouched(t *testing.T) {
	data := minimalPE()
	p := write(t, "s.exe", data)
	st1, _ := os.Stat(p)
	if _, err := Analyze(context.Background(), p, opts()); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	got, _ := os.ReadFile(p)
	if string(got) != string(data) || !st1.ModTime().Equal(st2.ModTime()) || st1.Mode() != st2.Mode() {
		t.Fatal("input was modified")
	}
}

func TestUnknownData(t *testing.T) {
	rep, err := Analyze(context.Background(), write(t, "x", []byte("hello")), opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Identification.Primary != "unknown" || rep.Findings[0].ID != "ident.unknown" {
		t.Fatalf("%+v", rep.Findings)
	}
	if rep.Findings[0].Confidence == "high" {
		t.Fatal("absence of a match must not be high confidence")
	}
}

func TestRejectsDirectoryAndOversize(t *testing.T) {
	if _, err := Analyze(context.Background(), t.TempDir(), opts()); err == nil {
		t.Fatal("directory accepted")
	}
	o := opts()
	o.Config.MaxFileSizeMB = 1
	big := write(t, "big", make([]byte, 2<<20))
	if _, err := Analyze(context.Background(), big, o); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestWorkerFailureIsReportedNotHidden(t *testing.T) {
	o := opts()
	o.Exe = "/nonexistent/worker"
	rep, err := Analyze(context.Background(), write(t, "s", minimalPE()), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Identification != nil || len(rep.Warnings) == 0 || rep.Modules[0].Status != "failed" {
		t.Fatalf("failure not surfaced: %+v", rep)
	}
}

func TestRequireSandboxFailsClosed(t *testing.T) {
	o := opts()
	o.Config.RequireSandbox = true
	o.Exe = "/nonexistent/worker"
	if _, err := Analyze(context.Background(), write(t, "s", minimalPE()), o); err == nil {
		t.Fatal("must fail when the sandbox cannot be established")
	}
}

func TestFullSandboxOnCapableKernel(t *testing.T) {
	rep, err := Analyze(context.Background(), write(t, "s", minimalPE()), opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Modules[0].Sandbox.Level != "full" {
		t.Skipf("full sandbox unavailable: %+v", rep.Modules[0].Sandbox)
	}
}

func TestStructureStageRunsInWorker(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"KERNEL32.dll": {"VirtualAlloc", "WriteProcessMemory"}},
		Overlay: []byte("tail"),
	})
	rep, err := Analyze(context.Background(), write(t, "s.bin", data), opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Binary == nil || rep.Binary.Format != "PE32+" || len(rep.Binary.Imports) != 1 || rep.Binary.Overlay == nil {
		t.Fatalf("%+v", rep.Binary)
	}
	var sawStructure bool
	for _, m := range rep.Modules {
		if m.Name == "structure" && m.Status == "ok" && m.Sandbox != nil {
			sawStructure = true
		}
	}
	if !sawStructure {
		t.Fatalf("structure module not recorded: %+v", rep.Modules)
	}
	// Facts only: no capability or behaviour claims exist yet.
	for _, f := range rep.Findings {
		if f.Category == "capability" {
			t.Fatalf("capability finding without a capability stage: %+v", f)
		}
	}
}

func TestStructureFailureDoesNotHideIdentification(t *testing.T) {
	// Looks like a PE to the identifier but has no usable optional header.
	b := make([]byte, 0x200)
	copy(b, "MZ")
	b[0x3c] = 0x80
	copy(b[0x80:], "PE\x00\x00")
	rep, err := Analyze(context.Background(), write(t, "bad.exe", b), opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Identification == nil {
		t.Fatal("identification lost")
	}
	if rep.Binary != nil {
		t.Fatalf("a broken file must not yield invented structure: %+v", rep.Binary)
	}
}

func TestContentAnalysisStage(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{
			"KERNEL32.dll": {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"},
			"USER32.dll":   {"MessageBoxW", "GetMessageW", "DispatchMessageW", "CreateWindowExW"},
		},
		Overlay: []byte("config: http://203.0.113.9/panel.php and C:\\Windows\\Temp\\drop.exe"),
	})
	rep, err := Analyze(context.Background(), write(t, "s.bin", data), opts())
	if err != nil {
		t.Fatal(err)
	}
	a := rep.Analysis
	if a == nil {
		t.Fatal("analysis missing")
	}
	var url, path, ip bool
	for _, i := range a.Indicators {
		url = url || (i.Type == "url" && i.Value == "http://203.0.113.9/panel.php")
		path = path || (i.Type == "windows-path" && i.Value == "C:\\Windows\\Temp\\drop.exe")
		ip = ip || (i.Type == "ipv4" && i.Value == "203.0.113.9")
	}
	if !url || !path {
		t.Fatalf("indicators: %+v", a.Indicators)
	}
	if ip {
		t.Fatal("host inside a URL must not be double-reported as a separate IP indicator")
	}
	if a.Packing.State != "unpacked" {
		t.Fatalf("packing %+v", a.Packing)
	}
	if a.Entropy.File <= 0 || len(a.Entropy.Sections) == 0 || a.Entropy.Overlay == nil {
		t.Fatalf("entropy %+v", a.Entropy)
	}
	if a.Strings.Total == 0 || len(a.Strings.Shown) == 0 {
		t.Fatalf("strings %+v", a.Strings)
	}
	// Every finding must reference evidence that exists, and inferences must
	// carry a rationale.
	ids := map[string]bool{}
	for _, e := range rep.Evidence {
		ids[e.ID] = true
	}
	for _, f := range rep.Findings {
		for _, id := range f.EvidenceID {
			if !ids[id] {
				t.Errorf("finding %s references missing evidence %s", f.ID, id)
			}
		}
		if f.Class == "inference" && f.Rationale == "" {
			t.Errorf("inference %s lacks a rationale", f.ID)
		}
	}
	for _, name := range []string{"entropy-analysis", "string-extraction", "indicator-extraction", "packing-assessment", "language-and-compiler-identification"} {
		for _, n := range rep.NotRun {
			if n == name {
				t.Errorf("%s still listed as not run", name)
			}
		}
	}
	var sawAnalysis bool
	for _, m := range rep.Modules {
		if m.Name == "content-analysis" && m.Status == "ok" && m.Sandbox != nil {
			sawAnalysis = true
		}
	}
	if !sawAnalysis {
		t.Fatalf("module not recorded: %+v", rep.Modules)
	}
}

func TestModulesCanExcludeAnalysis(t *testing.T) {
	o := opts()
	o.Modules = []string{"identification", "structure"}
	rep, err := Analyze(context.Background(), write(t, "s.bin", minimalPE()), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Analysis != nil || rep.Binary == nil {
		t.Fatalf("module selection ignored: analysis=%v binary=%v", rep.Analysis != nil, rep.Binary != nil)
	}
}

func TestCapabilitiesAndAnomaliesInReport(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		TextFlags: 0xe0000020, // rwx
		Imports:   map[string][]string{"KERNEL32.dll": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess"}},
		Overlay:   append([]byte("MZ"), make([]byte, 64)...),
	})
	rep, err := Analyze(context.Background(), write(t, "s.bin", data), opts())
	if err != nil {
		t.Fatal(err)
	}
	var cap, anom *models.Finding
	for i := range rep.Findings {
		f := &rep.Findings[i]
		switch f.ID {
		case "cap.inject.classic":
			cap = f
		case "anomaly.pe.section.writable-executable":
			anom = f
		}
	}
	if cap == nil || anom == nil {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	if cap.Class != models.ClassInference || len(cap.Attack) == 0 || cap.Attack[0] != "T1055" {
		t.Fatalf("%+v", cap)
	}
	if !strings.Contains(cap.Summary, "consistent with") {
		t.Fatalf("capability wording: %s", cap.Summary)
	}
	if anom.Class != models.ClassObservation || anom.Confidence != models.ConfidenceHigh {
		t.Fatalf("%+v", anom)
	}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if seen[f.ID] {
			t.Errorf("duplicate finding id %s", f.ID)
		}
		seen[f.ID] = true
		if f.Category == "capability" && f.Class != models.ClassInference {
			t.Errorf("capability %s must be an inference", f.ID)
		}
	}
	for _, n := range rep.NotRun {
		if n == "capability-inference" || n == "anomaly-detection" {
			t.Errorf("%s still listed as not run", n)
		}
	}
}
