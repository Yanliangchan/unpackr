package engine

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func needYara(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("yr"); err != nil {
		t.Skip("yr (YARA-X) not installed")
	}
}

func engineStatus(rep *models.Report, name string) *models.EngineStatus {
	if rep.Analysis == nil {
		return nil
	}
	for i := range rep.Analysis.Engines {
		if rep.Analysis.Engines[i].Name == name {
			return &rep.Analysis.Engines[i]
		}
	}
	return nil
}

func TestYaraAgreesWithNativeWithoutDoubleCounting(t *testing.T) {
	needYara(t)
	rep, err := Analyze(context.Background(), fixtures.GoBinary(t, "linux", "amd64"), opts())
	if err != nil {
		t.Fatal(err)
	}
	if e := engineStatus(rep, "YARA-X"); e == nil || e.Status != "used" || e.Version == "" {
		t.Fatalf("engine: %+v", e)
	}
	var sawRule bool
	for _, m := range rep.Analysis.Yara {
		sawRule = sawRule || m.Rule == "go_buildinfo"
	}
	if !sawRule {
		t.Fatalf("yara matches: %+v", rep.Analysis.Yara)
	}
	var lang *models.Hypothesis
	for i := range rep.Analysis.Fingerprint.Languages {
		if rep.Analysis.Fingerprint.Languages[i].Name == "Go" {
			lang = &rep.Analysis.Fingerprint.Languages[i]
		}
	}
	if lang == nil {
		t.Fatal("Go not identified")
	}
	merged := false
	for _, s := range lang.Signals {
		merged = merged || strings.Contains(s.Detail, "also matched by YARA-X rule go_buildinfo")
	}
	if !merged {
		t.Fatalf("native and YARA agreement should be shown on one signal: %+v", lang.Signals)
	}
}

func TestYaraAddsEvidenceNativeLacks(t *testing.T) {
	needYara(t)
	// UPX with the magic destroyed: native sees section names only; the YARA
	// layout rule is an independent structural line of evidence.
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "windows", "amd64"))
	data, _ := os.ReadFile(packed)
	data = bytes.ReplaceAll(data, []byte("UPX!"), []byte("UXP!"))
	p := write(t, "stripped.exe", data)
	rep, err := Analyze(context.Background(), p, opts())
	if err != nil {
		t.Fatal(err)
	}
	pk := rep.Analysis.Packing
	if pk.State != models.PackLikely || pk.Family != "UPX" {
		t.Fatalf("%+v", pk)
	}
	var y bool
	for _, s := range pk.Signals {
		y = y || strings.Contains(s.ID, "pack.yara.upx_pe_layout_without_magic")
	}
	if !y {
		t.Fatalf("signals: %+v", pk.Signals)
	}
	// Several independent structural lines of evidence can justify high
	// confidence, but only a validated unpack is definitive.
	if pk.Confidence == models.ConfidenceDefinitive {
		t.Fatalf("definitive confidence requires a validated unpack: %s", pk.Confidence)
	}
}

func TestMissingYaraIsReportedAndHarmless(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	o := opts()
	o.YaraName = "no-such-yr-binary"
	rep, err := Analyze(context.Background(), packed, o)
	if err != nil {
		t.Fatal(err)
	}
	e := engineStatus(rep, "YARA-X")
	if e == nil || e.Status != "missing" || !strings.Contains(e.Detail, "native signatures") {
		t.Fatalf("%+v", e)
	}
	if rep.Analysis.Packing.State != models.PackConfirmed {
		t.Fatalf("native detection must work without YARA-X: %+v", rep.Analysis.Packing)
	}
	if len(rep.Analysis.Yara) != 0 {
		t.Fatal("matches invented")
	}
}

func TestExperimentalAndUserRulesNeverBecomeEvidence(t *testing.T) {
	needYara(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mine.yar"), []byte(`rule mine : language { meta: name="Go" strength="strong" status="tested" family="go:buildinfo" strings: $a = "NSIS-MARK" condition: $a }`), 0o600); err != nil {
		t.Fatal(err)
	}
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"}, "USER32.dll": {"MessageBoxW", "GetMessageW", "DispatchMessageW", "CreateWindowExW"}},
		Overlay: []byte("Nullsoft Install System NSIS-MARK"),
	})
	o := opts()
	o.UserRuleDir = dir
	rep, err := Analyze(context.Background(), write(t, "s.exe", data), o)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, m := range rep.Analysis.Yara {
		status[m.Rule] = m.Status
	}
	if status["nsis_installer"] != "experimental" || status["mine"] != "user" {
		t.Fatalf("%v", status)
	}
	for _, l := range rep.Analysis.Fingerprint.Languages {
		if l.Name == "Go" {
			t.Fatal("an analyst rule that claims to be tested must not create a language verdict")
		}
		for _, s := range l.Signals {
			if strings.Contains(s.ID, "yara") {
				t.Fatalf("untrusted YARA match used as a signal: %+v", s)
			}
		}
	}
	for _, s := range rep.Analysis.Packing.Signals {
		if strings.Contains(s.ID, "yara") {
			t.Fatalf("untrusted YARA match used as a packing signal: %+v", s)
		}
	}
	var finding bool
	for _, f := range rep.Findings {
		finding = finding || f.ID == "signatures.yara"
	}
	if !finding {
		t.Fatal("matches should be listed for the analyst")
	}
}

func TestModulesCanSkipSignatures(t *testing.T) {
	o := opts()
	o.Modules = []string{"identification", "structure", "analysis"}
	rep, err := Analyze(context.Background(), fixtures.GoBinary(t, "linux", "amd64"), o)
	if err != nil {
		t.Fatal(err)
	}
	if e := engineStatus(rep, "YARA-X"); e == nil || e.Status != "skipped" || len(rep.Analysis.Yara) != 0 {
		t.Fatalf("%+v", e)
	}
}
