package engine

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func needR2(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("radare2"); err != nil {
		t.Skip("radare2 not installed")
	}
}

func reverseOf(t *testing.T, path string) *models.Report {
	t.Helper()
	o := opts()
	o.Reverse = true
	rep, err := Analyze(context.Background(), path, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Analysis == nil || rep.Analysis.Reverse == nil {
		t.Fatalf("no reverse result: %+v", rep.NotRun)
	}
	if rv := rep.Analysis.Reverse; rv.Skipped != "" {
		if strings.Contains(rv.Skipped, "sandbox") {
			t.Skip(rv.Skipped)
		}
		t.Fatalf("skipped: %s", rv.Skipped)
	}
	return rep
}

func calledFrom(rv *models.Reverse, api string) []string {
	var out []string
	for _, c := range rv.CallSites {
		if strings.EqualFold(c.API, api) && c.Kind == "call" {
			out = append(out, c.Function)
		}
	}
	return out
}

func TestReverseResolvesCallSitesInELF(t *testing.T) {
	needR2(t)
	rep := reverseOf(t, fixtures.LinuxNetworkProgram(t))
	rv := rep.Analysis.Reverse
	for _, api := range []string{"socket", "connect", "execl"} {
		if got := calledFrom(rv, api); len(got) != 1 || got[0] != "main" {
			t.Errorf("%s called from %v", api, got)
		}
	}
	// Evidence, findings and the capability note all point at the same facts.
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "reverse/callsite" && strings.Contains(f.Title, "socket") && len(f.EvidenceID) == 1 && f.Class == models.ClassObservation && f.Confidence != models.ConfidenceHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("no well-formed call-site finding: %+v", rep.Findings)
	}
	noted := false
	for _, c := range rep.Analysis.Capabilities {
		noted = noted || strings.Contains(c.Caveat, "radare2: socket is called from main")
	}
	if !noted {
		t.Error("the capability did not get its call-site note")
	}
	for _, n := range rep.NotRun {
		if n == NotRunReverse {
			t.Error("the stage ran; it must not be listed as not run")
		}
	}
	ids := map[string]bool{}
	for _, e := range rep.Evidence {
		if ids[e.ID] {
			t.Errorf("duplicate evidence id %s", e.ID)
		}
		ids[e.ID] = true
	}
}

func TestReverseResolvesCallSitesInPE(t *testing.T) {
	needR2(t)
	rep := reverseOf(t, fixtures.WindowsImportsProgram(t))
	rv := rep.Analysis.Reverse
	// Only APIs behind a reported capability are looked up (the adapter-level
	// test covers the others), so these two are the ones to expect.
	for _, api := range []string{"CreateProcessA", "GetProcAddress"} {
		if got := calledFrom(rv, api); len(got) == 0 || got[0] != "main" {
			t.Errorf("%s called from %v", api, got)
		}
	}
	if rv.Functions < 5 {
		t.Errorf("functions %d", rv.Functions)
	}
}

func TestReverseIsNotRunUnlessAsked(t *testing.T) {
	rep, err := Analyze(context.Background(), fixtures.LinuxNetworkProgram(t), opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Analysis.Reverse != nil {
		t.Error("radare2 must not run without -r")
	}
	listed := false
	for _, n := range rep.NotRun {
		listed = listed || n == NotRunReverse
	}
	if !listed {
		t.Errorf("the skipped stage must be listed: %v", rep.NotRun)
	}
}

func TestReverseWithoutRadare2SaysSo(t *testing.T) {
	sample := fixtures.LinuxNetworkProgram(t) // built before PATH is emptied
	t.Setenv("PATH", t.TempDir())
	o := opts()
	o.Reverse = true
	rep, err := Analyze(context.Background(), sample, o)
	if err != nil {
		t.Fatal(err)
	}
	rv := rep.Analysis.Reverse
	if rv == nil || !strings.Contains(rv.Skipped, "not installed") {
		t.Fatalf("%+v", rv)
	}
	listed := false
	for _, n := range rep.NotRun {
		listed = listed || strings.HasPrefix(n, "reverse-engineering: skipped")
	}
	if !listed {
		t.Errorf("not_run: %v", rep.NotRun)
	}
}

func TestReverseSkipsFormatsItWasNotVerifiedOn(t *testing.T) {
	o := opts()
	o.Reverse = true
	rep, err := Analyze(context.Background(), write(t, "m.bin", machoHeader()), o)
	if err != nil {
		t.Fatal(err)
	}
	if rv := rep.Analysis.Reverse; rv == nil || !strings.Contains(rv.Skipped, "ELF and PE") {
		t.Fatalf("%+v", rep.Analysis.Reverse)
	}
}

// machoHeader is a 64-bit little-endian Mach-O header with no load commands.
func machoHeader() []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	return h
}

func TestReverseTargetsCarryTheImportTableAddress(t *testing.T) {
	b := &models.Binary{Format: "PE32", ImageBase: 0x400000, Imports: []models.Import{{Library: "KERNEL32.dll", Functions: []models.ImportFn{{Name: "CreateProcessA", IATRVA: 0x2010}}}}}
	caps := []models.Capability{{Severity: models.SeverityHigh, Chain: []models.ChainStep{{Source: "imported", APIs: []string{"CreateProcessA"}}}}}
	got := reverseTargets(b, caps)
	if len(got) != 1 || got[0].VA != 0x402010 || got[0].Library != "KERNEL32.dll" {
		t.Errorf("%+v", got)
	}
}
