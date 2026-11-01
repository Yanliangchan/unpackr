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

func unpackOpts(t *testing.T) Options {
	o := opts()
	o.Unpack = true
	o.ArtifactDir = t.TempDir()
	return o
}

// requireUPX skips when the sandboxed UPX cannot run on this host; the
// refusal itself is covered by TestUPXRefusedWithoutSandbox style checks in
// the unpacking package.
func requireUnpackable(t *testing.T, rep *models.Report) {
	t.Helper()
	if rep.Unpack != nil && rep.Unpack.Status == unpackUnavailable {
		t.Skipf("unpacking unavailable here: %s", rep.Unpack.Message)
	}
}

func TestUnpackUPXEndToEnd(t *testing.T) {
	for _, tgt := range [][2]string{{"linux", "amd64"}, {"windows", "amd64"}} {
		packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, tgt[0], tgt[1]))
		before, _ := os.ReadFile(packed)
		stBefore, _ := os.Stat(packed)

		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		o := unpackOpts(t)
		rep, err := Analyze(context.Background(), packed, o)
		if err != nil {
			t.Fatal(err)
		}
		requireUnpackable(t, rep)
		if rep.Unpack == nil || rep.Unpack.Status != "unpacked" {
			t.Fatalf("%v: %+v", tgt, rep.Unpack)
		}
		if len(rep.Artifacts) != 1 {
			t.Fatalf("artifacts %d", len(rep.Artifacts))
		}
		a := rep.Artifacts[0]
		if a.Kind != "unpacked" || a.ParentSHA256 != rep.File.Hashes.SHA256 || a.Tool == "" || a.ToolVersion == "" {
			t.Fatalf("%+v", a)
		}
		for _, c := range a.Validation {
			if !c.Passed {
				t.Errorf("validation failed: %+v", c)
			}
		}
		// The artifact is stored under a content-derived name, mode 0600.
		if filepath.Base(a.Path) != a.Hashes.SHA256+".bin" {
			t.Errorf("artifact name %s", a.Path)
		}
		if st, err := os.Stat(a.Path); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("artifact mode: %v %v", st, err)
		}
		// The unpacked layer was analysed and differs as expected.
		cr := a.Report
		if cr == nil || cr.Analysis == nil || cr.Analysis.Packing.State != models.PackUnpacked {
			t.Fatalf("child analysis: %+v", cr)
		}
		if len(cr.Analysis.Fingerprint.Languages) == 0 || cr.Analysis.Fingerprint.Languages[0].Name != "Go" {
			t.Errorf("unpacked layer should reveal the language: %+v", cr.Analysis.Fingerprint.Languages)
		}
		if a.Comparison == nil || len(a.Comparison.Sections.OnlyB) == 0 || a.Comparison.Identical {
			t.Errorf("comparison: %+v", a.Comparison)
		}
		// Only a validated unpack makes the verdict definitive.
		if rep.Analysis.Packing.Confidence != models.ConfidenceDefinitive || rep.Analysis.Packing.State != models.PackConfirmed {
			t.Errorf("packing: %+v", rep.Analysis.Packing)
		}
		// The sample is untouched and the private work directory is gone.
		after, _ := os.ReadFile(packed)
		stAfter, _ := os.Stat(packed)
		if !bytes.Equal(before, after) || !stBefore.ModTime().Equal(stAfter.ModTime()) {
			t.Error("the packed sample was modified")
		}
		if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
			t.Errorf("temporary files left behind: %v", ents)
		}
	}
}

func TestUnpackNotApplicableToUnpackedFile(t *testing.T) {
	o := unpackOpts(t)
	rep, err := Analyze(context.Background(), fixtures.GoBinary(t, "linux", "amd64"), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unpack == nil || rep.Unpack.Status != "not-applicable" || len(rep.Artifacts) != 0 {
		t.Fatalf("%+v", rep.Unpack)
	}
	if len(rep.Unpack.Supported) == 0 || rep.Unpack.Supported[0] != "UPX" {
		t.Fatalf("support must be stated: %+v", rep.Unpack)
	}
	if _, err := os.Stat(filepath.Join(o.ArtifactDir, "artifacts")); err == nil {
		t.Error("an artifact directory was created although nothing was unpacked")
	}
}

func TestUnpackNotRequestedMeansNoAttempt(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	rep, err := Analyze(context.Background(), packed, opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unpack != nil || len(rep.Artifacts) != 0 {
		t.Fatal("unpacking ran without being requested")
	}
}

func TestUnpackToolMissingIsReportedNotFatal(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	o := unpackOpts(t)
	o.UnpackerName = "no-such-upx-binary"
	rep, err := Analyze(context.Background(), packed, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unpack.Status != "unavailable" || !strings.Contains(rep.Unpack.Message, "apt install upx-ucl") {
		t.Fatalf("%+v", rep.Unpack)
	}
	if rep.Analysis == nil || rep.Analysis.Packing.State != models.PackConfirmed {
		t.Fatal("the rest of the analysis must be unaffected when the tool is missing")
	}
	if rep.Analysis.Packing.Confidence == models.ConfidenceDefinitive {
		t.Fatal("definitive confidence requires a successful unpack")
	}
}

func TestUnpackFailureOnDefeatedUPX(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "windows", "amd64"))
	data, _ := os.ReadFile(packed)
	// Anti-unpacking tamper: destroy the UPX! header magic that `upx -d` needs.
	data = bytes.ReplaceAll(data, []byte("UPX!"), []byte("UXP!"))
	p := write(t, "tampered.exe", data)
	o := unpackOpts(t)
	rep, err := Analyze(context.Background(), p, o)
	if err != nil {
		t.Fatal(err)
	}
	requireUnpackable(t, rep)
	if rep.Unpack == nil || (rep.Unpack.Status != "failed" && rep.Unpack.Status != "not-applicable") {
		t.Fatalf("%+v", rep.Unpack)
	}
	if rep.Unpack.Status == "failed" && !strings.Contains(rep.Unpack.Message, "upx") {
		t.Fatalf("failure must carry an explanation: %q", rep.Unpack.Message)
	}
	if len(rep.Artifacts) != 0 {
		t.Fatal("no artifact may be produced from a failed unpack")
	}
	if rep.Analysis == nil {
		t.Fatal("analysis must survive a failed unpack")
	}
	if ents, _ := os.ReadDir(filepath.Join(o.ArtifactDir)); len(ents) != 0 {
		t.Errorf("files left in the output directory: %v", ents)
	}
}

func TestUnpackDepthLimit(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	o := unpackOpts(t)
	o.Depth = o.Config.MaxUnpackDepth
	rep, err := Analyze(context.Background(), packed, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unpack.Status != "rejected" || len(rep.Artifacts) != 0 {
		t.Fatalf("%+v", rep.Unpack)
	}
}

func TestUnpackedFindingsAreConsistent(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	rep, err := Analyze(context.Background(), packed, unpackOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	requireUnpackable(t, rep)
	var packing, unpack *models.Finding
	for i := range rep.Findings {
		switch rep.Findings[i].ID {
		case "packing.state":
			packing = &rep.Findings[i]
		case "unpack.upx":
			unpack = &rep.Findings[i]
		}
	}
	if packing == nil || unpack == nil {
		t.Fatalf("findings missing: %+v", rep.Findings)
	}
	if packing.Confidence != models.ConfidenceDefinitive || !strings.Contains(packing.Rationale, "validated unpack") {
		t.Fatalf("%+v", packing)
	}
}

// A UPX-packed PIE executable has no interpreter and no dynamic section, so it
// cannot be classified as executable or library; the unpacked output can. The
// kind check must not reject that valid unpack.
func TestUnpackUPXPackedPIEIsAccepted(t *testing.T) {
	cc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "p.c")
	if err := os.WriteFile(src, []byte("#include <stdio.h>\nint main(void){puts(\"hello from pie\");return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "p")
	if out, err := exec.Command(cc, "-O1", "-fPIE", "-pie", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("cannot build a PIE: %v %s", err, out)
	}
	packed := fixtures.PackWithUPX(t, bin)
	rep, err := Analyze(context.Background(), packed, unpackOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	requireUnpackable(t, rep)
	if rep.Binary == nil || rep.Binary.Kind != "executable-or-library" {
		t.Fatalf("packed PIE kind = %+v", rep.Binary)
	}
	if rep.Unpack == nil || rep.Unpack.Status != "unpacked" {
		t.Fatalf("unpack: %+v", rep.Unpack)
	}
}
