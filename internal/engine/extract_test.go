package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func extractOpts(t *testing.T) Options {
	o := opts()
	o.Extract = true
	o.ArtifactDir = t.TempDir()
	return o
}

func frozenPE(t *testing.T, entries []fixtures.PYIEntry) string {
	t.Helper()
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"}, "USER32.dll": {"MessageBoxW", "GetMessageW", "DispatchMessageW", "CreateWindowExW"}},
		Overlay: fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: 312, Entries: entries}),
	})
	return write(t, "frozen.exe", data)
}

func TestExtractEndToEnd(t *testing.T) {
	entries := []fixtures.PYIEntry{
		{Name: "main", Type: 's', Data: []byte("CODE"), Compress: true},
		{Name: "payload.dll", Type: 'b', Data: append([]byte("MZ"), make([]byte, 200)...)},
		{Name: "../escape", Type: 'x', Data: []byte("nope")},
	}
	p := frozenPE(t, entries)
	before, _ := os.ReadFile(p)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	o := extractOpts(t)
	rep, err := Analyze(context.Background(), p, o)
	if err != nil {
		t.Fatal(err)
	}
	ex := rep.Extraction
	if ex == nil || ex.Status != "extracted" || ex.Kind != "PyInstaller" || ex.PythonVersion != "3.12" {
		t.Fatalf("%+v", ex)
	}
	if !strings.HasPrefix(ex.Dir, filepath.Join(o.ArtifactDir, "artifacts", "pyinstaller-")) {
		t.Fatalf("dir %s", ex.Dir)
	}
	// Files exist, are private, match their recorded hashes, and nothing else is there.
	var files int
	for _, e := range ex.Entries {
		if e.Path == "" {
			continue
		}
		files++
		full := filepath.Join(ex.Dir, e.Path)
		st, err := os.Lstat(full)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", e.Path, st, err)
		}
		b, _ := os.ReadFile(full)
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			t.Fatalf("%s hash mismatch", e.Path)
		}
	}
	if files != 2 {
		t.Fatalf("files %d: %+v", files, ex.Entries)
	}
	var walked int
	filepath.WalkDir(ex.Dir, func(_ string, d os.DirEntry, _ error) error { //nolint:errcheck // test walk
		if !d.IsDir() {
			walked++
		}
		return nil
	})
	if walked != files {
		t.Fatalf("unexpected files on disk: %d vs %d", walked, files)
	}
	if _, err := os.Stat(filepath.Join(o.ArtifactDir, "artifacts", "escape")); err == nil {
		t.Fatal("traversal entry escaped")
	}
	var skipped *models.ExtractedEntry
	for i := range ex.Entries {
		if ex.Entries[i].Name == "../escape" {
			skipped = &ex.Entries[i]
		}
	}
	if skipped == nil || !strings.Contains(skipped.Skipped, "traversal") {
		t.Fatalf("%+v", skipped)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("sample modified")
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	var f *models.Finding
	for i := range rep.Findings {
		if rep.Findings[i].ID == "extract.pyinstaller" {
			f = &rep.Findings[i]
		}
	}
	if f == nil || !strings.Contains(f.Summary, "main") || !strings.Contains(f.Action, "does not run extracted content") {
		t.Fatalf("%+v", f)
	}
	// Re-running replaces the previous extraction of the same sample.
	rep2, err := Analyze(context.Background(), p, o)
	if err != nil || rep2.Extraction.Status != "extracted" || rep2.Extraction.Dir != ex.Dir {
		t.Fatalf("%v %+v", err, rep2.Extraction)
	}
}

func TestExtractNotApplicableAndNotRequested(t *testing.T) {
	o := extractOpts(t)
	rep, err := Analyze(context.Background(), fixtures.GoBinary(t, "linux", "amd64"), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Extraction == nil || rep.Extraction.Status != "not-applicable" || len(rep.Extraction.Supported) == 0 {
		t.Fatalf("%+v", rep.Extraction)
	}
	if _, err := os.Stat(filepath.Join(o.ArtifactDir, "artifacts")); err == nil {
		t.Fatal("an artifact directory was created although nothing was extracted")
	}
	rep, _ = Analyze(context.Background(), frozenPE(t, []fixtures.PYIEntry{{Name: "m", Type: 's', Data: []byte("x")}}), opts())
	if rep.Extraction != nil {
		t.Fatal("extraction ran without -x")
	}
}

func TestExtractLimitsFromConfig(t *testing.T) {
	var es []fixtures.PYIEntry
	for i := 0; i < 6; i++ {
		es = append(es, fixtures.PYIEntry{Name: string(rune('a' + i)), Type: 'x', Data: []byte(strings.Repeat("x", 100))})
	}
	o := extractOpts(t)
	o.Config.ExtractMaxEntries = 3
	rep, err := Analyze(context.Background(), frozenPE(t, es), o)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range rep.Extraction.Entries {
		if e.Path != "" {
			n++
		}
	}
	if n > 3 {
		t.Fatalf("extract_max_entries ignored: %d", n)
	}
}

func TestVerifyExtractionRejectsTampering(t *testing.T) {
	mk := func() (string, *models.Extraction) {
		dir := t.TempDir()
		b := []byte("content")
		if err := os.WriteFile(filepath.Join(dir, "a.bin"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return dir, &models.Extraction{Entries: []models.ExtractedEntry{{Name: "a", Path: "a.bin", Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}}}
	}
	dir, ex := mk()
	if err := verifyExtraction(dir, ex, 1<<20, 10); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(dir string, ex *models.Extraction){
		"extra file":     func(d string, _ *models.Extraction) { _ = os.WriteFile(filepath.Join(d, "extra"), []byte("x"), 0o600) },
		"symlink":        func(d string, _ *models.Extraction) { _ = os.Symlink("/etc/passwd", filepath.Join(d, "link")) },
		"wrong hash":     func(_ string, e *models.Extraction) { e.Entries[0].SHA256 = strings.Repeat("0", 64) },
		"wrong size":     func(_ string, e *models.Extraction) { e.Entries[0].Size = 99 },
		"wrong mode":     func(d string, _ *models.Extraction) { _ = os.Chmod(filepath.Join(d, "a.bin"), 0o755) },
		"path traversal": func(_ string, e *models.Extraction) { e.Entries[0].Path = "../a.bin" },
		"absolute path":  func(_ string, e *models.Extraction) { e.Entries[0].Path = "/etc/passwd" },
		"missing file":   func(d string, _ *models.Extraction) { _ = os.Remove(filepath.Join(d, "a.bin")) },
	}
	for name, mutate := range cases {
		dir, ex := mk()
		mutate(dir, ex)
		if err := verifyExtraction(dir, ex, 1<<20, 10); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
	dir, ex = mk()
	if err := verifyExtraction(dir, ex, 3, 10); err == nil {
		t.Error("byte limit not enforced")
	}
}

func TestRealPyInstallerEndToEnd(t *testing.T) {
	p := fixtures.PyInstallerBinary(t)
	rep, err := Analyze(context.Background(), p, extractOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Extraction == nil || rep.Extraction.Status != "extracted" {
		t.Fatalf("%+v", rep.Extraction)
	}
	var lang bool
	for _, l := range rep.Analysis.Fingerprint.Languages {
		lang = lang || strings.Contains(l.Name, "PyInstaller")
	}
	if !lang {
		t.Errorf("fingerprint should identify PyInstaller: %+v", rep.Analysis.Fingerprint.Languages)
	}
}
