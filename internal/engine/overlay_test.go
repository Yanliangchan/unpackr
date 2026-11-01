package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func needSevenZip(t *testing.T) {
	t.Helper()
	if _, err := locateSevenZip(); err != nil {
		t.Skip("no native 7-Zip installed")
	}
}

type zipFile struct {
	name string
	data []byte
	mode uint32 // unix mode bits, 0 for a plain file
}

func buildZip(t *testing.T, files ...zipFile) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		if f.mode != 0 {
			h.SetMode(fsModeFromUnix(f.mode))
		}
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(f.data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func peWithOverlay(t *testing.T, overlay []byte) string {
	t.Helper()
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"}, "USER32.dll": {"MessageBoxW", "GetMessageW", "DispatchMessageW", "CreateWindowExW"}},
		Overlay: overlay,
	})
	return write(t, "dropper.exe", data)
}

func TestOverlayZipIsExtractedAndVerified(t *testing.T) {
	needSevenZip(t)
	mz := append([]byte("MZ"), make([]byte, 300)...)
	z := buildZip(t, zipFile{name: "payload/stage2.exe", data: mz}, zipFile{name: "readme.txt", data: []byte("hello")}, zipFile{name: "../../escape.txt", data: []byte("nope")})
	// A self-extractor stub puts a little data before the archive.
	p := peWithOverlay(t, append([]byte("SFXSTUB\x00\x00\x00\x00"), z...))
	before, _ := os.ReadFile(p)
	o := extractOpts(t)
	rep, err := Analyze(context.Background(), p, o)
	if err != nil {
		t.Fatal(err)
	}
	ex := rep.Extraction
	if ex == nil || ex.Status != "extracted" || ex.Kind != "overlay-archive" || ex.ArchiveFormat != "ZIP" {
		t.Fatalf("%+v", ex)
	}
	if ex.ArchiveOffset <= rep.Binary.Overlay.Offset {
		t.Fatalf("archive offset ignores the stub: %d vs overlay %d", ex.ArchiveOffset, rep.Binary.Overlay.Offset)
	}
	var sawExe bool
	for _, e := range ex.Entries {
		if strings.Contains(e.Path, "..") || filepath.IsAbs(e.Path) {
			t.Fatalf("entry escapes: %q", e.Path)
		}
		if e.Name == "payload/stage2.exe" {
			sawExe = true
		}
		st, err := os.Stat(filepath.Join(ex.Dir, e.Path))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", e.Path, st, err)
		}
	}
	if !sawExe || len(ex.Entries) < 2 {
		t.Fatalf("entries: %+v", ex.Entries)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(ex.Dir), "escape.txt")); err == nil {
		t.Fatal("a ../ entry was written outside the output directory")
	}
	var f bool
	for _, x := range rep.Findings {
		if x.ID == "extract.overlay-archive" {
			f = true
		}
	}
	if !f {
		t.Fatal("no overlay finding")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("the sample was modified")
	}
}

func TestOverlayArchiveSymlinkIsNeverCreated(t *testing.T) {
	needSevenZip(t)
	z := buildZip(t, zipFile{name: "link", data: []byte("/etc/passwd"), mode: 0o120777}, zipFile{name: "ok.txt", data: []byte("x")})
	rep, err := Analyze(context.Background(), peWithOverlay(t, z), extractOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	ex := rep.Extraction
	if ex == nil || ex.Status != "extracted" {
		t.Fatalf("%+v", ex)
	}
	var skipped bool
	for _, e := range ex.Entries {
		if e.Name == "link" {
			skipped = e.Skipped != "" && e.Path == ""
		}
	}
	if !skipped {
		t.Fatalf("the link must be listed as not extracted: %+v", ex.Entries)
	}
	if _, err := os.Lstat(filepath.Join(ex.Dir, "link")); err == nil {
		t.Fatal("a link was created")
	}
}

func TestCollectRejectsLinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o755)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "l")); err != nil {
		t.Skip("cannot make symlinks here")
	}
	if _, err := collectOverlay(root, 1<<20, 10); err == nil {
		t.Fatal("a symlink was accepted by the parent-side check")
	}
	_ = os.Remove(filepath.Join(root, "l"))
	es, err := collectOverlay(root, 1<<20, 10)
	if err != nil || len(es) != 1 {
		t.Fatalf("%v %v", es, err)
	}
	if st, _ := os.Stat(filepath.Join(root, "f")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode not normalised: %o", st.Mode().Perm())
	}
}

func TestOverlayLimitsAreEnforcedBeforeExtraction(t *testing.T) {
	needSevenZip(t)
	var files []zipFile
	for i := 0; i < 6; i++ {
		files = append(files, zipFile{name: "f" + string(rune('a'+i)), data: []byte("data")})
	}
	o := extractOpts(t)
	o.Config.ExtractMaxEntries = 3
	rep, err := Analyze(context.Background(), peWithOverlay(t, buildZip(t, files...)), o)
	if err != nil {
		t.Fatal(err)
	}
	if ex := rep.Extraction; ex == nil || ex.Status != "rejected" || ex.Dir != "" {
		t.Fatalf("%+v", ex)
	}
}

func TestOverlayEncryptedArchiveIsReportedNotGuessed(t *testing.T) {
	needSevenZip(t)
	zipBin, err := exec.LookPath("zip")
	if err != nil {
		t.Skip("no zip tool to make an encrypted archive")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(zipBin, "-q", "-P", "pw", "enc.zip", "a.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	z, _ := os.ReadFile(filepath.Join(dir, "enc.zip"))
	rep, err := Analyze(context.Background(), peWithOverlay(t, z), extractOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	ex := rep.Extraction
	if ex == nil || ex.Status != "failed" || !strings.Contains(ex.Message, "password") {
		t.Fatalf("%+v", ex)
	}
}

func TestOverlayWithoutArchiveIsNotApplicable(t *testing.T) {
	rep, err := Analyze(context.Background(), peWithOverlay(t, bytes.Repeat([]byte("plain overlay "), 40)), extractOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if ex := rep.Extraction; ex == nil || ex.Status != "not-applicable" {
		t.Fatalf("%+v", ex)
	}
}

func TestParseListing(t *testing.T) {
	s := "7-Zip banner\n\n--\nPath = x.bin\nType = Rar5\nComment = \n{\nSetup=start.vbs\nSilent=1\n}\n\n----------\nPath = a\nSize = 10\nFolder = -\nEncrypted = -\n\nPath = d\nSize = 0\nFolder = +\n\nPath = b\nSize = 5\nFolder = -\nEncrypted = +\n"
	l := parseListing(s)
	if len(l.Files) != 2 || l.Total != 15 || !l.Encrypted {
		t.Fatalf("%+v", l)
	}
	if !strings.Contains(l.Comment, "Setup=start.vbs") || strings.Contains(l.Comment, "Path = a") {
		t.Fatalf("comment: %q", l.Comment)
	}
}

func TestIncompleteFilesAreReportedNotPassedOff(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "good"), []byte("12345"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "empty"), nil, 0o600)
	sk := dropIncomplete(root, []listedFile{{"good", 5}, {"empty", 100}, {"missing", 7}})
	if len(sk) != 2 {
		t.Fatalf("%+v", sk)
	}
	if _, err := os.Stat(filepath.Join(root, "empty")); err == nil {
		t.Fatal("a truncated file was left in place")
	}
	if _, err := os.Stat(filepath.Join(root, "good")); err != nil {
		t.Fatal("a complete file was removed")
	}
}

func fsModeFromUnix(m uint32) os.FileMode {
	mode := os.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o120000:
		mode |= os.ModeSymlink
	case 0o040000:
		mode |= os.ModeDir
	}
	return mode
}
