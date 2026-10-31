package pyinstaller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func extract(t *testing.T, data []byte, lim Limits) (*models.Extraction, string) {
	t.Helper()
	out := t.TempDir()
	ex, err := Extract(bytes.NewReader(data), int64(len(data)), out, lim)
	if err != nil {
		t.Fatal(err)
	}
	return ex, out
}

func entry(ex *models.Extraction, name string) *models.ExtractedEntry {
	for i := range ex.Entries {
		if ex.Entries[i].Name == name {
			return &ex.Entries[i]
		}
	}
	return nil
}

func sample() []fixtures.PYIEntry {
	return []fixtures.PYIEntry{
		{Name: "app", Type: 's', Data: []byte("CODEOBJECT-APP"), Compress: true},
		{Name: "helpers", Type: 'm', Data: []byte("CODEOBJECT-HELPERS")},
		{Name: "libz.so.1", Type: 'b', Data: append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 57)...), Compress: true},
		{Name: "data/config.json", Type: 'x', Data: []byte(`{"c2":"http://203.0.113.5"}`), Compress: true},
	}
}

func TestExtractsEverythingWithOffsetsAndHashes(t *testing.T) {
	prefix := bytes.Repeat([]byte("BOOTLOADER"), 100)
	data := append(append([]byte(nil), prefix...), fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: 311, Entries: sample()})...)
	ex, out := extract(t, data, Limits{})
	if ex.Status != "extracted" || ex.PythonVersion != "3.11" || ex.ArchiveOffset != int64(len(prefix)) {
		t.Fatalf("%+v", ex)
	}
	app := entry(ex, "app")
	if app == nil || app.Path != "app.pyc" || !app.Compressed || app.TypeName != "script" {
		t.Fatalf("%+v", app)
	}
	b, err := os.ReadFile(filepath.Join(out, "app.pyc"))
	if err != nil {
		t.Fatal(err)
	}
	// 3.11 header: magic + flags + mtime + size, then the code object.
	if !bytes.HasPrefix(b, []byte{0xa7, 0x0d, 0x0d, 0x0a}) || !bytes.HasSuffix(b, []byte("CODEOBJECT-APP")) || len(b) != 16+len("CODEOBJECT-APP") {
		t.Fatalf("pyc header wrong: %x", b[:20])
	}
	sum := sha256.Sum256(b)
	if app.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("recorded hash does not match the file")
	}
	// Offsets are absolute file offsets of the stored data.
	if app.Offset != ex.ArchiveOffset {
		t.Fatalf("first entry should start at the archive base: %d vs %d", app.Offset, ex.ArchiveOffset)
	}
	if e := entry(ex, "libz.so.1"); e == nil || e.Format != "ELF64" || e.Path != "libz.so.1" {
		t.Fatalf("%+v", e)
	}
	cfg, _ := os.ReadFile(filepath.Join(out, "data", "config.json"))
	if string(cfg) != `{"c2":"http://203.0.113.5"}` {
		t.Fatalf("nested path: %q", cfg)
	}
	st, _ := os.Stat(filepath.Join(out, "app.pyc"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestPythonVersionsAndHeaders(t *testing.T) {
	for _, tc := range []struct {
		code  int
		ver   string
		magic []byte
		hdr   int
	}{{306, "3.6", []byte{0x33, 0x0d, 0x0d, 0x0a}, 12}, {308, "3.8", []byte{0x55, 0x0d, 0x0d, 0x0a}, 16}, {310, "3.10", []byte{0x6f, 0x0d, 0x0d, 0x0a}, 16}, {313, "3.13", []byte{0xf3, 0x0d, 0x0d, 0x0a}, 16}} {
		data := fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: tc.code, Entries: []fixtures.PYIEntry{{Name: "s", Type: 's', Data: []byte("X")}}})
		ex, out := extract(t, data, Limits{})
		b, _ := os.ReadFile(filepath.Join(out, "s.pyc"))
		if ex.PythonVersion != tc.ver {
			t.Errorf("python code %d rendered as %q, want %q", tc.code, ex.PythonVersion, tc.ver)
		}
		if len(b) == 0 || !bytes.HasPrefix(b, tc.magic) || len(b) != tc.hdr+1 {
			t.Errorf("python code %d: header %x", tc.code, b)
		}
	}
	// Unknown interpreter version: no invented header.
	data := fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: 399, Entries: []fixtures.PYIEntry{{Name: "s", Type: 's', Data: []byte("X")}}})
	ex, out := extract(t, data, Limits{})
	if _, err := os.Stat(filepath.Join(out, "s.bin")); err != nil {
		t.Fatalf("unknown version should be saved as .bin: %v", err)
	}
	if len(ex.Notes) == 0 {
		t.Fatal("the missing header must be explained")
	}
}

func TestOldCookieAndTrailingBytes(t *testing.T) {
	arch := fixtures.BuildPyInstaller(fixtures.PYISpec{PyVersion: 27, OldCookie: true, Entries: sample()[:2]})
	data := append(append([]byte("MZ-ish bootloader"), arch...), []byte("signature or padding appended later")...)
	ex, _ := extract(t, data, Limits{})
	if ex.Status != "extracted" || !strings.Contains(ex.ArchiveFormat, "2.0") {
		t.Fatalf("%+v", ex)
	}
}

func TestLookalikeMagicInsideDataDoesNotConfuse(t *testing.T) {
	fake := append(append([]byte("junk"), Magic...), make([]byte, 100)...) // invalid cookie
	entries := append([]fixtures.PYIEntry{{Name: "decoy", Type: 'x', Data: fake}}, sample()[:1]...)
	data := fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: entries})
	ex, _ := extract(t, data, Limits{})
	if ex.Status != "extracted" || entry(ex, "app") == nil {
		t.Fatalf("%+v", ex)
	}
}

func TestUnsafeNamesAreSkippedNotRewritten(t *testing.T) {
	entries := []fixtures.PYIEntry{
		{Name: "../../etc/evil", Type: 'x', Data: []byte("a")},
		{Name: "/abs/path", Type: 'x', Data: []byte("b")},
		{Name: "C:\\Windows\\evil.dll", Type: 'b', Data: []byte("c")},
		{Name: "a/../../up", Type: 'x', Data: []byte("d")},
		{Name: "", Type: 'x', Data: []byte("e")},
		{Name: "ok/file.txt", Type: 'x', Data: []byte("fine")},
		{Name: "weird\x1b[2Jname\n", Type: 'x', Data: []byte("g")},
		{Name: "OK/FILE.TXT", Type: 'x', Data: []byte("collision")},
	}
	ex, out := extract(t, fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: entries}), Limits{})
	skipped := 0
	for _, e := range ex.Entries {
		if e.Skipped != "" {
			skipped++
			if e.Path != "" {
				t.Errorf("a skipped entry has a path: %+v", e)
			}
		}
		if strings.ContainsAny(e.Name, "\x1b\n") {
			t.Errorf("control bytes in a recorded name: %q", e.Name)
		}
	}
	if skipped != 5 {
		t.Fatalf("expected 5 skipped, got %d: %+v", skipped, ex.Entries)
	}
	// Nothing escaped the output directory.
	parent := filepath.Dir(out)
	for _, bad := range []string{"etc", "abs", "up", "evil"} {
		if _, err := os.Stat(filepath.Join(parent, bad)); err == nil {
			t.Fatalf("%s created outside the output directory", bad)
		}
	}
	filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error { //nolint:errcheck // test walk
		if rel, _ := filepath.Rel(out, p); strings.HasPrefix(rel, "..") {
			t.Errorf("file outside root: %s", p)
		}
		return nil
	})
	// Case-colliding names are both kept, under different file names.
	var kept int
	for _, e := range ex.Entries {
		if strings.EqualFold(e.Name, "ok/file.txt") && e.Path != "" {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("collision handling: kept %d", kept)
	}
}

func TestBombsAndLyingTablesAreRejectedPerEntry(t *testing.T) {
	big := bytes.Repeat([]byte{0}, 8<<20) // compresses to a few KiB
	entries := []fixtures.PYIEntry{
		{Name: "bomb", Type: 'x', Data: big, Compress: true},
		{Name: "lie-small", Type: 'x', Data: []byte("hello world, hello world"), Compress: true, RawLen: fixtures.Int32(5)},
		{Name: "lie-big", Type: 'x', Data: []byte("tiny"), Compress: true, RawLen: fixtures.Int32(1 << 30)},
		{Name: "oob", Type: 'x', Data: []byte("x"), Pos: fixtures.Int32(1 << 20)},
		{Name: "negative", Type: 'x', Data: []byte("x"), StoredLen: fixtures.Int32(-5)},
		{Name: "fine", Type: 'x', Data: []byte("good data")},
	}
	ex, _ := extract(t, fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: entries}), Limits{MaxRatio: 100})
	for _, n := range []string{"bomb", "lie-small", "lie-big", "oob", "negative"} {
		e := entry(ex, n)
		if e == nil || e.Skipped == "" || e.Path != "" {
			t.Errorf("%s was not rejected: %+v", n, e)
		}
	}
	if e := entry(ex, "fine"); e == nil || e.Path == "" {
		t.Fatalf("a bad entry must not stop the others: %+v", e)
	}
	if !strings.Contains(entry(ex, "bomb").Skipped, "bomb") {
		t.Fatalf("%q", entry(ex, "bomb").Skipped)
	}
}

func TestTotalAndEntryLimits(t *testing.T) {
	var es []fixtures.PYIEntry
	for i := 0; i < 10; i++ {
		es = append(es, fixtures.PYIEntry{Name: string(rune('a' + i)), Type: 'x', Data: bytes.Repeat([]byte{byte(i + 1)}, 1000)})
	}
	data := fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: es})
	ex, _ := extract(t, data, Limits{MaxTotalBytes: 3500})
	n := 0
	for _, e := range ex.Entries {
		if e.Path != "" {
			n++
		}
	}
	if n != 3 || ex.TotalBytes > 3500 {
		t.Fatalf("total limit: extracted %d, %d bytes", n, ex.TotalBytes)
	}
	ex, _ = extract(t, data, Limits{MaxEntries: 4})
	if len(ex.Entries) > 4 {
		t.Fatalf("entry limit: %d", len(ex.Entries))
	}
	ex, _ = extract(t, data, Limits{MaxEntryBytes: 500})
	for _, e := range ex.Entries {
		if e.Path != "" {
			t.Fatalf("per-entry limit not enforced: %+v", e)
		}
	}
}

func TestNotPyInstallerAndDamagedArchives(t *testing.T) {
	for _, d := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte("MEI"), 200), append([]byte("x"), Magic...)} {
		ex, _ := extract(t, d, Limits{})
		if ex.Status != "not-applicable" {
			t.Fatalf("%q: %s", d, ex.Status)
		}
	}
	good := fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: sample()})
	// Cookie intact but TOC offset pointing outside: not a valid cookie.
	bad := append([]byte(nil), good...)
	copy(bad[len(bad)-88+12:], []byte{0x7f, 0xff, 0xff, 0xff})
	if ex, _ := extract(t, bad, Limits{}); ex.Status != "not-applicable" {
		t.Fatalf("invalid cookie accepted: %s", ex.Status)
	}
	// Truncated TOC region.
	trunc := good[:len(good)-88-10]
	if ex, _ := extract(t, trunc, Limits{}); ex.Status == "extracted" {
		t.Fatal("truncated archive extracted")
	}
}

func TestMutationsNeverPanicOrHang(t *testing.T) {
	good := fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: sample()})
	for n := 0; n < len(good); n += 3 {
		_, _ = Extract(bytes.NewReader(good[:n]), int64(n), t.TempDir(), Limits{})
	}
	for i := 0; i < len(good); i++ {
		for _, v := range []byte{0x00, 0xff, 0x7f} {
			m := append([]byte(nil), good...)
			m[i] = v
			_, _ = Extract(bytes.NewReader(m), int64(len(m)), t.TempDir(), Limits{MaxTotalBytes: 1 << 20})
		}
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(fixtures.BuildPyInstaller(fixtures.PYISpec{Entries: sample()}))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir, err := os.MkdirTemp("", "pyifuzz")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(dir) //nolint:errcheck // fuzz scratch
		_, _ = Extract(bytes.NewReader(b), int64(len(b)), dir, Limits{MaxTotalBytes: 1 << 20, MaxEntryBytes: 1 << 20})
	})
}

// Ground truth: a real PyInstaller build, when PyInstaller is installed.
func TestRealPyInstallerBuild(t *testing.T) {
	p := fixtures.PyInstallerBinary(t)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	st, _ := f.Stat()
	out := t.TempDir()
	ex, err := Extract(f, st.Size(), out, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Status != "extracted" || !strings.HasPrefix(ex.PythonVersion, "3.") {
		t.Fatalf("%+v", ex)
	}
	hello := entry(ex, "hello")
	if hello == nil || hello.TypeName != "script" || hello.Path != "hello.pyc" {
		t.Fatalf("entry script not found: %+v", ex.Entries)
	}
	b, _ := os.ReadFile(filepath.Join(out, hello.Path))
	if !bytes.Contains(b, []byte("dumps")) || !bytes.Contains(b, []byte("fixture")) {
		t.Fatal("extracted script bytecode does not contain the original program's names and constants")
	}
	var libpython bool
	for _, e := range ex.Entries {
		libpython = libpython || (strings.Contains(e.Name, "python") && strings.HasPrefix(e.Format, "ELF"))
	}
	if !libpython {
		t.Error("the interpreter library was not found among the extracted entries")
	}
}
