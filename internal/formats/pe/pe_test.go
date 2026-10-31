package pe

import (
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func TestSyntheticPE(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		DLL: true,
		Imports: map[string][]string{
			"KERNEL32.dll": {"CreateFileW", "VirtualAlloc"},
			"WS2_32.dll":   {"connect"},
		},
		Exports:   []string{"Alpha", "Beta"},
		Overlay:   []byte("APPENDED-DATA"),
		Timestamp: 1700000000,
	})
	b, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != "PE32+" || b.Bits != 64 || b.Kind != "library" {
		t.Fatalf("%+v", b)
	}
	if !strings.Contains(strings.ToLower(b.Arch), "amd64") && !strings.Contains(strings.ToLower(b.Arch), "x86") && !strings.Contains(b.Arch, "64") {
		t.Fatalf("arch %q", b.Arch)
	}
	if b.CompiledAt != "2023-11-14T22:13:20Z" {
		t.Fatalf("timestamp %q", b.CompiledAt)
	}
	if len(b.Sections) != 3 || b.Sections[0].Name != ".text" || b.Sections[0].Perms != "r-x" {
		t.Fatalf("sections %+v", b.Sections)
	}
	if b.Entry == nil || b.Entry.RVA != 0x1000 || b.Entry.Section != ".text" || b.Entry.FileOffset == nil || *b.Entry.FileOffset != 0x200 || b.Entry.VA != 0x140001000 {
		t.Fatalf("entry %+v", b.Entry)
	}
	got := map[string][]string{}
	for _, im := range b.Imports {
		for _, f := range im.Functions {
			got[im.Library] = append(got[im.Library], f.Name)
		}
	}
	if strings.Join(got["KERNEL32.dll"], ",") != "CreateFileW,VirtualAlloc" || strings.Join(got["WS2_32.dll"], ",") != "connect" {
		t.Fatalf("imports %+v", got)
	}
	if len(b.Exports) != 2 || b.Exports[0].Name != "Alpha" || b.Exports[1].Name != "Beta" {
		t.Fatalf("exports %+v", b.Exports)
	}
	if b.Overlay == nil || b.Overlay.Size != int64(len("APPENDED-DATA")) || b.Overlay.Offset != int64(len(data)-len("APPENDED-DATA")) {
		t.Fatalf("overlay %+v", b.Overlay)
	}
	if b.ImportHash == "" {
		t.Fatal("imphash missing")
	}
}

func TestWritableExecutableSectionIsReportedAsPermissions(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{TextFlags: 0xe0000020})
	b, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if b.Sections[0].Perms != "rwx" {
		t.Fatalf("got %q", b.Sections[0].Perms)
	}
}

func TestNotPE(t *testing.T) {
	for _, d := range [][]byte{nil, []byte("MZ"), make([]byte, 4096), []byte(strings.Repeat("MZ", 500))} {
		if _, err := Parse(d); err == nil {
			t.Fatalf("accepted %d garbage bytes", len(d))
		}
	}
}

// Every truncation and every single-byte corruption of a valid file must be
// handled without panic or hang.
func TestMutationsNeverPanic(t *testing.T) {
	data := fixtures.BuildPE(fixtures.PESpec{
		Imports: map[string][]string{"A.dll": {"x", "y"}}, Exports: []string{"e"}, Overlay: []byte("zz"),
	})
	for n := 0; n < len(data); n += 7 {
		_, _ = Parse(data[:n])
	}
	for i := 0; i < 0x400; i++ {
		for _, v := range []byte{0x00, 0xff, 0x80} {
			m := append([]byte(nil), data...)
			m[i] = v
			_, _ = Parse(m)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"A.dll": {"x"}}, Exports: []string{"e"}}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}
