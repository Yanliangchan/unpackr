package anomalies

import (
	"os"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/formats/elf"
	"github.com/Yanliangchan/unpackr/internal/formats/macho"
	"github.com/Yanliangchan/unpackr/internal/formats/pe"
	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func run(data []byte, b *models.Binary) []models.Anomaly {
	return Detect(&analysis.Input{Data: data, Bin: b, Scan: content.ExtractStrings(data), Sink: analysis.NewSink("t")})
}

func ids(as []models.Anomaly) map[string]models.Anomaly {
	m := map[string]models.Anomaly{}
	for _, a := range as {
		m[a.ID] = a
	}
	return m
}

func parsePE(t *testing.T, d []byte) *models.Binary {
	b, err := pe.Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The catalogue must stay quiet on ordinary toolchain output. Anything above
// informational severity on a plain Go binary would be a false positive.
func TestOrdinaryBinariesRaiseNoMediumOrHighAnomalies(t *testing.T) {
	for _, tgt := range [][2]string{{"windows", "amd64"}, {"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		d, err := os.ReadFile(fixtures.GoBinary(t, tgt[0], tgt[1]))
		if err != nil {
			t.Fatal(err)
		}
		var b *models.Binary
		switch tgt[0] {
		case "windows":
			b, err = pe.Parse(d)
		case "linux":
			b, err = elf.Parse(d)
		default:
			b, err = macho.Parse(d)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range run(d, b) {
			if a.Severity == models.SeverityMedium || a.Severity == models.SeverityHigh {
				t.Errorf("%v: false positive %s (%s)", tgt, a.ID, a.Title)
			}
		}
	}
}

func TestPEWritableExecutableAndExplanations(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{TextFlags: 0xe0000020, Imports: map[string][]string{"K.dll": {"a"}}})
	got := ids(run(d, parsePE(t, d)))
	a, ok := got["pe.section.writable-executable"]
	if !ok {
		t.Fatalf("%v", got)
	}
	if a.Why == "" || a.Benign == "" || len(a.Evidence) == 0 {
		t.Fatalf("an anomaly must explain itself: %+v", a)
	}
}

func TestPEOverlayWithEmbeddedExecutable(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"K.dll": {"a"}}, Overlay: append([]byte("MZ"), make([]byte, 128)...)})
	if _, ok := ids(run(d, parsePE(t, d)))["file.overlay.embedded-file"]; !ok {
		t.Fatal("appended executable not noticed")
	}
	plain := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"K.dll": {"a"}}, Overlay: []byte("just trailing text bytes")})
	if _, ok := ids(run(plain, parsePE(t, plain)))["file.overlay.embedded-file"]; ok {
		t.Fatal("false positive on plain trailing data")
	}
}

func TestPEEntryAndImportAnomalies(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{}) // no imports at all
	b := parsePE(t, d)
	got := ids(run(d, b))
	if _, ok := got["pe.imports.none"]; !ok {
		t.Fatalf("empty import table not flagged: %v", got)
	}
	b.Entry.Section = ""
	if _, ok := ids(run(d, b))["pe.entry.outside-sections"]; !ok {
		t.Fatal("entry outside sections not flagged")
	}
}

func TestPETimestamps(t *testing.T) {
	future := fixtures.BuildPE(fixtures.PESpec{Timestamp: 4_000_000_000, Imports: map[string][]string{"K.dll": {"a"}}})
	if _, ok := ids(run(future, parsePE(t, future)))["pe.header.timestamp-future"]; !ok {
		t.Fatal("future timestamp not flagged")
	}
	zero := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"K.dll": {"a"}}})
	a, ok := ids(run(zero, parsePE(t, zero)))["pe.header.timestamp-zero"]
	if !ok || a.Severity != models.SeverityInfo {
		t.Fatalf("zero timestamp should be informational: %+v", a)
	}
}

func TestPESectionTableInconsistencies(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"K.dll": {"a"}}, SectionNames: []string{".text", ".text"}})
	got := ids(run(d, parsePE(t, d)))
	if _, ok := got["pe.section.duplicate-name"]; !ok {
		t.Fatalf("%v", got)
	}
	// Truncation: cut the file inside the last section.
	cut := d[:len(d)-300]
	b, err := pe.Parse(cut)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids(run(cut, b))["pe.section.beyond-end-of-file"]; !ok {
		t.Fatal("truncated section not flagged")
	}
}

func TestELFAnomalies(t *testing.T) {
	d, err := os.ReadFile(fixtures.GoBinary(t, "linux", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := elf.Parse(d)
	for i := range b.Segments {
		if len(b.Segments[i].Name) >= 4 && b.Segments[i].Name[:4] == "LOAD" {
			b.Segments[i].Perms = "rwx"
			break
		}
	}
	b.Attributes["interpreter"] = "/tmp/.hidden/ld.so"
	got := ids(run(d, b))
	for _, id := range []string{"elf.segment.writable-executable", "elf.interpreter.unusual"} {
		if _, ok := got[id]; !ok {
			t.Errorf("%s missing: %v", id, got)
		}
	}
	b.Attributes["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
	if _, ok := ids(run(d, b))["elf.interpreter.unusual"]; ok {
		t.Error("the standard loader path was flagged")
	}
	for _, p := range []string{"/lib/ld-musl-x86_64.so.1", "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", "/usr/lib/ld-linux.so.2"} {
		b.Attributes["interpreter"] = p
		if _, ok := ids(run(d, b))["elf.interpreter.unusual"]; ok {
			t.Errorf("%s flagged", p)
		}
	}
}

func TestMachOTextWritable(t *testing.T) {
	d, err := os.ReadFile(fixtures.GoBinary(t, "darwin", "arm64"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := macho.Parse(d)
	for i := range b.Segments {
		if b.Segments[i].Name == "__TEXT" {
			b.Segments[i].Perms = "rwx"
		}
	}
	got := ids(run(d, b))
	if _, ok := got["macho.text-writable"]; !ok {
		t.Fatalf("%v", got)
	}
}

func TestNilBinary(t *testing.T) {
	if got := run([]byte("x"), nil); len(got) != 0 {
		t.Fatal(got)
	}
}
