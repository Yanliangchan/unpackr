package packing

import (
	"testing"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/formats/pe"
	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

// assess parses a synthetic PE and runs the full packing logic over it, with
// optional entropy values injected per section name.
func assess(t *testing.T, data []byte, entropy map[string]float64) models.PackingAssessment {
	t.Helper()
	b, err := pe.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ent := &models.EntropyInfo{File: 5}
	for _, s := range b.Sections {
		e := 5.0
		if v, ok := entropy[s.Name]; ok {
			e = v
		}
		ent.Sections = append(ent.Sections, models.SectionEntropy{Name: s.Name, Entropy: e, Offset: s.RawOffset, Size: 4096, Perms: s.Perms})
	}
	in := &analysis.Input{Data: data, Family: "pe", Bin: b, Scan: content.ExtractStrings(data), Entropy: ent, Sink: analysis.NewSink("test")}
	return Assess(in)
}

func normalImports() map[string][]string {
	return map[string][]string{
		"KERNEL32.dll": {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "HeapAlloc"},
		"USER32.dll":   {"MessageBoxW", "GetMessageW", "DispatchMessageW", "CreateWindowExW"},
	}
}

func TestCleanBinaryIsUnpacked(t *testing.T) {
	r := assess(t, fixtures.BuildPE(fixtures.PESpec{Imports: normalImports()}), nil)
	if r.State != models.PackUnpacked {
		t.Fatalf("%+v", r)
	}
	if r.Confidence == models.ConfidenceHigh {
		t.Fatal("absence of indicators must never be high confidence")
	}
}

// The central rule: entropy by itself never produces a packed verdict.
func TestEntropyAloneNeverMeansPacked(t *testing.T) {
	r := assess(t, fixtures.BuildPE(fixtures.PESpec{Imports: normalImports()}), map[string]float64{".text": 7.95})
	if r.State == models.PackLikely || r.State == models.PackConfirmed {
		t.Fatalf("entropy alone produced %s", r.State)
	}
	if r.State != models.PackUnknown {
		t.Fatalf("expected unknown (indicator present but insufficient), got %s", r.State)
	}
}

func TestSingleStructuralOddityIsNotAVerdict(t *testing.T) {
	r := assess(t, fixtures.BuildPE(fixtures.PESpec{Imports: normalImports(), TextFlags: 0xe0000020}), nil) // rwx .text
	if r.State == models.PackLikely || r.State == models.PackConfirmed {
		t.Fatalf("%s from an rwx section alone", r.State)
	}
}

func TestSparseImportsPlusEntropyIsLikelyPacked(t *testing.T) {
	r := assess(t, fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"KERNEL32.dll": {"LoadLibraryA", "GetProcAddress", "ExitProcess"}}}), map[string]float64{".text": 7.9})
	if r.State != models.PackLikely {
		t.Fatalf("%+v", r)
	}
}

func TestUPXMagicWithSectionsIsConfirmed(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{Imports: normalImports(), SectionNames: []string{"UPX0", "UPX1", "UPX2"}, Overlay: []byte("UPX!\x0d\x16\x08\x01")})
	r := assess(t, d, nil)
	if r.State != models.PackConfirmed || r.Family != "UPX" {
		t.Fatalf("%+v", r)
	}
}

func TestSectionNamesAloneAreOnlyLikelyOrLess(t *testing.T) {
	d := fixtures.BuildPE(fixtures.PESpec{Imports: normalImports(), SectionNames: []string{".vmp0", ".vmp1", ".data"}})
	r := assess(t, d, nil)
	if r.State == models.PackConfirmed {
		t.Fatalf("names are renamable and cannot confirm: %+v", r)
	}
}

func TestMagicWithoutCorroborationIsOnlyLikely(t *testing.T) {
	r := assess(t, fixtures.BuildPE(fixtures.PESpec{Imports: normalImports(), Overlay: []byte("....UPX!....")}), nil)
	if r.State != models.PackLikely {
		t.Fatalf("%+v", r)
	}
}

func TestNoStructureMeansUnknown(t *testing.T) {
	in := &analysis.Input{Data: []byte("x"), Sink: analysis.NewSink("t")}
	if r := Assess(in); r.State != models.PackUnknown {
		t.Fatalf("%+v", r)
	}
}
