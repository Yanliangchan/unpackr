package comparison

import (
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

func rep(name, sha string, size int64, secs []models.Section, imports []string, pack string) *models.Report {
	b := &models.Binary{Format: "PE32+", Arch: "x86-64", Kind: "executable", Sections: secs}
	im := models.Import{Library: "KERNEL32.dll"}
	for _, f := range imports {
		im.Functions = append(im.Functions, models.ImportFn{Name: f})
	}
	b.Imports = []models.Import{im}
	return &models.Report{
		File:   models.FileInfo{Name: name, Size: size, Hashes: models.Hashes{SHA256: sha}},
		Binary: b,
		Analysis: &models.Analysis{
			Entropy: models.EntropyInfo{File: 7.8},
			Packing: models.PackingAssessment{State: pack},
		},
	}
}

func TestDiffReportsEveryDimension(t *testing.T) {
	a := rep("a.exe", "aa", 100, []models.Section{{Name: ".text", RawSize: 10, Perms: "rwx"}, {Name: "UPX1"}}, []string{"LoadLibraryA"}, "confirmed-packed")
	b := rep("b.exe", "bb", 300, []models.Section{{Name: ".text", RawSize: 99, Perms: "r-x"}, {Name: ".rdata"}}, []string{"CreateFileW", "ReadFile"}, "unpacked")
	b.Analysis.Entropy.File = 6.1
	b.Analysis.Capabilities = []models.Capability{{ID: "network.client.http"}}
	b.Analysis.Indicators = []models.Indicator{{Type: "url", Value: "http://x"}}
	c := Diff(a, b)
	if c.Identical {
		t.Fatal("identical")
	}
	if len(c.Sections.OnlyA) != 1 || c.Sections.OnlyA[0] != "UPX1" || c.Sections.OnlyB[0] != ".rdata" {
		t.Fatalf("sections %+v", c.Sections)
	}
	if len(c.SectionChanges) != 1 || c.SectionChanges[0].Name != ".text" || len(c.SectionChanges[0].Changes) != 2 {
		t.Fatalf("section changes %+v", c.SectionChanges)
	}
	if len(c.Imports.OnlyA) != 1 || len(c.Imports.OnlyB) != 2 {
		t.Fatalf("imports %+v", c.Imports)
	}
	if len(c.Packing) != 1 || c.Packing[0].B != "unpacked" {
		t.Fatalf("packing %+v", c.Packing)
	}
	if len(c.Entropy) == 0 || len(c.Capabilities.OnlyB) != 1 || len(c.Indicators.OnlyB) != 1 {
		t.Fatalf("%+v", c)
	}
	var sizeChange bool
	for _, h := range c.Header {
		sizeChange = sizeChange || (h.Field == "file size" && h.B == "300")
	}
	if !sizeChange {
		t.Fatalf("header %+v", c.Header)
	}
}

func TestIdenticalFilesAndPartialData(t *testing.T) {
	a := rep("a", "same", 1, nil, nil, "unpacked")
	b := rep("b", "same", 1, nil, nil, "unpacked")
	if c := Diff(a, b); !c.Identical || len(c.Notes) == 0 {
		t.Fatalf("%+v", c)
	}
	b.Binary, b.Analysis = nil, nil
	c := Diff(a, b)
	if len(c.Notes) < 2 {
		t.Fatalf("missing data must be stated, not silently skipped: %+v", c.Notes)
	}
}

func TestListsAreBounded(t *testing.T) {
	var many []string
	for i := 0; i < MaxListed+50; i++ {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('0'+i/676)))
	}
	d := setDiff(many, nil)
	if len(d.OnlyA) != MaxListed || !d.Truncated {
		t.Fatalf("%d %v", len(d.OnlyA), d.Truncated)
	}
}
