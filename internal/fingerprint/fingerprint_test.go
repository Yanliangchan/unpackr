package fingerprint

import (
	"os"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/formats/elf"
	"github.com/Yanliangchan/unpackr/internal/formats/macho"
	"github.com/Yanliangchan/unpackr/internal/formats/pe"
	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func input(data []byte, b *models.Binary) *analysis.Input {
	return &analysis.Input{Data: data, Bin: b, Scan: content.ExtractStrings(data), Sink: analysis.NewSink("t")}
}

func names(hs []models.Hypothesis) string {
	var n []string
	for _, h := range hs {
		n = append(n, h.Name+":"+string(h.Confidence))
	}
	return strings.Join(n, "|")
}

func TestGoDetectedOnAllPlatforms(t *testing.T) {
	for _, tgt := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		data, err := os.ReadFile(fixtures.GoBinary(t, tgt[0], tgt[1]))
		if err != nil {
			t.Fatal(err)
		}
		var b *models.Binary
		switch tgt[0] {
		case "linux":
			b, err = elf.Parse(data)
		case "windows":
			b, err = pe.Parse(data)
		default:
			b, err = macho.Parse(data)
		}
		if err != nil {
			t.Fatal(err)
		}
		fp := Detect(input(data, b))
		if len(fp.Languages) == 0 || fp.Languages[0].Name != "Go" || fp.Languages[0].Confidence != models.ConfidenceHigh {
			t.Fatalf("%v: languages %s", tgt, names(fp.Languages))
		}
		if len(fp.Compilers) == 0 || !strings.Contains(fp.Compilers[0].Detail, "go1.") {
			t.Fatalf("%v: compilers %s", tgt, names(fp.Compilers))
		}
	}
}

func TestMSVCCppVersusC(t *testing.T) {
	cpp := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{
		"VCRUNTIME140.dll": {"memset"}, "MSVCP140.dll": {"_Xlength_error"}, "KERNEL32.dll": {"ExitProcess"}}})
	b, _ := pe.Parse(cpp)
	fp := Detect(input(cpp, b))
	if len(fp.Compilers) == 0 || fp.Compilers[0].Name != "Microsoft Visual C/C++" {
		t.Fatalf("compilers %s", names(fp.Compilers))
	}
	if fp.Languages[0].Name != "C++" {
		t.Fatalf("languages %s", names(fp.Languages))
	}

	c := fixtures.BuildPE(fixtures.PESpec{Imports: map[string][]string{"VCRUNTIME140.dll": {"memset"}, "KERNEL32.dll": {"ExitProcess"}}})
	b, _ = pe.Parse(c)
	fp = Detect(input(c, b))
	var haveC, haveCpp bool
	for _, l := range fp.Languages {
		haveC = haveC || l.Name == "C"
		haveCpp = haveCpp || l.Name == "C++"
	}
	if !haveC || !haveCpp {
		t.Fatalf("C and C++ must both stay listed as alternatives: %s", names(fp.Languages))
	}
	for _, l := range fp.Languages {
		if l.Confidence == models.ConfidenceHigh || l.Confidence == models.ConfidenceMedium {
			t.Fatalf("C/C++ cannot be reliably told apart; got %s", names(fp.Languages))
		}
	}
	if !strings.Contains(fp.Languages[0].Detail, "not reliably distinguishable") {
		t.Fatalf("the limitation must be stated: %+v", fp.Languages[0])
	}
}

func TestRustFromPanicPath(t *testing.T) {
	d := append(make([]byte, 64), []byte("/rustc/90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf/library/core/src/panicking.rs\x00rust_begin_unwind")...)
	fp := Detect(input(d, &models.Binary{Format: "ELF64", Attributes: map[string]string{}}))
	if len(fp.Languages) == 0 || fp.Languages[0].Name != "Rust" || fp.Languages[0].Confidence != models.ConfidenceHigh {
		t.Fatalf("%s", names(fp.Languages))
	}
	if strings.Contains(fp.Compilers[0].Detail, "1.") && !strings.Contains(fp.Compilers[0].Detail, "hash alone") {
		t.Fatalf("must not invent a version from a commit hash: %q", fp.Compilers[0].Detail)
	}
}

func TestDotNetNeedsCLRHeader(t *testing.T) {
	b := &models.Binary{Format: "PE32", Attributes: map[string]string{"has_clr_header": "true"}, Imports: []models.Import{{Library: "mscoree.dll", Functions: []models.ImportFn{{Name: "_CorExeMain"}}}}}
	fp := Detect(input([]byte(".NETFramework,Version=v4.8"), b))
	if fp.Languages[0].Confidence != models.ConfidenceHigh || !strings.Contains(fp.Languages[0].Name, ".NET") {
		t.Fatalf("%s", names(fp.Languages))
	}
	if !strings.Contains(fp.Runtimes[0].Detail, "v4.8") {
		t.Fatalf("%+v", fp.Runtimes)
	}
	// The same strings without the CLR header prove nothing about .NET.
	b2 := &models.Binary{Format: "PE32", Attributes: map[string]string{"has_clr_header": "false"}}
	if fp := Detect(input([]byte(".NETFramework,Version=v4.8 _CorExeMain"), b2)); len(fp.Languages) != 0 {
		t.Fatalf("strings alone must not produce a .NET verdict: %s", names(fp.Languages))
	}
}

func TestGoStringsAloneAreNotHighConfidence(t *testing.T) {
	// A text file that merely mentions Go is not a Go binary: a single weak
	// string cannot reach high confidence.
	b := &models.Binary{Format: "ELF64", Attributes: map[string]string{}}
	fp := Detect(input([]byte("notes about runtime.goexit and go1.22 here\x00runtime.goexit\x00go1.22\x00"), b))
	for _, l := range fp.Languages {
		if l.Name == "Go" && l.Confidence == models.ConfidenceHigh {
			t.Fatalf("overconfident: %+v", l)
		}
	}
}

func TestUnknownToolchainReportsNothing(t *testing.T) {
	fp := Detect(input([]byte("nothing recognisable at all"), &models.Binary{Format: "ELF64", Attributes: map[string]string{}}))
	if len(fp.Languages)+len(fp.Compilers)+len(fp.Runtimes) != 0 {
		t.Fatalf("invented a result: %+v", fp)
	}
}
