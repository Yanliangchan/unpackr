package packing

import (
	"testing"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func dotnetInput(dn *models.DotNet) *analysis.Input {
	b := &models.Binary{Format: "PE32", Attributes: map[string]string{"has_clr_header": "true"}, DotNet: dn}
	return &analysis.Input{Family: "pe", Bin: b, Sink: analysis.NewSink("test"), Entropy: &models.EntropyInfo{}}
}

func ids(a models.PackingAssessment) map[string]bool {
	m := map[string]bool{}
	for _, s := range a.Signals {
		m[s.ID] = true
	}
	return m
}

func TestOrdinaryManagedAssemblyIsLeftAlone(t *testing.T) {
	a := Assess(dotnetInput(&models.DotNet{
		Counts: map[string]int{"MethodDef": 400, "TypeDef": 60},
		Names:  models.DotNetNames{Total: 900, Tiny: 12},
		Resources: []models.DotNetResource{
			{Name: "app.resources", Size: 200 * 1024, Entropy: 5.1},
		},
		EntryPoint: 0x06000001,
	}))
	if a.State != models.PackUnpacked || len(a.Signals) != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestReferenceAssemblyWithoutBodiesIsNotFlagged(t *testing.T) {
	// Reference assemblies carry metadata only, so every method lacks IL, but
	// they have no entry point.
	a := Assess(dotnetInput(&models.DotNet{Counts: map[string]int{"MethodDef": 5000}, MethodsWithoutBody: 5000, Names: models.DotNetNames{Total: 6000}}))
	if ids(a)["pack.dotnet.missing-bodies"] {
		t.Fatalf("reference assembly flagged: %+v", a)
	}
}

func TestUnreadableNamesAreOneModerateSignalNotAVerdict(t *testing.T) {
	a := Assess(dotnetInput(&models.DotNet{Counts: map[string]int{"MethodDef": 400}, Names: models.DotNetNames{Total: 600, NonPrintable: 540, NonASCII: 540}}))
	if !ids(a)["pack.dotnet.unreadable-names"] {
		t.Fatalf("not noticed: %+v", a)
	}
	if a.State == models.PackConfirmed || a.State == models.PackLikely {
		t.Fatalf("one signal must not make a packed verdict: %s", a.State)
	}
}

func TestRenamedAndBodilessEntryPointIsLikelyProtected(t *testing.T) {
	a := Assess(dotnetInput(&models.DotNet{
		Counts: map[string]int{"MethodDef": 300}, MethodsWithoutBody: 250, EntryPoint: 0x06000002,
		Names: models.DotNetNames{Total: 700, NonPrintable: 600},
	}))
	if a.State != models.PackLikely {
		t.Fatalf("%s: %+v", a.State, a.Signals)
	}
	if a.Family != "" {
		t.Fatalf("no tool can be named from structure alone: %q", a.Family)
	}
}

func TestEmbeddedExecutableResource(t *testing.T) {
	a := Assess(dotnetInput(&models.DotNet{Counts: map[string]int{}, Resources: []models.DotNetResource{{Name: "stage2", Size: 90000, Kind: "pe", Entropy: 6.1, Offset: 4096}}}))
	if !ids(a)["pack.dotnet.embedded-executable"] {
		t.Fatalf("%+v", a)
	}
	small := Assess(dotnetInput(&models.DotNet{Counts: map[string]int{}, Resources: []models.DotNetResource{{Name: "tiny", Size: 2000, Kind: "pe"}}}))
	if ids(small)["pack.dotnet.embedded-executable"] {
		t.Fatal("a 2 KB resource should not trigger this")
	}
}

func TestHighEntropyResourceAloneStaysUnknown(t *testing.T) {
	a := Assess(dotnetInput(&models.DotNet{Counts: map[string]int{}, Resources: []models.DotNetResource{{Name: "blob", Size: 300000, Entropy: 7.99}}}))
	if !ids(a)["pack.dotnet.high-entropy-resource"] || a.State != models.PackUnknown {
		t.Fatalf("%s %+v", a.State, a.Signals)
	}
}
