package reporting_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/reporting"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestMain(m *testing.M) {
	if worker.IsWorker() {
		worker.Serve()
	}
	os.Exit(m.Run())
}

func analyse(t *testing.T, path string, o func(*engine.Options)) *models.Report {
	t.Helper()
	opt := engine.Options{Config: config.Default(), Profile: engine.ProfileInfo, ArtifactDir: t.TempDir()}
	if o != nil {
		o(&opt)
	}
	rep, err := engine.Analyze(context.Background(), path, opt)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func richSample(t *testing.T) string {
	t.Helper()
	data := fixtures.BuildPE(fixtures.PESpec{
		TextFlags: 0xe0000020,
		Imports: map[string][]string{
			"KERNEL32.dll": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent", "GetProcAddress", "LoadLibraryA"},
			"WININET.dll":  {"InternetOpenA", "InternetConnectA", "HttpSendRequestA"},
			"GDI32.dll":    {"BitBlt", "CreateCompatibleDC", "CreateCompatibleBitmap"}, "USER32.dll": {"GetDC"},
		},
		Overlay: []byte("beacon http://203.0.113.9/gate.php?id=1 and evil.example.xyz vssadmin delete shadows /all C:\\Users\\Public\\x.exe"),
	})
	p := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var reURL = regexp.MustCompile(`https?://[^"'<> )]+`)

func render(t *testing.T, format string, r *models.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := reporting.Single(&b, format, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestHTMLReportHasEverySectionAndIsOffline(t *testing.T) {
	rep := analyse(t, richSample(t), nil)
	h := render(t, "html", rep)
	for _, id := range []string{"summary", "file", "fingerprint", "packing", "structure", "capabilities", "anomalies", "indicators", "payloads", "findings", "evidence", "recommendations", "limits"} {
		if !strings.Contains(h, `id="`+id+`"`) {
			t.Errorf("section %q missing", id)
		}
	}
	// Fully offline: no script, no external resource, strict CSP.
	for _, bad := range []string{"<script", "javascript:", "@import", "url(", "<iframe", "<link ", "<img", "<form"} {
		if strings.Contains(strings.ToLower(h), bad) {
			t.Errorf("report contains %q", bad)
		}
	}
	if !strings.Contains(h, "Content-Security-Policy") || !strings.Contains(h, "default-src 'none'") {
		t.Error("CSP missing")
	}
	// The only absolute URLs are ATT&CK reference links, never loaded resources.
	for _, u := range reURL.FindAllString(h, -1) {
		if !strings.HasPrefix(u, "https://attack.mitre.org/techniques/") {
			t.Errorf("unexpected URL in report: %s", u)
		}
	}
	// Sample-derived network indicators are defanged everywhere in the report.
	if strings.Contains(h, "203.0.113.9") || strings.Contains(h, "evil.example.xyz") {
		t.Error("a network indicator appears un-defanged")
	}
	if !strings.Contains(h, "hxxp://203[.]0[.]113[.]9/gate[.]php") {
		t.Error("defanged URL missing")
	}
	// Honesty statements are present.
	for _, want := range []string{"never executed", "nothing here is observed behaviour", "does not show that the sample uses or contacts them", "not a probability", "not a clean result"} {
		if !strings.Contains(h, want) {
			t.Errorf("report lacks the statement %q", want)
		}
	}
	for _, want := range []string{"@media print", "prefers-color-scheme", `name="viewport"`} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.ContainsRune(h, 0x1b) || strings.Contains(h, "ArtVault") {
		t.Error("terminal artwork or escape codes leaked into the report")
	}
	if render(t, "html", rep) != h {
		t.Error("rendering is not deterministic")
	}
}

func TestEveryFindingLinksToExistingEvidence(t *testing.T) {
	rep := analyse(t, richSample(t), nil)
	h := render(t, "html", rep)
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(h, -1) {
		if ids[m[1]] {
			t.Errorf("duplicate id %q", m[1])
		}
		ids[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(h, -1) {
		if !ids[m[1]] {
			t.Errorf("link to missing anchor %q", m[1])
		}
	}
}

func TestMarkdownReport(t *testing.T) {
	rep := analyse(t, richSample(t), nil)
	md := render(t, "markdown", rep)
	for _, want := range []string{"# UNPACKR report", "## Executive summary", "## Capabilities (inferred)", "## Indicators", "## Findings", "## Evidence", "## Limits of this report", "hxxp://203[.]0[.]113[.]9", "never executed"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if strings.Contains(md, "203.0.113.9") || strings.ContainsRune(md, 0x1b) {
		t.Error("un-defanged indicator or escape code in markdown")
	}
	// Tables stay well-formed: every row of a table has the same cell count.
	var cols int
	for _, l := range strings.Split(md, "\n") {
		if !strings.HasPrefix(l, "|") {
			cols = 0
			continue
		}
		n := len(regexp.MustCompile(`(^|[^\\])\|`).FindAllString(l, -1)) - 1
		if cols == 0 {
			cols = n
		} else if n != cols {
			t.Errorf("table row has %d cells, expected %d: %.120s", n, cols, l)
		}
	}
}

func TestCSVIndicatorsAreSafeAndParseable(t *testing.T) {
	rep := analyse(t, richSample(t), nil)
	rep.Analysis.Indicators = append(rep.Analysis.Indicators,
		models.Indicator{Type: "command", Value: `=HYPERLINK("http://x","click")`, Count: 1},
		models.Indicator{Type: "command", Value: "+cmd|' /C calc'!A0", Count: 1},
		models.Indicator{Type: "command", Value: "@SUM(1)\x1b[31m", Count: 1, Note: "-2+3"},
		models.Indicator{Type: "domain", Value: "has,comma\"quote\nnewline.xyz", Count: 1})
	out := render(t, "csv", rep)
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("not parseable: %v", err)
	}
	if len(recs) < 5 || recs[0][0] != "file_sha256" {
		t.Fatalf("%v", recs[0])
	}
	for _, r := range recs[1:] {
		if len(r) != len(recs[0]) {
			t.Fatalf("ragged row %v", r)
		}
		for _, cell := range r {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("formula-injection cell not neutralised: %q", cell)
			}
			if strings.ContainsRune(cell, 0x1b) {
				t.Errorf("escape byte in CSV: %q", cell)
			}
		}
	}
}

func TestHostileContentCannotInjectIntoAnyFormat(t *testing.T) {
	hostile := "</title><script>alert(1)</script><img src=x onerror=alert(1)>\x1b[31m\u202e|\n# injected heading\n[x](javascript:alert(1))`"
	rep := analyse(t, richSample(t), nil)
	rep.File.Name = hostile
	rep.Binary.Sections[0].Name = hostile
	rep.Binary.Imports[0].Library = hostile
	rep.Binary.Anomalies = append(rep.Binary.Anomalies, hostile)
	rep.Warnings = append(rep.Warnings, models.Warning{Module: hostile, Message: hostile})
	rep.Findings[0].Title, rep.Findings[0].Summary, rep.Findings[0].Rationale = hostile, hostile, hostile
	rep.Evidence = append(rep.Evidence, models.Evidence{ID: "xx", Kind: hostile, Value: hostile, Source: models.Source{Module: hostile}})
	rep.Analysis.Indicators = append(rep.Analysis.Indicators, models.Indicator{Type: "url", Value: "http://" + hostile, Count: 1, Note: hostile})
	rep.Analysis.Strings.Shown = append(rep.Analysis.Strings.Shown, models.StringHit{Text: hostile, Section: hostile, Encoding: "ascii"})
	rep.Analysis.Capabilities[0].Name, rep.Analysis.Capabilities[0].Summary = hostile, hostile
	rep.Analysis.Fingerprint.Languages = append(rep.Analysis.Fingerprint.Languages, models.Hypothesis{Name: hostile, Detail: hostile, Rationale: hostile})

	h := render(t, "html", rep)
	for _, bad := range []string{"<script>alert", "<img src=x", "<img ", "<script"} {
		if strings.Contains(h, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	md := render(t, "markdown", rep)
	for _, bad := range []string{"\n# injected heading", "<script", "<img"} {
		if strings.Contains(md, bad) {
			t.Errorf("Markdown contains %q", bad)
		}
	}
	// A live link needs an unescaped "](": an escaped "\](" is literal text.
	if regexp.MustCompile(`(^|[^\\])\]\(javascript:`).MatchString(md) {
		t.Error("Markdown contains a live javascript: link")
	}
	for name, out := range map[string]string{"html": h, "markdown": md, "csv": render(t, "csv", rep)} {
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x202e) {
			t.Errorf("%s: escape or bidi override survived", name)
		}
	}
}

func TestNestedUnpackedLayerAndComparison(t *testing.T) {
	packed := fixtures.PackWithUPX(t, fixtures.GoBinary(t, "linux", "amd64"))
	rep := analyse(t, packed, func(o *engine.Options) { o.Unpack = true })
	if rep.Unpack == nil || rep.Unpack.Status != "unpacked" {
		t.Skipf("unpacking unavailable: %+v", rep.Unpack)
	}
	h := render(t, "html", rep)
	if !strings.Contains(h, "Unpacked layer") || !strings.Contains(h, `id="n-summary"`) || !strings.Contains(h, "Differences") {
		t.Error("unpacked layer not rendered")
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(h, -1) {
		if ids[m[1]] {
			t.Errorf("duplicate id %q between the report and its nested layer", m[1])
		}
		ids[m[1]] = true
	}
	if !strings.Contains(render(t, "markdown", rep), "Unpacked layer report") {
		t.Error("markdown lacks the unpacked layer")
	}
	if !strings.Contains(h, "Likely language: Go") && !strings.Contains(h, "Unpacked layer: Likely language") {
		t.Error("summary should carry the unpacked layer's build information")
	}
}

func TestBatchAndCompareFormats(t *testing.T) {
	a := analyse(t, richSample(t), nil)
	b := analyse(t, fixtures.GoBinary(t, "linux", "amd64"), nil)
	var buf bytes.Buffer
	for _, f := range []string{"html", "markdown", "csv"} {
		buf.Reset()
		if err := reporting.Batch(&buf, f, []*models.Report{a, b}, map[string]string{"=bad.exe": "boom"}); err != nil {
			t.Fatal(f, err)
		}
		out := buf.String()
		if !strings.Contains(out, a.File.Hashes.SHA256[:16]) && f != "csv" || !strings.Contains(out, "boom") {
			t.Errorf("%s batch lacks content", f)
		}
		if f == "csv" {
			recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
			if err != nil || len(recs) != 4 {
				t.Fatalf("csv rows %d err %v", len(recs), err)
			}
			if !strings.HasPrefix(recs[3][0], "'=") {
				t.Errorf("a file name starting with = must be neutralised: %q", recs[3][0])
			}
		}
	}
	cmp := compare(a, b)
	for _, f := range []string{"html", "markdown", "csv"} {
		buf.Reset()
		if err := reporting.Compare(&buf, f, a, b, cmp); err != nil {
			t.Fatal(f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%s comparison empty", f)
		}
	}
	buf.Reset()
	_ = reporting.Compare(&buf, "html", a, b, cmp)
	if !strings.Contains(buf.String(), "Differences") || strings.Contains(buf.String(), "<script") {
		t.Error("comparison page wrong")
	}
	if err := reporting.Single(&buf, "pdf", a); err == nil {
		t.Error("unsupported format accepted")
	}
}

func compare(a, b *models.Report) *models.Comparison {
	return comparisonDiff(a, b)
}

// Golden Markdown for a small fixed report guards the layout against
// accidental change. Refresh with: go test ./internal/reporting -update
func TestMarkdownGolden(t *testing.T) {
	r := &models.Report{
		SchemaVersion: "0.1", Profile: "info", StartedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		File:           models.FileInfo{Name: "demo.exe", Size: 1234, Hashes: models.Hashes{MD5: "m", SHA1: "s", SHA256: strings.Repeat("ab", 32)}},
		Identification: &models.Identification{Primary: "PE32+"},
		Findings: []models.Finding{{ID: "f1", Title: "Format: PE32+", Summary: "s", Class: models.ClassObservation, Severity: models.SeverityInfo,
			Confidence: models.ConfidenceHigh, Rationale: "all checks passed", EvidenceID: []string{"e1"}, Action: "Look closer."}},
		Evidence: []models.Evidence{{ID: "e1", Kind: "structure-check", Value: "PE signature", Loc: models.Location{Offset: models.Int64(128)}, Source: models.Source{Module: "identification"}}},
		NotRun:   []string{"anomaly-detection"},
		Modules:  []models.ModuleRun{{Name: "identification", Status: "ok", DurationMS: 3}},
	}
	got := render(t, "markdown", r)
	// The version and platform line varies by build; drop it.
	got = regexp.MustCompile(`(?m)^\*Static analysis\. UNPACKR [^\n]*\n`).ReplaceAllString(got, "*Static analysis. UNPACKR <version>.*\n")
	golden := filepath.Join("testdata", "demo.md")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if got != string(want) {
		t.Errorf("markdown output changed; run with -update if intended.\n--- got ---\n%s", got)
	}
}
