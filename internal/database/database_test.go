package database

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func open(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "sub", "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func report(sha, name, version, pack string, indicators ...string) *models.Report {
	r := &models.Report{
		SchemaVersion: "0.1", Profile: "info", Tool: models.ToolMeta{Version: version},
		File:           models.FileInfo{Name: name, Size: 10, Hashes: models.Hashes{SHA256: sha, MD5: "m", SHA1: "s"}},
		Identification: &models.Identification{Primary: "PE32+"},
		Binary:         &models.Binary{Format: "PE32+", Arch: "x86-64", ImportHash: "imp-" + sha[:4], Sections: []models.Section{{Name: ".text", Perms: "r-x", RawSize: 16}}},
		Analysis: &models.Analysis{
			Packing:      models.PackingAssessment{State: pack},
			Fingerprint:  models.Fingerprint{Languages: []models.Hypothesis{{Name: "Go"}}},
			Capabilities: []models.Capability{{ID: "network.client.http", Attack: []string{"T1071.001"}}},
		},
		Findings: []models.Finding{{ID: "f", Severity: models.SeverityHigh}, {ID: "g", Severity: models.SeverityMedium}},
	}
	for _, v := range indicators {
		r.Analysis.Indicators = append(r.Analysis.Indicators, models.Indicator{Type: "domain", Value: v, Count: 1})
	}
	return r
}

func sha(c string) string { return strings.Repeat(c, 64) }

func TestOpenCreatesPrivateFileAndMigratesOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "db.sqlite")
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	dst, _ := os.Stat(filepath.Dir(p))
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("modes: file %o dir %o", st.Mode().Perm(), dst.Mode().Perm())
	}
	if err := d.Record(report(sha("a"), "a.exe", "1", "unpacked")); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	d2, err := Open(p) // reopening must not re-run migrations or lose data
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close() //nolint:errcheck // test
	if s, _ := d2.Stats(); s.Samples != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	d := open(t)
	if _, err := d.SQL().Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	p := d.Path()
	_ = d.Close()
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Fatalf("expected a newer-schema refusal, got %v", err)
	}
}

func TestKnownSampleAndChangesSinceLastTime(t *testing.T) {
	d := open(t)
	first := report(sha("a"), "a.exe", "1.0", "unpacked", "old.example.com")
	if err := d.Annotate(first); err != nil || first.Known != nil {
		t.Fatalf("a new file must not look known: %v %+v", err, first.Known)
	}
	if err := d.Record(first); err != nil {
		t.Fatal(err)
	}
	second := report(sha("a"), "renamed.exe", "1.1", "confirmed-packed", "new.example.com")
	if err := d.Annotate(second); err != nil {
		t.Fatal(err)
	}
	k := second.Known
	if k == nil || k.TimesSeen != 1 || k.Last == nil || k.Last.ToolVersion != "1.0" || k.Last.High != 1 || k.Last.Medium != 1 {
		t.Fatalf("%+v", k)
	}
	if k.ToolChange != "1.0 -> 1.1" {
		t.Fatalf("tool change: %q", k.ToolChange)
	}
	if k.Changes == nil || len(k.Changes.Packing) != 1 || k.Changes.Packing[0].B != "confirmed-packed" {
		t.Fatalf("packing change not reported: %+v", k.Changes)
	}
	if len(k.Changes.Indicators.OnlyA) != 1 || len(k.Changes.Indicators.OnlyB) != 1 {
		t.Fatalf("indicator change: %+v", k.Changes.Indicators)
	}
	if err := d.Record(second); err != nil {
		t.Fatal(err)
	}
	third := report(sha("a"), "renamed.exe", "1.1", "confirmed-packed", "new.example.com")
	_ = d.Annotate(third)
	if third.Known.TimesSeen != 2 || third.Known.Analyses != 2 {
		t.Fatalf("%+v", third.Known)
	}
}

func TestFeaturesAndPivots(t *testing.T) {
	d := open(t)
	for i, c := range []string{"a", "b", "c"} {
		r := report(sha(c), c+".exe", "1", "unpacked", "shared.example.com", fmt.Sprintf("own%d.example.org", i))
		if err := d.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	refs, err := d.Find("ioc", "shared.example.com")
	if err != nil || len(refs) != 3 {
		t.Fatalf("%v %v", err, refs)
	}
	if refs, _ := d.Find("ioc", "own1.example.org"); len(refs) != 1 || refs[0].SHA256 != sha("b") {
		t.Fatalf("%v", refs)
	}
	if refs, _ := d.Find("imphash", "imp-aaaa"); len(refs) != 1 {
		t.Fatalf("imphash pivot: %v", refs)
	}
	if refs, _ := d.Find("capability", "network.client.http"); len(refs) != 3 {
		t.Fatalf("capability pivot: %v", refs)
	}
	if refs, _ := d.Find("attack", "T1071.001"); len(refs) != 3 {
		t.Fatalf("attack pivot: %v", refs)
	}
	if refs, _ := d.Find("hash", sha("b")[:10]); len(refs) != 1 {
		t.Fatalf("hash prefix: %v", refs)
	}
	for _, bad := range []string{"%", "ab", "a%b%c%d%e%f%"} {
		if _, err := d.Find("hash", bad); err == nil {
			t.Errorf("wildcard or too-short prefix %q accepted", bad)
		}
	}
	// Features are replaced, not accumulated, on re-analysis.
	if err := d.Record(report(sha("a"), "a.exe", "1", "unpacked", "different.example.net")); err != nil {
		t.Fatal(err)
	}
	if refs, _ := d.Find("ioc", "own0.example.org"); len(refs) != 0 {
		t.Fatalf("stale indicator still pivots: %v", refs)
	}
}

func TestSQLInjectionIsInert(t *testing.T) {
	d := open(t)
	if err := d.Record(report(sha("a"), "a.exe", "1", "unpacked", "x.example.com")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"' OR '1'='1", "x'; DROP TABLE samples;--", `"; DELETE FROM features; --`} {
		if refs, err := d.Find("ioc", v); err != nil || len(refs) != 0 {
			t.Fatalf("%q: %v %v", v, refs, err)
		}
		if refs, _ := d.Find("yara'; DROP TABLE samples;--", v); len(refs) != 0 {
			t.Fatal("kind injection matched")
		}
	}
	if s, err := d.Stats(); err != nil || s.Samples != 1 {
		t.Fatalf("data damaged: %+v %v", s, err)
	}
	r := report(sha("b"), "x'); DROP TABLE samples;--.exe", "1", "unpacked")
	if err := d.Record(r); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.Stats(); s.Samples != 2 {
		t.Fatal("hostile file name broke recording")
	}
}

func TestOnlyTheLatestAnalysesAreKept(t *testing.T) {
	d := open(t)
	for i := 0; i < MaxStoredAnalyses+5; i++ {
		if err := d.Record(report(sha("a"), "a.exe", fmt.Sprintf("v%d", i), "unpacked")); err != nil {
			t.Fatal(err)
		}
	}
	k, err := d.Lookup(sha("a"))
	if err != nil || k.Analyses != MaxStoredAnalyses || k.TimesSeen != MaxStoredAnalyses+5 {
		t.Fatalf("%+v %v", k, err)
	}
	if k.Last.ToolVersion != fmt.Sprintf("v%d", MaxStoredAnalyses+4) {
		t.Fatalf("latest analysis not kept: %s", k.Last.ToolVersion)
	}
}

func TestDerivedFilesAreLinkedAndRecorded(t *testing.T) {
	d := open(t)
	parent := report(sha("a"), "packed.exe", "1", "confirmed-packed")
	child := report(sha("b"), "unpacked.bin", "1", "unpacked")
	parent.Artifacts = []models.Artifact{{Kind: "unpacked", Tool: "upx", ToolVersion: "4.2.2", ParentSHA256: sha("a"), Report: child}}
	if err := d.Record(parent); err != nil {
		t.Fatal(err)
	}
	k, _ := d.Lookup(sha("a"))
	if len(k.Derived) != 1 || k.Derived[0] != sha("b") {
		t.Fatalf("%+v", k)
	}
	if k2, _ := d.Lookup(sha("b")); k2 == nil {
		t.Fatal("the unpacked layer should be a sample of its own")
	}
	// A stored parent report does not duplicate the child's full report.
	if r, err := d.LoadReport(sha("a")); err != nil || len(r.Artifacts) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestForgetRemovesDerivedData(t *testing.T) {
	d := open(t)
	_ = d.Record(report(sha("a"), "a.exe", "1", "unpacked", "gone.example.com"))
	ok, err := d.Forget(sha("a"))
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	for _, q := range []string{"SELECT count(*) FROM analyses", "SELECT count(*) FROM features", "SELECT count(*) FROM samples"} {
		var n int
		if err := d.SQL().QueryRow(q).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d %v", q, n, err)
		}
	}
	if ok, _ := d.Forget(sha("a")); ok {
		t.Fatal("forgetting twice should report nothing removed")
	}
}

func TestCorruptStoredReportIsAnErrorNotAPanic(t *testing.T) {
	d := open(t)
	_ = d.Record(report(sha("a"), "a.exe", "1", "unpacked"))
	if _, err := d.SQL().Exec("UPDATE analyses SET report_gz = x'0102030405'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadReport(sha("a")); err == nil {
		t.Fatal("corrupt blob accepted")
	}
	r := report(sha("a"), "a.exe", "2", "unpacked")
	if err := d.Annotate(r); err != nil {
		t.Fatalf("a corrupt old report must not stop annotation: %v", err)
	}
	if r.Known == nil || r.Known.Changes != nil {
		t.Fatalf("%+v", r.Known)
	}
}

func TestHostsPivotAcrossDifferentURLs(t *testing.T) {
	d := open(t)
	a := report(sha("a"), "a.exe", "1", "unpacked")
	a.Analysis.Indicators = []models.Indicator{{Type: "url", Value: "http://C2.Shared.example.xyz:8080/one", Count: 1}}
	b := report(sha("b"), "b.exe", "1", "unpacked")
	b.Analysis.Indicators = []models.Indicator{{Type: "domain", Value: "c2.shared.example.xyz", Count: 1}, {Type: "url", Value: "::not a url::", Count: 1}}
	for _, r := range []*models.Report{a, b} {
		if err := d.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	refs, err := d.Find("ioc", "C2.shared.example.xyz")
	if err != nil || len(refs) != 2 {
		t.Fatalf("a URL and a bare domain naming the same host should pivot together: %v %v", refs, err)
	}
	if refs, _ := d.Find("host", "c2.shared.example.xyz"); len(refs) != 2 {
		t.Fatalf("%v", refs)
	}
}

func fuzzyReport(sha, name string, data []byte, imports []string) *models.Report {
	r := report(sha, name, "1", "unpacked")
	ssd, tl := similarity.Hash(data)
	r.Analysis.Fuzzy = models.Fuzzy{SSDeep: ssd, TLSH: tl}
	im := models.Import{Library: "K.dll"}
	for _, f := range imports {
		im.Functions = append(im.Functions, models.ImportFn{Name: f})
	}
	r.Binary.Imports = []models.Import{im}
	r.Binary.ImportHash = ""
	r.Binary.Sections = nil
	return r
}

func block(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func TestSimilarRanksCloseSamplesFirst(t *testing.T) {
	d := open(t)
	base := append(append([]byte(nil), bytes.Repeat([]byte("alpha beta gamma delta "), 6000)...), block(1, 20000)...)
	near := append([]byte(nil), base...)
	copy(near[50000:], block(2, 4000))
	far := append(bytes.Repeat([]byte("zzz yyy xxx www "), 7000), block(3, 20000)...)
	apis := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, x := range []struct {
		c    string
		data []byte
		imp  []string
	}{{"b", near, apis}, {"c", far, []string{"p", "q", "r", "s", "t", "u"}}} {
		if err := d.Record(fuzzyReport(sha(x.c), x.c+".exe", x.data, x.imp)); err != nil {
			t.Fatal(err)
		}
	}
	q := fuzzyReport(sha("a"), "query.exe", base, apis)
	hits, err := d.Similar(q, 5)
	if err != nil || len(hits) == 0 {
		t.Fatalf("%v %v", hits, err)
	}
	if hits[0].SHA256 != sha("b") {
		t.Fatalf("the edited copy should rank first: %+v", hits[0])
	}
	for _, h := range hits {
		if h.SHA256 == sha("a") {
			t.Fatal("a sample must not be reported as similar to itself")
		}
	}
	if !hits[0].Similarity.HasTLSH || hits[0].Similarity.TLSHDistance > 100 {
		t.Fatalf("%+v", hits[0].Similarity)
	}
	// A limit is honoured and an empty database finds nothing.
	if hits, _ := d.Similar(q, 1); len(hits) != 1 {
		t.Fatalf("limit ignored: %d", len(hits))
	}
	if hits, err := open(t).Similar(q, 5); err != nil || len(hits) != 0 {
		t.Fatalf("%v %v", hits, err)
	}
}

func TestSimilarSurvivesGarbageInTheStore(t *testing.T) {
	d := open(t)
	_ = d.Record(fuzzyReport(sha("b"), "b.exe", block(5, 5000), []string{"a"}))
	if _, err := d.SQL().Exec("UPDATE features SET value = 'T1zzzz' WHERE kind = 'tlsh'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().Exec("INSERT INTO features(sha256, kind, value) VALUES (?, 'ssdeep', ?)", sha("b"), "garbage:::"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Similar(fuzzyReport(sha("a"), "a.exe", block(6, 5000), nil), 5); err != nil {
		t.Fatalf("malformed stored hashes must be ignored, not fatal: %v", err)
	}
}
