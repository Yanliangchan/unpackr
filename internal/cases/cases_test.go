package cases

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/database"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func db(t *testing.T) *database.DB {
	t.Helper()
	d, err := database.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func rep(c, name string, inds ...string) *models.Report {
	sha := strings.Repeat(c, 64)
	r := &models.Report{Tool: models.ToolMeta{Version: "1"}, Profile: "info",
		File:           models.FileInfo{Name: name, Hashes: models.Hashes{SHA256: sha, MD5: "m", SHA1: "s"}},
		Identification: &models.Identification{Primary: "PE32+"},
		Analysis:       &models.Analysis{Packing: models.PackingAssessment{State: "unpacked"}}}
	for _, v := range inds {
		r.Analysis.Indicators = append(r.Analysis.Indicators, models.Indicator{Type: "domain", Value: v, Count: 1})
	}
	return r
}

func TestCaseLifecycleAndSharedIndicators(t *testing.T) {
	d := db(t)
	_ = d.Record(rep("a", "a.exe", "c2.example.com", "only-a.example.com"))
	_ = d.Record(rep("b", "b.exe", "c2.example.com"))
	if err := New(d, "op-night", "first look"); err != nil {
		t.Fatal(err)
	}
	if err := New(d, "op-night", ""); err == nil {
		t.Fatal("duplicate case accepted")
	}
	for _, bad := range []string{"", "-x", "has space", "a/b", "../x", strings.Repeat("x", 65), "x;DROP"} {
		if err := New(d, bad, ""); err == nil {
			t.Errorf("case name %q accepted", bad)
		}
	}
	a, _ := ResolveSample(d, strings.Repeat("a", 10))
	b, _ := ResolveSample(d, strings.Repeat("b", 10))
	if err := AddSample(d, "op-night", a); err != nil {
		t.Fatal(err)
	}
	if err := AddSample(d, "op-night", a); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := AddSample(d, "op-night", b); err != nil {
		t.Fatal(err)
	}
	if err := AddNote(d, "op-night", a, "Beacons to the shared domain."); err != nil {
		t.Fatal(err)
	}
	r, err := BuildReport(d, "op-night")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Samples) != 2 || r.Description != "first look" {
		t.Fatalf("%+v", r)
	}
	var shared *models.CaseIndicator
	for i := range r.Indicators {
		if r.Indicators[i].Value == "c2.example.com" {
			shared = &r.Indicators[i]
		}
	}
	if shared == nil || len(shared.Samples) != 2 {
		t.Fatalf("shared indicator not found across samples: %+v", r.Indicators)
	}
	// The timeline records what happened, once for each sample addition.
	adds := 0
	for _, e := range r.Timeline {
		if e.Kind == "sample-added" {
			adds++
		}
	}
	if adds != 2 || r.Timeline[0].Kind != "case-created" {
		t.Fatalf("%+v", r.Timeline)
	}
	// Re-analysing a sample that belongs to a case lands on that case's timeline.
	_ = d.Record(rep("a", "a.exe", "c2.example.com"))
	r, _ = BuildReport(d, "op-night")
	var re bool
	for _, e := range r.Timeline {
		re = re || (e.Kind == "analysed" && e.SHA256 == a)
	}
	if !re {
		t.Fatalf("%+v", r.Timeline)
	}
}

func TestSampleResolutionAndErrors(t *testing.T) {
	d := db(t)
	_ = d.Record(rep("a", "a.exe"))
	_ = d.Record(rep("b", "b.exe"))
	if _, err := ResolveSample(d, "cccccc"); !errors.Is(err, ErrNoSample) {
		t.Fatalf("%v", err)
	}
	if _, err := ResolveSample(d, "abc"); err == nil {
		t.Fatal("short prefix accepted")
	}
	if _, err := ResolveSample(d, "zzzzzzzz"); err == nil {
		t.Fatal("non-hex accepted")
	}
	// Both samples share no prefix, so ambiguity needs a shared one.
	sha := strings.Repeat("a", 32) + strings.Repeat("c", 32)
	r := rep("a", "twin.exe")
	r.File.Hashes.SHA256 = sha
	_ = d.Record(r)
	if _, err := ResolveSample(d, strings.Repeat("a", 10)); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("ambiguous prefix must be refused: %v", err)
	}
	if err := AddSample(d, "nope", strings.Repeat("a", 64)); !errors.Is(err, ErrNoCase) {
		t.Fatalf("%v", err)
	}
	if err := AddNote(d, "nope", "", "x"); !errors.Is(err, ErrNoCase) {
		t.Fatalf("%v", err)
	}
}

func TestNotesSearchIsSafeAndLimited(t *testing.T) {
	d := db(t)
	_ = New(d, "c1", "")
	_ = AddNote(d, "c1", "", "The dropper writes a Run key for persistence")
	_ = AddNote(d, "c1", "", "unrelated remark")
	hits, err := Search(d, "run key")
	if err != nil || len(hits) != 1 || hits[0].Case != "c1" {
		t.Fatalf("%v %v", hits, err)
	}
	// FTS operators and quotes typed by the user are data, not syntax.
	for _, q := range []string{`"`, `run OR key`, `NEAR(run key)`, `run*`, `a" AND "b`, `'; DROP TABLE notes;--`, `col:run`} {
		if _, err := Search(d, q); err != nil {
			t.Errorf("query %q broke search: %v", q, err)
		}
	}
	if _, err := Search(d, "  "); err == nil {
		t.Fatal("empty search accepted")
	}
	if err := AddNote(d, "c1", "", strings.Repeat("x", MaxNoteBytes+1)); err == nil {
		t.Fatal("oversize note accepted")
	}
	if err := AddNote(d, "c1", "", "   "); err == nil {
		t.Fatal("blank note accepted")
	}
}

func TestStatusAndList(t *testing.T) {
	d := db(t)
	_ = New(d, "one", "d1")
	_ = New(d, "two", "d2")
	if err := SetStatus(d, "one", "closed"); err != nil {
		t.Fatal(err)
	}
	if err := SetStatus(d, "one", "weird"); err == nil {
		t.Fatal("bad status accepted")
	}
	cs, err := List(d)
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %v", cs, err)
	}
	for _, c := range cs {
		if c.Name == "one" && c.Status != "closed" {
			t.Fatalf("%+v", c)
		}
	}
	r, _ := BuildReport(d, "one")
	if r.Timeline[len(r.Timeline)-1].Kind != "case-closed" {
		t.Fatalf("%+v", r.Timeline)
	}
}
