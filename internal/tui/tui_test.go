package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Yanliangchan/unpackr/internal/reporting"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func sample() *models.Report {
	off := int64(0x1207)
	n := int64(31)
	return &models.Report{
		File: models.FileInfo{Name: "evil\x1b[2J.exe", Size: 1234, Hashes: models.Hashes{SHA256: strings.Repeat("ab", 32)}},
		Analysis: &models.Analysis{
			Packing:    models.PackingAssessment{State: models.PackObfuscated, Confidence: models.ConfidenceHigh, Rationale: "a marker decodes"},
			Indicators: []models.Indicator{{Type: "url", Value: "http://evil.example.net/p\x1b]0;owned\x07", Count: 1, Offset: 0x1207, Encoding: "decoded:xor 0x5a"}},
			Capabilities: []models.Capability{{ID: "net.client", Name: "Network client", Severity: models.SeverityMedium, Confidence: models.ConfidenceLow,
				Summary: "sockets", EvidenceKinds: []string{"imported"}, Signals: []models.Signal{{ID: "s", Detail: "imports socket", Strength: "moderate", Evidence: []string{"x2"}}}}},
		},
		Findings: []models.Finding{
			{ID: "obfuscation.decoded", Title: "Hidden string recovered", Summary: "http://evil.example.net/payload", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Class: models.ClassObservation, Category: "obfuscation", EvidenceID: []string{"x1"}},
			{ID: "packing.state", Title: "Packing: obfuscated", Summary: "x", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Class: models.ClassInference, Category: "packing", EvidenceID: []string{"x1", "x2"}},
			{ID: "info.one", Title: "Nothing to see", Summary: "y", Severity: models.SeverityInfo, Confidence: models.ConfidenceLow, Class: models.ClassObservation, Category: "x"},
		},
		Evidence: []models.Evidence{
			{ID: "x1", Kind: "decoded-string", Value: "http://evil.example.net/payload", Loc: models.Location{Offset: &off, Length: &n}},
			{ID: "x2", Kind: "imports", Value: "socket"},
		},
	}
}

func newModel(t *testing.T) *Model {
	t.Helper()
	m := New(reporting.Sanitized(sample(), false), Options{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return m
}

func key(m *Model, s string) {
	switch s {
	case "enter":
		m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	case "esc":
		m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	case "tab":
		m.Update(tea.KeyMsg{Type: tea.KeyTab})
	case "down":
		m.Update(tea.KeyMsg{Type: tea.KeyDown})
	default:
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	}
}

func typeText(m *Model, s string) {
	for _, r := range s {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func TestNoEscapeByteReachesTheTerminal(t *testing.T) {
	m := newModel(t)
	for tabNo := 1; tabNo <= 6; tabNo++ {
		key(m, string(rune('0'+tabNo)))
		v := m.View()
		for _, r := range v {
			if r < 0x20 && r != '\n' || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("tab %d: control rune %U in view", tabNo, r)
			}
		}
	}
	key(m, "1")
	if !strings.Contains(m.View(), `\x1b`) {
		t.Fatal("escape should be shown visibly")
	}
}

func TestTabsAndCounts(t *testing.T) {
	m := newModel(t)
	v := m.View()
	for _, want := range []string{"1 Summary", "2 Findings (3)", "3 Evidence (2)", "4 Indicators (1)", "5 Capabilities (1)", "6 Structure"} {
		if !strings.Contains(v, want) {
			t.Errorf("missing %q in\n%s", want, v)
		}
	}
	key(m, "tab")
	if !strings.Contains(m.View(), "[2 Findings") {
		t.Fatal("tab did not advance")
	}
}

func TestSearchFiltersAndEscClears(t *testing.T) {
	m := newModel(t)
	key(m, "2")
	key(m, "/")
	typeText(m, "hidden")
	key(m, "enter")
	v := m.View()
	if !strings.Contains(v, "Hidden string recovered") || strings.Contains(v, "Nothing to see") {
		t.Fatalf("filter not applied:\n%s", v)
	}
	if !strings.Contains(v, "2 Findings (1/3)") {
		t.Fatalf("filtered count missing:\n%s", v)
	}
	key(m, "esc")
	if !strings.Contains(m.View(), "Nothing to see") {
		t.Fatal("esc did not clear the filter")
	}
}

func TestEvidenceNavigationBothWays(t *testing.T) {
	m := newModel(t)
	key(m, "2") // findings; first is obfuscation.decoded citing x1
	key(m, "e")
	v := m.View()
	if !strings.Contains(v, "[3 Evidence (1/2)") || !strings.Contains(v, "x1") || strings.Contains(v, "imports") {
		t.Fatalf("evidence jump wrong:\n%s", v)
	}
	if !strings.Contains(v, "Cited by findings: obfuscation.decoded, packing.state") {
		t.Fatalf("back references missing:\n%s", v)
	}
	key(m, "f")
	v = m.View()
	if !strings.Contains(v, "[2 Findings (2/3)") || strings.Contains(v, "Nothing to see") {
		t.Fatalf("finding jump wrong:\n%s", v)
	}
	key(m, "esc")
	if !strings.Contains(m.View(), "Nothing to see") {
		t.Fatal("esc did not clear the pin")
	}
}

func TestEvidenceKeyDoesNothingWithoutEvidence(t *testing.T) {
	m := newModel(t)
	key(m, "2")
	key(m, "down")
	key(m, "down") // info.one has no evidence
	key(m, "e")
	if !strings.Contains(m.View(), "[2 Findings") {
		t.Fatal("must stay on the findings tab")
	}
}

func TestSurvivesTinyWindowsAndEmptyReports(t *testing.T) {
	for _, sz := range [][2]int{{1, 1}, {10, 3}, {20, 8}, {200, 80}} {
		m := New(reporting.Sanitized(sample(), false), Options{})
		m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		for _, k := range []string{"2", "G", "3", "/", "x", "enter", "esc", "?", "?", "6"} {
			key(m, k)
			_ = m.View()
		}
	}
	empty := New(&models.Report{}, Options{})
	for _, k := range []string{"1", "2", "3", "4", "5", "6", "e", "f", "down", "G", "/", "enter"} {
		key(empty, k)
		_ = empty.View()
	}
}

func TestQuitAndHelp(t *testing.T) {
	m := newModel(t)
	key(m, "?")
	if !strings.Contains(m.View(), "Nothing was executed") {
		t.Fatal("help missing")
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if !m.Quit || cmd == nil {
		t.Fatal("q should quit")
	}
}

func TestListScrollsToKeepSelectionVisible(t *testing.T) {
	r := sample()
	for i := 0; i < 80; i++ {
		r.Findings = append(r.Findings, models.Finding{ID: "f" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Title: "bulk finding " + string(rune('A'+i%26)) + string(rune('a'+i/26)), Severity: models.SeverityLow, Confidence: models.ConfidenceLow})
	}
	m := New(r, Options{})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	key(m, "2")
	key(m, "G")
	v := m.View()
	if !strings.Contains(v, "> ") || !strings.Contains(v, "bulk finding") {
		t.Fatalf("selection not visible after G:\n%s", v)
	}
	lines := strings.Count(v, "\n")
	if lines > 24 {
		t.Fatalf("view is %d lines for a 24-line window", lines)
	}
}
