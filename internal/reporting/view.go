// Package reporting renders analysis reports as self-contained HTML, Markdown
// and CSV. It depends only on the data model and text helpers: terminal
// artwork, colour codes and progress output can never reach a report.
//
// Every string that came from a sample (names, strings, indicators, tool
// output) is sanitised before it is written, and HTML is produced by
// html/template so context-aware escaping applies as well.
package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// clean makes sample-derived text safe for any output format.
func clean(s string) string { return safeText(s) }

// Defang renders network indicators so they cannot be clicked or resolved by
// accident: hxxp://, [.] and [@].
func Defang(typ, v string) string {
	switch typ {
	case "url":
		v = strings.Replace(v, "http", "hxxp", 1)
		v = strings.Replace(v, "ftp://", "fxp://", 1)
		return defangDots(v)
	case "domain", "ipv4":
		return defangDots(v)
	case "email":
		return strings.NewReplacer("@", "[@]", ".", "[.]").Replace(v)
	}
	return v
}

func defangDots(s string) string { return strings.ReplaceAll(s, ".", "[.]") }

// Summary builds the executive summary. Every sentence is derived from the
// report; nothing is added that the analysis did not establish.
func Summary(r *models.Report) []string {
	var out []string
	out = append(out, fmt.Sprintf("File %s: %d bytes, SHA-256 %s.", clean(r.File.Name), r.File.Size, r.File.Hashes.SHA256))
	if r.Identification != nil {
		format := r.Identification.Primary
		if r.Binary != nil && r.Binary.Arch != "" {
			format += ", " + clean(r.Binary.Arch)
			if r.Binary.Kind != "" {
				format += " " + clean(r.Binary.Kind)
			}
		}
		line := "Identified as " + clean(format) + " from its content, not its name."
		if r.Identification.Polyglot {
			line += " It also satisfies the structure of another format, so appended or hidden content is possible."
		}
		out = append(out, line)
	}
	if a := r.Analysis; a != nil {
		out = append(out, buildSentence(a))
		out = append(out, packingSentence(r))
		if n := len(a.Capabilities); n > 0 {
			var top []string
			for i, c := range a.Capabilities {
				if i >= 5 {
					break
				}
				top = append(top, fmt.Sprintf("%s (%s confidence)", clean(c.Name), c.Confidence))
			}
			out = append(out, fmt.Sprintf("%d capabilit%s inferred from what the file references, for example: %s. These describe what the file could ask for, not behaviour that was observed.", n, plural(n, "y", "ies"), strings.Join(top, "; ")))
		} else {
			out = append(out, "No capabilities were inferred from the file's references.")
		}
		if n := len(a.Indicators); n > 0 {
			out = append(out, fmt.Sprintf("%d indicator-shaped strings were found (URLs, addresses, paths, registry keys, command lines). Their presence does not show that the file uses or contacts them.", n))
		}
		med := 0
		for _, an := range a.Anomalies {
			if an.Severity == models.SeverityMedium || an.Severity == models.SeverityHigh {
				med++
			}
		}
		out = append(out, fmt.Sprintf("%d structural anomal%s noted, %d of medium or high severity.", len(a.Anomalies), plural(len(a.Anomalies), "y", "ies"), med))
	}
	for _, art := range r.Artifacts {
		out = append(out, fmt.Sprintf("The file was unpacked with %s %s and the unpacked layer (SHA-256 %s) was analysed separately.", clean(art.Tool), clean(art.ToolVersion), art.Hashes.SHA256))
		if art.Report != nil && art.Report.Analysis != nil {
			out = append(out, "Unpacked layer: "+buildSentence(art.Report.Analysis)+" "+packingSentence(art.Report))
		}
	}
	if r.Extraction != nil && r.Extraction.Status == "extracted" {
		out = append(out, clean(r.Extraction.Message)+".")
	}
	if k := r.Known; k != nil {
		line := fmt.Sprintf("This file was seen before: first on %s, analysed %d time(s) previously, last on %s.", clean(k.FirstSeen), k.TimesSeen, clean(k.LastSeen))
		if len(k.Cases) > 0 {
			line += " It belongs to case(s): " + clean(strings.Join(k.Cases, ", ")) + "."
		}
		if k.ToolChange != "" {
			line += " The analysis tool changed (" + clean(k.ToolChange) + "), so differences may come from the analysis rather than the file."
		}
		out = append(out, line)
	}
	out = append(out, "This is a static analysis: the sample was never executed. Confidence labels describe how well the evidence supports a statement, and are not probabilities.")
	if len(r.NotRun) > 0 {
		out = append(out, fmt.Sprintf("%d analysis stage(s) are not available in this build, so their absence is not a clean result: %s.", len(r.NotRun), clean(strings.Join(shortNames(r.NotRun), "; "))))
	}
	return out
}

func buildSentence(a *models.Analysis) string {
	pick := func(hs []models.Hypothesis) string {
		if len(hs) == 0 {
			return ""
		}
		return fmt.Sprintf("%s (%s confidence)", clean(hs[0].Name), hs[0].Confidence)
	}
	l, c := pick(a.Fingerprint.Languages), pick(a.Fingerprint.Compilers)
	switch {
	case l == "" && c == "":
		return "The build toolchain could not be identified from the available evidence."
	case l != "" && c != "":
		return fmt.Sprintf("Likely language: %s. Likely compiler or toolchain: %s.", l, c)
	case l != "":
		return "Likely language: " + l + "."
	}
	return "Likely compiler or toolchain: " + c + "."
}

func packingSentence(r *models.Report) string {
	p := r.Analysis.Packing
	s := "Packing assessment: " + p.State
	if p.Family != "" {
		s += " (" + clean(p.Family) + ")"
	}
	s += fmt.Sprintf(", %s confidence.", p.Confidence)
	switch p.State {
	case models.PackConfirmed, models.PackLikely:
		s += " Imports, strings and capabilities of the packed file describe the packer stub and may not reflect the packed program."
	case models.PackUnpacked:
		s += " This means no packing indicators were found; it does not prove the file is unpacked."
	}
	return s
}

func shortNames(in []string) []string {
	var out []string
	for _, s := range in {
		if i := strings.Index(s, ":"); i > 0 {
			s = s[:i]
		}
		out = append(out, s)
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Recommendations collects the distinct recommended actions, ordered by the
// severity of the finding that suggested them, plus standing precautions.
func Recommendations(r *models.Report) []string {
	rank := map[models.Severity]int{models.SeverityHigh: 0, models.SeverityMedium: 1, models.SeverityLow: 2, models.SeverityInfo: 3}
	type item struct {
		text string
		rank int
	}
	seen := map[string]bool{}
	var items []item
	for _, f := range r.Findings {
		if f.Action == "" || seen[f.Action] {
			continue
		}
		seen[f.Action] = true
		items = append(items, item{clean(f.Action), rank[f.Severity]})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].rank < items[j].rank })
	var out []string
	for _, it := range items {
		out = append(out, it.text)
	}
	out = append(out,
		"Handle the sample only in an isolated, disposable environment; this report is static and cannot rule out behaviour.",
		"Confirm any capability or indicator by inspecting the code that uses it (disassembly or decompilation) before relying on it.")
	return out
}

// SeverityCounts tallies findings by severity.
func SeverityCounts(r *models.Report) map[models.Severity]int {
	m := map[models.Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// EvidenceIndex maps evidence ids to evidence.
func EvidenceIndex(r *models.Report) map[string]models.Evidence {
	m := make(map[string]models.Evidence, len(r.Evidence))
	for _, e := range r.Evidence {
		m[e.ID] = e
	}
	return m
}
