package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/confidence"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/fingerprint"
	"github.com/Yanliangchan/unpackr/internal/packing"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// TaskAnalyze runs the content-derived stages in a sandboxed worker:
// entropy, strings, indicators, fingerprinting and the packing assessment.
const TaskAnalyze = "analyze"

// AnalyzeParams carries the structure result into the worker.
type AnalyzeParams struct {
	Family string         `json:"family"`
	Binary *models.Binary `json:"binary,omitempty"`
}

func init() {
	worker.Register(TaskAnalyze, func(ctx context.Context, in io.ReaderAt, size int64, raw json.RawMessage) (any, error) {
		var p AnalyzeParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		n := size
		if n > MaxParseBytes {
			n = MaxParseBytes
		}
		data, err := io.ReadAll(io.NewSectionReader(in, 0, n))
		if err != nil {
			return nil, err
		}
		return RunAnalysis(data, p.Family, p.Binary), nil
	})
}

// RunAnalysis is the pure core of the analyze task.
func RunAnalysis(data []byte, family string, bin *models.Binary) *models.Analysis {
	// Universal Mach-O: work on the first slice's section table for mapping.
	view := bin
	if view != nil && len(view.Slices) > 0 {
		view = &view.Slices[0]
	}
	sectionOf := func(off int64) string {
		if view == nil {
			return ""
		}
		for _, s := range view.Sections {
			if s.RawSize > 0 && uint64(off) >= s.RawOffset && uint64(off) < s.RawOffset+s.RawSize {
				return s.Name
			}
		}
		return ""
	}

	ent := models.EntropyInfo{File: content.Entropy(data), Sections: []models.SectionEntropy{}}
	if view != nil {
		for _, s := range view.Sections {
			if d := content.Slice(data, s.RawOffset, s.RawSize); len(d) > 0 {
				ent.Sections = append(ent.Sections, models.SectionEntropy{Name: s.Name, Entropy: content.Entropy(d), Offset: s.RawOffset, Size: uint64(len(d)), Perms: s.Perms})
			}
		}
		if view.Overlay != nil {
			if d := content.Slice(data, uint64(view.Overlay.Offset), uint64(view.Overlay.Size)); len(d) > 0 {
				e := content.Entropy(d)
				ent.Overlay = &e
			}
		}
	}

	scan := content.ExtractStrings(data)
	sink := analysis.NewSink("analysis")
	in := &analysis.Input{Data: data, Family: family, Bin: view, Scan: scan, Entropy: &ent, Sink: sink}

	fp := fingerprint.Detect(in)
	pk := packing.Assess(in)
	if pk.State == models.PackConfirmed || pk.State == models.PackLikely {
		// What a packed file reveals about its build is what the stub and any
		// leftovers reveal, not necessarily the original program.
		caveat := "file appears packed: these traces may describe the packer, not the packed program"
		for _, list := range [][]models.Hypothesis{fp.Languages, fp.Compilers, fp.Runtimes} {
			for i := range list {
				list[i].Confidence = confidence.Lower(list[i].Confidence, 1)
				list[i].Rationale += "; " + caveat
			}
		}
	}
	out := &models.Analysis{
		Entropy:     ent,
		Strings:     scan.Summarize(sectionOf),
		Indicators:  content.ExtractIndicators(scan.Hits, sectionOf),
		Fingerprint: fp,
		Packing:     pk,
		Evidence:    sink.Evidence,
	}
	return out
}

// runAnalysis executes the analyze worker and merges the result.
func runAnalysis(ctx context.Context, f *os.File, size int64, rep *models.Report, family string, wo worker.Options) {
	start := time.Now()
	res, err := worker.Run(ctx, TaskAnalyze, AnalyzeParams{Family: family, Binary: rep.Binary}, f, size, wo)
	run := models.ModuleRun{Name: "content-analysis", DurationMS: time.Since(start).Milliseconds()}
	if res != nil {
		sb := res.Sandbox
		run.Sandbox = &sb
	}
	if err != nil {
		run.Status, run.Error = "failed", err.Error()
		rep.Modules = append(rep.Modules, run)
		rep.Warnings = append(rep.Warnings, models.Warning{Module: "content-analysis", Message: err.Error()})
		return
	}
	var a models.Analysis
	if err := json.Unmarshal(res.Raw, &a); err != nil {
		run.Status, run.Error = "failed", "undecodable worker result: "+err.Error()
		rep.Modules = append(rep.Modules, run)
		return
	}
	run.Status = "ok"
	rep.Modules = append(rep.Modules, run)
	rep.Analysis = &a
	rep.Evidence = append(rep.Evidence, a.Evidence...)
	addAnalysisFindings(rep, &a)
	rep.NotRun = withoutStages(rep.NotRun, "entropy-analysis", "string-extraction", "indicator-extraction", "language-and-compiler-identification", "packing-assessment")
}

func withoutStages(all []string, drop ...string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	var out []string
	for _, s := range all {
		if !skip[s] {
			out = append(out, s)
		}
	}
	return out
}

func evIDs(sigs []models.Signal) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, s := range sigs {
		for _, e := range s.Evidence {
			if !seen[e] {
				seen[e] = true
				ids = append(ids, e)
			}
		}
	}
	return ids
}

func addAnalysisFindings(rep *models.Report, a *models.Analysis) {
	top := func(kind, label string, hs []models.Hypothesis) {
		if len(hs) == 0 {
			return
		}
		h := hs[0]
		summary := h.Name
		if h.Detail != "" {
			summary += " — " + h.Detail
		}
		var alts []string
		for _, o := range hs[1:] {
			alts = append(alts, fmt.Sprintf("%s (%s)", o.Name, o.Confidence))
		}
		if len(alts) > 0 {
			summary += ". Alternatives: " + joinComma(alts)
		}
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "fingerprint." + kind, Rule: "fingerprint/" + kind, Class: models.ClassInference,
			Category: "fingerprint", Title: label + ": " + h.Name, Summary: summary,
			Severity: models.SeverityInfo, Confidence: h.Confidence, Rationale: h.Rationale,
			EvidenceID: evIDs(h.Signals),
		})
	}
	top("language", "Likely language", a.Fingerprint.Languages)
	top("compiler", "Likely compiler", a.Fingerprint.Compilers)
	top("runtime", "Runtime", a.Fingerprint.Runtimes)

	p := a.Packing
	sev := models.SeverityInfo
	action := ""
	title := "Packing: " + p.State
	switch p.State {
	case models.PackConfirmed, models.PackLikely:
		sev = models.SeverityMedium
		if p.Family != "" {
			title += " (" + p.Family + ")"
		}
		action = "Do not trust imports, strings or capabilities of the packed file. Unpack a copy with the packer's own tool in an isolated environment and analyse the result."
	case models.PackUnknown:
		action = "Review the listed indicators manually; they were not enough to call the file packed."
	}
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "packing.state", Rule: "packing/assessment", Class: models.ClassInference,
		Category: "packing", Title: title, Summary: packingSummary(p),
		Severity: sev, Confidence: p.Confidence, Rationale: p.Rationale,
		EvidenceID: evIDs(p.Signals), Action: action,
	})

	if len(a.Indicators) > 0 {
		counts := map[string]int{}
		for _, i := range a.Indicators {
			counts[i.Type]++
		}
		types := make([]string, 0, len(counts))
		for t := range counts {
			types = append(types, t)
		}
		sort.Strings(types)
		var parts []string
		for _, t := range types {
			parts = append(parts, fmt.Sprintf("%d %s", counts[t], t))
		}
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "indicators.found", Rule: "indicators/extraction", Class: models.ClassObservation,
			Category: "indicators", Title: fmt.Sprintf("%d indicator-like strings", len(a.Indicators)),
			Summary:  "Strings shaped like: " + joinComma(parts) + ". Presence in a string table does not show the sample uses or contacts them.",
			Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
			Rationale:  "extracted directly from the file's bytes with fixed patterns; interpretation is left to the analyst",
			EvidenceID: []string{}, Action: "Check each indicator against its surrounding context before treating it as an IOC.",
		})
	}
}

func packingSummary(p models.PackingAssessment) string {
	s := ""
	switch p.State {
	case models.PackConfirmed:
		s = "An exact packer signature is present and independent evidence supports it."
	case models.PackLikely:
		s = "Several independent indicators point to packing or protection."
	case models.PackUnknown:
		s = "Some indicators were found but they do not justify a packed verdict."
	case models.PackUnpacked:
		s = "No packing indicators were found."
	}
	if len(p.Notes) > 0 {
		s += " " + joinSpace(p.Notes)
	}
	return s
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func joinSpace(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x + "."
	}
	return out
}
