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
	"github.com/Yanliangchan/unpackr/internal/anomalies"
	"github.com/Yanliangchan/unpackr/internal/capabilities"
	"github.com/Yanliangchan/unpackr/internal/confidence"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/fingerprint"
	"github.com/Yanliangchan/unpackr/internal/obfuscation"
	"github.com/Yanliangchan/unpackr/internal/packing"
	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// NotRunFuzzy is reported when the quick profile skipped similarity hashing.
const NotRunFuzzy = "fuzzy-hashing: skipped by the quick profile (ssdeep, TLSH and the string sketch are empty, which does not mean the file is unique)"

// TaskAnalyze runs the content-derived stages in a sandboxed worker:
// entropy, strings, indicators, fingerprinting and the packing assessment.
const TaskAnalyze = "analyze"

// AnalyzeParams carries the structure result into the worker.
type AnalyzeParams struct {
	Family string             `json:"family"`
	Binary *models.Binary     `json:"binary,omitempty"`
	Yara   []models.YaraMatch `json:"yara,omitempty"`
	// SkipFuzzy omits ssdeep, TLSH and the string sketch (quick profile).
	SkipFuzzy bool `json:"skip_fuzzy,omitempty"`
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
		return analyzeBytes(data, p.Family, p.Binary, p.Yara, p.SkipFuzzy), nil
	})
}

// RunAnalysis is the pure core of the analyze task.
func RunAnalysis(data []byte, family string, bin *models.Binary, yaraMatches []models.YaraMatch) *models.Analysis {
	return analyzeBytes(data, family, bin, yaraMatches, false)
}

func analyzeBytes(data []byte, family string, bin *models.Binary, yaraMatches []models.YaraMatch, skipFuzzy bool) *models.Analysis {
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
	in := &analysis.Input{Data: data, Family: family, Bin: view, Scan: scan, Entropy: &ent, Sink: sink, Yara: yaraMatches}

	decoded := obfuscation.Find(data)
	for i := range decoded {
		d := &decoded[i]
		d.Evidence = sink.Add("decoded-string", d.Text, d.Offset, int64(d.Length), sectionOf(d.Offset), "obfuscation/"+d.Method, "decoded:"+d.Method)
	}
	in.Decoded = decoded

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
	caps := capabilities.Detect(in, pk.State)
	anoms := anomalies.Detect(in)
	var ssd, tl string
	var sketch []uint32
	if !skipFuzzy {
		ssd, tl = similarity.Hash(data)
		sketch = similarity.Sketch(func(yield func(string)) {
			for _, h := range scan.Hits {
				if len(h.Text) >= 8 {
					yield(h.Text)
				}
			}
		})
	}
	out := &models.Analysis{
		Fuzzy:        models.Fuzzy{SSDeep: ssd, TLSH: tl, StringSketch: sketch},
		Capabilities: caps,
		Anomalies:    anoms,
		Entropy:      ent,
		Strings:      scan.Summarize(sectionOf),
		Indicators:   mergeDecodedIndicators(content.ExtractIndicators(scan.Hits, sectionOf), decoded, sectionOf),
		Decoded:      nonNilDecoded(decoded),
		Fingerprint:  fp,
		Packing:      pk,
		Evidence:     sink.Evidence,
		Yara:         yaraMatches,
	}
	return out
}

// runAnalysis executes the analyze worker and merges the result.
func runAnalysis(ctx context.Context, f *os.File, size int64, rep *models.Report, family string, wo worker.Options, o Options) {
	matches, eng := runYara(ctx, f, size, o)
	start := time.Now()
	res, err := worker.Run(ctx, TaskAnalyze, AnalyzeParams{Family: family, Binary: rep.Binary, Yara: matches, SkipFuzzy: o.Profile == ProfileQuick}, f, size, wo)
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
	a.Engines = append(a.Engines, eng)
	if a.Yara == nil {
		a.Yara = []models.YaraMatch{}
	}
	rep.Analysis = &a
	rep.Evidence = append(rep.Evidence, a.Evidence...)
	addAnalysisFindings(rep, &a)
	if o.Profile == ProfileQuick {
		rep.NotRun = append(rep.NotRun, NotRunFuzzy)
	}
	rep.NotRun = withoutStages(rep.NotRun, "entropy-analysis", "string-extraction", "indicator-extraction", "language-and-compiler-identification", "packing-assessment", "capability-inference", "anomaly-detection")
}

func nonNilDecoded(d []models.DecodedString) []models.DecodedString {
	if d == nil {
		return []models.DecodedString{}
	}
	return d
}

// mergeDecodedIndicators adds indicators found in recovered strings. They are
// kept apart from ordinary string hits so their provenance stays visible.
func mergeDecodedIndicators(ind []models.Indicator, dec []models.DecodedString, sectionOf func(int64) string) []models.Indicator {
	var hits []content.Hit
	for _, d := range dec {
		if d.Method == "base64" {
			continue
		}
		enc := "decoded:" + d.Method
		if d.Key != "" {
			enc += " " + d.Key
		}
		hits = append(hits, content.Hit{Offset: d.Offset, Enc: enc, Text: d.Text})
	}
	if len(hits) == 0 {
		return ind
	}
	have := map[string]bool{}
	for _, i := range ind {
		have[i.Type+"\x00"+i.Value] = true
	}
	for _, n := range content.ExtractIndicators(hits, sectionOf) {
		if have[n.Type+"\x00"+n.Value] {
			continue
		}
		if n.Note != "" {
			n.Note += "; "
		}
		n.Note += "recovered from an encoded form (" + n.Encoding + "), not visible as plain text"
		ind = append(ind, n)
	}
	return ind
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
	case models.PackObfuscated:
		sev = models.SeverityMedium
		action = "Review the recovered strings. Other content may be hidden in forms this tool does not recover (multi-byte keys, RC4/AES, computed strings); dynamic analysis in an isolated lab is the next step."
	}
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "packing.state", Rule: "packing/assessment", Class: models.ClassInference,
		Category: "packing", Title: title, Summary: packingSummary(p),
		Severity: sev, Confidence: p.Confidence, Rationale: p.Rationale,
		EvidenceID: evIDs(p.Signals), Action: action,
	})

	used := map[string]int{}
	uniq := func(id string) string {
		used[id]++
		if used[id] > 1 {
			return fmt.Sprintf("%s#%d", id, used[id])
		}
		return id
	}
	for _, c := range a.Capabilities {
		ev := evIDs(c.Signals)
		action := ""
		if c.Severity == models.SeverityHigh || c.Severity == models.SeverityMedium {
			action = "Check the call sites and surrounding code (disassembly) before drawing conclusions; the import table alone cannot show how or whether the API is used."
		}
		rep.Findings = append(rep.Findings, models.Finding{
			ID: uniq("cap." + c.ID), Rule: "capability/" + c.ID, Class: models.ClassInference,
			Category: "capability", Title: "Possible capability: " + c.Name,
			Summary: c.Summary, Severity: c.Severity, Confidence: c.Confidence, Rationale: c.Rationale,
			EvidenceID: ev, Action: action, Attack: c.Attack,
		})
	}
	for i, d := range a.Decoded {
		if i >= 12 {
			break
		}
		sev, conf, how := models.SeverityMedium, models.ConfidenceHigh, "decoding the bytes with the stated key reproduces this text exactly; the key was derived from a known marker, not guessed"
		switch d.Method {
		case "stack":
			sev, conf = models.SeverityLow, models.ConfidenceMedium
			how = "the text was assembled from consecutive constant stores matched by byte pattern, not by disassembly"
		case "base64":
			how = "the base64 run decodes cleanly and begins with an executable header"
		}
		title := "Hidden string recovered (" + d.Method
		if d.Key != "" {
			title += " key " + d.Key
		}
		title += ")"
		rep.Findings = append(rep.Findings, models.Finding{
			ID: uniq("obfuscation.decoded"), Rule: "obfuscation/" + d.Method, Class: models.ClassObservation,
			Category: "obfuscation", Title: title, Summary: d.Text, Severity: sev, Confidence: conf,
			Rationale:  how + ". Whether the author meant to conceal it is an inference.",
			EvidenceID: []string{d.Evidence},
			Action:     "Treat the recovered text like any other string: check its context before treating it as an indicator of compromise.",
		})
	}
	for _, an := range a.Anomalies {
		rep.Findings = append(rep.Findings, models.Finding{
			ID: uniq("anomaly." + an.ID), Rule: "anomaly/" + an.ID, Class: models.ClassObservation,
			Category: "anomaly", Title: an.Title,
			Summary: an.Why + benignSuffix(an.Benign), Severity: an.Severity, Confidence: models.ConfidenceHigh,
			Rationale:  "the condition is read directly from the file's structure; its meaning is the analyst's call",
			EvidenceID: an.Evidence,
		})
	}

	if len(a.Yara) > 0 {
		var parts []string
		for _, m := range a.Yara {
			parts = append(parts, fmt.Sprintf("%s [%s]", m.Rule, m.Status))
		}
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "signatures.yara", Rule: "yara/matches", Class: models.ClassObservation, Category: "signatures",
			Title:    fmt.Sprintf("%d YARA-X rule(s) matched", len(a.Yara)),
			Summary:  "Matched: " + joinComma(parts) + ". Only rules marked tested count as evidence; experimental and analyst rules are listed for review.",
			Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
			Rationale:  "the rule engine reported the match; the weight given to it is stated per rule",
			EvidenceID: []string{},
		})
	}
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
	case models.PackObfuscated:
		s = "Text that the file keeps in an encoded form was recovered. This is not evidence that the program itself is compressed or encrypted."
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

func benignSuffix(b string) string {
	if b == "" {
		return ""
	}
	return " Common and harmless in: " + b
}
