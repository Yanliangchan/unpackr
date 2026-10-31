// Package engine orchestrates analysis. It never imports presentation code.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/hashing"
	"github.com/Yanliangchan/unpackr/internal/safety"
	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Profiles.
const (
	ProfileQuick = "quick"
	ProfileInfo  = "info"
)

// Options configure one analysis.
type Options struct {
	Config  config.Config
	Profile string
	// Exe overrides the worker executable (tests).
	Exe string
	// Modules restricts the run to the named modules; empty means all.
	Modules []string
}

// NotImplemented lists the investigation stages that this build does not
// provide. They are written into every report so that a missing stage can
// never be mistaken for a clean result.
var NotImplemented = []string{
	"structure-details: PE resources/TLS/relocations/debug directory/Authenticode validation, ELF notes and relocations, Mach-O code signature and chained fixups",
	"language-and-compiler-identification",
	"packing-assessment",
	"entropy-analysis",
	"string-extraction",
	"capability-inference",
	"indicator-extraction",
	"anomaly-detection",
}

// ErrModified is returned when the input changed while it was analysed.
var ErrModified = fmt.Errorf("input file changed during analysis")

// Analyze runs the available stages on one file. The file is opened read-only,
// hashed before and after, and never executed.
func Analyze(ctx context.Context, path string, o Options) (*models.Report, error) {
	f, st, err := safety.OpenInput(path, o.Config.MaxFileSizeMB<<20)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only descriptor

	rep := &models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool:          models.ToolMeta{Name: "unpackr", Version: version.Version, Platform: version.Platform(), Offline: true},
		Profile:       o.Profile,
		StartedAt:     time.Now().UTC(),
		Findings:      []models.Finding{},
		Evidence:      []models.Evidence{},
		Warnings:      []models.Warning{},
		NotRun:        append([]string(nil), NotImplemented...),
	}
	abs, _ := filepath.Abs(path)
	rep.File = models.FileInfo{Path: abs, Name: filepath.Base(path), Size: st.Size()}

	h, n, err := hashing.Sum(sectionReader(f, st.Size()))
	if err != nil {
		return nil, fmt.Errorf("hashing %s: %w", path, err)
	}
	if n != st.Size() {
		return nil, fmt.Errorf("%s: read %d bytes but file is %d", path, n, st.Size())
	}
	rep.File.Hashes = h

	wo := worker.Options{
		Exe:              o.Exe,
		Timeout:          time.Duration(o.Config.TimeoutSeconds) * time.Second,
		MemoryLimitBytes: uint64(o.Config.WorkerMemoryMB) << 20,
		RequireSandbox:   o.Config.RequireSandbox,
	}
	start := time.Now()
	res, werr := worker.Run(ctx, TaskIdentify, nil, f, st.Size(), wo)
	run := models.ModuleRun{Name: "identification", DurationMS: time.Since(start).Milliseconds()}
	if res != nil {
		sb := res.Sandbox
		run.Sandbox = &sb
	}
	if werr != nil {
		run.Status, run.Error = "failed", werr.Error()
		rep.Modules = append(rep.Modules, run)
		rep.Warnings = append(rep.Warnings, models.Warning{Module: "identification", Message: werr.Error()})
		if o.Config.RequireSandbox {
			return rep, werr
		}
		return rep, nil
	}
	var id models.Identification
	if err := json.Unmarshal(res.Raw, &id); err != nil {
		run.Status, run.Error = "failed", "undecodable worker result: "+err.Error()
		rep.Modules = append(rep.Modules, run)
		return rep, nil
	}
	run.Status = "ok"
	rep.Modules = append(rep.Modules, run)
	rep.Identification = &id
	if res.Sandbox.Level != safety.LevelFull {
		rep.Warnings = append(rep.Warnings, models.Warning{Module: "sandbox",
			Message: "worker confinement was " + res.Sandbox.Level + ": " + res.Sandbox.Detail})
	}
	addIdentificationFindings(rep, &id)
	if wants(o.Modules, "structure") && len(id.Candidates) > 0 && id.Primary != "unknown" {
		runStructure(ctx, f, st.Size(), rep, id.Candidates[0].Family, wo)
	}

	// Evidence preservation: the input must be byte-identical afterwards.
	h2, _, err := hashing.Sum(sectionReader(f, st.Size()))
	if err != nil {
		return rep, fmt.Errorf("re-hashing %s: %w", path, err)
	}
	if h2 != h {
		return rep, ErrModified
	}
	return rep, nil
}

func confidenceFor(score int) (models.Confidence, string) {
	switch {
	case score >= 90:
		return models.ConfidenceHigh, "all principal structural checks passed"
	case score >= 70:
		return models.ConfidenceMedium, "most structural checks passed"
	default:
		return models.ConfidenceLow, "only part of the expected structure is present"
	}
}

func addIdentificationFindings(rep *models.Report, id *models.Identification) {
	nextEv := 0
	addEvidence := func(c models.FormatCandidate) []string {
		var ids []string
		for _, ch := range c.Checks {
			if !ch.Passed {
				continue
			}
			nextEv++
			eid := fmt.Sprintf("e%d", nextEv)
			rep.Evidence = append(rep.Evidence, models.Evidence{
				ID: eid, Kind: "structure-check", Value: ch.Name + detailSuffix(ch.Detail),
				Loc:    models.Location{Offset: models.Int64(ch.Offset), Length: models.Int64(ch.Length)},
				Source: models.Source{Module: "identification", Rule: "probe/" + c.Family},
				Family: "structure/" + c.Family,
			})
			ids = append(ids, eid)
		}
		return ids
	}
	if id.Primary == "unknown" {
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "ident.unknown", Rule: "identification/no-match", Class: models.ClassObservation,
			Category: "identification", Title: "Format not recognised",
			Summary:  "No supported format probe reached the minimum structural score. The file may be data, an unsupported format, or corrupt.",
			Severity: models.SeverityInfo, Confidence: models.ConfidenceLow,
			Rationale:  "absence of a match is not proof of what the file is",
			EvidenceID: []string{}, Action: "Inspect the file manually (hex dump, strings) or check whether it is encrypted or compressed data.",
		})
		return
	}
	primary := id.Candidates[0]
	conf, why := confidenceFor(primary.Score)
	passed, total := 0, len(primary.Checks)
	for _, c := range primary.Checks {
		if c.Passed {
			passed++
		}
	}
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "ident.format", Rule: "identification/primary-format", Class: models.ClassObservation,
		Category: "identification", Title: "Format: " + id.Primary,
		Summary:  describe(primary),
		Severity: models.SeverityInfo, Confidence: conf,
		Rationale:  fmt.Sprintf("%d of %d structural checks passed (score %d/100): %s", passed, total, primary.Score, why),
		EvidenceID: addEvidence(primary),
	})
	if id.Polyglot {
		var names []string
		var ev []string
		for _, c := range id.Candidates {
			if c.Score >= 50 {
				names = append(names, c.Format)
				ev = append(ev, addEvidence(c)...)
			}
		}
		sort.Strings(names)
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "ident.polyglot", Rule: "identification/multiple-families", Class: models.ClassInference,
			Category: "identification", Title: "File satisfies more than one format",
			Summary:  fmt.Sprintf("Structural checks pass for several format families: %v. Treat the file as a possible polyglot or a file with appended data.", names),
			Severity: models.SeverityLow, Confidence: models.ConfidenceMedium,
			Rationale:  "independent structural probes each exceeded the acceptance threshold",
			EvidenceID: ev, Action: "Analyse each format separately; look for appended or embedded content.",
		})
	}
}

func detailSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (" + d + ")"
}

func describe(c models.FormatCandidate) string {
	s := c.Format
	keys := make([]string, 0, len(c.Attributes))
	for k := range c.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s += fmt.Sprintf("; %s=%s", k, c.Attributes[k])
	}
	return s
}

// runStructure parses the executable structure in a worker. A failure is
// recorded as a warning and a failed module; it never hides the identification.
func runStructure(ctx context.Context, f *os.File, size int64, rep *models.Report, family string, wo worker.Options) {
	switch family {
	case "pe", "elf", "macho":
	default:
		return
	}
	start := time.Now()
	res, err := worker.Run(ctx, TaskParse, ParseParams{Family: family}, f, size, wo)
	run := models.ModuleRun{Name: "structure", DurationMS: time.Since(start).Milliseconds()}
	if res != nil {
		sb := res.Sandbox
		run.Sandbox = &sb
	}
	if err != nil {
		run.Status, run.Error = "failed", err.Error()
		rep.Modules = append(rep.Modules, run)
		rep.Warnings = append(rep.Warnings, models.Warning{Module: "structure", Message: err.Error()})
		return
	}
	var b models.Binary
	if err := json.Unmarshal(res.Raw, &b); err != nil {
		run.Status, run.Error = "failed", "undecodable worker result: "+err.Error()
		rep.Modules = append(rep.Modules, run)
		return
	}
	run.Status = "ok"
	rep.Modules = append(rep.Modules, run)
	rep.Binary = &b
	if len(b.Anomalies) > 0 {
		var ids []string
		for _, a := range b.Anomalies {
			id := fmt.Sprintf("a%d", len(rep.Evidence)+1)
			rep.Evidence = append(rep.Evidence, models.Evidence{ID: id, Kind: "parser-anomaly", Value: a,
				Source: models.Source{Module: "structure", Engine: family + " parser"}, Family: "parser/" + family})
			ids = append(ids, id)
		}
		rep.Findings = append(rep.Findings, models.Finding{
			ID: "structure.parser-anomalies", Rule: "structure/parser-anomalies", Class: models.ClassObservation,
			Category: "structure", Title: fmt.Sprintf("%d structural anomalies reported by the parser", len(b.Anomalies)),
			Summary:  "The parser noticed inconsistencies while reading the file. Each one is a fact about the file's bytes; none is by itself a verdict about intent.",
			Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
			Rationale:  "reported directly by the format parser",
			EvidenceID: ids, Action: "Review each anomaly; damaged or unusual headers are common in packed, protected and hand-made files, and also in corrupt ones.",
		})
	}
}

func wants(sel []string, name string) bool {
	if len(sel) == 0 {
		return true
	}
	for _, s := range sel {
		if s == name {
			return true
		}
	}
	return false
}
