// Package models defines the structured data exchanged between analysis
// modules, workers and report renderers. It has no dependencies on the rest of
// the project.
package models

import "time"

// SchemaVersion is the version of the JSON report schema.
const SchemaVersion = "0.1"

// Class says how a statement was obtained. It is the central honesty
// mechanism: observations are read from bytes, inferences are derived by a
// named rule, hypotheses are weakly supported. Runtime behaviour is never a
// class because samples are never executed.
type Class string

const (
	ClassObservation Class = "observation"
	ClassInference   Class = "inference"
	ClassHypothesis  Class = "hypothesis"
)

// Severity is the impact if the finding is true.
type Severity string

const (
	SeverityInfo   Severity = "informational"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Confidence is an ordinal scale, never a percentage.
type Confidence string

const (
	ConfidenceSpeculative Confidence = "speculative"
	ConfidenceLow         Confidence = "low"
	ConfidenceMedium      Confidence = "medium"
	ConfidenceHigh        Confidence = "high"
	ConfidenceDefinitive  Confidence = "definitive"
)

// Location pins evidence to bytes. Fields are optional because not every kind
// of evidence has every address.
type Location struct {
	Offset  *int64  `json:"offset,omitempty"`
	Length  *int64  `json:"length,omitempty"`
	RVA     *uint64 `json:"rva,omitempty"`
	VA      *uint64 `json:"va,omitempty"`
	Section string  `json:"section,omitempty"`
	Path    string  `json:"path,omitempty"` // path inside a container artifact
}

// Source records which module and engine produced a piece of evidence.
type Source struct {
	Module  string `json:"module"`
	Engine  string `json:"engine,omitempty"`
	Version string `json:"version,omitempty"`
	Rule    string `json:"rule,omitempty"`
}

// Evidence is one observed fact. Family groups evidence that is not
// independent (for example two signatures matching the same bytes) so that it
// is counted once when confidence is derived.
type Evidence struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Value  string   `json:"value"`
	Loc    Location `json:"location"`
	Source Source   `json:"source"`
	Family string   `json:"family,omitempty"`
}

// Finding is a conclusion with the evidence supporting it.
type Finding struct {
	ID         string     `json:"id"`
	Rule       string     `json:"rule"`
	Class      Class      `json:"class"`
	Category   string     `json:"category"`
	Title      string     `json:"title"`
	Summary    string     `json:"summary"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Rationale  string     `json:"confidence_rationale"`
	EvidenceID []string   `json:"evidence"`
	Action     string     `json:"recommended_action,omitempty"`
	Dissent    []string   `json:"dissent,omitempty"`
}

// Hashes of the whole file.
type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// FileInfo describes the analysed input.
type FileInfo struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Hashes Hashes `json:"hashes"`
}

// Check is a single structural test performed by a format probe.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Detail string `json:"detail,omitempty"`
}

// FormatCandidate is one hypothesis about what a file is.
type FormatCandidate struct {
	Format     string            `json:"format"`
	Family     string            `json:"family"`
	Score      int               `json:"score"` // 0-100 structural validity, not a probability
	Checks     []Check           `json:"checks"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Identification is the ranked outcome of content-based format detection.
type Identification struct {
	Candidates []FormatCandidate `json:"candidates"`
	Primary    string            `json:"primary"`
	Polyglot   bool              `json:"polyglot"`
}

// Warning is a non-fatal problem reported by a module.
type Warning struct {
	Module  string `json:"module"`
	Message string `json:"message"`
}

// SandboxStatus says what confinement a worker actually achieved.
type SandboxStatus struct {
	Level       string `json:"level"` // full | partial | none
	NoNewPrivs  bool   `json:"no_new_privs"`
	Landlock    bool   `json:"landlock"`
	LandlockABI int    `json:"landlock_abi"`
	LandlockNet bool   `json:"landlock_net"`
	Seccomp     bool   `json:"seccomp"`
	MemoryLimit bool   `json:"memory_limit"`
	Detail      string `json:"detail,omitempty"`
}

// ModuleRun records one module execution.
type ModuleRun struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"` // ok | failed
	DurationMS int64          `json:"duration_ms"`
	Sandbox    *SandboxStatus `json:"sandbox,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// ToolMeta identifies the producing build.
type ToolMeta struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Offline  bool   `json:"offline"`
}

// Report is the canonical, renderer-independent analysis result.
type Report struct {
	SchemaVersion  string          `json:"schema_version"`
	Tool           ToolMeta        `json:"tool"`
	Profile        string          `json:"profile"`
	StartedAt      time.Time       `json:"started_at"`
	File           FileInfo        `json:"file"`
	Identification *Identification `json:"identification,omitempty"`
	Findings       []Finding       `json:"findings"`
	Evidence       []Evidence      `json:"evidence"`
	Warnings       []Warning       `json:"warnings"`
	Modules        []ModuleRun     `json:"modules"`
	// NotRun lists analysis stages that this build does not implement. A
	// report never silently omits a stage.
	NotRun []string `json:"not_run"`
}

// Int64 and Uint64 return pointers for optional location fields.
func Int64(v int64) *int64    { return &v }
func Uint64(v uint64) *uint64 { return &v }
