package models

// UnpackAttempt records what happened when unpacking was requested.
type UnpackAttempt struct {
	Requested   bool     `json:"requested"`
	Status      string   `json:"status"` // unpacked | failed | unavailable | not-applicable | rejected
	Tool        string   `json:"tool,omitempty"`
	ToolVersion string   `json:"tool_version,omitempty"`
	Message     string   `json:"message"`
	Supported   []string `json:"supported_packers"`
}

// ValidationCheck is one test applied to an extracted artifact before it is
// trusted as a result.
type ValidationCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Artifact is a file derived from the sample (an unpacked layer, an extracted
// resource). It is analysed like any sample, and the edge says how it came to
// exist.
type Artifact struct {
	Kind         string            `json:"kind"` // unpacked
	Tool         string            `json:"tool"`
	ToolVersion  string            `json:"tool_version"`
	ParentSHA256 string            `json:"parent_sha256"`
	Path         string            `json:"path"`
	Size         int64             `json:"size"`
	Hashes       Hashes            `json:"hashes"`
	Validation   []ValidationCheck `json:"validation"`
	Report       *Report           `json:"report,omitempty"`
	Comparison   *Comparison       `json:"comparison,omitempty"`
}

// FileRef identifies one side of a comparison.
type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Change is a value that differs between two files.
type Change struct {
	Field string `json:"field"`
	A     string `json:"a"`
	B     string `json:"b"`
}

// SectionDiff describes a section present in both files whose properties differ.
type SectionDiff struct {
	Name    string   `json:"name"`
	Changes []Change `json:"changes"`
}

// SetDiff lists items only in one side.
type SetDiff struct {
	OnlyA     []string `json:"only_in_a"`
	OnlyB     []string `json:"only_in_b"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Comparison is the structured difference between two analysed files.
type Comparison struct {
	FileA          FileRef       `json:"a"`
	FileB          FileRef       `json:"b"`
	Identical      bool          `json:"identical"`
	Header         []Change      `json:"header"`
	Sections       SetDiff       `json:"sections"`
	SectionChanges []SectionDiff `json:"section_changes"`
	Libraries      SetDiff       `json:"imported_libraries"`
	Imports        SetDiff       `json:"imported_functions"`
	Exports        SetDiff       `json:"exports"`
	Entropy        []Change      `json:"entropy"`
	Packing        []Change      `json:"packing"`
	Fingerprint    []Change      `json:"fingerprint"`
	Capabilities   SetDiff       `json:"capabilities"`
	Indicators     SetDiff       `json:"indicators"`
	Strings        []Change      `json:"strings"`
	Notes          []string      `json:"notes"`
}

// ExtractedEntry is one item found inside an embedded container.
type ExtractedEntry struct {
	Name       string `json:"name"`
	Type       string `json:"type"`      // single-letter code from the container
	TypeName   string `json:"type_name"` // script, module, binary, data, pyz ...
	Offset     int64  `json:"file_offset"`
	StoredSize int64  `json:"stored_size"`
	Size       int64  `json:"size"`
	Compressed bool   `json:"compressed"`
	Path       string `json:"path,omitempty"` // relative to Extraction.Dir; empty when skipped
	SHA256     string `json:"sha256,omitempty"`
	Format     string `json:"format,omitempty"` // content-based identification of the extracted bytes
	Skipped    string `json:"skipped,omitempty"`
}

// Extraction records embedded content pulled out of a container. Extracted
// files are data: they are written without execute permission and never run.
type Extraction struct {
	Requested     bool             `json:"requested"`
	Status        string           `json:"status"` // extracted | not-applicable | failed | rejected
	Kind          string           `json:"kind,omitempty"`
	Message       string           `json:"message"`
	Supported     []string         `json:"supported_containers"`
	ArchiveFormat string           `json:"archive_format,omitempty"`
	PythonVersion string           `json:"python_version,omitempty"`
	ArchiveOffset int64            `json:"archive_offset,omitempty"`
	ArchiveLength int64            `json:"archive_length,omitempty"`
	Entries       []ExtractedEntry `json:"entries"`
	TotalBytes    int64            `json:"total_bytes"`
	Dir           string           `json:"dir,omitempty"`
	Notes         []string         `json:"notes,omitempty"`
}
