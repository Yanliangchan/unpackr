package models

// EntropyInfo holds Shannon entropy (bits per byte, 0-8) of file regions.
// Entropy is a measurement, not a verdict: compressed data, encrypted data and
// some legitimate resources all score high.
type EntropyInfo struct {
	File     float64          `json:"file"`
	Overlay  *float64         `json:"overlay,omitempty"`
	Sections []SectionEntropy `json:"sections"`
}

// SectionEntropy is the entropy of one section's raw bytes.
type SectionEntropy struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	Offset  uint64  `json:"offset"`
	Size    uint64  `json:"size"`
	Perms   string  `json:"permissions"`
}

// StringHit is one extracted string with its location.
type StringHit struct {
	Offset   int64  `json:"offset"`
	Encoding string `json:"encoding"` // ascii | utf16le
	Text     string `json:"text"`
	Section  string `json:"section,omitempty"`
}

// StringsInfo summarises string extraction. Shown is a bounded sample in file
// order; Total counts every string found.
type StringsInfo struct {
	MinLength int         `json:"min_length"`
	Total     int         `json:"total"`
	ASCII     int         `json:"ascii"`
	UTF16     int         `json:"utf16le"`
	Shown     []StringHit `json:"shown"`
	Truncated bool        `json:"truncated"`
}

// Indicator is something that looks like an IOC. It is a string observation,
// not a statement that the sample uses the value.
type Indicator struct {
	Type     string `json:"type"` // url | ipv4 | domain | email | windows-path | unix-path | registry | command
	Value    string `json:"value"`
	Count    int    `json:"count"`
	Offset   int64  `json:"offset"`
	Encoding string `json:"encoding"`
	Section  string `json:"section,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Signal is one weighted observation feeding a hypothesis. Signals sharing a
// Family are not independent and count once toward confidence.
type Signal struct {
	ID       string   `json:"id"`
	Detail   string   `json:"detail"`
	Strength string   `json:"strength"` // strong | moderate | weak
	Family   string   `json:"family"`
	Evidence []string `json:"evidence,omitempty"`
}

// Hypothesis is a ranked possibility with the reasons behind it.
type Hypothesis struct {
	Name       string     `json:"name"`
	Detail     string     `json:"detail,omitempty"`
	Confidence Confidence `json:"confidence"`
	Rationale  string     `json:"confidence_rationale"`
	Signals    []Signal   `json:"signals"`
}

// Fingerprint answers "how was this built". Each list is ranked, so
// alternatives stay visible. Compiled C and C++ cannot always be told apart,
// and the lists say so rather than guess.
type Fingerprint struct {
	Languages []Hypothesis `json:"languages"`
	Compilers []Hypothesis `json:"compilers"`
	Runtimes  []Hypothesis `json:"runtimes"`
}

// Packing states.
const (
	PackUnpacked  = "unpacked"
	PackLikely    = "likely-packed"
	PackConfirmed = "confirmed-packed"
	PackUnknown   = "unknown"
)

// PackingAssessment answers "is anything concealed". Entropy alone can never
// produce a packed state.
type PackingAssessment struct {
	State      string     `json:"state"`
	Family     string     `json:"family,omitempty"` // packer or protector name when one is indicated
	Confidence Confidence `json:"confidence"`
	Rationale  string     `json:"confidence_rationale"`
	Signals    []Signal   `json:"signals"`
	Notes      []string   `json:"notes,omitempty"`
}

// Analysis is the output of the content-analysis worker.
type Analysis struct {
	Entropy     EntropyInfo       `json:"entropy"`
	Strings     StringsInfo       `json:"strings"`
	Indicators  []Indicator       `json:"indicators"`
	Fingerprint Fingerprint       `json:"fingerprint"`
	Packing     PackingAssessment `json:"packing"`
	Evidence    []Evidence        `json:"evidence"`
}
