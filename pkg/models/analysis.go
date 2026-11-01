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
	// PackObfuscated means content is concealed (for example encoded strings
	// were recovered) but no packer was identified and nothing suggests the
	// program body is compressed or encrypted.
	PackObfuscated = "obfuscated"
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

// Capability is a possible behaviour suggested by what a file references. It
// is inference from static evidence: an imported API shows that code may be
// able to ask for something, never that it ran or succeeded.
type Capability struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Category   string      `json:"category"`
	Attack     []string    `json:"attack,omitempty"`
	Confidence Confidence  `json:"confidence"`
	Rationale  string      `json:"confidence_rationale"`
	Severity   Severity    `json:"severity"`
	Summary    string      `json:"summary"`
	Chain      []ChainStep `json:"chain"`
	// EvidenceKinds says how the capability is supported: imported (named in
	// the import table), string-referenced (name present as a string, e.g.
	// resolved at run time) or structural. "Observed at run time" does not
	// exist because samples are never executed.
	EvidenceKinds []string `json:"evidence_kinds"`
	Signals       []Signal `json:"signals"`
	Caveat        string   `json:"caveat,omitempty"`
}

// ChainStep is one stage of an API relationship (for example allocate,
// write, execute) with the names that matched.
type ChainStep struct {
	Label  string   `json:"label"`
	APIs   []string `json:"apis"`
	Source string   `json:"source"` // imported | string-referenced
}

// DecodedString is text recovered from bytes that are not plain in the file.
// Method says how: the bytes at Offset really do decode this way (an
// observation); whether the author meant to hide them is an inference.
type DecodedString struct {
	Method   string `json:"method"`        // xor | add | base64 | stack
	Key      string `json:"key,omitempty"` // for xor and add, e.g. "0x5a"
	Offset   int64  `json:"offset"`
	Length   int    `json:"length"`
	Text     string `json:"text"`
	Matched  string `json:"matched,omitempty"` // the known marker that located it
	Evidence string `json:"evidence,omitempty"`
}

// Anomaly is a structural oddity with an explanation of why it is notable and
// where it is common and harmless.
type Anomaly struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Why      string   `json:"why_notable"`
	Benign   string   `json:"benign_causes,omitempty"`
	Severity Severity `json:"severity"`
	Evidence []string `json:"evidence"`
}

// YaraMatch is one rule that matched, with where it matched.
type YaraMatch struct {
	Rule        string `json:"rule"`
	Namespace   string `json:"namespace"`          // builtin | user
	Category    string `json:"category,omitempty"` // first tag: packer, language, installer ...
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Strength    string `json:"strength,omitempty"`
	Family      string `json:"family,omitempty"`
	// Status is "tested" for built-in rules with fixtures, "experimental" for
	// built-in rules without, and "user" for rules supplied by the analyst.
	// Only tested rules count as evidence; the rest are listed for the analyst.
	Status  string       `json:"status"`
	Matches []YaraString `json:"matches"`
}

// YaraString is one pattern hit.
type YaraString struct {
	Identifier string `json:"identifier"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
	Data       string `json:"data,omitempty"`
}

// EngineStatus says whether an optional engine took part in the analysis.
type EngineStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // used | missing | failed | skipped
	Version string `json:"version,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Analysis is the output of the content-analysis worker.
type Analysis struct {
	Entropy      EntropyInfo       `json:"entropy"`
	Strings      StringsInfo       `json:"strings"`
	Indicators   []Indicator       `json:"indicators"`
	Fingerprint  Fingerprint       `json:"fingerprint"`
	Packing      PackingAssessment `json:"packing"`
	Capabilities []Capability      `json:"capabilities"`
	Anomalies    []Anomaly         `json:"anomalies"`
	Decoded      []DecodedString   `json:"decoded_strings"`
	Disasm       *Disassembly      `json:"disassembly,omitempty"`
	Reverse      *Reverse          `json:"reverse,omitempty"`
	Evidence     []Evidence        `json:"evidence"`
	Yara         []YaraMatch       `json:"yara_matches"`
	Engines      []EngineStatus    `json:"engines"`
	Fuzzy        Fuzzy             `json:"fuzzy"`
}

// Fuzzy holds locality-sensitive hashes of the whole file and a sketch of its
// strings, used only to recognise related files locally.
type Fuzzy struct {
	SSDeep       string   `json:"ssdeep,omitempty"`
	TLSH         string   `json:"tlsh,omitempty"`
	StringSketch []uint32 `json:"string_sketch,omitempty"`
}

// SimilarityComponent is the overlap of one property of two files.
type SimilarityComponent struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"` // 0 (nothing shared) to 1 (identical sets)
	Weight float64 `json:"weight"`
	Note   string  `json:"note"`
}

// Similarity is how alike two files are. Overlap is a weighted mean of the
// components that could be compared, shown only when there are enough of
// them. It is not a probability and not evidence of a shared origin.
type Similarity struct {
	Components   []SimilarityComponent `json:"components"`
	Overlap      float64               `json:"weighted_structural_overlap"`
	HasOverlap   bool                  `json:"has_overlap"`
	TLSHDistance int                   `json:"tlsh_distance"`
	HasTLSH      bool                  `json:"has_tlsh"`
	SSDeepScore  int                   `json:"ssdeep_score"`
	HasSSDeep    bool                  `json:"has_ssdeep"`
}

// Disassembly summarises the bounded code-pattern pass of the deep profile.
// It is a linear sweep over executable bytes, not a recovered program: it
// finds instruction idioms, and every site is a heuristic observation.
type Disassembly struct {
	Arch         string         `json:"arch"`
	Bytes        int            `json:"bytes_examined"`
	Instructions int            `json:"instructions"`
	Truncated    bool           `json:"truncated,omitempty"`
	Skipped      string         `json:"skipped,omitempty"` // why nothing was examined
	Counts       map[string]int `json:"counts"`
	Sites        []DisasmSite   `json:"sites"`
}

// DisasmSite is one place where an idiom was seen.
type DisasmSite struct {
	Kind     string `json:"kind"` // peb-access | peb-ldr-walk | api-hash-ror13 | state-dispatcher
	Offset   int64  `json:"file_offset"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence,omitempty"`
}

// Reverse is what an external reverse-engineering engine (radare2) reported
// for the -r profile. Addresses are virtual addresses in the engine's view of
// the loaded image, not file offsets. Everything here is the engine's output,
// parsed strictly; it is as trustworthy as that engine's analysis of a possibly
// hostile file.
type Reverse struct {
	Engine    string        `json:"engine"`
	Version   string        `json:"version,omitempty"`
	Skipped   string        `json:"skipped,omitempty"` // why nothing was run
	Functions int           `json:"functions"`
	Entry     string        `json:"entry_function,omitempty"`
	Largest   []ReverseFunc `json:"largest_functions,omitempty"`
	CallSites []ReverseCall `json:"call_sites,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

// ReverseFunc is a function the engine discovered.
type ReverseFunc struct {
	Name   string `json:"name"`
	VA     uint64 `json:"va"`
	Size   int    `json:"size"`
	Blocks int    `json:"basic_blocks"`
}

// ReverseCall is a place in the code that refers to an imported API.
type ReverseCall struct {
	API      string `json:"api"`
	Library  string `json:"library,omitempty"`
	Function string `json:"function,omitempty"` // the function containing the reference
	FuncVA   uint64 `json:"function_va,omitempty"`
	At       uint64 `json:"at_va"`
	Kind     string `json:"kind"` // call | jump | data
	// ViaThunk is set when the reference reaches the API through a small stub
	// function (Delphi and some linkers call imports through a table of
	// one-instruction jump stubs); Function is then the caller of the stub.
	ViaThunk bool   `json:"via_thunk,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}
