// Package yarasuggest drafts a candidate YARA rule from an analysis report.
//
// It is an assistant, not an oracle. It chooses features that are specific to
// the sample as far as the report can tell (recovered hidden strings,
// indicators, unusual long strings), refuses to write a rule when there is not
// enough to go on, and says plainly what it could not check. A draft must be
// tested against clean files before anyone relies on it; the test helpers in
// internal/yara exist for that, and the CLI runs them.
//
// Drafts never use raw code bytes: they are brittle across rebuilds and easy to
// get wrong. Strings are written with explicit escapes so a hostile sample
// cannot inject rule syntax.
package yarasuggest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Options tune the draft.
type Options struct {
	Name       string // rule identifier; default derived from the SHA-256
	MaxStrings int    // default 8
	Imphash    bool   // add a PE import-hash alternative
	Version    string // tool version recorded in the rule
}

// Feature is a string chosen for the rule, with the reason it was chosen.
type Feature struct {
	ID       string // $s1, $x1 ...
	Text     string
	Modifier string // "ascii", "wide" or "xor"
	Why      string
	Score    float64
	Evidence string
}

// Dropped is a candidate that was not used, and why.
type Dropped struct {
	Text string
	Why  string
}

// Suggestion is the draft and how it was made.
type Suggestion struct {
	Name      string
	Rule      string
	Features  []Feature
	Dropped   []Dropped
	Required  int // how many of the strings the condition asks for
	Warnings  []string
	SHA256    string
	Condition string
}

// ErrNotEnough is returned when the report offers too little to build a
// specific rule.
type ErrNotEnough struct{ Reason string }

func (e *ErrNotEnough) Error() string {
	return "not enough distinctive features for a rule: " + e.Reason
}

type cand struct {
	text, mod, why, ev string
	score              float64
	strong             bool // an indicator or recovered string: specific on its own
}

// Build drafts a rule for the report's sample.
func Build(r *models.Report, o Options) (*Suggestion, error) {
	if r == nil || r.Analysis == nil {
		return nil, &ErrNotEnough{"the sample has no content analysis (run it without --modules restrictions)"}
	}
	if o.MaxStrings <= 0 || o.MaxStrings > 16 {
		o.MaxStrings = 8
	}
	sha := r.File.Hashes.SHA256
	name := o.Name
	if name == "" {
		name = "unpackr_" + safeID(sha, 12)
	}
	if !validIdent(name) {
		return nil, fmt.Errorf("%q is not a valid rule name (letters, digits and underscores, not starting with a digit)", name)
	}

	var cands []cand
	var dropped []Dropped
	seen := map[string]bool{}
	add := func(c cand) {
		if why := reject(c.text, c.strong); why != "" {
			if len(dropped) < 40 {
				dropped = append(dropped, Dropped{c.text, why})
			}
			return
		}
		key := c.mod + "\x00" + c.text
		if seen[key] {
			return
		}
		seen[key] = true
		cands = append(cands, c)
	}

	a := r.Analysis
	// 1. Strings recovered from an encoded form: the best features, because the
	// plain string scan (and most rules) cannot see them.
	for _, d := range a.Decoded {
		switch d.Method {
		case "xor":
			add(cand{text: d.Text, mod: "xor", strong: true, score: 12 + lenScore(d.Text),
				why: fmt.Sprintf("hidden string recovered under single-byte XOR key %s; the xor modifier matches it under any key", d.Key), ev: d.Evidence})
		default:
			dropped = append(dropped, Dropped{d.Text, fmt.Sprintf("%s-encoded text cannot be written as a YARA string modifier", d.Method)})
		}
	}
	// 2. Indicators.
	for _, in := range a.Indicators {
		mod := "ascii"
		if strings.Contains(in.Encoding, "utf16") {
			mod = "wide"
		}
		if strings.HasPrefix(in.Encoding, "decoded:") {
			continue // covered by the recovered string itself
		}
		if note := strings.ToLower(in.Note); strings.Contains(note, "loopback") || strings.Contains(note, "private") || strings.Contains(note, "link-local") || strings.Contains(note, "version number") || strings.Contains(note, "boilerplate") {
			dropped = append(dropped, Dropped{in.Value, "indicator is local, private, ambiguous or library boilerplate"})
			continue
		}
		bonus := map[string]float64{"url": 8, "domain": 6, "ipv4": 5, "email": 5, "registry": 5, "command": 4, "windows-path": 2, "unix-path": 1}[in.Type]
		if bonus == 0 {
			continue
		}
		add(cand{text: in.Value, mod: mod, strong: bonus >= 5, score: bonus + lenScore(in.Value), why: in.Type + " indicator in the sample", ev: ""})
	}
	// 3. Long, unusual strings.
	for _, s := range a.Strings.Shown {
		mod := "ascii"
		if s.Encoding == "utf16le" {
			mod = "wide"
		}
		add(cand{text: s.Text, mod: mod, score: lenScore(s.Text) + varietyScore(s.Text), why: "long string that does not look like library boilerplate"})
	}

	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].text < cands[j].text
	})
	// Anchor on specific features when there are any. Ordinary strings only add
	// false positives to a rule that already has something specific to hold on to
	// (a draft padded with compiler start-up symbols matched clean files built
	// with the same compiler), so they are used only when nothing specific exists.
	strongN := 0
	for _, c := range cands {
		if c.strong {
			strongN++
		}
	}
	pool := cands
	if strongN > 0 {
		pool = pool[:0:0]
		for _, c := range cands {
			if c.strong {
				pool = append(pool, c)
			} else if len(dropped) < 40 {
				dropped = append(dropped, Dropped{c.text, "not needed: the rule is anchored on a specific feature, and ordinary strings only add false positives"})
			}
		}
	}
	// Do not keep a string that is wholly contained in a better one already chosen.
	var chosen []cand
	for _, c := range pool {
		redundant := false
		for _, k := range chosen {
			if k.mod == c.mod && strings.Contains(k.text, c.text) {
				redundant = true
				break
			}
		}
		if redundant {
			if len(dropped) < 40 {
				dropped = append(dropped, Dropped{c.text, "contained in a better candidate"})
			}
			continue
		}
		chosen = append(chosen, c)
		if len(chosen) == o.MaxStrings {
			break
		}
	}
	if strongN == 0 && len(chosen) < 3 {
		return nil, &ErrNotEnough{fmt.Sprintf("%d usable string(s) found and none is an indicator or a recovered hidden string; a rule built on ordinary strings needs at least three, and would still need testing against clean files", len(chosen))}
	}

	s := &Suggestion{Name: name, SHA256: sha, Dropped: dropped}
	for i, c := range chosen {
		id := fmt.Sprintf("$s%d", i+1)
		if c.mod == "xor" {
			id = fmt.Sprintf("$x%d", i+1)
		}
		s.Features = append(s.Features, Feature{ID: id, Text: c.text, Modifier: c.mod, Why: c.why, Score: c.score, Evidence: c.ev})
	}
	switch {
	case len(chosen) == 1:
		s.Required = 1
	case strongN > 0:
		// Several specific features: asking for two keeps one coincidental
		// match (a shared hosting domain, say) from being enough.
		s.Required = 2
	default:
		s.Required = min(len(chosen), max(2, (len(chosen)*6+9)/10)) // 60%, at least two
	}
	hidden := false
	for _, c := range chosen {
		hidden = hidden || c.mod == "xor"
	}
	if strongN > 0 && !hidden {
		s.Warnings = append(s.Warnings, "no hidden string was recovered, so the rule rests on indicators found as plain text; legitimate software contains URLs and domains too, and a rule on them identifies a project or vendor as readily as malware")
	}
	if strongN == 0 {
		s.Warnings = append(s.Warnings, "no indicator or hidden string was found, so the rule rests on ordinary strings only; test it against clean files before use")
	}
	header, size := headerCondition(r)
	if header == "" {
		s.Warnings = append(s.Warnings, "the file type could not be determined, so the rule has no header check")
	}
	s.Condition = buildCondition(header, size, s.Required, s.Features, r, o)
	if o.Imphash && r.Binary != nil && r.Binary.ImportHash != "" && strings.HasPrefix(r.Binary.Format, "PE") {
		s.Warnings = append(s.Warnings, "the import-hash alternative matches every file with the same imports (often the same build tool or library), not only this family")
	}
	s.Rule = render(s, r, o)
	return s, nil
}

// reject explains why a string is not a good rule feature, or returns "".
func reject(t string, strong bool) string {
	n := len(t)
	switch {
	case n < 6 || (n < 8 && !strong):
		return "too short to be specific"
	case n > 200:
		return "too long"
	}
	for i := 0; i < n; i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return "contains non-printable or non-ASCII characters"
		}
	}
	if strong {
		return ""
	}
	alnum := 0
	for i := 0; i < n; i++ {
		c := t[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			alnum++
		}
	}
	if alnum*10 < n*6 {
		return "mostly punctuation"
	}
	low := strings.ToLower(t)
	for _, b := range boilerplate {
		if strings.Contains(low, b) {
			return "looks like library or compiler boilerplate (" + b + ")"
		}
	}
	if strings.Count(t, " ") > 6 {
		return "looks like prose (message text), which clean programs share"
	}
	return ""
}

// boilerplate lists fragments common to compilers, runtimes and the system.
var boilerplate = []string{
	"runtime.", "glibc", "gcc:", "gnu c", "libc.", "libstdc", ".so.", "/usr/", "/lib/", "/etc/", "/proc/", "/sys/", "_zn", "std::", "__cxa", "__gmon", "_init", "_fini",
	"go.buildid", "go:", "type:", ".go", "internal/", "vendor/", "golang.org", "github.com/", "github.io", "rust_", "core::", "alloc::", ".rs", "cargo", "rustc",
	"kernel32", "ntdll", "user32", "advapi32", "msvcr", "vcruntime", "ucrtbase", "api-ms-win", "this program cannot be run", "microsoft", "windows", "mscoree", "mscorlib", "system.", ".dll",
	".text", ".data", ".rdata", ".bss", ".idata", ".reloc", ".rsrc", ".pdata", ".tls", ".plt", ".got",
	"_itm_", "global_offset", "do_global", "stdin_used", "tm_clones", "frame_dummy", "abi-tag", ".note", ".eh_", "_dl_", "dso_handle", "data_start", "libc_", "init_array",
	"fini_array", ".symtab", ".strtab", ".shstrtab", ".interp", ".rela", ".dynsym", ".dynstr", ".dynamic", ".gnu", "gnu_", "_start", "_edata", "_end", "completed.", "unknown error", "invalid argument", "permission denied", "no such file",
	"%s", "%d", "%x", "usage:", "error:", "warning:", "failed to", "cannot ", "could not", "version", "copyright", "license", "http://www.w3.org", "schemas.microsoft", "xmlns",
}

func lenScore(s string) float64 { return float64(min(len(s), 48)) / 12 }

func varietyScore(s string) float64 {
	var upper, lower, digit, other bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			other = true
		}
	}
	n := 0.0
	for _, b := range []bool{upper, lower, digit, other} {
		if b {
			n += 0.5
		}
	}
	return n
}

func headerCondition(r *models.Report) (string, int64) {
	size := r.File.Size
	if size > 0 {
		// Allow growth from rebuilds and appended data: round up generously.
		size = (size*2 + 4095) &^ 4095
	}
	f := ""
	if r.Binary != nil {
		f = r.Binary.Family()
	}
	switch f {
	case "pe":
		return "uint16(0) == 0x5A4D", size
	case "elf":
		return "uint32(0) == 0x464C457F", size
	case "macho":
		return "(uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA or uint32(0) == 0xCAFEBABE or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE)", size
	}
	return "", size
}

func buildCondition(header string, size int64, req int, fs []Feature, r *models.Report, o Options) string {
	var parts []string
	if header != "" {
		parts = append(parts, header)
	}
	if size > 0 {
		parts = append(parts, fmt.Sprintf("filesize < %d", size))
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	switch {
	case len(fs) == 1:
		parts = append(parts, fs[0].ID)
	case req == len(fs):
		parts = append(parts, "all of them")
	default:
		parts = append(parts, fmt.Sprintf("%d of (%s)", req, strings.Join(ids, ", ")))
	}
	cond := strings.Join(parts, " and ")
	if o.Imphash && r.Binary != nil && r.Binary.ImportHash != "" && strings.HasPrefix(r.Binary.Format, "PE") {
		cond = "(" + cond + ") or (" + strings.Join(parts[:len(parts)-1], " and ") + fmt.Sprintf(" and pe.imphash() == %q)", strings.ToLower(r.Binary.ImportHash))
	}
	return cond
}

func render(s *Suggestion, r *models.Report, o Options) string {
	var b strings.Builder
	b.WriteString("// Candidate rule drafted by UNPACKR from one sample. It is a starting point:\n")
	b.WriteString("// review every string, and test it against clean files before relying on it.\n")
	for _, w := range s.Warnings {
		b.WriteString("// NOTE: " + oneLine(w) + "\n")
	}
	if o.Imphash && r.Binary != nil && r.Binary.ImportHash != "" && strings.HasPrefix(r.Binary.Format, "PE") {
		b.WriteString("import \"pe\"\n")
	}
	fmt.Fprintf(&b, "rule %s {\n    meta:\n", s.Name)
	b.WriteString("        description = \"Candidate rule drafted by UNPACKR; review and test before use\"\n")
	fmt.Fprintf(&b, "        sha256 = %s\n", quote(s.SHA256))
	b.WriteString("        status = \"experimental\"\n")
	if o.Version != "" {
		fmt.Fprintf(&b, "        generated_by = %s\n", quote("unpackr "+o.Version))
	}
	b.WriteString("    strings:\n")
	for _, f := range s.Features {
		fmt.Fprintf(&b, "        // %s\n", oneLine(f.Why))
		fmt.Fprintf(&b, "        %s = %s %s\n", f.ID, quote(f.Text), f.Modifier)
	}
	b.WriteString("    condition:\n        " + s.Condition + "\n}\n")
	return b.String()
}

// quote writes s as a YARA string literal. Only printable ASCII reaches this;
// backslash and the quote are escaped and anything else would be written as
// \xNN, so a sample cannot add syntax to the rule.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func safeID(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'f' || r >= '0' && r <= '9' || r >= 'A' && r <= 'F' {
			b.WriteRune(r)
		}
		if b.Len() == n {
			break
		}
	}
	if b.Len() == 0 {
		return "sample"
	}
	return b.String()
}

func validIdent(s string) bool {
	if s == "" || len(s) > 128 || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
