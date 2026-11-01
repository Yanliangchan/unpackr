// Package packing assesses whether an executable appears packed, protected or
// otherwise concealed. It combines independent signals; entropy is one input
// among several and can never produce a packed verdict on its own.
package packing

import (
	"fmt"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/confidence"
	"github.com/Yanliangchan/unpackr/internal/obfuscation"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Entropy above which an executable section is considered notable. It is a
// property of compressed or encrypted data, not proof of packing.
const HighEntropy = 7.2

// sectionNames maps (case-insensitive) section names to the tool that creates
// them by default. Section names are trivially renamed, so they are only a
// moderate signal.
var sectionNames = map[string]string{
	"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", "upx!": "UPX",
	".aspack": "ASPack", ".adata": "ASPack", "aspack": "ASPack",
	".themida": "Themida", ".winlice": "Themida / WinLicense",
	".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
	".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
	".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
	".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
	"pec1": "PECompact", "pec2": "PECompact", "pecompact2": "PECompact",
}

// byteSignatures are exact markers. They can be copied into a file, so they
// are strong rather than conclusive and still want corroboration.
var byteSignatures = []struct {
	name, label string
	needle      []byte
}{
	{"UPX", "UPX! header magic", []byte("UPX!")},
	{"UPX", "UPX stub banner", []byte("This file is packed with the UPX executable packer")},
	{"MPRESS", "MPRESS marker", []byte("MPRESS1")},
}

// obfuscatorMarkers are names that .NET protectors leave in metadata.
var obfuscatorMarkers = []string{"ConfusedByAttribute", "ObfuscatedByAgileDotNet", "Dotfuscator", "SmartAssembly", ".NET Reactor", "Eziriz", "ObfuscationAttribute", "BabelObfuscator", "CryptoObfuscator"}

type collector struct {
	in      *analysis.Input
	signals []models.Signal
	packer  map[string]int
}

func (c *collector) add(id, detail, strength, family string, ev ...string) {
	c.signals = append(c.signals, models.Signal{ID: id, Detail: detail, Strength: strength, Family: family, Evidence: ev})
}

func (c *collector) names(name string) {
	c.packer[name]++
}

// Assess runs every packing signal and combines them.
func Assess(in *analysis.Input) models.PackingAssessment {
	c := &collector{in: in, packer: map[string]int{}}
	out := models.PackingAssessment{Signals: []models.Signal{}}
	if in.Bin == nil {
		out.State, out.Confidence = models.PackUnknown, models.ConfidenceSpeculative
		out.Rationale = "executable structure could not be parsed, so packing cannot be assessed"
		return out
	}

	c.bytes()
	c.yara()
	c.sectionNameSignals()
	c.structure()
	c.entropy()
	c.dotnet()
	c.decoded()
	c.codePatterns()

	out.Signals = append(out.Signals, c.signals...)
	return c.verdict(out)
}

func (c *collector) bytes() {
	for _, sig := range byteSignatures {
		if off := c.in.FindBytes(sig.needle); off >= 0 {
			ev := c.in.Sink.Add("signature", sig.label, off, int64(len(sig.needle)), c.in.SectionAt(off), "packing/bytes/"+strings.ToLower(sig.name), "sig:"+sig.name)
			c.add("pack.sig."+strings.ToLower(sig.name), sig.label+" found", "strong", "sig:"+sig.name, ev)
			c.names(sig.name)
		}
	}
}

func (c *collector) yara() {
	for _, m := range c.in.TestedYara("packer") {
		fam := m.Family
		if fam == "" {
			fam = "yara:" + m.Rule
		}
		ev := c.in.YaraEvidence(m, fam)
		c.signals = analysis.MergeSignal(c.signals, models.Signal{
			ID: "pack.yara." + m.Rule, Detail: m.Description + " (YARA-X rule " + m.Rule + ")", Strength: m.Strength, Family: fam, Evidence: []string{ev},
		}, "also matched by YARA-X rule "+m.Rule)
		c.names(m.Name)
	}
}

func (c *collector) sectionNameSignals() {
	byPacker := map[string][]string{}
	evByPacker := map[string][]string{}
	var order []string
	seen := map[string]bool{}
	for _, s := range c.in.Bin.Sections {
		name, ok := sectionNames[strings.ToLower(s.Name)]
		if !ok || seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		if _, known := byPacker[name]; !known {
			order = append(order, name)
		}
		byPacker[name] = append(byPacker[name], s.Name)
		evByPacker[name] = append(evByPacker[name], c.in.Sink.Add("section-name", s.Name, int64(s.RawOffset), 0, s.Name, "packing/section-name/"+strings.ToLower(name), "name:"+name))
		c.names(name)
	}
	for _, name := range order {
		c.add("pack.section-name", fmt.Sprintf("section name(s) %s are the defaults used by %s (names are easily changed)", strings.Join(byPacker[name], ", "), name), "moderate", "name:"+name, evByPacker[name]...)
	}
}

func (c *collector) structure() {
	b := c.in.Bin
	// Entry point placement.
	if b.Entry != nil && b.Family() != "macho" {
		switch {
		case b.Entry.Section == "" && len(b.Sections) > 0:
			ev := c.in.Sink.Add("entry-point", fmt.Sprintf("entry RVA 0x%x lies outside every section", b.Entry.RVA), -1, 0, "", "packing/entry-outside", "structure:entry")
			c.add("pack.entry.outside", "entry point is not inside any section", "moderate", "structure:entry", ev)
		case len(b.Sections) >= 3 && b.Entry.Section == b.Sections[len(b.Sections)-1].Name && !isConventionalLast(b.Entry.Section):
			ev := c.in.Sink.Add("entry-point", "entry point is in the last section "+b.Entry.Section, -1, 0, b.Entry.Section, "packing/entry-last", "structure:entry")
			c.add("pack.entry.last-section", "entry point is in the last section, where stubs are commonly appended", "moderate", "structure:entry", ev)
		}
		if e := b.Entry.Section; e != "" {
			for _, s := range b.Sections {
				if s.Name == e && s.Perms == "rwx" {
					ev := c.in.Sink.Add("section", fmt.Sprintf("%s is readable, writable and executable", e), int64(s.RawOffset), int64(s.RawSize), e, "packing/entry-in-rwx", "structure:rwx")
					c.add("pack.entry.rwx", "entry point lies in a writable and executable section (self-modifying stubs need this)", "moderate", "structure:rwx", ev)
				}
			}
		}
	}
	// Executable section that has no file backing but a large memory image:
	// the classic in-place unpacking buffer.
	for _, s := range b.Sections {
		if b.Family() == "pe" && s.RawSize == 0 && s.VirtualSize >= 64*1024 && strings.Contains(s.Perms, "x") {
			ev := c.in.Sink.Add("section", fmt.Sprintf("%s: 0 bytes on disk, 0x%x bytes in memory, %s", s.Name, s.VirtualSize, s.Perms), int64(s.RawOffset), 0, s.Name, "packing/empty-exec-section", "structure:empty-exec")
			c.add("pack.empty-exec-section", "executable section with no file data but a large memory size: space to unpack into", "moderate", "structure:empty-exec", ev)
			break
		}
	}
	// RWX sections in general.
	for _, s := range b.Sections {
		if s.Perms == "rwx" {
			ev := c.in.Sink.Add("section", s.Name+" is rwx", int64(s.RawOffset), int64(s.RawSize), s.Name, "packing/rwx-section", "structure:rwx-any")
			c.add("pack.rwx-section", "section "+s.Name+" is readable, writable and executable (also seen in JIT and some legitimate code)", "weak", "structure:rwx-any", ev)
			break
		}
	}
	// Sparse imports with a runtime loader.
	if b.Family() == "pe" && len(b.Imports) > 0 && c.in.ImportCount() <= 8 && c.in.HasImport("GetProcAddress") && (c.in.HasImport("LoadLibraryA") || c.in.HasImport("LoadLibraryW") || c.in.HasImport("LoadLibraryExA") || c.in.HasImport("LoadLibraryExW")) {
		ev := c.in.Sink.Add("imports", fmt.Sprintf("%d imported symbols including GetProcAddress and LoadLibrary", c.in.ImportCount()), -1, 0, "", "packing/sparse-imports", "structure:imports")
		c.add("pack.sparse-imports", "very few imports, among them the pair needed to resolve everything else at run time", "moderate", "structure:imports", ev)
	}
	// ELF stub layout: a small loadable image that reserves far more memory
	// than it holds (room to unpack into), with no interpreter or dynamic
	// section. Packers that strip their own markers still leave this shape.
	if b.Family() == "elf" && len(b.Sections) == 0 && c.in.Bin.Attributes["interpreter"] == "" {
		for _, sg := range b.Segments {
			if sg.Kind == "segment" && strings.Contains(sg.Perms, "w") && sg.VirtualSize >= 3*sg.RawSize && sg.VirtualSize-sg.RawSize >= 8192 {
				ev := c.in.Sink.Add("segment", fmt.Sprintf("%s: %d bytes in the file, %d in memory, %s", sg.Name, sg.RawSize, sg.VirtualSize, sg.Perms), int64(sg.RawOffset), int64(sg.RawSize), "", "packing/elf-expanding-segment", "structure:elf-stub")
				c.add("pack.elf.expanding-segment", "writable segment that reserves much more memory than the file supplies, in a file with no section headers or interpreter (the layout of an in-memory unpacker)", "moderate", "structure:elf-stub", ev)
				break
			}
		}
	}
	// ELF/Mach-O with no section table.
	if b.Family() == "elf" && len(b.Sections) == 0 {
		ev := c.in.Sink.Add("header", "no section headers", -1, 0, "", "packing/no-section-headers", "structure:no-sections")
		c.add("pack.no-section-headers", "ELF file has no section header table (stripped by packers, but also by some build tools)", "moderate", "structure:no-sections", ev)
	}
}

func isConventionalLast(name string) bool {
	switch strings.ToLower(name) {
	case ".reloc", ".rsrc", ".tls", ".symtab", ".debug", ".bss", ".gopclntab":
		return true
	}
	return false
}

func (c *collector) entropy() {
	e := c.in.Entropy
	if e == nil {
		return
	}
	for _, s := range e.Sections {
		if s.Size >= 1024 && s.Entropy >= HighEntropy && strings.Contains(s.Perms, "x") {
			ev := c.in.Sink.Add("entropy", fmt.Sprintf("%s entropy %.2f", s.Name, s.Entropy), int64(s.Offset), int64(s.Size), s.Name, "packing/high-entropy-exec", "entropy")
			c.add("pack.entropy.exec-section", fmt.Sprintf("executable section %s has entropy %.2f (compressed or encrypted data scores above %.1f)", s.Name, s.Entropy, HighEntropy), "moderate", "entropy", ev)
			return
		}
	}
	if e.Overlay != nil && *e.Overlay >= HighEntropy && c.in.Bin.Overlay != nil && c.in.Bin.Overlay.Size >= 4096 {
		ev := c.in.Sink.Add("entropy", fmt.Sprintf("overlay entropy %.2f", *e.Overlay), c.in.Bin.Overlay.Offset, c.in.Bin.Overlay.Size, "", "packing/high-entropy-overlay", "entropy")
		strength, note := "weak", ""
		if total := int64(len(c.in.Data)); total > 0 && c.in.Bin.Overlay.Size*4 >= total && *e.Overlay >= 7.5 {
			// A large, near-random appended block is where a loader keeps an
			// encrypted payload. Compressed archives and signed installers look
			// the same, so this stays an entropy-family signal that cannot
			// decide the verdict alone.
			strength, note = "moderate", fmt.Sprintf("; it is %d%% of the file", c.in.Bin.Overlay.Size*100/total)
		}
		c.add("pack.entropy.overlay", fmt.Sprintf("appended data has entropy %.2f%s", *e.Overlay, note), strength, "entropy", ev)
	}
}

// codePatterns turns the deep profile's instruction idioms into signals. They
// are heuristics over short windows of linear disassembly, so each is at most
// moderate and none names a tool.
func (c *collector) codePatterns() {
	d := c.in.Disasm
	if d == nil || d.Skipped != "" {
		return
	}
	for _, spec := range []struct {
		kind, id, family, detail string
	}{
		{"peb-ldr-walk", "pack.code.peb-walk", "disasm:peb", "code reads the process environment block and walks its loaded-module list, finding modules without importing them"},
		{"api-hash-ror13", "pack.code.api-hash", "disasm:hash", "code contains the ror-13 name-hashing loop used to find API functions by hash"},
		{"state-dispatcher", "pack.code.flattening", "disasm:flatten", "code contains a dispatcher that compares many of the same large constants it stores, the shape of control-flow flattening"},
	} {
		n := d.Counts[spec.kind]
		if n == 0 {
			continue
		}
		var evs []string
		for _, st := range d.Sites {
			if st.Kind == spec.kind && st.Evidence != "" && len(evs) < 5 {
				evs = append(evs, st.Evidence)
			}
		}
		c.add(spec.id, fmt.Sprintf("%s (%d place(s))", spec.detail, n), "moderate", spec.family, evs...)
	}
}

// decoded turns recovered strings into signals. A string that decodes to a
// known marker under a single-byte key is direct evidence that content is
// kept encoded; a stack string is only counted when it contains such a marker,
// because compilers also build short constant arrays on the stack.
func (c *collector) decoded() {
	var evs []string
	n := map[string]int{}
	for _, d := range c.in.Decoded {
		if d.Evidence == "" {
			continue
		}
		if d.Method == "stack" && !hasMarker(d.Text) {
			continue
		}
		evs = append(evs, d.Evidence)
		n[d.Method]++
	}
	if len(evs) == 0 {
		return
	}
	var parts []string
	for _, m := range []string{"xor", "add", "base64", "stack"} {
		if n[m] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[m], m))
		}
	}
	c.add("pack.encoded-strings", "text is kept out of plain sight and was recovered ("+strings.Join(parts, ", ")+")", "moderate", "encoding", evs...)
}

func hasMarker(s string) bool {
	for _, m := range obfuscation.Markers() {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// dotnetMetadata turns the assembly's metadata statistics into signals. Each
// is a property of the file's tables; none is specific to one protector, and
// each says what it saw rather than naming a tool.
func (c *collector) dotnetMetadata() {
	dn := c.in.Bin.DotNet
	if dn == nil {
		return
	}
	n := dn.Names
	switch {
	case n.Total >= 50 && n.NonPrintable*4 >= n.Total:
		ev := c.in.Sink.Add("dotnet", fmt.Sprintf("%d of %d type, method and field names contain control or non-ASCII characters", n.NonPrintable, n.Total), -1, 0, "", "packing/dotnet-unreadable-names", "dotnet:names")
		c.add("pack.dotnet.unreadable-names", fmt.Sprintf("%d%% of the names in the metadata are unreadable (control or non-ASCII characters), the way renaming obfuscators leave them", n.NonPrintable*100/n.Total), "moderate", "dotnet:names", ev)
	case n.Total >= 100 && n.Tiny*10 >= n.Total*7:
		ev := c.in.Sink.Add("dotnet", fmt.Sprintf("%d of %d names are one or two characters long", n.Tiny, n.Total), -1, 0, "", "packing/dotnet-tiny-names", "dotnet:names")
		c.add("pack.dotnet.tiny-names", fmt.Sprintf("%d%% of the names in the metadata are one or two characters (compilers do not produce this; renaming tools do)", n.Tiny*100/n.Total), "weak", "dotnet:names", ev)
	}
	// An executable whose methods mostly have no IL in the file gets its code
	// from somewhere else at run time. Reference assemblies look the same but
	// have no entry point.
	if methods := dn.Counts["MethodDef"]; methods >= 20 && dn.EntryPoint != 0 && dn.MethodsWithoutBody*2 >= methods {
		ev := c.in.Sink.Add("dotnet", fmt.Sprintf("%d of %d methods have no IL body in the file", dn.MethodsWithoutBody, methods), -1, 0, "", "packing/dotnet-missing-bodies", "dotnet:bodies")
		c.add("pack.dotnet.missing-bodies", fmt.Sprintf("%d of %d methods that should contain code have none in the file: the code is supplied later (decrypted or loaded at run time)", dn.MethodsWithoutBody, methods), "moderate", "dotnet:bodies", ev)
	}
	for _, r := range dn.Resources {
		if r.External || r.Size < 32*1024 {
			continue
		}
		switch {
		case r.Kind == "pe":
			ev := c.in.Sink.Add("dotnet", fmt.Sprintf("resource %s (%d bytes) begins with an MZ header", r.Name, r.Size), int64(r.Offset), int64(r.Size), "", "packing/dotnet-embedded-pe", "dotnet:payload")
			c.add("pack.dotnet.embedded-executable", fmt.Sprintf("manifest resource %q is a Windows executable embedded in the assembly (loaders and installers do this; so do droppers)", r.Name), "moderate", "dotnet:payload", ev)
		case r.Entropy >= 7.5 && r.Size >= 64*1024:
			ev := c.in.Sink.Add("entropy", fmt.Sprintf("resource %s entropy %.2f, %d bytes", r.Name, r.Entropy, r.Size), int64(r.Offset), int64(r.Size), "", "packing/dotnet-encrypted-resource", "entropy")
			c.add("pack.dotnet.high-entropy-resource", fmt.Sprintf("manifest resource %q is %d bytes of near-random data (compressed or encrypted)", r.Name, r.Size), "weak", "entropy", ev)
		}
	}
}

func (c *collector) dotnet() {
	if c.in.Bin.Attributes["has_clr_header"] != "true" {
		return
	}
	c.dotnetMetadata()
	for _, m := range obfuscatorMarkers {
		if off := c.in.FindBytes([]byte(m)); off >= 0 {
			ev := c.in.Sink.Add("signature", ".NET obfuscator marker "+m, off, int64(len(m)), c.in.SectionAt(off), "packing/dotnet-obfuscator", "name:dotnet-"+m)
			c.add("pack.dotnet.marker", ".NET protector marker "+m+" present in the file", "moderate", "name:dotnet-"+m, ev)
			c.names(".NET obfuscator (" + m + ")")
			return
		}
	}
}

// verdict combines signals into a state. The rules, in order:
//  1. A strong packer signature plus an independent corroborating signal is
//     "confirmed-packed".
//  2. A strong signature alone, or two independent families with at least one
//     structural (non-entropy) signal, is "likely-packed".
//  3. Anything weaker, entropy alone included, is "unknown".
//  4. No signals on a parsed executable is "unpacked", with the explicit caveat
//     that absence of indicators is not proof.
func (c *collector) verdict(out models.PackingAssessment) models.PackingAssessment {
	sigs := c.signals
	families := map[string]bool{}
	nonEntropy := map[string]bool{}
	var strong []models.Signal
	for _, s := range sigs {
		families[s.Family] = true
		if s.Family != "entropy" {
			nonEntropy[s.Family] = true
		}
		if s.Strength == "strong" {
			strong = append(strong, s)
		}
	}
	// Recovered strings and code idioms say content is concealed; they are not
	// evidence that a packer compressed or encrypted the program, so the packed
	// verdicts are judged on the other signals only.
	var packSigs []models.Signal
	packFamilies, packNonEntropy := map[string]bool{}, map[string]bool{}
	for _, sg := range sigs {
		if sg.Family == "encoding" || strings.HasPrefix(sg.Family, "disasm:") {
			continue
		}
		packSigs = append(packSigs, sg)
		packFamilies[sg.Family] = true
		if sg.Family != "entropy" {
			packNonEntropy[sg.Family] = true
		}
	}
	best, bestN := "", 0
	for n, k := range c.packer {
		if k > bestN || (k == bestN && n < best) {
			best, bestN = n, k
		}
	}
	conf, why := confidence.Derive(sigs, 0)
	switch {
	case len(strong) > 0 && len(families) >= 2:
		out.State, out.Family = models.PackConfirmed, best
	case len(strong) > 0:
		out.State, out.Family = models.PackLikely, best
		out.Notes = append(out.Notes, "an exact signature was found but nothing independent corroborates it")
	case len(packFamilies) >= 2 && len(packNonEntropy) >= 1 && hasAtLeast(packSigs, "moderate", 2):
		out.State, out.Family = models.PackLikely, best
	case families["encoding"] || hasPrefixFamily(families, "disasm:"):
		// Concealed content was recovered, but nothing says the program body is
		// packed. The state says what was found and no more.
		out.State = models.PackObfuscated
		conf = models.ConfidenceMedium
		why = "stack-built text matched a known marker; assembled by byte pattern rather than disassembly"
		if !families["encoding"] {
			conf = models.ConfidenceLow
			why = "instruction patterns typical of API hashing, module walking or flattening were found by linear disassembly; these are heuristics"
		}
		for _, d := range c.in.Decoded {
			if d.Method != "stack" {
				conf = models.ConfidenceHigh
				why = "a known marker decodes exactly under a single-byte key, so the text really is stored encoded"
				break
			}
		}
		if families["encoding"] {
			out.Notes = append(out.Notes, "text is kept in a form the plain string scan does not see; only single-byte XOR/ADD, base64-embedded executables and stack-built strings are recovered, so other content may still be hidden")
		}
		if hasPrefixFamily(families, "disasm:") {
			out.Notes = append(out.Notes, "found by a bounded linear disassembly of the executable sections; idioms in code that was not reached, or obfuscation of other kinds, are not seen")
		}
	case len(sigs) > 0:
		out.State = models.PackUnknown
		out.Notes = append(out.Notes, "indicators exist but are not sufficient to call the file packed; entropy alone or a single structural oddity is never a verdict")
	default:
		out.State = models.PackUnpacked
		conf = models.ConfidenceLow
		why = "no packing indicators were found; absence of evidence does not prove a file is unpacked"
		if c.in.ImportCount() >= 10 || len(c.in.Bin.Libraries) > 0 {
			conf = models.ConfidenceMedium
			why = "no packing indicators found and the file has a normal-looking import structure; custom packers can still evade these checks"
		}
		out.Confidence, out.Rationale = conf, why
		return out
	}
	if out.State == models.PackUnknown {
		conf = models.ConfidenceSpeculative
		if len(nonEntropy) > 0 {
			conf = models.ConfidenceLow
		}
	}
	out.Confidence, out.Rationale = conf, why
	return out
}

func hasPrefixFamily(fam map[string]bool, prefix string) bool {
	for f := range fam {
		if strings.HasPrefix(f, prefix) {
			return true
		}
	}
	return false
}

// hasAtLeast counts signals of at least the given strength.
func hasAtLeast(sigs []models.Signal, strength string, n int) bool {
	rank := map[string]int{"weak": 0, "moderate": 1, "strong": 2}
	count := 0
	for _, s := range sigs {
		if rank[s.Strength] >= rank[strength] {
			count++
		}
	}
	return count >= n
}
