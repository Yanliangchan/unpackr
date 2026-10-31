// Package packing assesses whether an executable appears packed, protected or
// otherwise concealed. It combines independent signals; entropy is one input
// among several and can never produce a packed verdict on its own.
package packing

import (
	"fmt"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/confidence"
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
	c.sectionNameSignals()
	c.structure()
	c.entropy()
	c.dotnet()

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
		c.add("pack.entropy.overlay", fmt.Sprintf("appended data has entropy %.2f", *e.Overlay), "weak", "entropy", ev)
	}
}

func (c *collector) dotnet() {
	if c.in.Bin.Attributes["has_clr_header"] != "true" {
		return
	}
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
	case len(families) >= 2 && len(nonEntropy) >= 1 && hasAtLeast(sigs, "moderate", 2):
		out.State, out.Family = models.PackLikely, best
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
