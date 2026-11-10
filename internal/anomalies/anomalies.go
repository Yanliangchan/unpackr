// Package anomalies catalogues structural oddities in executables. Each entry
// states a fact about the file and explains why it is notable and where it is
// common and harmless, so an analyst can weigh it instead of obeying a
// colour. An anomaly is not a verdict: crafted files show them, and so do
// unusual-but-legitimate toolchains.
package anomalies

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

type collector struct {
	in  *analysis.Input
	out []models.Anomaly
}

func (c *collector) add(id, title, why, benign string, sev models.Severity, evKind, evValue string, off, length int64, section string) {
	ev := c.in.Sink.Add(evKind, evValue, off, length, section, "anomaly/"+id, "anomaly:"+id)
	c.out = append(c.out, models.Anomaly{ID: id, Title: title, Why: why, Benign: benign, Severity: sev, Evidence: []string{ev}})
}

// Detect runs the catalogue for the input's format.
func Detect(in *analysis.Input) []models.Anomaly {
	c := &collector{in: in}
	b := in.Bin
	if b == nil {
		return []models.Anomaly{}
	}
	switch b.Family() {
	case "pe":
		c.pe()
	case "elf":
		c.elf()
	case "macho":
		c.macho()
	}
	c.overlay()
	c.hostileStructures()
	if c.out == nil {
		return []models.Anomaly{}
	}
	return c.out
}

func attrInt(b *models.Binary, k string) uint64 {
	v, _ := strconv.ParseUint(b.Attributes[k], 10, 64)
	return v
}

func alignUp(v, a uint64) uint64 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

func (c *collector) pe() {
	b := c.in.Bin
	fileSize := uint64(len(c.in.Data))
	fileAlign, secAlign := attrInt(b, "file_alignment"), attrInt(b, "section_alignment")
	tiny := fileAlign != 0 && fileAlign == secAlign && secAlign < 0x1000 // low-alignment images pack sections tightly by design

	nameCount := map[string]int{}
	for _, s := range b.Sections {
		nameCount[s.Name]++
	}
	var lastVEnd uint64
	for i, s := range b.Sections {
		off := int64(s.RawOffset)
		if s.Perms == "rwx" {
			c.add("pe.section.writable-executable", fmt.Sprintf("Section %s is writable and executable", s.Name),
				"Code that can be rewritten while it runs is how unpackers, injectors and self-modifying code work, and it defeats memory protections that assume code is read-only.",
				"Some JIT engines, old linkers and installers produce it.", models.SeverityMedium, "section", s.Name+" "+s.Perms, off, int64(s.RawSize), s.Name)
		}
		if strings.Contains(s.Perms, "x") && s.Kind != "code" {
			switch strings.ToLower(s.Name) {
			case ".data", ".rdata", ".rsrc", ".bss", ".idata", ".edata", ".reloc", ".pdata", ".xdata":
				c.add("pe.section.executable-data-section", fmt.Sprintf("Data section %s is marked executable", s.Name),
					"Sections named for data are normally not executable. Marking one executable lets bytes stored as data be run as code.",
					"A few linkers mark merged sections executable.", models.SeverityMedium, "section", s.Name+" "+s.Perms, off, int64(s.RawSize), s.Name)
			}
		}
		if s.Name == "" {
			c.add("pe.section.empty-name", fmt.Sprintf("Section %d has no name", i), "Compilers always name sections. A blank name is typical of crafted or post-processed files.", "Minimal hand-made test files.", models.SeverityLow, "section", fmt.Sprintf("section %d unnamed", i), off, 0, "")
		} else if !printable(s.Name) {
			c.add("pe.section.unprintable-name", fmt.Sprintf("Section %d name contains non-printable bytes", i), "Toolchains use readable names; control or high bytes suggest a packer or deliberate obfuscation.", "", models.SeverityMedium, "section", fmt.Sprintf("%q", s.Name), off, 0, "")
		}
		if nameCount[s.Name] > 1 && s.Name != "" {
			nameCount[s.Name] = 0 // report once
			c.add("pe.section.duplicate-name", fmt.Sprintf("Several sections are named %s", s.Name), "Linkers merge sections of the same name. Duplicates imply the table was edited or built by hand.", "", models.SeverityLow, "section", s.Name, off, 0, s.Name)
		}
		if s.RawSize > 0 && s.RawOffset+s.RawSize > fileSize {
			c.add("pe.section.beyond-end-of-file", fmt.Sprintf("Section %s claims data past the end of the file", s.Name),
				"The section header says more bytes exist than the file contains. The file is truncated, or the header was altered; loaders handle this inconsistently, which crafted files exploit.",
				"A download that was cut off.", models.SeverityMedium, "section", fmt.Sprintf("%s: raw 0x%x+0x%x, file is 0x%x", s.Name, s.RawOffset, s.RawSize, fileSize), off, int64(s.RawSize), s.Name)
		}
		if !tiny && s.RawSize > 0 && fileAlign != 0 && s.RawOffset%fileAlign != 0 {
			c.add("pe.section.raw-offset-unaligned", fmt.Sprintf("Section %s starts at 0x%x, not a multiple of the file alignment 0x%x", s.Name, s.RawOffset, fileAlign),
				"Linkers align section data to the file alignment. Misalignment is rare in compiler output and common in hand-edited or protected files.",
				"", models.SeverityLow, "section", fmt.Sprintf("%s raw offset 0x%x", s.Name, s.RawOffset), off, 0, s.Name)
		}
		if end := s.VirtualAddress + maxU(s.VirtualSize, s.RawSize); end > lastVEnd {
			lastVEnd = end
		}
		for j := 0; j < i; j++ {
			o := b.Sections[j]
			if overlap(s.VirtualAddress, maxU(s.VirtualSize, 1), o.VirtualAddress, maxU(o.VirtualSize, 1)) {
				c.add("pe.section.virtual-overlap", fmt.Sprintf("Sections %s and %s overlap in memory", o.Name, s.Name),
					"Two sections mapped at the same addresses means one overwrites the other when loaded. Compilers never produce this; crafted files use it to hide content from tools that read the file naively.",
					"", models.SeverityMedium, "section", o.Name+" / "+s.Name, off, 0, s.Name)
			}
			if s.RawSize > 0 && o.RawSize > 0 && overlap(s.RawOffset, s.RawSize, o.RawOffset, o.RawSize) {
				c.add("pe.section.raw-overlap", fmt.Sprintf("Sections %s and %s share bytes in the file", o.Name, s.Name),
					"Sections normally occupy separate file ranges. Sharing bytes lets the same data appear in two places, which is unusual outside hand-built files.",
					"", models.SeverityMedium, "section", o.Name+" / "+s.Name, off, 0, s.Name)
			}
		}
	}
	// SizeOfImage consistency.
	if soi := attrInt(b, "size_of_image"); soi != 0 && len(b.Sections) > 0 && secAlign != 0 {
		if want := alignUp(lastVEnd, secAlign); soi < lastVEnd {
			c.add("pe.header.size-of-image-too-small", fmt.Sprintf("SizeOfImage 0x%x is smaller than the end of the last section 0x%x", soi, lastVEnd),
				"The loader maps SizeOfImage bytes. If sections extend past it, some are not fully mapped. Linkers always compute it correctly.", "", models.SeverityMedium, "header", fmt.Sprintf("SizeOfImage=0x%x, sections end at 0x%x", soi, lastVEnd), -1, 0, "")
		} else if soi != want && soi > want+secAlign {
			c.add("pe.header.size-of-image-padded", fmt.Sprintf("SizeOfImage 0x%x is far larger than the sections need (0x%x)", soi, want),
				"A reserved but unused memory tail is where some packers unpack to or stage code.", "Some linkers reserve space deliberately.", models.SeverityLow, "header", fmt.Sprintf("SizeOfImage=0x%x, expected 0x%x", soi, want), -1, 0, "")
		}
	}
	if soh := attrInt(b, "size_of_headers"); soh != 0 {
		for _, s := range b.Sections {
			if s.RawSize > 0 && s.RawOffset < soh {
				c.add("pe.section.overlaps-headers", fmt.Sprintf("Section %s begins at 0x%x inside the headers (SizeOfHeaders 0x%x)", s.Name, s.RawOffset, soh),
					"Headers and section data should not share bytes. Overlap is characteristic of tiny hand-crafted PE files.", "Minimal test executables.", models.SeverityLow, "section", s.Name, int64(s.RawOffset), 0, s.Name)
				break
			}
		}
	}
	// Entry point.
	if e := b.Entry; e != nil {
		switch {
		case e.Section == "" && len(b.Sections) > 0:
			c.add("pe.entry.outside-sections", fmt.Sprintf("Entry point RVA 0x%x is not inside any section", e.RVA),
				"Execution would start in memory the file does not back with section data. Packers and crafted files do this; compilers do not.", "Entry in the headers of tiny hand-made files.", models.SeverityHigh, "entry-point", fmt.Sprintf("RVA 0x%x", e.RVA), -1, 0, "")
		case e.Section != "":
			for _, s := range b.Sections {
				if s.Name == e.Section && !strings.Contains(s.Perms, "x") {
					c.add("pe.entry.non-executable-section", fmt.Sprintf("Entry point lies in %s, which is not marked executable", s.Name),
						"With data execution prevention the program would fault on its first instruction unless the loader treats the section as executable. This points to altered section flags.", "", models.SeverityMedium, "entry-point", fmt.Sprintf("%s %s", s.Name, s.Perms), -1, 0, s.Name)
				}
			}
			if n := len(b.Sections); n >= 3 && e.Section == b.Sections[n-1].Name {
				switch strings.ToLower(e.Section) {
				case ".text", "code":
				default:
					c.add("pe.entry.in-last-section", fmt.Sprintf("Entry point is in the last section (%s)", e.Section),
						"Compilers start programs in the first code section. A start in the last section is where stubs added after the fact usually sit.", "Some linkers place code last.", models.SeverityMedium, "entry-point", e.Section, -1, 0, e.Section)
				}
			}
		}
	}
	// Timestamp.
	switch ts := b.CompiledAt; ts {
	case "":
		c.add("pe.header.timestamp-zero", "The header timestamp is zero", "Reproducible-build toolchains zero it on purpose, and forgers blank it. It cannot be used to date the file.", "Go and other reproducible builds.", models.SeverityInfo, "header", "TimeDateStamp=0", -1, 0, "")
	default:
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			if t.After(time.Now().Add(48 * time.Hour)) {
				c.add("pe.header.timestamp-future", "The header timestamp is in the future ("+ts+")", "A build time later than now means the field was forged or the clock was wrong. Do not use it for attribution.", "Builder clock errors.", models.SeverityLow, "header", ts, -1, 0, "")
			} else if t.Year() < 1993 {
				c.add("pe.header.timestamp-implausible", "The header timestamp predates the PE format ("+ts+")", "PE files did not exist before 1993, so this value is a placeholder or forged.", "", models.SeverityLow, "header", ts, -1, 0, "")
			}
		}
	}
	if b.Attributes["dos_stub_message"] == "false" {
		c.add("pe.header.no-dos-stub-message", "The DOS stub has no \"This program\" message", "Microsoft's linker always writes one. Its absence indicates a different toolchain or a rewritten header.", "Other linkers, tiny PE files.", models.SeverityInfo, "header", "DOS stub text not found in the first 1 KiB", 0, 0, "")
	}
	if n := attrInt(b, "tls_callbacks"); n > 0 {
		c.add("pe.tls.callbacks", fmt.Sprintf("%d TLS callback(s) run before the entry point", n), "Callbacks execute before the main entry point, where debuggers usually break. Anti-debugging and early-stage code sometimes hide there.", "The C runtime uses TLS callbacks for thread-local destructors.", models.SeverityLow, "tls", fmt.Sprintf("%d callbacks", n), -1, 0, "")
	}
	// Imports.
	total, ordinal := 0, 0
	libs := map[string]int{}
	for _, im := range b.Imports {
		if im.Delay {
			continue
		}
		libs[strings.ToLower(im.Library)]++
		for _, f := range im.Functions {
			total++
			if f.ByOrdinal {
				ordinal++
			}
		}
	}
	if b.Kind == "executable" && total == 0 && len(b.Sections) > 0 && b.Attributes["has_clr_header"] != "true" {
		c.add("pe.imports.none", "The executable imports nothing", "Every program needs the operating system. With no imports it must find APIs itself by walking loader structures, which shellcode and protectors do.", "Tiny test programs that use only system calls.", models.SeverityMedium, "imports", "import table empty or absent", -1, 0, "")
	}
	if total >= 10 && ordinal*2 >= total {
		c.add("pe.imports.mostly-ordinals", fmt.Sprintf("%d of %d imports are by ordinal", ordinal, total), "Ordinals hide API names from simple inspection. Compilers import by name except for a few undocumented functions.", "Older software and some system DLL consumers.", models.SeverityLow, "imports", fmt.Sprintf("%d/%d", ordinal, total), -1, 0, "")
	}
	for lib, n := range libs {
		if n > 1 {
			c.add("pe.imports.duplicate-library", fmt.Sprintf("%s is listed %d times in the import table", lib, n), "Linkers emit one entry per library. Duplicates come from edited import tables.", "Some protectors and merged images.", models.SeverityLow, "imports", lib, -1, 0, "")
			break
		}
	}
}

func (c *collector) elf() {
	b := c.in.Bin
	fileSize := uint64(len(c.in.Data))
	for _, s := range b.Segments {
		isLoad := strings.HasPrefix(s.Name, "LOAD")
		switch {
		case isLoad && s.Perms == "rwx":
			c.add("elf.segment.writable-executable", fmt.Sprintf("Segment %s is writable and executable", s.Name), "Memory that is both writable and executable allows code to be rewritten at run time and weakens exploit mitigations.", "Some packed binaries and JIT hosts.", models.SeverityMedium, "segment", s.Name+" "+s.Perms, int64(s.RawOffset), int64(s.RawSize), "")
		case strings.HasPrefix(s.Name, "GNU_STACK") && strings.Contains(s.Perms, "x"):
			c.add("elf.stack.executable", "The stack is marked executable", "An executable stack lets injected data run as code; modern toolchains disable it by default.", "Legacy code, some assembly programs and trampolines.", models.SeverityMedium, "segment", s.Name+" "+s.Perms, -1, 0, "")
		}
		if s.RawSize > 0 && s.RawOffset+s.RawSize > fileSize {
			c.add("elf.segment.beyond-end-of-file", fmt.Sprintf("Segment %s claims data past the end of the file", s.Name), "The program header says more bytes exist than the file contains: truncation or an altered header.", "A download that was cut off.", models.SeverityMedium, "segment", s.Name, int64(s.RawOffset), int64(s.RawSize), "")
		}
	}
	if e := b.Entry; e != nil {
		inExec := false
		for _, s := range b.Segments {
			if strings.HasPrefix(s.Name, "LOAD") && e.VA >= s.VirtualAddress && e.VA < s.VirtualAddress+s.VirtualSize {
				inExec = strings.Contains(s.Perms, "x")
				if !inExec {
					c.add("elf.entry.non-executable-segment", "Entry point is in a segment that is not executable", "Execution would fault on the first instruction, which points to altered segment flags.", "", models.SeverityMedium, "entry-point", fmt.Sprintf("0x%x in %s %s", e.VA, s.Name, s.Perms), -1, 0, "")
				}
				goto entryDone
			}
		}
		if len(b.Segments) > 0 && b.Kind != "library" && b.Kind != "object" {
			c.add("elf.entry.outside-segments", fmt.Sprintf("Entry point 0x%x is not inside any loadable segment", e.VA), "The program starts in memory that the file does not map.", "", models.SeverityHigh, "entry-point", fmt.Sprintf("0x%x", e.VA), -1, 0, "")
		}
	}
entryDone:
	if interp := b.Attributes["interpreter"]; interp != "" && !reInterp.MatchString(interp) {
		c.add("elf.interpreter.unusual", "Unusual dynamic loader path "+interp, "The interpreter field decides what loads the program. Distribution loaders live under /lib or /usr/lib; another path means a custom loader or a redirected one.", "Nix, Guix, cross-compiled and container images.", models.SeverityMedium, "header", interp, -1, 0, "")
	}
}

var reInterp = regexp.MustCompile(`^/(?:usr/)?(?:lib|lib32|lib64|libx32)(?:/[\w.+-]+)*/(?:ld-linux[\w.+-]*|ld-musl[\w.+-]*|ld\.so[\w.+-]*|ld-[\w.+-]+)$|^/system/bin/linker(?:64)?$`)

func (c *collector) macho() {
	b := c.in.Bin
	bins := []*models.Binary{b}
	if len(b.Slices) > 0 {
		bins = nil
		for i := range b.Slices {
			bins = append(bins, &b.Slices[i])
		}
	}
	for _, sl := range bins {
		for _, s := range sl.Segments {
			if s.Perms == "rwx" {
				c.add("macho.segment.writable-executable", fmt.Sprintf("Segment %s is writable and executable", s.Name), "Memory that is both writable and executable allows code to be rewritten at run time; Apple platforms restrict it.", "JIT hosts with the right entitlements.", models.SeverityMedium, "segment", s.Name+" "+s.Perms, int64(s.RawOffset), int64(s.RawSize), "")
			}
			if s.Name == "__TEXT" && strings.Contains(s.Perms, "w") {
				c.add("macho.text-writable", "The __TEXT segment is writable", "Code segments are mapped read-only. A writable one is a sign of self-modifying code or an edited file.", "", models.SeverityMedium, "segment", s.Name+" "+s.Perms, int64(s.RawOffset), int64(s.RawSize), "")
			}
		}
		if e := sl.Entry; e != nil && e.Section == "" && sl.Kind == "executable" {
			c.add("macho.entry.outside-sections", "Entry point is not inside any section", "The program starts in memory not described by a section.", "", models.SeverityMedium, "entry-point", fmt.Sprintf("0x%x", e.VA), -1, 0, "")
		}
	}
}

var overlayMagic = []struct {
	magic []byte
	what  string
}{
	{[]byte("MZ"), "a Windows executable"}, {[]byte("\x7fELF"), "an ELF executable"}, {[]byte("PK\x03\x04"), "a ZIP archive"},
	{[]byte("Rar!"), "a RAR archive"}, {[]byte("7z\xbc\xaf\x27\x1c"), "a 7-Zip archive"}, {[]byte("\x1f\x8b"), "a gzip stream"},
	{[]byte("%PDF-"), "a PDF"}, {[]byte("MSCF"), "a Cabinet archive"}, {[]byte("\xd0\xcf\x11\xe0"), "an OLE2 document"},
}

func (c *collector) overlay() {
	b := c.in.Bin
	if len(b.Slices) > 0 || b.Overlay == nil {
		return
	}
	o := b.Overlay
	total := int64(len(c.in.Data))
	if o.Offset >= 0 && o.Offset+4 <= total {
		head := c.in.Data[o.Offset:min64(o.Offset+8, total)]
		for _, m := range overlayMagic {
			if len(head) >= len(m.magic) && string(head[:len(m.magic)]) == string(m.magic) {
				c.add("file.overlay.embedded-file", fmt.Sprintf("Data appended after the program starts like %s", m.what),
					"Content stored after the last section is invisible to the loader but available to the program itself. Droppers and installers keep their payload this way.",
					"Self-extracting installers and signed files with certificates appended.", models.SeverityMedium, "overlay", fmt.Sprintf("%d bytes at 0x%x begin with %s", o.Size, o.Offset, m.what), o.Offset, o.Size, "")
				return
			}
		}
	}
	if o.Size >= 1<<20 && total > 0 && o.Size*4 >= total {
		c.add("file.overlay.large", fmt.Sprintf("%d bytes (%d%% of the file) follow the last section", o.Size, o.Size*100/total),
			"A large share of the file is outside the program structure. It may be an embedded payload, installer data or a certificate.", "Installers and files with Authenticode signatures.", models.SeverityLow, "overlay", fmt.Sprintf("0x%x+%d", o.Offset, o.Size), o.Offset, o.Size, "")
	}
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func maxU(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func overlap(a, al, b, bl uint64) bool { return a < b+bl && b < a+al }

// hostileStructures reports header tables that are broken in ways ordinary
// toolchains do not produce and that stall or mislead analysis tools. They are
// facts about the bytes; the parser has already bounded its own work on them.
func (c *collector) hostileStructures() {
	b := c.in.Bin
	if b == nil {
		return
	}
	has := func(sub string) (string, bool) {
		for _, a := range b.Anomalies {
			if strings.Contains(strings.ToLower(a), sub) {
				return a, true
			}
		}
		return "", false
	}
	if a, ok := has("export list truncated"); ok {
		c.add("pe.exports.flooded", fmt.Sprintf("The export table is enormous (%d entries read; the rest were not)", len(b.Exports)),
			"Programs do not normally export a hundred thousand names, least of all repeated ones. A flooded export table makes tools slow, exhausts their memory, and buries real exports, and some packers and file bloaters do it on purpose.",
			"Very large frameworks export tens of thousands of names; repeated entries are not normal.",
			models.SeverityMedium, "header", a, -1, 0, "")
	}
	if a, ok := has("thunk addressofdata beyond limits"); ok {
		c.add("pe.imports.unreadable", "Import table entries point outside the file",
			"The Windows loader and analysis tools read the import table differently when its entries are out of bounds, so a tool may report no imports for a program that has them, or fewer than the loader resolves. Imports-based findings are therefore unreliable for this file.",
			"Corrupted or truncated downloads.", models.SeverityMedium, "header", a, -1, 0, "")
	}
	if a, ok := has("lies outside the image"); ok {
		c.add("pe.directories.outside-image", "A data directory points outside the image",
			"The loader and analysis tools disagree about what such a file contains. A directory entry that is garbage (for example a .NET header address of about 1.4 billion in a 4 MB file) makes simple type checks, which trust the directory, misreport the file.",
			"A damaged or truncated file.", models.SeverityMedium, "header", a, -1, 0, "")
	}
	// A file that is mostly padding: a very low entropy over a large size.
	if e := c.in.Entropy; e != nil && len(c.in.Data) >= 16<<20 && e.File < 2.0 {
		c.add("file.mostly-padding", fmt.Sprintf("A %d MiB file with entropy %.2f bits per byte is mostly padding", len(c.in.Data)>>20, e.File),
			"Padding a file to tens of megabytes keeps it below no real size limit but above the limit many scanners and upload services apply, and it dilutes statistics such as entropy and string density.",
			"Debug builds, sparse installers and images with large uninitialised regions.", models.SeverityLow, "entropy", fmt.Sprintf("file entropy %.3f", e.File), -1, 0, "")
	}
}
