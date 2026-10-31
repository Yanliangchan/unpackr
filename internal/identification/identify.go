// Package identification determines what a file is from its content. File
// names and extensions are never consulted. Every probe reports the
// structural checks it performed so that a result can be explained.
package identification

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MinPrimaryScore is the lowest structural score accepted as a primary format.
const MinPrimaryScore = 50

const maxZipEntries = 100000

type probe func(r io.ReaderAt, size int64) *models.FormatCandidate

var probes = []probe{probePE, probeELF, probeMachO, probeFat, probeJavaClass, probeZip, probeMagic, probeScript}

// Identify runs every probe and returns the ranked candidates.
func Identify(r io.ReaderAt, size int64) *models.Identification {
	var cands []models.FormatCandidate
	for _, p := range probes {
		if c := p(r, size); c != nil && c.Score > 0 {
			cands = append(cands, *c)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Score > cands[j].Score })
	id := &models.Identification{Candidates: cands, Primary: "unknown"}
	if cands == nil {
		id.Candidates = []models.FormatCandidate{}
	}
	if len(cands) > 0 && cands[0].Score >= MinPrimaryScore {
		id.Primary = cands[0].Format
		families := map[string]bool{}
		for _, c := range cands {
			if c.Score >= MinPrimaryScore {
				families[c.Family] = true
			}
		}
		id.Polyglot = len(families) > 1
	}
	return id
}

// readAt reads exactly n bytes at off, or returns nil if they are not all
// inside the file.
func readAt(r io.ReaderAt, size, off int64, n int) []byte {
	if off < 0 || n < 0 || off > size || int64(n) > size-off {
		return nil
	}
	b := make([]byte, n)
	if _, err := r.ReadAt(b, off); err != nil && err != io.EOF {
		return nil
	}
	return b
}

type builder struct {
	c     *models.FormatCandidate
	score int
}

func newBuilder(format, family string) *builder {
	return &builder{c: &models.FormatCandidate{Format: format, Family: family, Attributes: map[string]string{}}}
}

func (b *builder) check(name string, passed bool, off, length int64, detail string, points int) {
	b.c.Checks = append(b.c.Checks, models.Check{Name: name, Passed: passed, Offset: off, Length: length, Detail: detail})
	if passed {
		b.score += points
	}
}

func (b *builder) done() *models.FormatCandidate {
	if b.score > 100 {
		b.score = 100
	}
	b.c.Score = b.score
	return b.c
}

var peMachines = map[uint16]string{
	0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0x1c4: "ARMv7 (Thumb-2)",
	0xaa64: "ARM64", 0x200: "IA-64", 0x5032: "RISC-V32", 0x5064: "RISC-V64", 0x6232: "LoongArch32", 0x6264: "LoongArch64",
}

func probePE(r io.ReaderAt, size int64) *models.FormatCandidate {
	mz := readAt(r, size, 0, 2)
	if !bytes.Equal(mz, []byte("MZ")) {
		return nil
	}
	b := newBuilder("DOS MZ executable", "pe")
	b.check("DOS signature MZ", true, 0, 2, "", 20)
	lf := readAt(r, size, 0x3c, 4)
	if lf == nil {
		b.check("e_lfanew readable", false, 0x3c, 4, "file shorter than DOS header", 0)
		return b.done()
	}
	off := int64(binary.LittleEndian.Uint32(lf))
	sig := readAt(r, size, off, 4)
	okSig := bytes.Equal(sig, []byte("PE\x00\x00"))
	b.check("PE signature at e_lfanew", okSig, off, 4, fmt.Sprintf("e_lfanew=0x%x", off), 50)
	if !okSig {
		return b.done()
	}
	fh := readAt(r, size, off+4, 20)
	if fh == nil {
		b.check("COFF file header readable", false, off+4, 20, "truncated", 0)
		return b.done()
	}
	machine := binary.LittleEndian.Uint16(fh[0:])
	nsec := binary.LittleEndian.Uint16(fh[2:])
	chars := binary.LittleEndian.Uint16(fh[18:])
	optSize := binary.LittleEndian.Uint16(fh[16:])
	mname, known := peMachines[machine]
	if !known {
		mname = fmt.Sprintf("unknown (0x%04x)", machine)
	}
	b.check("known machine type", known, off+4, 2, mname, 5)
	b.c.Attributes["architecture"] = mname
	b.c.Attributes["sections"] = fmt.Sprint(nsec)
	b.c.Attributes["dll"] = fmt.Sprint(chars&0x2000 != 0)
	om := readAt(r, size, off+24, 2)
	if om == nil || optSize < 2 {
		b.check("optional header magic", false, off+24, 2, "missing", 0)
		return b.done()
	}
	switch binary.LittleEndian.Uint16(om) {
	case 0x10b:
		b.c.Format = "PE32"
		b.check("optional header magic", true, off+24, 2, "0x10b (PE32)", 25)
	case 0x20b:
		b.c.Format = "PE32+"
		b.check("optional header magic", true, off+24, 2, "0x20b (PE32+)", 25)
	case 0x107:
		b.c.Format = "PE ROM image"
		b.check("optional header magic", true, off+24, 2, "0x107 (ROM)", 25)
	default:
		b.check("optional header magic", false, off+24, 2, fmt.Sprintf("0x%x", binary.LittleEndian.Uint16(om)), 0)
	}
	return b.done()
}

var elfMachines = map[uint16]string{
	3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 243: "RISC-V",
	20: "PowerPC", 21: "PowerPC64", 22: "S/390", 258: "LoongArch", 4: "m68k", 42: "SuperH",
}
var elfTypes = map[uint16]string{1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core"}

func probeELF(r io.ReaderAt, size int64) *models.FormatCandidate {
	h := readAt(r, size, 0, 20)
	if h == nil || !bytes.Equal(h[:4], []byte("\x7fELF")) {
		return nil
	}
	b := newBuilder("ELF", "elf")
	b.check("ELF magic", true, 0, 4, "", 50)
	var bo binary.ByteOrder
	switch h[5] {
	case 1:
		bo = binary.LittleEndian
	case 2:
		bo = binary.BigEndian
	}
	b.check("valid EI_DATA", bo != nil, 5, 1, fmt.Sprint(h[5]), 15)
	switch h[4] {
	case 1:
		b.c.Format = "ELF32"
		b.check("valid EI_CLASS", true, 4, 1, "ELF32", 15)
	case 2:
		b.c.Format = "ELF64"
		b.check("valid EI_CLASS", true, 4, 1, "ELF64", 15)
	default:
		b.check("valid EI_CLASS", false, 4, 1, fmt.Sprint(h[4]), 0)
	}
	b.check("EI_VERSION is 1", h[6] == 1, 6, 1, "", 5)
	if bo != nil {
		t, m := bo.Uint16(h[16:]), bo.Uint16(h[18:])
		tn, tok := elfTypes[t]
		b.check("known e_type", tok, 16, 2, tn, 5)
		mn, mok := elfMachines[m]
		if !mok {
			mn = fmt.Sprintf("unknown (%d)", m)
		}
		b.check("known e_machine", mok, 18, 2, mn, 10)
		b.c.Attributes["architecture"] = mn
		b.c.Attributes["type"] = tn
		b.c.Attributes["endianness"] = map[bool]string{true: "little", false: "big"}[h[5] == 1]
	}
	return b.done()
}

var machoCPU = map[uint32]string{
	7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "ARM64", 0x0200000c: "ARM64_32", 18: "PowerPC", 0x01000012: "PowerPC64",
}
var machoFileType = map[uint32]string{1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib stub", 10: "dSYM", 11: "kext bundle"}

func probeMachO(r io.ReaderAt, size int64) *models.FormatCandidate {
	h := readAt(r, size, 0, 32)
	if h == nil {
		h = readAt(r, size, 0, 28)
	}
	if h == nil {
		return nil
	}
	var bo binary.ByteOrder
	var format string
	switch {
	case bytes.Equal(h[:4], []byte{0xfe, 0xed, 0xfa, 0xce}):
		bo, format = binary.BigEndian, "Mach-O 32-bit"
	case bytes.Equal(h[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}):
		bo, format = binary.BigEndian, "Mach-O 64-bit"
	case bytes.Equal(h[:4], []byte{0xce, 0xfa, 0xed, 0xfe}):
		bo, format = binary.LittleEndian, "Mach-O 32-bit"
	case bytes.Equal(h[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}):
		bo, format = binary.LittleEndian, "Mach-O 64-bit"
	default:
		return nil
	}
	b := newBuilder(format, "macho")
	b.check("Mach-O magic", true, 0, 4, "", 50)
	cpu, ft, ncmds := bo.Uint32(h[4:]), bo.Uint32(h[12:]), bo.Uint32(h[16:])
	cn, cok := machoCPU[cpu]
	if !cok {
		cn = fmt.Sprintf("unknown (0x%x)", cpu)
	}
	b.check("known cputype", cok, 4, 4, cn, 15)
	tn, tok := machoFileType[ft]
	b.check("known filetype", tok, 12, 4, tn, 15)
	b.check("plausible load command count", ncmds > 0 && ncmds < 4096, 16, 4, fmt.Sprint(ncmds), 10)
	b.c.Attributes["architecture"] = cn
	b.c.Attributes["type"] = tn
	return b.done()
}

func probeFat(r io.ReaderAt, size int64) *models.FormatCandidate {
	h := readAt(r, size, 0, 8)
	if h == nil {
		return nil
	}
	fat64 := bytes.Equal(h[:4], []byte{0xca, 0xfe, 0xba, 0xbf})
	if !fat64 && !bytes.Equal(h[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return nil
	}
	n := binary.BigEndian.Uint32(h[4:])
	b := newBuilder("Mach-O universal (fat) binary", "macho")
	b.check("fat magic", true, 0, 4, "", 30)
	// 0xCAFEBABE is shared with Java class files, where this field is
	// minor<<16|major with major >= 45. A real fat header has few archs.
	plausible := n >= 1 && n <= 30
	b.check("plausible architecture count", plausible, 4, 4, fmt.Sprint(n), 30)
	if !plausible {
		return b.done()
	}
	entry := int64(20)
	if fat64 {
		entry = 32
	}
	if readAt(r, size, 8, int(int64(n)*entry)) != nil {
		b.check("architecture table inside file", true, 8, int64(n)*entry, "", 30)
	} else {
		b.check("architecture table inside file", false, 8, int64(n)*entry, "truncated", 0)
	}
	b.c.Attributes["architectures"] = fmt.Sprint(n)
	return b.done()
}

func probeJavaClass(r io.ReaderAt, size int64) *models.FormatCandidate {
	h := readAt(r, size, 0, 10)
	if h == nil || !bytes.Equal(h[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return nil
	}
	minor, major, cp := binary.BigEndian.Uint16(h[4:]), binary.BigEndian.Uint16(h[6:]), binary.BigEndian.Uint16(h[8:])
	b := newBuilder("Java class file", "java")
	b.check("class magic", true, 0, 4, "", 30)
	okMajor := major >= 45 && major <= 100
	b.check("plausible major version", okMajor, 6, 2, fmt.Sprintf("%d.%d", major, minor), 40)
	b.check("constant pool count >= 1", cp >= 1, 8, 2, fmt.Sprint(cp), 20)
	if okMajor {
		b.c.Attributes["java_version"] = fmt.Sprint(int(major) - 44)
	}
	return b.done()
}

func probeZip(r io.ReaderAt, size int64) *models.FormatCandidate {
	h := readAt(r, size, 0, 4)
	if h == nil || !(bytes.Equal(h, []byte("PK\x03\x04")) || bytes.Equal(h, []byte("PK\x05\x06"))) {
		return nil
	}
	b := newBuilder("ZIP archive", "zip")
	b.check("local file header signature", true, 0, 4, "", 40)
	zr, err := zip.NewReader(r, size)
	if err != nil {
		b.check("central directory parses", false, 0, 0, err.Error(), 0)
		return b.done()
	}
	b.check("central directory parses", true, 0, 0, fmt.Sprintf("%d entries", len(zr.File)), 50)
	b.c.Attributes["entries"] = fmt.Sprint(len(zr.File))
	if len(zr.File) > maxZipEntries {
		b.c.Attributes["note"] = "entry scan skipped: too many entries"
		return b.done()
	}
	var manifest, androidManifest, dex bool
	for _, f := range zr.File {
		switch f.Name {
		case "META-INF/MANIFEST.MF":
			manifest = true
		case "AndroidManifest.xml":
			androidManifest = true
		case "classes.dex":
			dex = true
		}
	}
	switch {
	case androidManifest && dex:
		b.c.Format = "Android APK"
	case manifest:
		b.c.Format = "Java JAR"
	}
	return b.done()
}

type magic struct {
	off    int64
	bytes  []byte
	format string
	family string
}

var magics = []magic{
	{0, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "OLE2 compound file (legacy Office / MSI)", "ole"},
	{0, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, "7-Zip archive", "7z"},
	{0, []byte("Rar!\x1a\x07"), "RAR archive", "rar"},
	{0, []byte{0x1f, 0x8b}, "gzip stream", "gzip"},
	{0, []byte("MSCF"), "Microsoft Cabinet", "cab"},
	{0, []byte("%PDF-"), "PDF document", "pdf"},
	{0, []byte("\x00asm"), "WebAssembly module", "wasm"},
	{0, []byte("dex\n"), "Android DEX", "dex"},
}

func probeMagic(r io.ReaderAt, size int64) *models.FormatCandidate {
	for _, m := range magics {
		if got := readAt(r, size, m.off, len(m.bytes)); got != nil && bytes.Equal(got, m.bytes) {
			b := newBuilder(m.format, m.family)
			b.check("magic bytes", true, m.off, int64(len(m.bytes)), "", 60)
			return b.done()
		}
	}
	return nil
}

func probeScript(r io.ReaderAt, size int64) *models.FormatCandidate {
	n := 256
	if size < int64(n) {
		n = int(size)
	}
	h := readAt(r, size, 0, n)
	if len(h) < 3 || h[0] != '#' || h[1] != '!' {
		return nil
	}
	end := bytes.IndexByte(h, '\n')
	if end < 0 {
		end = len(h)
	}
	line := h[2:end]
	for _, c := range line {
		if c < 0x20 || c > 0x7e {
			return nil
		}
	}
	b := newBuilder("Script with interpreter line", "script")
	b.check("shebang line", true, 0, int64(end), string(bytes.TrimSpace(line)), 60)
	b.c.Attributes["interpreter"] = string(bytes.TrimSpace(line))
	return b.done()
}
