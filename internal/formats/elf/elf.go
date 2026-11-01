// Package elf turns an ELF image into the neutral models.Binary. It uses the
// standard library parser first and falls back to reading program headers
// directly when the section header table is missing or damaged, which is the
// normal state of stripped, packed and hand-crafted binaries.
package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits bound the work done on hostile input.
const (
	MaxSymbols  = 200000
	MaxSegments = 4096
)

// ErrNotELF means the data is not an ELF image.
var ErrNotELF = errors.New("not an ELF image")

// Parse analyses data.
func Parse(data []byte) (b *models.Binary, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("elf parser panic: %v", r)
		}
	}()
	if len(data) < 20 || !bytes.Equal(data[:4], []byte("\x7fELF")) {
		return nil, ErrNotELF
	}
	f, ferr := elf.NewFile(bytes.NewReader(data))
	if ferr != nil {
		return fallback(data, ferr)
	}
	defer f.Close() //nolint:errcheck // in-memory reader

	b = base(f.Class, f.Data, f.Machine, f.Type, f.Entry)
	b.Attributes["os_abi"] = f.OSABI.String()
	b.Attributes["abi_version"] = fmt.Sprint(f.ABIVersion)

	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			if buf := make([]byte, minU64(p.Filesz, 256)); len(buf) > 0 {
				if n, _ := p.ReadAt(buf, 0); n > 0 {
					b.Attributes["interpreter"] = cstr(buf[:n])
				}
			}
		}
	}
	b.Kind = kind(f.Type, hasInterp || isPIE(f))
	if f.Type == elf.ET_DYN && b.Kind == "library" && !hasDynamic(f) {
		// No interpreter, no PIE flag and no dynamic section: a static-PIE
		// executable, a packed file or a stripped image. It cannot be called a
		// library on this evidence.
		b.Kind = KindAmbiguous
	}

	for i, s := range f.Sections {
		if i == 0 && s.Type == elf.SHT_NULL {
			continue
		}
		b.Sections = append(b.Sections, models.Section{
			Name: s.Name, VirtualAddress: s.Addr, VirtualSize: s.Size,
			RawOffset: s.Offset, RawSize: rawSize(s), Perms: secPerms(s.Flags),
			Flags: uint64(s.Flags), Kind: strings.ToLower(strings.TrimPrefix(s.Type.String(), "SHT_")),
		})
		if s.Name == ".note.gnu.build-id" {
			if d, err := s.Data(); err == nil {
				if id := buildID(d, f.ByteOrder); id != "" {
					b.Attributes["build_id"] = id
				}
			}
		}
		if s.Name == ".go.buildinfo" || s.Name == ".gopclntab" {
			b.Attributes["go_sections"] = "present"
		}
	}
	if len(f.Sections) <= 1 {
		b.Anomalies = append(b.Anomalies, "no section headers: the section table is absent or empty; using program headers")
	}
	// Segments are always reported: they are what the loader actually uses.
	for i, p := range f.Progs {
		if i >= MaxSegments {
			b.Anomalies = append(b.Anomalies, "segment list truncated")
			break
		}
		b.Segments = append(b.Segments, models.Section{
			Name:           fmt.Sprintf("%s#%d", strings.TrimPrefix(p.Type.String(), "PT_"), i),
			VirtualAddress: p.Vaddr, VirtualSize: p.Memsz, RawOffset: p.Off, RawSize: p.Filesz,
			Perms: progPerms(p.Flags), Flags: uint64(p.Flags), Kind: "segment",
		})
	}

	libs, _ := f.ImportedLibraries()
	b.Libraries = libs
	imps, _ := f.ImportedSymbols()
	byLib := map[string][]models.ImportFn{}
	for i, s := range imps {
		if i >= MaxSymbols {
			b.Anomalies = append(b.Anomalies, "import list truncated")
			break
		}
		byLib[s.Library] = append(byLib[s.Library], models.ImportFn{Name: s.Name})
	}
	libNames := make([]string, 0, len(byLib))
	for l := range byLib {
		libNames = append(libNames, l)
	}
	sort.Strings(libNames)
	for _, l := range libNames {
		b.Imports = append(b.Imports, models.Import{Library: l, Functions: byLib[l]})
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		for i, s := range syms {
			if i >= MaxSymbols {
				break
			}
			if s.Section != elf.SHN_UNDEF && s.Name != "" && elf.ST_BIND(s.Info) != elf.STB_LOCAL {
				b.Exports = append(b.Exports, models.Export{Name: s.Name, RVA: s.Value})
			}
		}
	}
	if _, err := f.Symbols(); err == nil {
		b.Attributes["stripped"] = "false"
	} else {
		b.Attributes["stripped"] = "true"
	}

	b.Entry = mapEntry(b, f.Entry)
	// Overlay: data after the end of the last section / segment.
	if end := fileEnd(b); end > 0 && end < uint64(len(data)) {
		b.Overlay = &models.Region{Offset: int64(end), Size: int64(uint64(len(data)) - end)}
	}
	return b, nil
}

func fileEnd(b *models.Binary) uint64 {
	var end uint64
	for _, s := range b.Sections {
		if s.Kind != "nobits" && s.RawOffset+s.RawSize > end {
			end = s.RawOffset + s.RawSize
		}
	}
	for _, s := range b.Segments {
		if s.RawOffset+s.RawSize > end {
			end = s.RawOffset + s.RawSize
		}
	}
	return end
}

func base(c elf.Class, d elf.Data, m elf.Machine, t elf.Type, entry uint64) *models.Binary {
	b := &models.Binary{Attributes: map[string]string{}, Sections: []models.Section{}, Imports: []models.Import{}, Exports: []models.Export{}}
	if c == elf.ELFCLASS64 {
		b.Format, b.Bits = "ELF64", 64
	} else {
		b.Format, b.Bits = "ELF32", 32
	}
	b.Endian = map[bool]string{true: "little", false: "big"}[d == elf.ELFDATA2LSB]
	b.Arch = archName(m)
	b.Attributes["type"] = strings.TrimPrefix(t.String(), "ET_")
	return b
}

// KindAmbiguous is the Kind of an ET_DYN file that carries no evidence either
// way (no interpreter, no DF_1_PIE and no dynamic section).
const KindAmbiguous = "executable-or-library"

func isPIE(f *elf.File) bool {
	v, err := f.DynValue(elf.DT_FLAGS_1)
	if err != nil {
		return false
	}
	for _, x := range v {
		if x&uint64(elf.DF_1_PIE) != 0 {
			return true
		}
	}
	return false
}

func hasDynamic(f *elf.File) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			return true
		}
	}
	return false
}

func kind(t elf.Type, interp bool) string {
	switch t {
	case elf.ET_EXEC:
		return "executable"
	case elf.ET_DYN:
		if interp {
			return "executable" // position-independent executable
		}
		return "library"
	case elf.ET_REL:
		return "object"
	case elf.ET_CORE:
		return "core"
	}
	return "other"
}

func rawSize(s *elf.Section) uint64 {
	if s.Type == elf.SHT_NOBITS {
		return 0
	}
	return s.FileSize
}

func secPerms(f elf.SectionFlag) string {
	r, w, x := "-", "-", "-"
	if f&elf.SHF_ALLOC != 0 {
		r = "r"
	}
	if f&elf.SHF_WRITE != 0 {
		w = "w"
	}
	if f&elf.SHF_EXECINSTR != 0 {
		x = "x"
	}
	return r + w + x
}

func progPerms(f elf.ProgFlag) string {
	r, w, x := "-", "-", "-"
	if f&elf.PF_R != 0 {
		r = "r"
	}
	if f&elf.PF_W != 0 {
		w = "w"
	}
	if f&elf.PF_X != 0 {
		x = "x"
	}
	return r + w + x
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func buildID(note []byte, bo binary.ByteOrder) string {
	if len(note) < 12 {
		return ""
	}
	namesz, descsz := bo.Uint32(note[0:]), bo.Uint32(note[4:])
	off := 12 + (int(namesz)+3)&^3
	if off < 0 || uint64(off)+uint64(descsz) > uint64(len(note)) || descsz == 0 || descsz > 64 {
		return ""
	}
	return fmt.Sprintf("%x", note[off:off+int(descsz)])
}

// mapEntry locates the entry point in the loadable segments.
func mapEntry(b *models.Binary, entry uint64) *models.Address {
	a := &models.Address{RVA: entry, VA: entry}
	for _, s := range b.Segments {
		if s.Name[:4] != "LOAD" {
			continue
		}
		if entry >= s.VirtualAddress && entry < s.VirtualAddress+s.VirtualSize {
			if off := entry - s.VirtualAddress; off < s.RawSize {
				fo := int64(s.RawOffset + off)
				a.FileOffset = &fo
			}
			for _, sec := range b.Sections {
				if sec.VirtualAddress != 0 && entry >= sec.VirtualAddress && entry < sec.VirtualAddress+sec.VirtualSize {
					a.Section = sec.Name
					break
				}
			}
			return a
		}
	}
	return a
}

// fallback reads the ELF header and program headers by hand. It is used when
// the standard library rejects the file, typically because the section header
// table is damaged or absent.
func fallback(data []byte, cause error) (*models.Binary, error) {
	var bo binary.ByteOrder
	switch data[5] {
	case 1:
		bo = binary.LittleEndian
	case 2:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("%w: invalid data encoding", ErrNotELF)
	}
	class := elf.Class(data[4])
	var phoff, phentsize, phnum, entry uint64
	switch class {
	case elf.ELFCLASS64:
		if len(data) < 64 {
			return nil, fmt.Errorf("%w: truncated header", ErrNotELF)
		}
		entry, phoff = bo.Uint64(data[24:]), bo.Uint64(data[32:])
		phentsize, phnum = uint64(bo.Uint16(data[54:])), uint64(bo.Uint16(data[56:]))
	case elf.ELFCLASS32:
		if len(data) < 52 {
			return nil, fmt.Errorf("%w: truncated header", ErrNotELF)
		}
		entry, phoff = uint64(bo.Uint32(data[24:])), uint64(bo.Uint32(data[28:]))
		phentsize, phnum = uint64(bo.Uint16(data[42:])), uint64(bo.Uint16(data[44:]))
	default:
		return nil, fmt.Errorf("%w: invalid class", ErrNotELF)
	}
	b := base(class, elf.Data(data[5]), elf.Machine(bo.Uint16(data[18:])), elf.Type(bo.Uint16(data[16:])), entry)
	b.Kind = kind(elf.Type(bo.Uint16(data[16:])), false)
	b.Anomalies = append(b.Anomalies, "standard parser rejected the file ("+cause.Error()+"); reading program headers directly")
	need := uint64(32)
	if class == elf.ELFCLASS64 {
		need = 56
	}
	if phentsize < need || phnum == 0 {
		b.Anomalies = append(b.Anomalies, "no usable program header table")
		b.Entry = &models.Address{RVA: entry, VA: entry}
		return b, nil
	}
	if phnum > MaxSegments {
		phnum = MaxSegments
		b.Anomalies = append(b.Anomalies, "segment list truncated")
	}
	for i := uint64(0); i < phnum; i++ {
		o := phoff + i*phentsize
		if o+need > uint64(len(data)) || o+need < o {
			b.Anomalies = append(b.Anomalies, fmt.Sprintf("program header %d lies outside the file", i))
			break
		}
		h := data[o:]
		var typ, flags uint32
		var off, vaddr, filesz, memsz uint64
		if class == elf.ELFCLASS64 {
			typ, flags = bo.Uint32(h[0:]), bo.Uint32(h[4:])
			off, vaddr, filesz, memsz = bo.Uint64(h[8:]), bo.Uint64(h[16:]), bo.Uint64(h[32:]), bo.Uint64(h[40:])
		} else {
			typ = bo.Uint32(h[0:])
			off, vaddr, filesz, memsz, flags = uint64(bo.Uint32(h[4:])), uint64(bo.Uint32(h[8:])), uint64(bo.Uint32(h[16:])), uint64(bo.Uint32(h[20:])), bo.Uint32(h[24:])
		}
		b.Segments = append(b.Segments, models.Section{
			Name:           fmt.Sprintf("%s#%d", strings.TrimPrefix(elf.ProgType(typ).String(), "PT_"), i),
			VirtualAddress: vaddr, VirtualSize: memsz, RawOffset: off, RawSize: filesz,
			Perms: progPerms(elf.ProgFlag(flags)), Flags: uint64(flags), Kind: "segment",
		})
	}
	b.Entry = mapEntry(b, entry)
	if end := fileEnd(b); end > 0 && end < uint64(len(data)) {
		b.Overlay = &models.Region{Offset: int64(end), Size: int64(uint64(len(data)) - end)}
	}
	return b, nil
}

var machines = map[elf.Machine]string{
	elf.EM_386: "x86", elf.EM_X86_64: "x86-64", elf.EM_ARM: "ARM", elf.EM_AARCH64: "ARM64",
	elf.EM_MIPS: "MIPS", elf.EM_PPC: "PowerPC", elf.EM_PPC64: "PowerPC64", elf.EM_RISCV: "RISC-V",
	elf.EM_S390: "S/390", elf.EM_LOONGARCH: "LoongArch", elf.EM_68K: "m68k", elf.EM_SH: "SuperH",
}

func archName(m elf.Machine) string {
	if n, ok := machines[m]; ok {
		return n
	}
	return strings.TrimPrefix(m.String(), "EM_")
}
