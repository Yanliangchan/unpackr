// Package macho turns a Mach-O image, thin or universal, into the neutral
// models.Binary using the standard library parser plus the pieces it omits
// (LC_MAIN entry point, overlay). Code-signature and chained-fixup decoding
// are not implemented yet; the report says so through Attributes.
package macho

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits bound the work done on hostile input.
const (
	MaxSymbols = 200000
	MaxSlices  = 32
)

// ErrNotMachO means the data is not a Mach-O image.
var ErrNotMachO = errors.New("not a Mach-O image")

const (
	lcMain       = 0x80000028
	lcUnixThread = 0x5
)

// Parse analyses data.
func Parse(data []byte) (b *models.Binary, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("mach-o parser panic: %v", r)
		}
	}()
	ff, ferr := macho.NewFatFile(bytes.NewReader(data))
	switch {
	case ferr == nil:
		defer ff.Close() //nolint:errcheck // in-memory reader
		u := &models.Binary{Format: "Mach-O universal", Kind: "universal", Attributes: map[string]string{},
			Sections: []models.Section{}, Imports: []models.Import{}, Exports: []models.Export{}}
		var archs []string
		for i, a := range ff.Arches {
			if i >= MaxSlices {
				u.Anomalies = append(u.Anomalies, "slice list truncated")
				break
			}
			sl := fromFile(a.File, uint64(a.Offset), uint64(a.Size), data)
			sl.Attributes["slice_offset"] = fmt.Sprint(a.Offset)
			sl.Attributes["slice_size"] = fmt.Sprint(a.Size)
			archs = append(archs, sl.Arch)
			u.Slices = append(u.Slices, *sl)
		}
		u.Attributes["architectures"] = strings.Join(archs, ",")
		return u, nil
	case errors.Is(ferr, macho.ErrNotFat):
		f, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotMachO, err)
		}
		defer f.Close() //nolint:errcheck // in-memory reader
		return fromFile(f, 0, uint64(len(data)), data), nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrNotMachO, ferr)
	}
}

var cpuNames = map[macho.Cpu]string{
	macho.Cpu386: "x86", macho.CpuAmd64: "x86-64", macho.CpuArm: "ARM", macho.CpuArm64: "ARM64",
	macho.CpuPpc: "PowerPC", macho.CpuPpc64: "PowerPC64",
}

var typeNames = map[macho.Type]string{macho.TypeObj: "object", macho.TypeExec: "executable", macho.TypeDylib: "library", macho.TypeBundle: "library"}

// fromFile converts one image. base is the image's offset inside the whole
// file (non-zero for universal slices); size is the image length.
func fromFile(f *macho.File, base, size uint64, whole []byte) *models.Binary {
	b := &models.Binary{Attributes: map[string]string{}, Sections: []models.Section{}, Imports: []models.Import{}, Exports: []models.Export{}}
	if f.Magic == macho.Magic64 {
		b.Format, b.Bits = "Mach-O 64-bit", 64
	} else {
		b.Format, b.Bits = "Mach-O 32-bit", 32
	}
	b.Endian = map[bool]string{true: "little", false: "big"}[f.ByteOrder == binary.LittleEndian]
	if n, ok := cpuNames[f.Cpu]; ok {
		b.Arch = n
	} else {
		b.Arch = f.Cpu.String()
	}
	if k, ok := typeNames[f.Type]; ok {
		b.Kind = k
	} else {
		b.Kind = "other"
	}
	b.Attributes["code_signature_parsed"] = "false"
	b.Attributes["chained_fixups_parsed"] = "false"

	var textAddr uint64
	var haveText bool
	for _, l := range f.Loads {
		switch v := l.(type) {
		case *macho.Segment:
			b.Segments = append(b.Segments, models.Section{
				Name: v.Name, VirtualAddress: v.Addr, VirtualSize: v.Memsz,
				RawOffset: base + v.Offset, RawSize: v.Filesz, Perms: prot(v.Prot), Flags: uint64(v.Flag), Kind: "segment",
			})
			if v.Name == "__TEXT" {
				textAddr, haveText = v.Addr, true
			}
		case macho.LoadBytes:
			raw := []byte(v)
			if len(raw) < 16 {
				break
			}
			switch f.ByteOrder.Uint32(raw[0:]) {
			case lcMain:
				off := f.ByteOrder.Uint64(raw[8:])
				a := &models.Address{RVA: off, FileOffset: models.Int64(int64(base + off))}
				if haveText {
					a.VA = textAddr + off
				}
				b.Entry = a
			case lcUnixThread:
				// Older toolchains (and Go on amd64) start the program from
				// the initial register state instead of LC_MAIN.
				if pc, ok := threadPC(f, raw); ok {
					b.Entry = &models.Address{RVA: pc, VA: pc}
				}
			}
		}
	}
	for _, s := range f.Sections {
		var perm string
		for _, seg := range b.Segments {
			if seg.Name == s.Seg {
				perm = seg.Perms
			}
		}
		b.Sections = append(b.Sections, models.Section{
			Name: s.Seg + "," + s.Name, VirtualAddress: s.Addr, VirtualSize: s.Size,
			RawOffset: base + uint64(s.Offset), RawSize: s.Size, Perms: perm, Flags: uint64(s.Flags),
		})
	}
	if b.Entry != nil {
		for _, s := range b.Sections {
			if b.Entry.VA >= s.VirtualAddress && b.Entry.VA < s.VirtualAddress+s.VirtualSize {
				b.Entry.Section = s.Name
				break
			}
		}
	}

	libs, _ := f.ImportedLibraries()
	b.Libraries = libs
	if syms, err := f.ImportedSymbols(); err == nil {
		fns := make([]models.ImportFn, 0, len(syms))
		for i, s := range syms {
			if i >= MaxSymbols {
				b.Anomalies = append(b.Anomalies, "import list truncated")
				break
			}
			fns = append(fns, models.ImportFn{Name: s})
		}
		sort.Slice(fns, func(i, j int) bool { return fns[i].Name < fns[j].Name })
		// Two-level namespace binding is not decoded, so the library for each
		// symbol is not known and the symbols are grouped under all libraries.
		b.Imports = append(b.Imports, models.Import{Library: "(all linked libraries; per-symbol binding not decoded)", Functions: fns})
	}
	if f.Symtab != nil {
		for i, s := range f.Symtab.Syms {
			if i >= MaxSymbols {
				break
			}
			if s.Type&0x0e == 0x0e && s.Name != "" && s.Type&0x01 != 0 { // N_SECT | N_EXT
				b.Exports = append(b.Exports, models.Export{Name: s.Name, RVA: s.Value})
			}
		}
	}

	var end uint64
	for _, s := range b.Segments {
		if s.RawOffset+s.RawSize > end {
			end = s.RawOffset + s.RawSize
		}
	}
	sliceEnd := base + size
	if end > 0 && end < sliceEnd && sliceEnd <= uint64(len(whole)) {
		b.Overlay = &models.Region{Offset: int64(end), Size: int64(sliceEnd - end)}
	}
	return b
}

func prot(p uint32) string {
	r, w, x := "-", "-", "-"
	if p&1 != 0 {
		r = "r"
	}
	if p&2 != 0 {
		w = "w"
	}
	if p&4 != 0 {
		x = "x"
	}
	return r + w + x
}

// threadPC extracts the initial program counter from an LC_UNIXTHREAD command.
func threadPC(f *macho.File, raw []byte) (uint64, bool) {
	bo := f.ByteOrder
	flavor := bo.Uint32(raw[8:])
	at := func(off int, size int) (uint64, bool) {
		if off+size > len(raw) {
			return 0, false
		}
		if size == 8 {
			return bo.Uint64(raw[off:]), true
		}
		return uint64(bo.Uint32(raw[off:])), true
	}
	switch {
	case f.Cpu == macho.CpuAmd64 && flavor == 4: // x86_THREAD_STATE64: rip is register 16
		return at(16+16*8, 8)
	case f.Cpu == macho.CpuArm64 && flavor == 6: // ARM_THREAD_STATE64: pc follows x0-x28, fp, lr, sp
		return at(16+32*8, 8)
	case f.Cpu == macho.Cpu386 && flavor == 1: // x86_THREAD_STATE32: eip is register 10
		return at(16+10*4, 4)
	}
	return 0, false
}
