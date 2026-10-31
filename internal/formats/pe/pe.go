// Package pe turns a PE/COFF image into the neutral models.Binary. It wraps
// github.com/saferwall/pe, which tolerates malformed files the way pefile
// does, and adds bounds, panic containment and the pieces the library does
// not provide (overlay, entry-point mapping, permissions).
package pe

import (
	"errors"
	"fmt"
	"strings"
	"time"

	sw "github.com/saferwall/pe"
	swlog "github.com/saferwall/pe/log"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits protect against files that declare absurd structures.
const (
	MaxImportFunctions = 200000
	MaxExports         = 100000
)

// ErrNotPE means the data is not a PE image at all.
var ErrNotPE = errors.New("not a PE image")

// discard silences the library: a worker's stdout is its protocol channel and
// must never receive stray log lines.
type discard struct{}

func (discard) Log(swlog.Level, ...interface{}) error { return nil }

// Parse analyses data. It returns an error only when no usable headers could
// be read; damage further in is reported through Binary.Anomalies.
func Parse(data []byte) (b *models.Binary, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("pe parser panic: %v", r)
		}
	}()
	p, err := sw.NewBytes(data, &sw.Options{
		Logger:                     discard{},
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
	})
	if err != nil {
		return nil, err
	}
	perr := p.Parse()
	if p.NtHeader.Signature != 0x4550 || p.NtHeader.OptionalHeader == nil {
		if perr == nil {
			perr = ErrNotPE
		}
		return nil, fmt.Errorf("%w: %v", ErrNotPE, perr)
	}

	b = &models.Binary{Attributes: map[string]string{}, Sections: []models.Section{}, Imports: []models.Import{}, Exports: []models.Export{}}
	if perr != nil {
		b.Anomalies = append(b.Anomalies, "parsing stopped early: "+perr.Error())
	}

	var sizeOfHeaders uint32
	var epRVA uint32
	switch oh := p.NtHeader.OptionalHeader.(type) {
	case sw.ImageOptionalHeader64:
		b.Format, b.Bits, b.ImageBase = "PE32+", 64, oh.ImageBase
		epRVA, sizeOfHeaders = oh.AddressOfEntryPoint, oh.SizeOfHeaders
		b.Attributes["subsystem"] = oh.Subsystem.String()
		b.Attributes["dll_characteristics"] = strings.Join(oh.DllCharacteristics.String(), ",")
		b.Attributes["linker_version"] = fmt.Sprintf("%d.%d", oh.MajorLinkerVersion, oh.MinorLinkerVersion)
		b.Attributes["checksum"] = fmt.Sprintf("0x%x", oh.CheckSum)
	case sw.ImageOptionalHeader32:
		b.Format, b.Bits, b.ImageBase = "PE32", 32, uint64(oh.ImageBase)
		epRVA, sizeOfHeaders = oh.AddressOfEntryPoint, oh.SizeOfHeaders
		b.Attributes["subsystem"] = oh.Subsystem.String()
		b.Attributes["dll_characteristics"] = strings.Join(oh.DllCharacteristics.String(), ",")
		b.Attributes["linker_version"] = fmt.Sprintf("%d.%d", oh.MajorLinkerVersion, oh.MinorLinkerVersion)
		b.Attributes["checksum"] = fmt.Sprintf("0x%x", oh.CheckSum)
	default:
		return nil, fmt.Errorf("%w: unexpected optional header type %T", ErrNotPE, oh)
	}
	b.Endian = "little"
	b.Arch = archName(uint16(p.NtHeader.FileHeader.Machine), p.NtHeader.FileHeader.Machine.String())
	switch {
	case p.IsDriver():
		b.Kind = "driver"
	case p.IsDLL():
		b.Kind = "library"
	case p.IsEXE():
		b.Kind = "executable"
	default:
		b.Kind = "other"
	}
	if ts := p.NtHeader.FileHeader.TimeDateStamp; ts != 0 {
		b.CompiledAt = time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
	}
	b.Attributes["has_clr_header"] = fmt.Sprint(p.HasCLR)
	b.Attributes["has_certificate_table"] = fmt.Sprint(p.IsSigned)
	b.Attributes["signature_validated"] = "false" // validation is not performed by this build
	b.Attributes["rich_header"] = fmt.Sprint(len(p.RichHeader.CompIDs) > 0)

	// Sections.
	rawEnd := uint64(sizeOfHeaders)
	for i := range p.Sections {
		s := &p.Sections[i]
		h := s.Header
		sec := models.Section{
			Name:           s.String(),
			VirtualAddress: uint64(h.VirtualAddress),
			VirtualSize:    uint64(h.VirtualSize),
			RawOffset:      uint64(h.PointerToRawData),
			RawSize:        uint64(h.SizeOfRawData),
			Perms:          perms(h.Characteristics),
			Flags:          uint64(h.Characteristics),
			Kind:           kind(h.Characteristics),
		}
		b.Sections = append(b.Sections, sec)
		if h.SizeOfRawData > 0 {
			if end := uint64(h.PointerToRawData) + uint64(h.SizeOfRawData); end > rawEnd {
				rawEnd = end
			}
		}
	}

	// Entry point.
	b.Entry = mapAddress(b, uint64(epRVA))

	// Imports.
	total := 0
	for _, imp := range p.Imports {
		out := models.Import{Library: imp.Name, Functions: []models.ImportFn{}}
		for _, f := range imp.Functions {
			if total++; total > MaxImportFunctions {
				b.Anomalies = append(b.Anomalies, fmt.Sprintf("import list truncated at %d functions", MaxImportFunctions))
				break
			}
			out.Functions = append(out.Functions, models.ImportFn{Name: f.Name, Ordinal: f.Ordinal, ByOrdinal: f.ByOrdinal, Hint: f.Hint})
		}
		b.Imports = append(b.Imports, out)
		if total > MaxImportFunctions {
			break
		}
	}
	for _, d := range p.DelayImports {
		out := models.Import{Library: d.Name, Delay: true, Functions: []models.ImportFn{}}
		for _, f := range d.Functions {
			if total++; total > MaxImportFunctions {
				break
			}
			out.Functions = append(out.Functions, models.ImportFn{Name: f.Name, Ordinal: f.Ordinal, ByOrdinal: f.ByOrdinal, Hint: f.Hint})
		}
		b.Imports = append(b.Imports, out)
	}
	if h, err := p.ImpHash(); err == nil {
		b.ImportHash = h
	}

	// Exports.
	for i, f := range p.Export.Functions {
		if i >= MaxExports {
			b.Anomalies = append(b.Anomalies, fmt.Sprintf("export list truncated at %d entries", MaxExports))
			break
		}
		b.Exports = append(b.Exports, models.Export{Name: f.Name, Ordinal: f.Ordinal, RVA: uint64(f.FunctionRVA), Forwarder: f.Forwarder})
	}

	// Overlay: bytes after the last section's raw data. A certificate table
	// lives there by design, which is noted rather than hidden.
	if int64(rawEnd) < int64(len(data)) {
		b.Overlay = &models.Region{Offset: int64(rawEnd), Size: int64(len(data)) - int64(rawEnd)}
	}

	b.Anomalies = append(b.Anomalies, p.Anomalies...)
	return b, nil
}

func perms(c uint32) string {
	r, w, x := "-", "-", "-"
	if c&0x40000000 != 0 {
		r = "r"
	}
	if c&0x80000000 != 0 {
		w = "w"
	}
	if c&0x20000000 != 0 {
		x = "x"
	}
	return r + w + x
}

func kind(c uint32) string {
	switch {
	case c&0x20 != 0:
		return "code"
	case c&0x40 != 0:
		return "initialized-data"
	case c&0x80 != 0:
		return "uninitialized-data"
	}
	return ""
}

// mapAddress resolves an RVA to a virtual address, section and file offset.
func mapAddress(b *models.Binary, rva uint64) *models.Address {
	a := &models.Address{RVA: rva, VA: b.ImageBase + rva}
	for _, s := range b.Sections {
		size := s.VirtualSize
		if size == 0 {
			size = s.RawSize
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			a.Section = s.Name
			if off := rva - s.VirtualAddress; off < s.RawSize {
				fo := int64(s.RawOffset + off)
				a.FileOffset = &fo
			}
			return a
		}
	}
	return a
}

var machines = map[uint16]string{
	0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0x1c4: "ARM", 0xaa64: "ARM64", 0xa641: "ARM64EC",
	0x200: "IA-64", 0x5032: "RISC-V", 0x5064: "RISC-V", 0x6232: "LoongArch", 0x6264: "LoongArch",
}

func archName(m uint16, fallback string) string {
	if n, ok := machines[m]; ok {
		return n
	}
	return fallback
}
