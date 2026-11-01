package models

// Binary is the format-neutral view of an executable's structure. Every field
// is something a parser read from the file, so the whole structure is
// observation-class data. Interpretation happens in later stages.
type Binary struct {
	Format    string   `json:"format"` // PE32, PE32+, ELF64, Mach-O 64-bit ...
	Arch      string   `json:"architecture"`
	Bits      int      `json:"bits"`
	Endian    string   `json:"endianness"`
	Kind      string   `json:"kind"` // executable | library | object | driver | core | other
	Entry     *Address `json:"entry_point,omitempty"`
	ImageBase uint64   `json:"image_base,omitempty"`
	// CompiledAt is the timestamp stored in the header. It is attacker
	// controlled and often forged or zeroed; it is never evidence of when a
	// file was really built.
	CompiledAt string `json:"header_timestamp,omitempty"`

	Sections []Section `json:"sections"`
	// Segments are the loader's view (ELF program headers, Mach-O segments).
	Segments  []Section `json:"segments,omitempty"`
	Imports   []Import  `json:"imports"`
	Exports   []Export  `json:"exports"`
	Libraries []string  `json:"libraries,omitempty"` // ELF DT_NEEDED, Mach-O dylibs

	Overlay *Region `json:"overlay,omitempty"`
	// DotNet is set for managed assemblies whose metadata could be read.
	DotNet *DotNet `json:"dotnet,omitempty"`

	// Hashes of structure: stable identifiers for similarity.
	ImportHash string `json:"import_hash,omitempty"` // pefile-compatible imphash (PE only)

	// Attributes carries format-specific facts such as the PE subsystem.
	Attributes map[string]string `json:"attributes,omitempty"`

	// Anomalies are structural inconsistencies noticed while parsing. They are
	// parser observations, not verdicts.
	Anomalies []string `json:"parser_anomalies,omitempty"`

	// Slices holds the per-architecture images of a universal (fat) binary.
	Slices []Binary `json:"slices,omitempty"`

	// Truncated is true when only part of a very large file was parsed.
	Truncated bool `json:"truncated,omitempty"`
}

// Address is an entry point or other address in the three coordinate systems.
type Address struct {
	RVA        uint64 `json:"rva"`
	VA         uint64 `json:"va"`
	FileOffset *int64 `json:"file_offset,omitempty"` // nil when the address maps to no file bytes
	Section    string `json:"section,omitempty"`
}

// Section is one section or segment.
type Section struct {
	Name           string `json:"name"`
	VirtualAddress uint64 `json:"virtual_address"`
	VirtualSize    uint64 `json:"virtual_size"`
	RawOffset      uint64 `json:"raw_offset"`
	RawSize        uint64 `json:"raw_size"`
	Perms          string `json:"permissions"` // e.g. "r-x"
	Flags          uint64 `json:"flags"`
	Kind           string `json:"kind,omitempty"`
}

// Import is a library and the functions requested from it.
type Import struct {
	Library   string     `json:"library"`
	Functions []ImportFn `json:"functions"`
	Delay     bool       `json:"delay_load,omitempty"`
}

// ImportFn is one imported symbol.
type ImportFn struct {
	Name      string `json:"name,omitempty"`
	Ordinal   uint32 `json:"ordinal,omitempty"`
	ByOrdinal bool   `json:"by_ordinal,omitempty"`
	Hint      uint16 `json:"hint,omitempty"`
	// IATRVA is the address of this import's slot in the import address table
	// (PE only): where calls through the table read the function pointer.
	IATRVA uint32 `json:"iat_rva,omitempty"`
}

// Export is one exported symbol.
type Export struct {
	Name      string `json:"name,omitempty"`
	Ordinal   uint32 `json:"ordinal"`
	RVA       uint64 `json:"rva"`
	Forwarder string `json:"forwarder,omitempty"`
}

// Region is a byte range of the file.
type Region struct {
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

// Family returns "pe", "elf" or "macho" derived from Format.
func (b *Binary) Family() string {
	switch {
	case len(b.Format) >= 2 && b.Format[:2] == "PE":
		return "pe"
	case len(b.Format) >= 3 && b.Format[:3] == "ELF":
		return "elf"
	case len(b.Format) >= 6 && b.Format[:6] == "Mach-O":
		return "macho"
	}
	return ""
}

// DotNet describes the metadata of a managed (.NET) assembly. It is read from
// the file's tables only; no code is run and no method body is decompiled.
type DotNet struct {
	MetadataVersion string           `json:"metadata_version,omitempty"` // e.g. v4.0.30319
	Flags           []string         `json:"clr_flags,omitempty"`
	EntryPoint      uint32           `json:"entry_point_token,omitempty"`
	Streams         []DotNetStream   `json:"streams"`
	AssemblyName    string           `json:"assembly_name,omitempty"`
	AssemblyVersion string           `json:"assembly_version,omitempty"`
	ModuleName      string           `json:"module_name,omitempty"`
	Counts          map[string]int   `json:"counts"`
	AssemblyRefs    []string         `json:"assembly_refs,omitempty"`
	PInvokes        []DotNetPInvoke  `json:"pinvokes,omitempty"`
	MemberRefs      []string         `json:"member_refs,omitempty"` // "Type.Member" pairs the code refers to
	Resources       []DotNetResource `json:"resources,omitempty"`
	// Identifier statistics, used to judge name obfuscation.
	Names DotNetNames `json:"names"`
	// MethodsWithoutBody counts methods that should have IL but have none in
	// the file (encrypted or fetched at run time by some protectors).
	MethodsWithoutBody int      `json:"methods_without_body"`
	Anomalies          []string `json:"anomalies,omitempty"`
	Truncated          bool     `json:"truncated,omitempty"`
}

// DotNetStream is one metadata heap.
type DotNetStream struct {
	Name   string `json:"name"`
	Offset uint64 `json:"file_offset"`
	Size   uint32 `json:"size"`
}

// DotNetPInvoke is a native function the assembly declares it calls.
type DotNetPInvoke struct {
	Module   string `json:"module"`
	Function string `json:"function"`
}

// DotNetResource is a manifest resource.
type DotNetResource struct {
	Name     string  `json:"name"`
	Size     uint32  `json:"size"`
	Offset   uint64  `json:"file_offset,omitempty"`
	Entropy  float64 `json:"entropy,omitempty"`
	Kind     string  `json:"kind,omitempty"` // pe | zip | gzip | ""
	External bool    `json:"external,omitempty"`
}

// DotNetNames summarises how readable the type, method and field names are.
type DotNetNames struct {
	Total        int `json:"total"`
	NonPrintable int `json:"non_printable"` // contain control or non-ASCII characters outside letters
	NonASCII     int `json:"non_ascii"`
	Tiny         int `json:"tiny"` // one or two characters
	Unique       int `json:"unique"`
}
