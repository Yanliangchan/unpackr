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
