// Package dotnet reads the metadata of a managed (.NET) assembly as described
// by ECMA-335 partition II: the CLR header, the metadata root, the heaps and
// the tables.
//
// The reader is for untrusted input. Every offset and count is checked against
// the file, tables are limited in rows, strings in length and results in
// number, and nothing is allocated from an attacker-supplied size without a
// cap. It reads names and references only: no method body is decoded and no
// code is run.
package dotnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits.
const (
	maxRows      = 4 << 20
	maxStreams   = 32
	maxString    = 1024
	maxList      = 4096
	maxNames     = 200_000
	maxResBytes  = 8 << 20
	maxResources = 512
)

// ErrNotManaged is returned when the CLR header or metadata root is absent or
// unusable.
var ErrNotManaged = errors.New("not a readable .NET assembly")

// Mapper converts a relative virtual address to a file offset.
type Mapper func(rva uint32) (off int, ok bool)

var le = binary.LittleEndian

// ---- table schema (ECMA-335 II.22)

type kind int

const (
	kU8 kind = iota
	kU16
	kU32
	kStr
	kGUID
	kBlob
	kIdx   // simple index into table n
	kCoded // coded index, set n
)

type col struct {
	k kind
	n int // table id for kIdx, coded set for kCoded
}

type codedSet struct {
	tables []int // -1 = unused tag
	bits   int
}

var coded = []codedSet{
	{[]int{0x02, 0x01, 0x1B}, 2}, // 0 TypeDefOrRef
	{[]int{0x04, 0x08, 0x17}, 2}, // 1 HasConstant
	{[]int{0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B}, 5}, // 2 HasCustomAttribute
	{[]int{0x04, 0x08}, 1},                   // 3 HasFieldMarshal
	{[]int{0x02, 0x06, 0x20}, 2},             // 4 HasDeclSecurity
	{[]int{0x02, 0x01, 0x1A, 0x06, 0x1B}, 3}, // 5 MemberRefParent
	{[]int{0x14, 0x17}, 1},                   // 6 HasSemantics
	{[]int{0x06, 0x0A}, 1},                   // 7 MethodDefOrRef
	{[]int{0x04, 0x06}, 1},                   // 8 MemberForwarded
	{[]int{0x26, 0x23, 0x27}, 2},             // 9 Implementation
	{[]int{-1, -1, 0x06, 0x0A, -1}, 3},       // 10 CustomAttributeType
	{[]int{0x00, 0x1A, 0x23, 0x01}, 2},       // 11 ResolutionScope
	{[]int{0x02, 0x06}, 1},                   // 12 TypeOrMethodDef
}

func u8() col         { return col{k: kU8} }
func u16() col        { return col{k: kU16} }
func u32() col        { return col{k: kU32} }
func str() col        { return col{k: kStr} }
func guid() col       { return col{k: kGUID} }
func blob() col       { return col{k: kBlob} }
func idx(t int) col   { return col{k: kIdx, n: t} }
func cod(set int) col { return col{k: kCoded, n: set} }

// schema lists the columns of every table defined by ECMA-335.
var schema = map[int][]col{
	0x00: {u16(), str(), guid(), guid(), guid()},
	0x01: {cod(11), str(), str()},
	0x02: {u32(), str(), str(), cod(0), idx(0x04), idx(0x06)},
	0x03: {idx(0x04)},
	0x04: {u16(), str(), blob()},
	0x05: {idx(0x06)},
	0x06: {u32(), u16(), u16(), str(), blob(), idx(0x08)},
	0x07: {idx(0x08)},
	0x08: {u16(), u16(), str()},
	0x09: {idx(0x02), cod(0)},
	0x0A: {cod(5), str(), blob()},
	0x0B: {u8(), u8(), cod(1), blob()},
	0x0C: {cod(2), cod(10), blob()},
	0x0D: {cod(3), blob()},
	0x0E: {u16(), cod(4), blob()},
	0x0F: {u16(), u32(), idx(0x02)},
	0x10: {u32(), idx(0x04)},
	0x11: {blob()},
	0x12: {idx(0x02), idx(0x14)},
	0x13: {idx(0x14)},
	0x14: {u16(), str(), cod(0)},
	0x15: {idx(0x02), idx(0x17)},
	0x16: {idx(0x17)},
	0x17: {u16(), str(), blob()},
	0x18: {u16(), idx(0x06), cod(6)},
	0x19: {idx(0x02), cod(7), cod(7)},
	0x1A: {str()},
	0x1B: {blob()},
	0x1C: {u16(), cod(8), str(), idx(0x1A)},
	0x1D: {u32(), idx(0x04)},
	0x1E: {u32(), u32()},
	0x1F: {u32()},
	0x20: {u32(), u16(), u16(), u16(), u16(), u32(), blob(), str(), str()},
	0x21: {u32()},
	0x22: {u32(), u32(), u32()},
	0x23: {u16(), u16(), u16(), u16(), u32(), blob(), str(), str(), blob()},
	0x24: {u32(), idx(0x23)},
	0x25: {u32(), u32(), u32(), idx(0x23)},
	0x26: {u32(), str(), blob()},
	0x27: {u32(), u32(), str(), str(), cod(9)},
	0x28: {u32(), u32(), str(), cod(9)},
	0x29: {idx(0x02), idx(0x02)},
	0x2A: {u16(), u16(), cod(12), str()},
	0x2B: {cod(7), blob()},
	0x2C: {idx(0x2A), cod(0)},
}

const lastTable = 0x2C

type tables struct {
	data    []byte // the whole tables stream
	rows    [64]int
	offs    [64]int // start of each table inside data
	rowSize [64]int
	cols    [64][]col
	colOff  [64][]int
	wide    struct{ str, guid, blob bool }
}

func (t *tables) simpleWide(tbl int) bool { return t.rows[tbl&63] >= 1<<16 }

func (t *tables) codedWide(set int) bool {
	cs := coded[set]
	limit := 1 << (16 - cs.bits)
	for _, tb := range cs.tables {
		if tb >= 0 && t.rows[tb] >= limit {
			return true
		}
	}
	return false
}

func (t *tables) size(c col) int {
	switch c.k {
	case kU8:
		return 1
	case kU16:
		return 2
	case kU32:
		return 4
	case kStr:
		return b2i(t.wide.str, 4, 2)
	case kGUID:
		return b2i(t.wide.guid, 4, 2)
	case kBlob:
		return b2i(t.wide.blob, 4, 2)
	case kIdx:
		return b2i(t.simpleWide(c.n), 4, 2)
	default:
		return b2i(t.codedWide(c.n), 4, 2)
	}
}

func b2i(b bool, y, n int) int {
	if b {
		return y
	}
	return n
}

// get reads column c of 1-based row r of table tb. Out-of-range reads give 0.
func (t *tables) get(tb, r, c int) uint32 {
	if r < 1 || r > t.rows[tb] {
		return 0
	}
	p := t.offs[tb] + (r-1)*t.rowSize[tb] + t.colOff[tb][c]
	n := t.size(t.cols[tb][c])
	if p < 0 || p+n > len(t.data) {
		return 0
	}
	switch n {
	case 1:
		return uint32(t.data[p])
	case 2:
		return uint32(le.Uint16(t.data[p:]))
	}
	return le.Uint32(t.data[p:])
}

// resolve splits a coded index into (table, 1-based row).
func resolve(set int, v uint32) (tbl, row int) {
	cs := coded[set]
	tag := int(v & (1<<cs.bits - 1))
	if tag >= len(cs.tables) {
		return -1, 0
	}
	return cs.tables[tag], int(v >> cs.bits)
}

// ---- heaps

type heap []byte

func (h heap) str(i uint32) string {
	if int(i) >= len(h) {
		return ""
	}
	b := h[i:]
	end := 0
	for end < len(b) && b[end] != 0 && end < maxString {
		end++
	}
	return string(b[:end])
}

// ---- parse

// Parse reads the metadata of the assembly whose CLR header is at clrRVA.
func Parse(data []byte, clrRVA, clrSize uint32, toOff Mapper) (*models.DotNet, error) {
	if clrRVA == 0 || clrSize < 72 {
		return nil, fmt.Errorf("%w: no CLR header", ErrNotManaged)
	}
	co, ok := toOff(clrRVA)
	if !ok || co < 0 || co+72 > len(data) {
		return nil, fmt.Errorf("%w: CLR header is outside the file", ErrNotManaged)
	}
	h := data[co:]
	out := &models.DotNet{Counts: map[string]int{}, Streams: []models.DotNetStream{}}
	flags := le.Uint32(h[16:])
	for _, f := range []struct {
		bit  uint32
		name string
	}{{1, "il-only"}, {2, "32bit-required"}, {8, "strong-name-signed"}, {0x10, "native-entry-point"}, {0x20000, "32bit-preferred"}} {
		if flags&f.bit != 0 {
			out.Flags = append(out.Flags, f.name)
		}
	}
	out.EntryPoint = le.Uint32(h[20:])
	mdRVA, mdSize := le.Uint32(h[8:]), le.Uint32(h[12:])
	resRVA, resSize := le.Uint32(h[24:]), le.Uint32(h[28:])

	mo, ok := toOff(mdRVA)
	if !ok || mo < 0 || mo+16 > len(data) || mdSize < 16 {
		return nil, fmt.Errorf("%w: metadata root is outside the file", ErrNotManaged)
	}
	md := data[mo:min(len(data), mo+int(min(uint64(mdSize), 1<<31)))]
	if le.Uint32(md) != 0x424A5342 {
		return nil, fmt.Errorf("%w: metadata signature is not BSJB", ErrNotManaged)
	}
	vlen := int(le.Uint32(md[12:]))
	if vlen < 0 || vlen > 255 || 16+vlen+4 > len(md) {
		return nil, fmt.Errorf("%w: invalid metadata version length", ErrNotManaged)
	}
	out.MetadataVersion = strings.TrimRight(string(md[16:16+vlen]), "\x00")
	p := 16 + vlen
	nStreams := int(le.Uint16(md[p+2:]))
	p += 4
	if nStreams > maxStreams {
		out.Anomalies = append(out.Anomalies, fmt.Sprintf("declares %d streams; only the first %d are read", nStreams, maxStreams))
		nStreams = maxStreams
	}
	heaps := map[string][]byte{}
	seen := map[string]bool{}
	for i := 0; i < nStreams; i++ {
		if p+8 > len(md) {
			out.Anomalies = append(out.Anomalies, "stream directory runs past the metadata")
			break
		}
		off, size := int(le.Uint32(md[p:])), int(le.Uint32(md[p+4:]))
		p += 8
		start := p
		for p < len(md) && md[p] != 0 && p-start < 64 {
			p++
		}
		name := string(md[start:p])
		p = (p + 4) &^ 3 // name plus NUL, padded to 4
		if p-start > 68 || p > len(md)+3 {
			out.Anomalies = append(out.Anomalies, "stream name is malformed")
			break
		}
		if seen[name] {
			out.Anomalies = append(out.Anomalies, "stream "+printable(name)+" appears more than once")
		}
		seen[name] = true
		out.Streams = append(out.Streams, models.DotNetStream{Name: printable(name), Offset: uint64(mo + off), Size: uint32(size)})
		if off < 0 || size < 0 || off > len(md) || off+size > len(md) {
			out.Anomalies = append(out.Anomalies, "stream "+printable(name)+" lies outside the metadata block")
			continue
		}
		if _, dup := heaps[name]; !dup {
			heaps[name] = md[off : off+size]
		}
		switch name {
		case "#~", "#Strings", "#US", "#GUID", "#Blob", "#-":
		default:
			out.Anomalies = append(out.Anomalies, "non-standard stream "+printable(name))
		}
	}
	if seen["#~"] && seen["#-"] {
		out.Anomalies = append(out.Anomalies, "both #~ and #- table streams are present")
	}
	out.Counts["UserStringBytes"] = len(heaps["#US"])
	ts := heaps["#~"]
	if ts == nil {
		ts = heaps["#-"]
	}
	if ts == nil {
		out.Anomalies = append(out.Anomalies, "no metadata table stream")
		return out, nil
	}
	if err := readTables(out, ts, heap(heaps["#Strings"]), heap(heaps["#Blob"]), data, resRVA, resSize, toOff); err != nil {
		out.Anomalies = append(out.Anomalies, err.Error())
		out.Truncated = true
	}
	return out, nil
}

func readTables(out *models.DotNet, ts []byte, strs, _ heap, data []byte, resRVA, resSize uint32, toOff Mapper) error {
	if len(ts) < 24 {
		return errors.New("table stream is too short")
	}
	hs := ts[6]
	valid := le.Uint64(ts[8:])
	t := &tables{data: ts}
	t.wide.str, t.wide.guid, t.wide.blob = hs&1 != 0, hs&2 != 0, hs&4 != 0
	p := 24
	for i := 0; i < 64; i++ {
		if valid&(1<<uint(i)) == 0 {
			continue
		}
		if p+4 > len(ts) {
			return errors.New("row counts run past the table stream")
		}
		n := int(le.Uint32(ts[p:]))
		p += 4
		if i > lastTable {
			out.Anomalies = append(out.Anomalies, fmt.Sprintf("table 0x%02x is not defined by ECMA-335; the tables after it cannot be located", i))
			return errors.New("unsupported table in the stream")
		}
		if n < 0 || n > maxRows {
			return fmt.Errorf("table 0x%02x claims %d rows", i, n)
		}
		t.rows[i] = n
	}
	if hs&0x40 != 0 {
		p += 4
	}
	// Row layouts need the final row counts, so they are computed after the loop.
	for tb := 0; tb <= lastTable; tb++ {
		cs := schema[tb]
		t.cols[tb] = cs
		t.colOff[tb] = make([]int, len(cs))
		sz := 0
		for i, c := range cs {
			t.colOff[tb][i] = sz
			sz += t.size(c)
		}
		t.rowSize[tb] = sz
	}
	for tb := 0; tb <= lastTable; tb++ {
		t.offs[tb] = p
		need := t.rows[tb] * t.rowSize[tb]
		if need < 0 || p+need > len(ts) || p+need < p {
			return fmt.Errorf("table 0x%02x (%d rows) runs past the table stream", tb, t.rows[tb])
		}
		p += need
	}

	name := func(tb, r, c int) string { return strs.str(t.get(tb, r, c)) }
	counts := map[string]int{"Module": 0x00, "TypeRef": 0x01, "TypeDef": 0x02, "Field": 0x04, "MethodDef": 0x06, "MemberRef": 0x0A,
		"CustomAttribute": 0x0C, "ModuleRef": 0x1A, "ImplMap": 0x1C, "AssemblyRef": 0x23, "ManifestResource": 0x28}
	for k, tb := range counts {
		out.Counts[k] = t.rows[tb]
	}

	if t.rows[0x00] >= 1 {
		out.ModuleName = printable(name(0x00, 1, 1))
	}
	if t.rows[0x20] >= 1 {
		out.AssemblyName = printable(name(0x20, 1, 7))
		out.AssemblyVersion = fmt.Sprintf("%d.%d.%d.%d", t.get(0x20, 1, 1), t.get(0x20, 1, 2), t.get(0x20, 1, 3), t.get(0x20, 1, 4))
	}
	for r := 1; r <= t.rows[0x23] && len(out.AssemblyRefs) < maxList; r++ {
		out.AssemblyRefs = append(out.AssemblyRefs, fmt.Sprintf("%s %d.%d.%d.%d", printable(name(0x23, r, 6)), t.get(0x23, r, 0), t.get(0x23, r, 1), t.get(0x23, r, 2), t.get(0x23, r, 3)))
	}

	// Identifier statistics over types, methods and fields.
	uniq := map[string]struct{}{}
	stat := func(s string) {
		n := &out.Names
		n.Total++
		if s == "" {
			return
		}
		if utf8.RuneCountInString(s) <= 2 {
			n.Tiny++
		}
		weird, nonASCII := false, false
		for _, r := range s {
			switch {
			case r >= 0x80:
				nonASCII = true
				weird = true
			case r < 0x20 || r == 0x7f:
				weird = true
			}
		}
		if weird {
			n.NonPrintable++
		}
		if nonASCII {
			n.NonASCII++
		}
		if len(uniq) < maxNames {
			uniq[s] = struct{}{}
		}
	}
	for _, spec := range [][2]int{{0x02, 1}, {0x06, 3}, {0x04, 1}} {
		for r := 1; r <= t.rows[spec[0]] && r <= maxNames; r++ {
			stat(name(spec[0], r, spec[1]))
		}
	}
	out.Names.Unique = len(uniq)

	// Methods that should have IL but have none.
	for r := 1; r <= t.rows[0x06] && r <= maxNames; r++ {
		rva, impl, fl := t.get(0x06, r, 0), t.get(0x06, r, 1), t.get(0x06, r, 2)
		if rva == 0 && impl&0x3 == 0 && fl&0x0400 == 0 && fl&0x2000 == 0 && impl&0x1000 == 0 {
			out.MethodsWithoutBody++
		}
	}

	// References the code makes, as "Type.Member".
	typeName := func(tbl, row int) string {
		switch tbl {
		case 0x01:
			return name(0x01, row, 1)
		case 0x02:
			return name(0x02, row, 1)
		case 0x1A:
			return "[" + name(0x1A, row, 0) + "]"
		}
		return ""
	}
	seenRef := map[string]bool{}
	for r := 1; r <= t.rows[0x0A] && len(out.MemberRefs) < maxList*2; r++ {
		tbl, row := resolve(5, t.get(0x0A, r, 0))
		tn := typeName(tbl, row)
		if tn == "" {
			continue
		}
		ref := printable(tn + "." + name(0x0A, r, 1))
		if !seenRef[ref] {
			seenRef[ref] = true
			out.MemberRefs = append(out.MemberRefs, ref)
		}
	}

	// P/Invoke declarations.
	for r := 1; r <= t.rows[0x1C] && len(out.PInvokes) < maxList; r++ {
		mod := name(0x1A, int(t.get(0x1C, r, 3)), 0)
		fn := name(0x1C, r, 2)
		if fn != "" || mod != "" {
			out.PInvokes = append(out.PInvokes, models.DotNetPInvoke{Module: printable(mod), Function: printable(fn)})
		}
	}

	// Manifest resources.
	var base int
	haveRes := false
	if resRVA != 0 && resSize >= 4 {
		if o, ok := toOff(resRVA); ok && o >= 0 && o < len(data) {
			base, haveRes = o, true
		}
	}
	for r := 1; r <= t.rows[0x28] && len(out.Resources) < maxResources; r++ {
		off, nm := int(t.get(0x28, r, 0)), printable(name(0x28, r, 2))
		impl := t.get(0x28, r, 3)
		res := models.DotNetResource{Name: nm, External: impl != 0}
		if !res.External && haveRes && off >= 0 && base+off+4 <= len(data) && uint32(off)+4 <= resSize {
			n := int(le.Uint32(data[base+off:]))
			start := base + off + 4
			if n >= 0 && start+n <= len(data) && uint32(off)+4+uint32(n) <= resSize {
				res.Size, res.Offset = uint32(n), uint64(start)
				blob := data[start : start+min(n, maxResBytes)]
				res.Entropy = math.Round(entropy(blob)*1000) / 1000
				res.Kind = sniff(blob)
			}
		}
		out.Resources = append(out.Resources, res)
	}
	return nil
}

func sniff(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		return "pe"
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4:
		return "zip"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	}
	return ""
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var c [256]int
	for _, x := range b {
		c[x]++
	}
	var h float64
	n := float64(len(b))
	for _, k := range c {
		if k > 0 {
			p := float64(k) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// printable makes a metadata string safe to store in a report: control bytes
// become visible escapes. (Reports are sanitised again before display.)
func printable(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == utf8.RuneError }) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
