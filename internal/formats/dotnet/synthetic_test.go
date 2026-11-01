package dotnet

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// A small assembly built by hand from ECMA-335. Row sizes are written out
// literally (all heaps and indexes are two bytes wide) rather than derived from
// the parser's schema, so the two descriptions of the format check each other.
type strHeap struct {
	b   bytes.Buffer
	idx map[string]uint16
}

func newStrHeap() *strHeap {
	h := &strHeap{idx: map[string]uint16{}}
	h.b.WriteByte(0)
	return h
}

func (h *strHeap) add(s string) uint16 {
	if s == "" {
		return 0
	}
	if i, ok := h.idx[s]; ok {
		return i
	}
	i := uint16(h.b.Len())
	h.b.WriteString(s)
	h.b.WriteByte(0)
	h.idx[s] = i
	return i
}

func w16(b *bytes.Buffer, v ...uint16) {
	for _, x := range v {
		_ = binary.Write(b, binary.LittleEndian, x)
	}
}
func w32(b *bytes.Buffer, v ...uint32) {
	for _, x := range v {
		_ = binary.Write(b, binary.LittleEndian, x)
	}
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

func buildAssembly(resource []byte) []byte {
	h := newStrHeap()
	var tb bytes.Buffer

	// Module (0x00): Generation, Name, Mvid, EncId, EncBaseId = 10 bytes
	w16(&tb, 0, h.add("synthetic.dll"), 1, 0, 0)
	// TypeRef (0x01) x2: ResolutionScope(coded 2), Name, Namespace = 6 bytes
	w16(&tb, 0x0B, h.add("Process"), h.add("System.Diagnostics")) // scope AssemblyRef row 2? use row 2 -> (2<<2)|2
	w16(&tb, 0x0A, h.add("Assembly"), h.add("System.Reflection"))
	// TypeDef (0x02) x1: Flags u32, Name, Namespace, Extends(coded 2), FieldList, MethodList = 14 bytes
	w32(&tb, 0)
	w16(&tb, h.add("<Module>"), 0, 0, 1, 1)
	// Method (0x06) x3: RVA u32, ImplFlags, Flags, Name, Signature, ParamList = 14 bytes
	w32(&tb, 0)
	w16(&tb, 0, 0x0006, h.add("Run"), 0, 1) // IL, no body: counted
	w32(&tb, 0)
	w16(&tb, 0, 0x2093, h.add("AllocNative"), 0, 1) // pinvokeimpl: not counted
	w32(&tb, 0)
	w16(&tb, 0, 0x0446, h.add("Abstract"), 0, 1) // abstract: not counted
	// MemberRef (0x0A) x2: Class(coded 3), Name, Signature = 6 bytes; TypeRef tag = 1
	w16(&tb, 1<<3|1, h.add("Start"), 0)
	w16(&tb, 2<<3|1, h.add("Load"), 0)
	// ModuleRef (0x1A) x1: Name
	w16(&tb, h.add("kernel32"))
	// ImplMap (0x1C) x1: MappingFlags, MemberForwarded(coded 1, Method tag 1), ImportName, ImportScope = 8 bytes
	w16(&tb, 0x0240, 2<<1|1, h.add("VirtualAlloc"), 1)
	// Assembly (0x20) x1: HashAlg u32, 4 x u16, Flags u32, PublicKey, Name, Culture = 22 bytes
	w32(&tb, 0x8004)
	w16(&tb, 1, 2, 3, 4)
	w32(&tb, 0)
	w16(&tb, 0, h.add("synthetic"), 0)
	// AssemblyRef (0x23) x2: 4 x u16, Flags u32, PublicKeyOrToken, Name, Culture, HashValue = 20 bytes
	for _, n := range []string{"mscorlib", "System"} {
		w16(&tb, 4, 0, 0, 0)
		w32(&tb, 0)
		w16(&tb, 0, h.add(n), 0, 0)
	}
	// ManifestResource (0x28) x1: Offset u32, Flags u32, Name, Implementation(coded 2) = 12 bytes
	w32(&tb, 0, 1)
	w16(&tb, h.add("payload.bin"), 0)

	var ts bytes.Buffer
	w32(&ts, 0)
	ts.Write([]byte{2, 0, 0, 1}) // major, minor, heap sizes (all 2 bytes), reserved
	valid := uint64(0)
	rows := map[int]uint32{0x00: 1, 0x01: 2, 0x02: 1, 0x06: 3, 0x0A: 2, 0x1A: 1, 0x1C: 1, 0x20: 1, 0x23: 2, 0x28: 1}
	for t := range rows {
		valid |= 1 << uint(t)
	}
	_ = binary.Write(&ts, binary.LittleEndian, valid)
	_ = binary.Write(&ts, binary.LittleEndian, uint64(0))
	for t := 0; t < 64; t++ {
		if n, ok := rows[t]; ok {
			w32(&ts, n)
		}
	}
	ts.Write(tb.Bytes())
	pad4(&ts)

	var md bytes.Buffer
	w32(&md, 0x424A5342)
	w16(&md, 1, 1)
	w32(&md, 0)
	ver := "v4.0.30319\x00\x00"
	w32(&md, uint32(len(ver)))
	md.WriteString(ver)
	w16(&md, 0, 5)
	strsB := h.b.Bytes()
	heaps := []struct {
		name string
		data []byte
	}{{"#~", ts.Bytes()}, {"#Strings", append(append([]byte(nil), strsB...), 0, 0, 0)[:(len(strsB)+3)&^3]}, {"#US", []byte{0, 0, 0, 0}}, {"#GUID", make([]byte, 16)}, {"#Blob", []byte{0, 0, 0, 0}}}
	hdrLen := md.Len()
	for _, hp := range heaps {
		hdrLen += 8 + (len(hp.name)+1+3)&^3
	}
	off := hdrLen
	for _, hp := range heaps {
		w32(&md, uint32(off), uint32(len(hp.data)))
		md.WriteString(hp.name)
		md.WriteByte(0)
		pad4(&md)
		off += len(hp.data)
	}
	for _, hp := range heaps {
		md.Write(hp.data)
	}

	img := make([]byte, 0x3000)
	copy(img[0x200:], md.Bytes())
	var clr bytes.Buffer
	w32(&clr, 72)
	w16(&clr, 2, 5)
	w32(&clr, 0x200, uint32(md.Len())) // metadata
	w32(&clr, 1)                       // IL only
	w32(&clr, 0x06000001)              // entry point token
	w32(&clr, 0x1000, uint32(len(resource)+4))
	copy(img[0x100:], clr.Bytes())
	if resource != nil {
		binary.LittleEndian.PutUint32(img[0x1000:], uint32(len(resource)))
		copy(img[0x1004:], resource)
	}
	return img
}

func identity(rva uint32) (int, bool) { return int(rva), true }

func TestSyntheticAssembly(t *testing.T) {
	payload := append([]byte("MZ"), bytes.Repeat([]byte{0x90}, 300)...)
	img := buildAssembly(payload)
	d, err := Parse(img, 0x100, 72, identity)
	if err != nil {
		t.Fatal(err)
	}
	if d.AssemblyName != "synthetic" || d.AssemblyVersion != "1.2.3.4" || d.ModuleName != "synthetic.dll" || d.MetadataVersion != "v4.0.30319" {
		t.Errorf("identity: %+v", d)
	}
	if got := strings.Join(d.AssemblyRefs, ","); got != "mscorlib 4.0.0.0,System 4.0.0.0" {
		t.Errorf("assembly refs: %s", got)
	}
	if len(d.PInvokes) != 1 || d.PInvokes[0].Module != "kernel32" || d.PInvokes[0].Function != "VirtualAlloc" {
		t.Errorf("pinvokes: %+v", d.PInvokes)
	}
	if got := strings.Join(d.MemberRefs, ","); got != "Process.Start,Assembly.Load" {
		t.Errorf("member refs: %s", got)
	}
	if d.MethodsWithoutBody != 1 {
		t.Errorf("methods without body = %d, want 1 (only the plain IL method)", d.MethodsWithoutBody)
	}
	if len(d.Resources) != 1 || d.Resources[0].Name != "payload.bin" || d.Resources[0].Kind != "pe" || d.Resources[0].Size != uint32(len(payload)) || d.Resources[0].External {
		t.Errorf("resources: %+v", d.Resources)
	}
	if d.EntryPoint != 0x06000001 || len(d.Flags) != 1 || d.Flags[0] != "il-only" {
		t.Errorf("clr header: %+v %v", d.EntryPoint, d.Flags)
	}
	if len(d.Anomalies) != 0 {
		t.Errorf("anomalies: %v", d.Anomalies)
	}
}

func TestSyntheticDamage(t *testing.T) {
	img := buildAssembly([]byte("MZ........"))
	// Every single-byte corruption of the metadata and header must be survivable.
	for i := 0x100; i < 0x100+72; i++ {
		c := append([]byte(nil), img...)
		c[i] ^= 0xFF
		_, _ = Parse(c, 0x100, 72, identity)
	}
	for i := 0x200; i < 0x200+700; i++ {
		for _, x := range []byte{0x00, 0xFF, 0x80} {
			c := append([]byte(nil), img...)
			c[i] = x
			_, _ = Parse(c, 0x100, 72, identity)
		}
	}
	if _, err := Parse(img[:0x180], 0x100, 72, identity); err == nil {
		t.Error("a truncated file should not parse")
	}
	if _, err := Parse(img, 0, 0, identity); err == nil {
		t.Error("no CLR header should be reported")
	}
}

func TestHugeRowCountsAreRejectedNotAllocated(t *testing.T) {
	img := buildAssembly(nil)
	// Claim 0x7fffffff rows in TypeDef: the reader must refuse, not allocate.
	meta := 0x200
	i := bytes.Index(img[meta:], []byte("#~")) // stream name; the table stream starts at its offset
	_ = i
	ts := bytes.Index(img[meta:], []byte{0, 0, 0, 0, 2, 0, 0, 1}) + meta
	rowsAt := ts + 24 + 4*2 // third present table (TypeDef) after Module and TypeRef counts
	binary.LittleEndian.PutUint32(img[rowsAt:], 0x7fffffff)
	d, err := Parse(img, 0x100, 72, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated || len(d.Anomalies) == 0 {
		t.Errorf("expected a truncation anomaly: %+v", d)
	}
}
