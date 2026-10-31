// Package fixtures builds small, harmless, synthetic executables for tests.
// Nothing here is real malware and none of it is ever executed.
package fixtures

import (
	"encoding/binary"
	"strings"
)

// PESpec describes a synthetic PE32+ image.
type PESpec struct {
	Machine   uint16              // default 0x8664
	DLL       bool                // sets IMAGE_FILE_DLL
	TextFlags uint32              // section characteristics for .text (default code|read|exec)
	Imports   map[string][]string // library -> function names (iteration order is sorted by the builder)
	Exports   []string            // exported names, all pointing into .text
	Overlay   []byte
	Timestamp uint32
}

const (
	fileAlign = 0x200
	secAlign  = 0x1000
)

func align(v, a int) int { return (v + a - 1) / a * a }

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// BuildPE returns the bytes of a minimal, structurally valid PE32+ file.
func BuildPE(s PESpec) []byte {
	if s.Machine == 0 {
		s.Machine = 0x8664
	}
	if s.TextFlags == 0 {
		s.TextFlags = 0x60000020 // code | execute | read
	}
	le := binary.LittleEndian

	// .text: a few harmless bytes (int3 padding); it is never run.
	text := make([]byte, 0x40)
	for i := range text {
		text[i] = 0xcc
	}

	// .idata
	idataRVA := 0x2000
	var idata []byte
	dataDirImport := [2]uint32{}
	if len(s.Imports) > 0 {
		libs := sortedKeys(s.Imports)
		nd := (len(libs) + 1) * 20
		// compute sizes
		type lib struct {
			name     string
			funcs    []string
			ilt, iat int
			nameOff  int
			hintOffs []int
		}
		var ls []lib
		off := nd
		for _, n := range libs {
			l := lib{name: n, funcs: s.Imports[n]}
			l.ilt = off
			off += (len(l.funcs) + 1) * 8
			l.iat = off
			off += (len(l.funcs) + 1) * 8
			ls = append(ls, l)
		}
		for i := range ls {
			ls[i].nameOff = off
			off += len(ls[i].name) + 1
			if off%2 == 1 {
				off++
			}
			for _, f := range ls[i].funcs {
				ls[i].hintOffs = append(ls[i].hintOffs, off)
				off += 2 + len(f) + 1
				if off%2 == 1 {
					off++
				}
			}
		}
		idata = make([]byte, off)
		for i, l := range ls {
			d := idata[i*20:]
			le.PutUint32(d[0:], uint32(idataRVA+l.ilt))
			le.PutUint32(d[12:], uint32(idataRVA+l.nameOff))
			le.PutUint32(d[16:], uint32(idataRVA+l.iat))
			copy(idata[l.nameOff:], l.name)
			for j, f := range l.funcs {
				ho := l.hintOffs[j]
				le.PutUint16(idata[ho:], uint16(j))
				copy(idata[ho+2:], f)
				le.PutUint64(idata[l.ilt+j*8:], uint64(idataRVA+ho))
				le.PutUint64(idata[l.iat+j*8:], uint64(idataRVA+ho))
			}
		}
		dataDirImport = [2]uint32{uint32(idataRVA), uint32(nd)}
	}

	// .edata
	edataRVA := idataRVA + align(len(idata), secAlign)
	if len(idata) == 0 {
		edataRVA = idataRVA
	}
	var edata []byte
	dataDirExport := [2]uint32{}
	if len(s.Exports) > 0 {
		n := len(s.Exports)
		const dir = 40
		funcsOff := dir
		namesOff := funcsOff + 4*n
		ordsOff := namesOff + 4*n
		strOff := ordsOff + 2*n
		modName := "synthetic.dll"
		size := strOff + len(modName) + 1
		for _, e := range s.Exports {
			size += len(e) + 1
		}
		edata = make([]byte, size)
		le.PutUint32(edata[12:], uint32(edataRVA+strOff)) // Name
		le.PutUint32(edata[16:], 1)                       // Base
		le.PutUint32(edata[20:], uint32(n))
		le.PutUint32(edata[24:], uint32(n))
		le.PutUint32(edata[28:], uint32(edataRVA+funcsOff))
		le.PutUint32(edata[32:], uint32(edataRVA+namesOff))
		le.PutUint32(edata[36:], uint32(edataRVA+ordsOff))
		copy(edata[strOff:], modName)
		p := strOff + len(modName) + 1
		for i, e := range s.Exports {
			le.PutUint32(edata[funcsOff+4*i:], 0x1000) // all at start of .text
			le.PutUint32(edata[namesOff+4*i:], uint32(edataRVA+p))
			le.PutUint16(edata[ordsOff+2*i:], uint16(i))
			copy(edata[p:], e)
			p += len(e) + 1
		}
		dataDirExport = [2]uint32{uint32(edataRVA), uint32(len(edata))}
	}

	type sect struct {
		name  string
		rva   int
		data  []byte
		flags uint32
	}
	secs := []sect{{".text", 0x1000, text, s.TextFlags}}
	if len(idata) > 0 {
		secs = append(secs, sect{".idata", idataRVA, idata, 0xc0000040})
	}
	if len(edata) > 0 {
		secs = append(secs, sect{".edata", edataRVA, edata, 0x40000040})
	}

	const optSize = 0xf0
	hdrEnd := 0x80 + 4 + 20 + optSize + 40*len(secs)
	sizeOfHeaders := align(hdrEnd, fileAlign)
	raw := sizeOfHeaders
	img := make([]byte, sizeOfHeaders)
	copy(img, "MZ")
	le.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], "PE\x00\x00")
	fh := img[0x84:]
	le.PutUint16(fh[0:], s.Machine)
	le.PutUint16(fh[2:], uint16(len(secs)))
	le.PutUint32(fh[4:], s.Timestamp)
	le.PutUint16(fh[16:], optSize)
	chars := uint16(0x0022) // executable image | large address aware
	if s.DLL {
		chars |= 0x2000
	}
	le.PutUint16(fh[18:], chars)
	oh := img[0x98:]
	le.PutUint16(oh[0:], 0x20b)
	oh[2], oh[3] = 14, 0          // linker version
	le.PutUint32(oh[16:], 0x1000) // entry point
	le.PutUint64(oh[24:], 0x140000000)
	le.PutUint32(oh[32:], secAlign)
	le.PutUint32(oh[36:], fileAlign)
	le.PutUint16(oh[40:], 6) // OS version
	le.PutUint16(oh[48:], 6) // subsystem version
	lastRVA, lastSize := 0, 0
	for _, sc := range secs {
		if sc.rva >= lastRVA {
			lastRVA, lastSize = sc.rva, len(sc.data)
		}
	}
	le.PutUint32(oh[56:], uint32(lastRVA+align(lastSize, secAlign))) // SizeOfImage
	le.PutUint32(oh[60:], uint32(sizeOfHeaders))
	le.PutUint16(oh[68:], 3) // console subsystem
	le.PutUint16(oh[70:], 0x8160)
	le.PutUint64(oh[72:], 0x100000)
	le.PutUint64(oh[80:], 0x1000)
	le.PutUint64(oh[88:], 0x100000)
	le.PutUint64(oh[96:], 0x1000)
	le.PutUint32(oh[108:], 16) // NumberOfRvaAndSizes
	dd := oh[112:]
	le.PutUint32(dd[0:], dataDirExport[0])
	le.PutUint32(dd[4:], dataDirExport[1])
	le.PutUint32(dd[8:], dataDirImport[0])
	le.PutUint32(dd[12:], dataDirImport[1])

	sh := img[0x98+optSize:]
	for i, sc := range secs {
		h := sh[i*40:]
		copy(h, sc.name)
		le.PutUint32(h[8:], uint32(len(sc.data)))
		le.PutUint32(h[12:], uint32(sc.rva))
		rs := align(len(sc.data), fileAlign)
		le.PutUint32(h[16:], uint32(rs))
		le.PutUint32(h[20:], uint32(raw))
		le.PutUint32(h[36:], sc.flags)
		raw += rs
	}
	// Bodies are appended only after every header is written, because append
	// may reallocate img and would orphan slices taken from it.
	for _, sc := range secs {
		body := make([]byte, align(len(sc.data), fileAlign))
		copy(body, sc.data)
		img = append(img, body...)
	}
	img = append(img, s.Overlay...)
	return img
}

// Names joins names for assertions.
func Names(ss ...string) string { return strings.Join(ss, ",") }
