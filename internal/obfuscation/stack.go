package obfuscation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Stack strings are built by storing constants into a stack frame a few bytes
// at a time, so the text never appears contiguously in the file. The
// recogniser follows the usual x86 and x86-64 encodings of those stores:
//
//	C6 45 d8 ib | C6 44 24 d8 ib | C6 85 d32 ib   mov byte  [rbp/rsp+d], imm8
//	66 C7 45 d8 iw | 66 C7 44 24 d8 iw            mov word  [rbp/rsp+d], imm16
//	C7 45 d8 id | C7 44 24 d8 id                  mov dword [rbp/rsp+d], imm32
//	48/49 B8+r imm64                              movabs reg, imm64
//	48/4C 89 /r  (rbp/rsp base, no disp, disp8 or disp32)  mov qword [rbp/rsp+d], reg
//
// A register holding a constant from a movabs is tracked, so the common
// "movabs rax, imm64 ; mov [rsp+d], rax" pairs are understood. A run of
// back-to-back recognised instructions is one chain; its stores are joined by
// frame offset and the result is examined as if it were a buffer: printable
// text is reported, and the XOR/ADD marker search runs over it too, which
// recovers encoded strings that a compiler built on the stack.
//
// This is a pattern match over raw bytes, not disassembly or emulation. It
// cannot see strings built through computation, and a chain that starts in
// the middle of another instruction is possible, so results need the same
// scrutiny as any other string.
const minStackText = 6

type store struct {
	base byte // 0 rbp, 1 rsp
	disp int32
	val  []byte
}

type insn struct {
	n     int
	reg   int // movabs: destination register, -1 otherwise
	imm   uint64
	store *store // stores of known constants
	// regStore is a store of a register (value resolved by the caller).
	regStore bool
	rbase    byte
	rdisp    int32
	rsrc     int
}

func le32(d []byte) uint32 {
	return uint32(d[0]) | uint32(d[1])<<8 | uint32(d[2])<<16 | uint32(d[3])<<24
}
func le64(d []byte) uint64 { return uint64(le32(d)) | uint64(le32(d[4:]))<<32 }

func decode(d []byte, p int) (insn, bool) {
	r := func(n int) bool { return p+n <= len(d) }
	in := insn{reg: -1}
	switch {
	case r(10) && (d[p] == 0x48 || d[p] == 0x49) && d[p+1]&0xF8 == 0xB8:
		in.n, in.reg, in.imm = 10, int(d[p+1]&7)+8*int(d[p]&1), le64(d[p+2:])
		return in, true
	case r(4) && d[p] == 0xC6 && d[p+1] == 0x45:
		in.n, in.store = 4, &store{0, int32(int8(d[p+2])), []byte{d[p+3]}}
		return in, true
	case r(5) && d[p] == 0xC6 && d[p+1] == 0x44 && d[p+2] == 0x24:
		in.n, in.store = 5, &store{1, int32(int8(d[p+3])), []byte{d[p+4]}}
		return in, true
	case r(7) && d[p] == 0xC6 && d[p+1] == 0x85:
		in.n, in.store = 7, &store{0, int32(le32(d[p+2:])), []byte{d[p+6]}}
		return in, true
	case r(6) && d[p] == 0x66 && d[p+1] == 0xC7 && d[p+2] == 0x45:
		in.n, in.store = 6, &store{0, int32(int8(d[p+3])), []byte{d[p+4], d[p+5]}}
		return in, true
	case r(7) && d[p] == 0x66 && d[p+1] == 0xC7 && d[p+2] == 0x44 && d[p+3] == 0x24:
		in.n, in.store = 7, &store{1, int32(int8(d[p+4])), []byte{d[p+5], d[p+6]}}
		return in, true
	case r(7) && d[p] == 0xC7 && d[p+1] == 0x45:
		in.n, in.store = 7, &store{0, int32(int8(d[p+2])), append([]byte(nil), d[p+3:p+7]...)}
		return in, true
	case r(8) && d[p] == 0xC7 && d[p+1] == 0x44 && d[p+2] == 0x24:
		in.n, in.store = 8, &store{1, int32(int8(d[p+3])), append([]byte(nil), d[p+4:p+8]...)}
		return in, true
	case r(4) && (d[p] == 0x48 || d[p] == 0x4C) && d[p+1] == 0x89 && d[p+2]&0xC7 == 0x04 && d[p+3] == 0x24:
		in.n, in.regStore, in.rbase, in.rdisp, in.rsrc = 4, true, 1, 0, int(d[p+2]>>3&7)+8*int(d[p]>>2&1)
		return in, true
	case r(5) && (d[p] == 0x48 || d[p] == 0x4C) && d[p+1] == 0x89 && d[p+2]&0xC7 == 0x44 && d[p+3] == 0x24:
		in.n, in.regStore, in.rbase, in.rdisp, in.rsrc = 5, true, 1, int32(int8(d[p+4])), int(d[p+2]>>3&7)+8*int(d[p]>>2&1)
		return in, true
	case r(4) && (d[p] == 0x48 || d[p] == 0x4C) && d[p+1] == 0x89 && d[p+2]&0xC7 == 0x45:
		in.n, in.regStore, in.rbase, in.rdisp, in.rsrc = 4, true, 0, int32(int8(d[p+3])), int(d[p+2]>>3&7)+8*int(d[p]>>2&1)
		return in, true
	case r(8) && (d[p] == 0x48 || d[p] == 0x4C) && d[p+1] == 0x89 && d[p+2]&0xC7 == 0x84 && d[p+3] == 0x24:
		in.n, in.regStore, in.rbase, in.rdisp, in.rsrc = 8, true, 1, int32(le32(d[p+4:])), int(d[p+2]>>3&7)+8*int(d[p]>>2&1)
		return in, true
	case r(7) && (d[p] == 0x48 || d[p] == 0x4C) && d[p+1] == 0x89 && d[p+2]&0xC7 == 0x85:
		in.n, in.regStore, in.rbase, in.rdisp, in.rsrc = 7, true, 0, int32(le32(d[p+3:])), int(d[p+2]>>3&7)+8*int(d[p]>>2&1)
		return in, true
	}
	return in, false
}

func findStack(data []byte) []models.DecodedString {
	var out []models.DecodedString
	for p := 0; p < len(data) && len(out) < MaxResults; {
		// Cheap first-byte filter: every recognised form starts with one of these.
		switch data[p] {
		case 0x48, 0x49, 0x4C, 0xC6, 0xC7, 0x66:
		default:
			p++
			continue
		}
		first, ok := decode(data, p)
		if !ok {
			p++
			continue
		}
		start := p
		regs := map[int]uint64{}
		var stores []store
		count := 0
		in := first
		q := p
		for ok && count < 1024 {
			count++
			switch {
			case in.reg >= 0:
				regs[in.reg] = in.imm
			case in.store != nil:
				stores = append(stores, *in.store)
			case in.regStore:
				if v, known := regs[in.rsrc]; known {
					b := make([]byte, 8)
					for i := range b {
						b[i] = byte(v >> (8 * i))
					}
					stores = append(stores, store{in.rbase, in.rdisp, b})
				}
			}
			q += in.n
			in, ok = decode(data, q)
		}
		if len(stores) >= 2 || (len(stores) == 1 && len(stores[0].val) >= minStackText) {
			out = append(out, fromChain(stores, int64(start), q-start)...)
		}
		p = q
	}
	return out
}

// fromChain examines the frame a chain of stores built.
func fromChain(stores []store, off int64, length int) []models.DecodedString {
	var out []models.DecodedString
	for _, run := range frameRuns(stores) {
		// Encoded text: the same marker search as for data in the file.
		for _, d := range findDiff(run) {
			d.Offset, d.Length = off, length
			d.Matched += " (assembled from stack stores)"
			out = append(out, d)
		}
		// Plain text built on the stack.
		if txt := longestText(run); len(txt) >= minStackText && textLike(txt) {
			out = append(out, models.DecodedString{
				Method: "stack", Offset: off, Length: length, Text: txt,
				Matched: fmt.Sprintf("constants stored into a stack frame by %d consecutive instructions", len(stores)),
			})
		}
	}
	return out
}

// frameRuns joins stores by offset into contiguous byte runs.
func frameRuns(stores []store) [][]byte {
	var runs [][]byte
	for base := byte(0); base < 2; base++ {
		mem := map[int32]byte{}
		var keys []int32
		for _, s := range stores {
			if s.base != base {
				continue
			}
			for i, b := range s.val {
				k := s.disp + int32(i)
				if _, dup := mem[k]; !dup {
					keys = append(keys, k)
				}
				mem[k] = b
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var cur []byte
		for i, k := range keys {
			if i > 0 && k != keys[i-1]+1 {
				if len(cur) > 0 {
					runs = append(runs, cur)
				}
				cur = nil
			}
			cur = append(cur, mem[k])
		}
		if len(cur) > 0 {
			runs = append(runs, cur)
		}
	}
	return runs
}

// longestText returns the longest printable stretch, stopping at zero bytes.
func longestText(b []byte) string {
	best, cur := "", []byte{}
	for _, c := range b {
		if printable(c) {
			cur = append(cur, c)
			continue
		}
		if len(cur) > len(best) {
			best = string(cur)
		}
		cur = cur[:0]
	}
	if len(cur) > len(best) {
		best = string(cur)
	}
	return best
}

// textLike separates human-readable text from printable noise such as the
// encoded bytes of an XOR string, which are printable by accident. It asks for
// mostly letters, digits, spaces and the punctuation of paths and URLs, at
// at least 40% letters, and at least one vowel.
func textLike(s string) bool {
	letters, ok, vowels := 0, 0, 0
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters++
			ok++
			if strings.IndexByte("aeiouAEIOU", c) >= 0 {
				vowels++
			}
		case c >= '0' && c <= '9' || strings.IndexByte(" ./:_-@\\%=?&+", c) >= 0:
			ok++
		}
	}
	return ok*10 >= len(s)*9 && letters*10 >= len(s)*4 && vowels > 0
}
