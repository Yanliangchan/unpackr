// Package disasm looks for obfuscation idioms in x86 and x86-64 code with a
// bounded linear sweep. It decodes instructions to see their operands; it does
// not build a control-flow graph, recover functions or run anything.
//
// Three idioms are recognised:
//
//   - reads of the process environment block through the segment register
//     (fs:[0x30] or gs:[0x60]) followed by the loader-list offsets, which is how
//     code finds loaded modules without importing anything;
//   - the ror-13 rotate-and-add loop over the bytes of a name, the widely copied
//     API-name hash (other rotate loops are ordinary hash functions and are not
//     reported);
//   - a control-flow-flattening dispatcher: a window of code in which many of
//     the same large constants are both stored as a "next state" and compared to
//     select a block.
//
// All three are heuristics over short windows. They are reported as
// observations of instruction patterns with their offsets; they do not prove
// intent, and the absence of a site does not mean the code is not obfuscated.
package disasm

import (
	"fmt"
	"runtime"
	"sort"
	"sync"

	"golang.org/x/arch/x86/x86asm"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits.
const (
	MaxBytes      = 32 << 20 // code examined in total
	maxSites      = 64
	maxChunkSites = 4096
	chunkBytes    = 1 << 20
	chunkOverlap  = 256
	windowBytes   = 4096 // dispatcher window
	minShared     = 12   // constants both stored and compared; ordinary code reaches 6 by accident
	minLarge      = 0x10000
)

// Region is a run of executable bytes and where it sits in the file.
type Region struct {
	Name   string
	Offset int64 // file offset of Code[0]
	Code   []byte
}

// Analyze sweeps the regions. bits is 32 or 64.
//
// Regions are cut into chunks that are swept independently, each starting by
// resynchronising on instruction boundaries, so the work spreads over the
// available CPUs. Chunks overlap slightly so an idiom on a boundary is seen;
// sites seen twice are merged.
func Analyze(regions []Region, bits int) *models.Disassembly {
	out := &models.Disassembly{Arch: fmt.Sprintf("x86-%d", bits), Counts: map[string]int{}, Sites: []models.DisasmSite{}}
	budget := MaxBytes
	var chunks []Region
	for _, r := range regions {
		code := r.Code
		if len(code) > budget {
			code = code[:budget]
			out.Truncated = true
		}
		budget -= len(code)
		out.Bytes += len(code)
		for start := 0; start < len(code); start += chunkBytes {
			end := min(len(code), start+chunkBytes+chunkOverlap)
			chunks = append(chunks, Region{Name: r.Name, Offset: r.Offset + int64(start), Code: code[start:end]})
		}
		if budget <= 0 {
			out.Truncated = true
			break
		}
	}
	parts := make([]*models.Disassembly, len(chunks))
	sem := make(chan struct{}, max(1, min(runtime.GOMAXPROCS(0), 8)))
	var wg sync.WaitGroup
	for i, c := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c Region) {
			defer wg.Done()
			defer func() { <-sem }()
			d := &models.Disassembly{Counts: map[string]int{}}
			sweep(d, c, c.Code, bits)
			parts[i] = d
		}(i, c)
	}
	wg.Wait()

	type key struct {
		kind string
		off  int64
	}
	seen := map[key]bool{}
	var all []models.DisasmSite
	for _, d := range parts {
		out.Instructions += d.Instructions
		for _, st := range d.Sites {
			if k := (key{st.Kind, st.Offset}); !seen[k] {
				seen[k] = true
				all = append(all, st)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Offset < all[j].Offset })
	for _, st := range all {
		out.Counts[st.Kind]++
		if len(out.Sites) < maxSites {
			out.Sites = append(out.Sites, st)
		}
	}
	return out
}

// add records a site in a chunk's partial result; counts are computed after
// the chunks are merged, so a site seen in two overlapping chunks counts once.
func add(out *models.Disassembly, kind string, off int64, detail string) {
	if len(out.Sites) < maxChunkSites {
		out.Sites = append(out.Sites, models.DisasmSite{Kind: kind, Offset: off, Detail: detail})
	}
}

// seenInst is a decoded instruction and its position in the region.
type seenInst struct {
	pos int
	in  x86asm.Inst
}

// pending is a short forward-looking check started at an anchor instruction.
type pending struct {
	kind   string
	off    int64
	left   int
	aux    int  // rotate amount
	sawA   bool // PEB: Ldr seen; hash: accumulate seen
	sawB   bool // PEB: module list seen; hash: backward branch seen
	loadAt int  // hash: position of the byte load the loop must enclose
	op     x86asm.Op
}

const lookahead = 14

func sweep(out *models.Disassembly, r Region, code []byte, bits int) {
	var recent []seenInst
	const keep = 12
	var pend []*pending
	cmpConsts := map[uint32]bool{}
	movConsts := map[uint32]bool{}
	winStart := 0
	reportedAt := -1 << 30
	ldr, lists := int64(0x0c), map[int64]bool{0x0c: true, 0x14: true, 0x1c: true}
	if bits == 64 {
		ldr, lists = 0x18, map[int64]bool{0x10: true, 0x20: true, 0x30: true}
	}

	for pos := 0; pos < len(code); {
		in, err := x86asm.Decode(code[pos:], bits)
		if err != nil || in.Len == 0 {
			pos++ // resynchronise: data or a misaligned start
			continue
		}
		out.Instructions++
		fileOff := r.Offset + int64(pos)

		// Advance the pending checks with this instruction.
		live := pend[:0]
		for _, p := range pend {
			p.left--
			switch p.kind {
			case "peb":
				for _, arg := range in.Args {
					if m, ok := arg.(x86asm.Mem); ok && m.Base != 0 {
						if !p.sawA && m.Disp == ldr {
							p.sawA = true
						} else if p.sawA && lists[m.Disp] {
							p.sawB = true
						}
					}
				}
				if p.sawB {
					add(out, "peb-ldr-walk", p.off, "reads the PEB, then its loader data and module list: finds loaded modules without importing them")
					continue
				}
			case "hash":
				switch in.Op {
				case x86asm.ADD, x86asm.XOR, x86asm.SUB:
					p.sawA = true
				case x86asm.LOOP, x86asm.JNE, x86asm.JE, x86asm.JA, x86asm.JB, x86asm.JG, x86asm.JL, x86asm.JAE, x86asm.JBE, x86asm.JMP:
					if nargs(in) == 1 {
						// The branch must jump back to the byte load or just
						// before it, so load, rotate and accumulate all sit in
						// one short loop.
						if rel, ok := in.Args[0].(x86asm.Rel); ok && rel < 0 {
							target := pos + in.Len + int(rel)
							if target <= p.loadAt && p.loadAt-target <= 8 && pos+in.Len-target <= 48 {
								p.sawB = true
							}
						}
					}
				}
				if p.sawA && p.sawB {
					// Only the specific, widely copied form is reported. Rotate-and-add
					// loops over bytes are what every ordinary hash function looks
					// like, and reporting them all would bury the signal.
					if p.op == x86asm.ROR && p.aux == 13 {
						add(out, "api-hash-ror13", p.off, "ror 13 in a byte-wise add loop: the widely copied API-name hash")
					}
					continue
				}
			}
			if p.left > 0 {
				live = append(live, p)
			}
		}
		pend = live

		// PEB access starts a loader-walk check.
		if seg, disp, ok := segmentLoad(in); ok && ((bits == 32 && seg == x86asm.FS && disp == 0x30) || (bits == 64 && seg == x86asm.GS && disp == 0x60)) {
			add(out, "peb-access", fileOff, fmt.Sprintf("reads the process environment block at %s:[0x%x]", seg, disp))
			pend = append(pend, &pending{kind: "peb", off: fileOff, left: lookahead})
		}
		// A rotate by an immediate after a byte load starts a hash-loop check.
		if (in.Op == x86asm.ROR || in.Op == x86asm.ROL) && nargs(in) == 2 {
			if imm, ok := in.Args[1].(x86asm.Imm); ok && imm >= 1 && imm <= 31 {
				if at, found := byteLoadBefore(recent); found {
					pend = append(pend, &pending{kind: "hash", off: fileOff, left: lookahead, aux: int(imm), op: in.Op, loadAt: at})
				}
			}
		}

		// Dispatcher constants.
		if c, isCmp, ok := largeImm(in); ok {
			if isCmp {
				cmpConsts[c] = true
			} else {
				movConsts[c] = true
			}
		}
		if pos-winStart >= windowBytes {
			if n := shared(cmpConsts, movConsts); n >= minShared && pos-reportedAt > windowBytes {
				add(out, "state-dispatcher", r.Offset+int64(winStart), fmt.Sprintf("%d distinct large constants are both stored and compared within %d bytes: a control-flow-flattening state machine", n, pos-winStart))
				reportedAt = pos
			}
			cmpConsts = map[uint32]bool{}
			movConsts = map[uint32]bool{}
			winStart = pos
		}

		recent = append(recent, seenInst{pos, in})
		if len(recent) > keep {
			recent = recent[1:]
		}
		pos += in.Len
	}
	if n := shared(cmpConsts, movConsts); n >= minShared {
		add(out, "state-dispatcher", r.Offset+int64(winStart), fmt.Sprintf("%d distinct large constants are both stored and compared within %d bytes: a control-flow-flattening state machine", n, len(code)-winStart))
	}
}

// segmentLoad reports a load from seg:[disp] with no base or index register.
func segmentLoad(in x86asm.Inst) (x86asm.Reg, int64, bool) {
	if in.Op != x86asm.MOV {
		return 0, 0, false
	}
	for _, a := range in.Args {
		if m, ok := a.(x86asm.Mem); ok && m.Segment != 0 && m.Base == 0 && m.Index == 0 {
			return m.Segment, m.Disp, true
		}
	}
	return 0, 0, false
}

// byteLoadBefore finds the most recent byte load (lodsb, movzx, or a move into
// an 8-bit register) in the recent instructions and returns its position: the
// start of a loop that walks a name.
func byteLoadBefore(recent []seenInst) (int, bool) {
	for i := len(recent) - 1; i >= 0; i-- {
		w := recent[i]
		switch w.in.Op {
		case x86asm.LODSB, x86asm.MOVZX:
			return w.pos, true
		case x86asm.MOV:
			if nargs(w.in) == 2 {
				if r, ok := w.in.Args[0].(x86asm.Reg); ok && r >= x86asm.AL && r <= x86asm.BL {
					return w.pos, true
				}
			}
		}
	}
	return 0, false
}

// largeImm returns a constant of at least minLarge from a compare (isCmp) or a
// move/store, as flattening code uses both with its state values. Small
// negative numbers (sign-extended immediates) are not state values.
func largeImm(in x86asm.Inst) (uint32, bool, bool) {
	if nargs(in) != 2 {
		return 0, false, false
	}
	imm, ok := in.Args[1].(x86asm.Imm)
	if !ok {
		return 0, false, false
	}
	v := uint32(imm)
	if v < minLarge || v >= 0xFFFF0000 {
		return 0, false, false
	}
	switch in.Op {
	case x86asm.CMP:
		return v, true, true
	case x86asm.MOV:
		return v, false, true
	}
	return 0, false, false
}

func shared(a, b map[uint32]bool) int {
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return n
}

// Kinds returns the site kinds in a stable order (for tests and rendering).
func Kinds(d *models.Disassembly) []string {
	var ks []string
	for k := range d.Counts {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// nargs counts an instruction's operands (Inst.Args is a fixed-size array).
func nargs(in x86asm.Inst) int {
	n := 0
	for _, a := range in.Args {
		if a == nil {
			break
		}
		n++
	}
	return n
}
