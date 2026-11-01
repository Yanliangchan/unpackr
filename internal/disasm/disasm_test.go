package disasm

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func run(code []byte, bits int) map[string]int {
	return Analyze([]Region{{Name: ".text", Offset: 0x400, Code: code}}, bits).Counts
}

func pad(b []byte) []byte {
	return append(append(bytes.Repeat([]byte{0x90}, 16), b...), bytes.Repeat([]byte{0x90}, 16)...)
}

// mov eax, fs:[0x30] ; mov eax,[eax+0xc] ; mov esi,[eax+0x14] ; lodsd ; ...
var peb32 = []byte{0x64, 0xA1, 0x30, 0, 0, 0, 0x8B, 0x40, 0x0C, 0x8B, 0x70, 0x14}

// mov rax, gs:[0x60] ; mov rax,[rax+0x18] ; mov rdx,[rax+0x20]
var peb64 = []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x50, 0x20}

func TestPEBLoaderWalk(t *testing.T) {
	if c := run(pad(peb32), 32); c["peb-access"] != 1 || c["peb-ldr-walk"] != 1 {
		t.Errorf("32-bit: %v", c)
	}
	if c := run(pad(peb64), 64); c["peb-access"] != 1 || c["peb-ldr-walk"] != 1 {
		t.Errorf("64-bit: %v", c)
	}
}

func TestPEBAccessAloneIsNotAWalk(t *testing.T) {
	// mov eax, fs:[0x30] ; xor eax, eax: e.g. a being-debugged check without a module walk
	c := run(pad([]byte{0x64, 0xA1, 0x30, 0, 0, 0, 0x31, 0xC0, 0x90, 0x90, 0x90}), 32)
	if c["peb-access"] != 1 || c["peb-ldr-walk"] != 0 {
		t.Errorf("%v", c)
	}
}

func TestSegmentOtherThanThePEBIsIgnored(t *testing.T) {
	// mov eax, fs:[0x18] (the TEB self pointer) is everywhere in ordinary code
	if c := run(pad([]byte{0x64, 0xA1, 0x18, 0, 0, 0}), 32); len(c) != 0 {
		t.Errorf("%v", c)
	}
}

func TestRor13HashLoop(t *testing.T) {
	// loop: lodsb ; ror edi,13 ; add edi,eax ; jne loop
	code := []byte{0xAC, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x75, 0xF8}
	if c := run(pad(code), 32); c["api-hash-ror13"] != 1 {
		t.Errorf("%v", c)
	}
	// the same loop with another rotate amount is an ordinary hash: not reported
	code[3] = 0x07
	if c := run(pad(code), 32); len(c) != 0 {
		t.Errorf("%v", c)
	}
}

func TestRotateWithoutAByteLoopIsIgnored(t *testing.T) {
	// ror edi,13 ; add edi,eax with no byte load and no backward branch
	if c := run(pad([]byte{0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x90, 0x90}), 32); len(c) != 0 {
		t.Errorf("%v", c)
	}
}

func TestFlatteningDispatcher(t *testing.T) {
	var code []byte
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 16; i++ {
		v := rng.Uint32()&0x7fffffff | 0x10000
		var imm [4]byte
		binary.LittleEndian.PutUint32(imm[:], v)
		code = append(code, 0xC7, 0x44, 0x24, 0x04) // mov dword [esp+4], imm32
		code = append(code, imm[:]...)
		code = append(code, 0x81, 0x7C, 0x24, 0x04) // cmp dword [esp+4], imm32
		code = append(code, imm[:]...)
		code = append(code, 0x74, 0x02, 0x90, 0x90) // je +2
	}
	if c := run(code, 32); c["state-dispatcher"] < 1 {
		t.Errorf("%v", c)
	}
}

func TestComparesWithoutMatchingStoresAreNotADispatcher(t *testing.T) {
	var code []byte
	for i := 0; i < 40; i++ {
		var imm [4]byte
		binary.LittleEndian.PutUint32(imm[:], uint32(0x20000+i*977))
		code = append(code, 0x81, 0x7C, 0x24, 0x04) // cmp dword [esp+4], imm32 (a big switch)
		code = append(code, imm[:]...)
		code = append(code, 0x74, 0x02, 0x90, 0x90)
	}
	if c := run(code, 32); len(c) != 0 {
		t.Errorf("a large switch is not flattening: %v", c)
	}
}

func TestNoiseAndEmptyInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for _, bits := range []int{32, 64} {
		buf := make([]byte, 3<<20)
		rng.Read(buf)
		d := Analyze([]Region{{Code: buf}}, bits)
		if d.Counts["state-dispatcher"] != 0 || d.Counts["api-hash-ror13"] != 0 || d.Counts["peb-ldr-walk"] != 0 {
			t.Errorf("random bytes produced sites: %v", d.Counts)
		}
	}
	if d := Analyze(nil, 64); d.Instructions != 0 || len(d.Sites) != 0 {
		t.Errorf("%+v", d)
	}
}

func TestSitesAreCappedAndOffsetsAreFileOffsets(t *testing.T) {
	code := bytes.Repeat(pad(peb32), 200)
	d := Analyze([]Region{{Offset: 0x1000, Code: code}}, 32)
	if len(d.Sites) > maxSites {
		t.Fatalf("%d sites", len(d.Sites))
	}
	if d.Counts["peb-access"] != 200 {
		t.Errorf("counts must keep counting past the cap: %v", d.Counts)
	}
	if d.Sites[0].Offset < 0x1000 {
		t.Errorf("offset %#x is not a file offset", d.Sites[0].Offset)
	}
}

func BenchmarkSweep8MB(b *testing.B) {
	rng := rand.New(rand.NewSource(5))
	buf := make([]byte, 8<<20)
	rng.Read(buf)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		Analyze([]Region{{Code: buf}}, 64)
	}
}
