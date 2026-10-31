package macho

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func load(t *testing.T, arch string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtures.GoBinary(t, "darwin", arch))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealMachO(t *testing.T) {
	for arch, want := range map[string]string{"amd64": "x86-64", "arm64": "ARM64"} {
		b, err := Parse(load(t, arch))
		if err != nil {
			t.Fatal(err)
		}
		if b.Format != "Mach-O 64-bit" || b.Arch != want || b.Kind != "executable" {
			t.Fatalf("%s: %+v", arch, b)
		}
		if b.Entry == nil || b.Entry.Section != "__TEXT,__text" {
			t.Fatalf("%s: entry %+v", arch, b.Entry)
		}
		if len(b.Segments) < 3 || len(b.Libraries) == 0 {
			t.Fatalf("%s: segments=%d libs=%v", arch, len(b.Segments), b.Libraries)
		}
		if b.Attributes["code_signature_parsed"] != "false" {
			t.Fatal("unimplemented decoding must be declared")
		}
	}
}

// fat builds a universal binary from two thin images.
func fat(a, b []byte, cpuA, cpuB uint32) []byte {
	const align = 0x4000
	offA, offB := align, align+((len(a)+align-1)/align)*align
	out := make([]byte, offB+len(b))
	be := binary.BigEndian
	be.PutUint32(out[0:], 0xcafebabe)
	be.PutUint32(out[4:], 2)
	put := func(i int, cpu uint32, off, size int) {
		h := out[8+20*i:]
		be.PutUint32(h[0:], cpu)
		be.PutUint32(h[8:], uint32(off))
		be.PutUint32(h[12:], uint32(size))
		be.PutUint32(h[16:], 14)
	}
	put(0, cpuA, offA, len(a))
	put(1, cpuB, offB, len(b))
	copy(out[offA:], a)
	copy(out[offB:], b)
	return out
}

func TestUniversalBinary(t *testing.T) {
	u := fat(load(t, "amd64"), load(t, "arm64"), 0x01000007, 0x0100000c)
	b, err := Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format != "Mach-O universal" || len(b.Slices) != 2 {
		t.Fatalf("%+v", b)
	}
	if b.Slices[0].Arch != "x86-64" || b.Slices[1].Arch != "ARM64" {
		t.Fatalf("%v %v", b.Slices[0].Arch, b.Slices[1].Arch)
	}
	if !strings.Contains(b.Attributes["architectures"], "ARM64") {
		t.Fatal(b.Attributes)
	}
	if b.Slices[1].Segments[1].RawOffset < 0x4000 {
		t.Fatal("slice offsets must be absolute file offsets")
	}
}

func TestNotMachOAndMutations(t *testing.T) {
	if _, err := Parse([]byte("hello world, definitely not mach-o")); err == nil {
		t.Fatal("accepted text")
	}
	d := load(t, "arm64")
	for n := 0; n < 4096; n += 9 {
		_, _ = Parse(d[:n])
	}
	for i := 0; i < 1024; i++ {
		m := append([]byte(nil), d[:8192]...)
		m[i] ^= 0xff
		_, _ = Parse(m)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}
