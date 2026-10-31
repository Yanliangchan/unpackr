package elf

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func load(t *testing.T, arch string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtures.GoBinary(t, "linux", arch))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRealELF(t *testing.T) {
	for arch, want := range map[string]string{"amd64": "x86-64", "arm64": "ARM64"} {
		b, err := Parse(load(t, arch))
		if err != nil {
			t.Fatal(err)
		}
		if b.Format != "ELF64" || b.Arch != want || b.Kind != "executable" || b.Endian != "little" {
			t.Fatalf("%s: %+v", arch, b)
		}
		if len(b.Sections) < 5 || len(b.Segments) < 2 {
			t.Fatalf("%s: sections=%d segments=%d", arch, len(b.Sections), len(b.Segments))
		}
		if b.Entry == nil || b.Entry.Section != ".text" || b.Entry.FileOffset == nil {
			t.Fatalf("%s: entry %+v", arch, b.Entry)
		}
		if b.Attributes["go_sections"] != "present" {
			t.Fatalf("%s: go sections not noticed", arch)
		}
	}
}

func TestMissingSectionHeadersStillAnalysed(t *testing.T) {
	d := load(t, "amd64")
	// e_shnum = 0, e_shoff = 0: what a stripped-to-the-bone or packed file looks like.
	binary.LittleEndian.PutUint64(d[40:], 0)
	binary.LittleEndian.PutUint16(d[60:], 0)
	b, err := Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Segments) < 2 || b.Entry == nil || len(b.Anomalies) == 0 {
		t.Fatalf("%+v", b)
	}
}

func TestDamagedSectionTableUsesFallback(t *testing.T) {
	d := load(t, "amd64")
	binary.LittleEndian.PutUint16(d[58:], 3) // e_shentsize invalid for ELF64, e_shnum untouched
	b, err := Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Segments) < 2 {
		t.Fatalf("fallback lost the segments: %+v", b)
	}
	found := false
	for _, a := range b.Anomalies {
		if len(a) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("damage was not reported")
	}
}

func TestNotELFAndMutations(t *testing.T) {
	if _, err := Parse([]byte("hello")); err == nil {
		t.Fatal("accepted text")
	}
	d := load(t, "arm64")
	for n := 0; n < 4096; n += 5 {
		_, _ = Parse(d[:n])
	}
	for i := 0; i < 1024; i++ {
		m := append([]byte(nil), d[:8192]...)
		m[i] ^= 0xff
		_, _ = Parse(m)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Parse(b) })
}
