package identification

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
)

func id(b []byte) (string, bool) {
	r := Identify(bytes.NewReader(b), int64(len(b)))
	return r.Primary, r.Polyglot
}

func minimalPE(opt uint16, machine uint16) []byte {
	b := make([]byte, 0x200)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	binary.LittleEndian.PutUint16(b[0x84+16:], 0xe0)
	binary.LittleEndian.PutUint16(b[0x98:], opt)
	return b
}

func TestPE(t *testing.T) {
	if p, _ := id(minimalPE(0x20b, 0x8664)); p != "PE32+" {
		t.Fatalf("got %q", p)
	}
	if p, _ := id(minimalPE(0x10b, 0x14c)); p != "PE32" {
		t.Fatalf("got %q", p)
	}
}

func TestPEBrokenPointerIsNotPE(t *testing.T) {
	b := minimalPE(0x20b, 0x8664)
	binary.LittleEndian.PutUint32(b[0x3c:], 0xfffffff0)
	r := Identify(bytes.NewReader(b), int64(len(b)))
	if r.Primary == "PE32+" {
		t.Fatal("must not report PE32+ with a bad e_lfanew")
	}
	if len(r.Candidates) == 0 || r.Candidates[0].Format != "DOS MZ executable" {
		t.Fatalf("expected DOS MZ candidate, got %+v", r.Candidates)
	}
}

func TestTruncatedInputsNeverPanic(t *testing.T) {
	full := minimalPE(0x20b, 0x8664)
	for n := 0; n <= len(full); n++ {
		Identify(bytes.NewReader(full[:n]), int64(n))
	}
	Identify(bytes.NewReader(nil), 0)
}

func TestELF(t *testing.T) {
	b := make([]byte, 64)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	if p, _ := id(b); p != "ELF64" {
		t.Fatalf("got %q", p)
	}
}

func TestJavaVersusFat(t *testing.T) {
	class := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 10, 0, 0}
	if p, _ := id(class); p != "Java class file" {
		t.Fatalf("java: got %q", p)
	}
	fat := make([]byte, 8+20*2)
	copy(fat, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2})
	if p, _ := id(fat); p != "Mach-O universal (fat) binary" {
		t.Fatalf("fat: got %q", p)
	}
}

func TestMachO64LE(t *testing.T) {
	b := make([]byte, 64)
	copy(b, []byte{0xcf, 0xfa, 0xed, 0xfe})
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], 10)
	if p, _ := id(b); p != "Mach-O 64-bit" {
		t.Fatalf("got %q", p)
	}
}

func TestJar(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("META-INF/MANIFEST.MF")
	_, _ = f.Write([]byte("Manifest-Version: 1.0\n"))
	_ = w.Close()
	if p, _ := id(buf.Bytes()); p != "Java JAR" {
		t.Fatalf("got %q", p)
	}
}

func TestExtensionIsIrrelevantAndUnknownIsUnknown(t *testing.T) {
	if p, _ := id([]byte("just some text")); p != "unknown" {
		t.Fatalf("got %q", p)
	}
	if p, _ := id([]byte("#!/bin/sh\necho hi\n")); p != "Script with interpreter line" {
		t.Fatalf("got %q", p)
	}
}

func FuzzIdentify(f *testing.F) {
	f.Add(minimalPE(0x20b, 0x8664))
	f.Add([]byte("\x7fELF\x02\x01\x01"))
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1})
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		Identify(bytes.NewReader(b), int64(len(b)))
	})
}
