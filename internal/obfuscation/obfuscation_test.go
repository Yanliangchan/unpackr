package obfuscation

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

func pad(b []byte, n int) []byte {
	out := make([]byte, 0, len(b)+2*n)
	out = append(out, bytes.Repeat([]byte{0x90}, n)...)
	out = append(out, b...)
	return append(out, bytes.Repeat([]byte{0x90}, n)...)
}

func TestXORKeyIsRecoveredWithoutTryingKeys(t *testing.T) {
	for _, key := range []byte{0x01, 0x5a, 0x7f, 0xaa, 0xff} {
		plain := []byte("http://evil.example.net/payload\x00")
		enc := make([]byte, len(plain))
		for i, c := range plain {
			enc[i] = c ^ key
		}
		got := Find(pad(enc, 64))
		if len(got) == 0 {
			t.Fatalf("key %#x: nothing recovered", key)
		}
		d := got[0]
		if d.Method != "xor" || d.Text != "http://evil.example.net/payload" || d.Offset != 64 {
			t.Fatalf("key %#x: %+v", key, d)
		}
		if want := strings.ToLower(hex(key)); d.Key != want {
			t.Fatalf("key = %s, want %s", d.Key, want)
		}
	}
}

func hex(b byte) string {
	const h = "0123456789abcdef"
	return "0x" + string([]byte{h[b>>4], h[b&15]})
}

func TestADDEncodingIsRecovered(t *testing.T) {
	plain := []byte("cmd.exe /c whoami\x00")
	enc := make([]byte, len(plain))
	for i, c := range plain {
		enc[i] = c + 0x13
	}
	got := Find(pad(enc, 32))
	if len(got) == 0 || got[0].Method != "add" || got[0].Text != "cmd.exe /c whoami" || got[0].Key != "0x13" {
		t.Fatalf("%+v", got)
	}
}

func TestPlainTextAndNoiseDoNotProduceResults(t *testing.T) {
	if got := Find(pad([]byte("http://example.com/plain text is not encoded\x00"), 32)); len(got) != 0 {
		t.Fatalf("plain text reported as encoded: %+v", got)
	}
	rng := rand.New(rand.NewSource(7))
	noise := make([]byte, 4<<20)
	rng.Read(noise)
	if got := Find(noise); len(got) != 0 {
		t.Fatalf("random data produced %d results, first %+v", len(got), got[0])
	}
	if got := Find(make([]byte, 1<<20)); len(got) != 0 {
		t.Fatalf("zeros produced %+v", got)
	}
}

func TestEncodedZeroPaddingIsNotAbsorbed(t *testing.T) {
	enc := []byte("/bin/sh\x00")
	for i := range enc {
		enc[i] ^= 0x41
	}
	data := append(append(make([]byte, 40), enc...), make([]byte, 40)...)
	got := Find(data)
	if len(got) != 1 || got[0].Text != "/bin/sh" {
		t.Fatalf("%+v", got)
	}
}

func TestBase64EmbeddedExecutable(t *testing.T) {
	pe := append([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"), bytes.Repeat([]byte{0xB8, 1, 2, 3}, 80)...)
	b := []byte(base64.StdEncoding.EncodeToString(pe))
	got := Find(pad(b, 16))
	if len(got) != 1 || got[0].Method != "base64" || !strings.Contains(got[0].Text, "Windows executable") {
		t.Fatalf("%+v", got)
	}
	if got := Find(pad([]byte("TVqQAAMAAAAEAAAA"), 16)); len(got) != 0 {
		t.Fatalf("a bare 16-character magic is not a payload: %+v", got)
	}
}

func movByte(disp int8, c byte) []byte { return []byte{0xC6, 0x45, byte(disp), c} }

func TestStackStringsFromByteAndDwordStores(t *testing.T) {
	var code []byte
	for i, c := range []byte("wget http://x.test/a\x00") {
		code = append(code, movByte(int8(-0x30+i), c)...)
	}
	got := Find(pad(code, 10))
	if len(got) != 1 || got[0].Method != "stack" || got[0].Text != "wget http://x.test/a" {
		t.Fatalf("%+v", got)
	}
	// dword stores, out of order, rsp-based
	var d []byte
	words := []string{"http", "://e", "vil.", "test"}
	for _, i := range []int{2, 0, 3, 1} {
		w := []byte(words[i])
		d = append(d, 0xC7, 0x44, 0x24, byte(0x10+4*i), w[0], w[1], w[2], w[3])
	}
	got = Find(pad(d, 10))
	if len(got) != 1 || got[0].Text != "http://evil.test" {
		t.Fatalf("%+v", got)
	}
}

// movabs rax, imm64 ; mov [rsp+d], rax is what compilers emit for 8 bytes.
func movabsStore(reg byte, disp int8, chunk []byte) []byte {
	c := append([]byte{0x48, 0xB8 + reg}, chunk...)
	return append(c, 0x48, 0x89, 0x44|reg<<3, 0x24, byte(disp))
}

func TestEncodedStringBuiltOnTheStackIsDecoded(t *testing.T) {
	plain := []byte("http://evil.example.net/payload\x00")
	enc := make([]byte, len(plain))
	for i, c := range plain {
		enc[i] = c ^ 0x5a
	}
	var code []byte
	for i := 0; i < len(enc); i += 8 {
		code = append(code, movabsStore(0, int8(0x20+i), enc[i:i+8])...)
	}
	got := Find(pad(code, 16))
	var found bool
	for _, d := range got {
		if d.Method == "xor" && d.Key == "0x5a" && d.Text == "http://evil.example.net/payload" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", got)
	}
}

func TestOrdinaryStackTextIsNotListed(t *testing.T) {
	var code []byte
	for i, c := range []byte("runtime error: \x00") {
		code = append(code, movByte(int8(i), c)...)
	}
	if got := Find(pad(code, 10)); len(got) != 0 {
		t.Fatalf("compiler-built constant text should not be reported: %+v", got)
	}
}

func TestPrintableNoiseOnTheStackIsNotText(t *testing.T) {
	var code []byte
	for i, c := range []byte(")591?.Zq") {
		code = append(code, movByte(int8(i), c)...)
	}
	if got := Find(pad(code, 10)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestShortOrIsolatedStoresAreIgnored(t *testing.T) {
	var code []byte
	for i, c := range []byte("abc") {
		code = append(code, movByte(int8(i), c)...)
	}
	if got := Find(pad(code, 10)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func BenchmarkFind16MB(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	d := make([]byte, 16<<20)
	rng.Read(d)
	b.SetBytes(int64(len(d)))
	for i := 0; i < b.N; i++ {
		Find(d)
	}
}

func TestDoubledLettersInRecoveredTextSurvive(t *testing.T) {
	plain := []byte("http://www.google.com/aa\x00")
	enc := make([]byte, len(plain))
	for i, c := range plain {
		enc[i] = c ^ 0x37
	}
	got := Find(pad(enc, 16))
	if len(got) != 1 || got[0].Text != "http://www.google.com/aa" {
		t.Fatalf("%+v", got)
	}
}
