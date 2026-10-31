package content

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestEntropy(t *testing.T) {
	if Entropy(nil) != 0 || Entropy(bytes.Repeat([]byte{7}, 1000)) != 0 {
		t.Fatal("constant data must have zero entropy")
	}
	all := make([]byte, 256*16)
	for i := range all {
		all[i] = byte(i)
	}
	if e := Entropy(all); math.Abs(e-8) > 0.001 {
		t.Fatalf("uniform data entropy %v", e)
	}
	if e := Entropy([]byte("abababababababab")); math.Abs(e-1) > 0.001 {
		t.Fatalf("two-symbol entropy %v", e)
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

func TestStringExtraction(t *testing.T) {
	var d []byte
	d = append(d, 0, 0, 1, 2)
	d = append(d, []byte("hello world")...)
	d = append(d, 0xff, 0xfe)
	d = append(d, []byte("abc")...) // too short
	d = append(d, 0)
	d = append(d, utf16le("wide string")...)
	d = append(d, 0, 0, 0, 0)
	s := ExtractStrings(d)
	var got []string
	for _, h := range s.Hits {
		got = append(got, h.Enc+":"+h.Text)
	}
	joined := strings.Join(got, "|")
	if !strings.Contains(joined, "ascii:hello world") || !strings.Contains(joined, "utf16le:") || !strings.Contains(joined, "wide string") {
		t.Fatalf("got %v", got)
	}
	if strings.Contains(joined, "abc") {
		t.Fatal("short string kept")
	}
	for _, h := range s.Hits {
		if h.Enc == "ascii" && h.Text == "hello world" && h.Offset != 4 {
			t.Fatalf("offset %d", h.Offset)
		}
	}
}

func TestUTF16OddAlignment(t *testing.T) {
	d := append([]byte{0x01}, utf16le("odd offset text")...)
	s := ExtractStrings(d)
	found := false
	for _, h := range s.Hits {
		if h.Enc == "utf16le" && h.Text == "odd offset text" && h.Offset == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", s.Hits)
	}
}

func hits(ss ...string) []Hit {
	var h []Hit
	for i, s := range ss {
		h = append(h, Hit{Offset: int64(i * 100), Enc: "ascii", Text: s})
	}
	return h
}

func TestIndicators(t *testing.T) {
	in := ExtractIndicators(hits(
		"GET http://evil.example.net/gate.php?id=1 HTTP/1.1",
		"connect to 203.0.113.77 now",
		"version 10.0.19041.1234",
		"C:\\Users\\Public\\payload.exe",
		"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
		"cmd.exe /c whoami",
		"powershell -enc SQBFAFgA",
		"contact admin@bad-domain.ru",
		"beacon.badhost.xyz",
		"golang.org/x/net/context",
		"System.Net.Http.HttpClient",
		"http://www.w3.org/2001/XMLSchema",
		"/etc/passwd.bak",
		"203.0.113.77",
	), func(int64) string { return ".rdata" })
	types := map[string][]string{}
	for _, i := range in {
		types[i.Type] = append(types[i.Type], i.Value)
	}
	want := map[string]string{
		"url": "http://evil.example.net/gate.php?id=1", "ipv4": "203.0.113.77", "windows-path": "C:\\Users\\Public\\payload.exe",
		"registry": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "email": "admin@bad-domain.ru",
		"domain": "beacon.badhost.xyz", "unix-path": "/etc/passwd.bak",
	}
	for typ, v := range want {
		ok := false
		for _, x := range types[typ] {
			ok = ok || x == v
		}
		if !ok {
			t.Errorf("%s %q missing; have %v", typ, v, types[typ])
		}
	}
	if len(types["command"]) != 2 {
		t.Errorf("commands: %v", types["command"])
	}
	// False-positive guards.
	for _, d := range types["domain"] {
		if strings.Contains(d, "golang") || strings.Contains(strings.ToLower(d), "system.net") {
			t.Errorf("false positive domain %q", d)
		}
	}
	for _, u := range types["url"] {
		if strings.Contains(u, "w3.org") {
			t.Errorf("schema URL reported: %q", u)
		}
	}
	for _, ip := range types["ipv4"] {
		if strings.HasPrefix(ip, "10.0.19041") {
			t.Errorf("version number reported as IP: %q", ip)
		}
	}
	for _, i := range in {
		if i.Type == "ipv4" && i.Value == "203.0.113.77" && i.Count != 2 {
			t.Errorf("duplicate not merged: count %d", i.Count)
		}
	}
}

func TestRealWorldNoiseIsSuppressed(t *testing.T) {
	// Shapes seen in Go binaries: symbol names, glued string pools, device paths.
	in := ExtractIndicators(hits(
		"*eq.io", "itab.net.Conn", "type:.hash.net",
		"https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac6",
		"\\\\.\\UNCCopySidWSARecvWSASendavx512fSHA-224",
		"this long text mentions "+strings.Repeat("padding ", 20)+" beacon.badhost.xyz somewhere",
	), func(int64) string { return "" })
	for _, i := range in {
		switch {
		case i.Type == "domain":
			t.Errorf("noise reported as domain: %q", i.Value)
		case i.Type == "windows-path" && strings.Contains(i.Value, "UNCCopySid"):
			t.Errorf("device-path garbage reported: %q", i.Value)
		case i.Type == "url" && strings.Contains(i.Value, "b3312fa7"):
			t.Errorf("glued string swallowed into URL: %q", i.Value)
		}
	}
	var url bool
	for _, i := range in {
		url = url || (i.Type == "url" && i.Value == "https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size")
	}
	if !url {
		t.Errorf("the real URL prefix should survive: %+v", in)
	}
}

func TestFrequentIndicatorsAreFlagged(t *testing.T) {
	var h []Hit
	for i := 0; i < 60; i++ {
		h = append(h, Hit{Offset: int64(i), Enc: "ascii", Text: "https://example.net/lib/path"})
	}
	in := ExtractIndicators(h, func(int64) string { return "" })
	if len(in) != 1 || in[0].Count != 60 || !strings.Contains(in[0].Note, "boilerplate") {
		t.Fatalf("%+v", in)
	}
}

func TestSummarizeBounds(t *testing.T) {
	var d []byte
	for i := 0; i < MaxShown+50; i++ {
		d = append(d, []byte("string number here\x00")...)
	}
	d = append(d, []byte(strings.Repeat("x", 1000))...)
	s := ExtractStrings(d)
	sum := s.Summarize(func(int64) string { return "" })
	if len(sum.Shown) != MaxShown || !sum.Truncated || sum.Total != MaxShown+51 {
		t.Fatalf("shown=%d total=%d trunc=%v", len(sum.Shown), sum.Total, sum.Truncated)
	}
}

func FuzzStrings(f *testing.F) {
	f.Add([]byte("hello\x00w\x00o\x00r\x00l\x00d\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s := ExtractStrings(b)
		ExtractIndicators(s.Hits, func(int64) string { return "" })
	})
}
