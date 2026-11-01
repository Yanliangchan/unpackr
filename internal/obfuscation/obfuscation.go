// Package obfuscation recovers text that a program keeps in an encoded form:
// strings hidden with a single-byte XOR or ADD, executables embedded as base64,
// and strings built one instruction at a time on the stack.
//
// Everything here is a bounded, deterministic byte search. Nothing is
// executed or emulated. A recovered string is an observation (these bytes do
// decode to this text); that the author meant to conceal it is an inference
// and is left to the caller to word accordingly.
//
// Limits, stated so they are not mistaken for coverage: multi-byte or rolling
// keys, RC4/AES/custom ciphers, UTF-16 encodings and strings assembled
// through computation are not recovered.
package obfuscation

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MaxScan bounds the bytes examined; the difference arrays cost two further
// copies of the input.
const MaxScan = 64 << 20

// MaxResults bounds the number of recovered strings.
const MaxResults = 64

// markers are the plain-text forms that give a recovered string away. Each is
// long and varied enough that a chance match is negligible: a marker of n
// bytes with distinct neighbouring differences matches random data with
// probability about 256^-(n-1) per position.
var markers = []string{
	"http://", "https://", "/bin/sh", "/bin/bash", "/etc/passwd", "/etc/shadow",
	"cmd.exe", "powershell", "kernel32", "ntdll.dll", "wininet", "ws2_32",
	"VirtualAlloc", "VirtualProtect", "CreateProcess", "CreateRemoteThread",
	"WriteProcessMemory", "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute",
	"User-Agent", "Software\\Microsoft\\Windows", "SeDebugPrivilege",
	"curl ", "wget ", "chmod +x", "nc -e", "bash -i", "id_rsa", ".onion",
}

// A recovered string starts at its marker and runs forward to the first byte
// that does not decode to printable text. It is not extended backwards: the
// byte before it may be padding, and padding such as 0x90 or 0xCC decodes to
// something printable under many keys. It also stops at a run of identical bytes, for
// the same reason, after a run of four identical bytes ("www" and "google" are
// unaffected).

var reInteresting = regexp.MustCompile(`://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[a-z0-9-]{2,}\.(?:com|net|org|ru|cn|xyz|top|io|info|biz|onion)\b`)

func interesting(s string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return reInteresting.MatchString(s)
}

// Markers returns the plain-text markers used to recognise recovered strings.
func Markers() []string { return markers }

// Find returns the strings recovered from data, ordered by offset.
func Find(data []byte) []models.DecodedString {
	if len(data) > MaxScan {
		data = data[:MaxScan]
	}
	var out []models.DecodedString
	out = append(out, findDiff(data)...)
	out = append(out, findBase64(data)...)
	for _, d := range findStack(data) {
		// Compilers build plenty of ordinary constant text on the stack, so a
		// plain stack string is listed only when it is worth an analyst's eye:
		// an encoded one (not Method "stack") always is; plain text must hold a
		// known marker or look like a URL, address or domain.
		if d.Method != "stack" || interesting(d.Text) {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return dedupe(out)
}

func dedupe(in []models.DecodedString) []models.DecodedString {
	var out []models.DecodedString
	for _, d := range in {
		dup := false
		for _, o := range in {
			// A fragment of a longer recovered string (for example the first
			// eight bytes, which sit in one immediate) adds nothing.
			if o.Method == d.Method && len(o.Text) > len(d.Text) && strings.Contains(o.Text, d.Text) {
				dup = true
				break
			}
		}
		for _, o := range out {
			if o.Method == d.Method && o.Text == d.Text && o.Offset < d.Offset+int64(d.Length) && d.Offset < o.Offset+int64(o.Length) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, d)
		}
		if len(out) >= MaxResults {
			break
		}
	}
	return out
}

func printable(b byte) bool { return (b >= 0x20 && b < 0x7f) || b == '\t' }

// findDiff locates XOR- and ADD-encoded markers without trying any key. If
// e = p ^ k then e[i]^e[i+1] = p[i]^p[i+1] for every key, and if e = p + k then
// e[i+1]-e[i] = p[i+1]-p[i]. Looking for the marker's differences therefore
// finds it under any single-byte key at once, and the key follows from the
// first byte. One pass tests the first two differences of every position
// against a small bitmap; the rest of the marker is verified only at the few
// positions that pass.
func findDiff(data []byte) []models.DecodedString {
	if len(data) < 8 {
		return nil
	}
	type mode struct {
		name   string
		diff   func(a, b byte) byte
		key    func(e, p byte) byte
		dec    func(e, k byte) byte
		bitmap [1 << 13]byte
		cands  map[uint32][]string
	}
	xor := &mode{name: "xor", diff: func(a, b byte) byte { return a ^ b }, key: func(e, p byte) byte { return e ^ p }, dec: func(e, k byte) byte { return e ^ k }, cands: map[uint32][]string{}}
	add := &mode{name: "add", diff: func(a, b byte) byte { return b - a }, key: func(e, p byte) byte { return e - p }, dec: func(e, k byte) byte { return e - k }, cands: map[uint32][]string{}}
	for _, md := range []*mode{xor, add} {
		for _, m := range markers {
			pat := make([]byte, len(m)-1)
			for i := range pat {
				pat[i] = md.diff(m[i], m[i+1])
			}
			if distinct(pat) < 3 {
				continue
			}
			k := uint32(pat[0])<<8 | uint32(pat[1])
			md.bitmap[k>>3] |= 1 << (k & 7)
			md.cands[k] = append(md.cands[k], m)
		}
	}
	var out []models.DecodedString
	perMarker := map[string]int{}
	check := func(md *mode, i int, k uint32) {
		for _, m := range md.cands[k] {
			if i+len(m) > len(data) || perMarker[md.name+m] >= 8 {
				continue
			}
			ok := true
			for j := 0; j < len(m)-1; j++ {
				if md.diff(data[i+j], data[i+j+1]) != md.diff(m[j], m[j+1]) {
					ok = false
					break
				}
			}
			kb := md.key(data[i], m[0])
			if !ok || kb == 0 {
				continue // kb == 0 is plain text; the ordinary string scan covers it
			}
			perMarker[md.name+m]++
			// A recovered string starts at its marker and runs forward.
			hi := i + len(m)
			for hi < len(data) && hi-i < 512 && !paddingRun(data, hi) && printable(md.dec(data[hi], kb)) {
				hi++
			}
			text := make([]byte, hi-i)
			for j := range text {
				text[j] = md.dec(data[i+j], kb)
			}
			out = append(out, models.DecodedString{
				Method: md.name, Key: fmt.Sprintf("0x%02x", kb), Offset: int64(i), Length: hi - i,
				Text: string(text), Matched: m,
			})
		}
	}
	for i := 0; i+3 <= len(data); i++ {
		a, b, c := data[i], data[i+1], data[i+2]
		kx := uint32(a^b)<<8 | uint32(b^c)
		if xor.bitmap[kx>>3]&(1<<(kx&7)) != 0 {
			check(xor, i, kx)
		}
		ka := uint32(b-a)<<8 | uint32(c-b)
		if add.bitmap[ka>>3]&(1<<(ka&7)) != 0 {
			check(add, i, ka)
		}
	}
	return out
}

// paddingRun reports whether data[i] ends a run of four identical bytes, which
// is how padding looks.
func paddingRun(data []byte, i int) bool {
	return i >= 3 && data[i] == data[i-1] && data[i-1] == data[i-2] && data[i-2] == data[i-3]
}

func distinct(b []byte) int {
	var seen [256]bool
	n := 0
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			n++
		}
	}
	return n
}

// Base64 forms of the first bytes of a Windows PE (DOS header) and an ELF.
var b64Magic = []struct{ text, what string }{
	{"TVqQAAMAAAAEAAAA", "a Windows executable (MZ header)"},
	{"TVpQAAIAAAAEAA8A", "a Windows executable (MZ header)"},
	{"TVoAAAAAAAAAAAAA", "a Windows executable (MZ header)"},
	{"TVqAAAEAAAAEAP//", "a Windows executable (MZ header)"},
	{"f0VMRgIBAQ", "a 64-bit ELF executable"},
	{"f0VMRgEBAQ", "a 32-bit ELF executable"},
}

func findBase64(data []byte) []models.DecodedString {
	var out []models.DecodedString
	isB64 := func(b byte) bool {
		return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
	}
	add := func(i int, what, matched string) {
		lo, hi := i, i
		for hi < len(data) && hi-i < 1<<20 && isB64(data[hi]) {
			hi++
		}
		run := data[lo:hi]
		// Only whole 4-character groups decode.
		run = run[:len(run)/4*4]
		if len(run) < 64 {
			return
		}
		dec, err := base64.StdEncoding.DecodeString(string(bytes.TrimRight(run, "=")) + padding(len(bytes.TrimRight(run, "="))))
		if err != nil {
			return
		}
		out = append(out, models.DecodedString{
			Method: "base64", Offset: int64(lo), Length: hi - lo,
			Text: fmt.Sprintf("%d bytes of base64 decode to %s", len(dec), what), Matched: matched,
		})
	}
	for _, m := range b64Magic {
		from := 0
		for n := 0; n < 4; n++ {
			i := bytes.Index(data[from:], []byte(m.text))
			if i < 0 {
				break
			}
			i += from
			from = i + len(m.text)
			add(i, m.what, m.text)
		}
	}
	return out
}

func padding(n int) string {
	switch n % 4 {
	case 2:
		return "=="
	case 3:
		return "="
	}
	return ""
}
