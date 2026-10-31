// Package terminal contains output helpers: TTY detection, colour policy and
// sanitisation of sample-derived text. Analysis code never imports it.
package terminal

import (
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled applies the usual conventions: NO_COLOR, TERM=dumb, --no-color
// and non-terminals all disable colour.
func ColorEnabled(f *os.File, noColorFlag bool) bool {
	if noColorFlag || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return IsTTY(f)
}

// Sanitize makes text taken from a sample safe to print: control characters,
// escape sequences, bidirectional overrides and invalid UTF-8 are replaced by
// visible escapes so a hostile string cannot repaint the screen, retitle the
// window, or visually reorder text.
func Sanitize(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n == 1 {
			b.WriteString(`\x`)
			b.WriteString(hex2(s[0]))
			s = s[1:]
			continue
		}
		switch {
		case r == '\t':
			b.WriteString(" ")
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			b.WriteString(`\x`)
			b.WriteString(hex2(byte(r)))
		case isBidiControl(r) || !unicode.IsPrint(r) && r != ' ':
			b.WriteString(`\u`)
			b.WriteString(hex4(r))
		default:
			b.WriteRune(r)
		}
		s = s[n:]
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

const hexd = "0123456789abcdef"

func hex2(b byte) string { return string([]byte{hexd[b>>4], hexd[b&15]}) }
func hex4(r rune) string {
	return string([]byte{hexd[(r>>12)&15], hexd[(r>>8)&15], hexd[(r>>4)&15], hexd[r&15]})
}

// Style wraps text in an ANSI style when enabled.
type Style struct{ On bool }

func (s Style) wrap(code, t string) string {
	if !s.On {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }
func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }
