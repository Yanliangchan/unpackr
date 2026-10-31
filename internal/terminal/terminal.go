// Package terminal contains output helpers: TTY detection, colour policy and
// sanitisation of sample-derived text. Analysis code never imports it.
package terminal

import (
	"os"

	"github.com/Yanliangchan/unpackr/internal/textutil"
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

// Sanitize makes sample-derived text safe to print; see textutil.Sanitize.
func Sanitize(s string) string { return textutil.Sanitize(s) }

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
