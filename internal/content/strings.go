package content

import (
	"sort"
	"unicode/utf8"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Extraction limits.
const (
	MinLength    = 5
	MaxShown     = 3000
	MaxTextLen   = 256
	MaxCollected = 2_000_000 // hard cap on strings kept in memory
)

// Hit is a string with its offset, kept in full for matching.
type Hit struct {
	Offset int64
	Enc    string
	Text   string
}

// Scan is the result of one extraction pass.
type Scan struct {
	Hits      []Hit
	ASCII     int
	UTF16     int
	Truncated bool // MaxCollected reached
}

func isPrintable(c byte) bool { return (c >= 0x20 && c <= 0x7e) || c == '\t' }

// ExtractStrings finds ASCII and UTF-16LE runs of at least MinLength
// characters. Results are in file order within each encoding and merged by
// offset.
func ExtractStrings(data []byte) *Scan {
	s := &Scan{}
	// ASCII
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= MinLength {
			if len(s.Hits) < MaxCollected {
				s.Hits = append(s.Hits, Hit{Offset: int64(start), Enc: "ascii", Text: string(data[start:end])})
				s.ASCII++
			} else {
				s.Truncated = true
			}
		}
		start = -1
	}
	for i, c := range data {
		if isPrintable(c) {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(data))

	// UTF-16LE: printable ASCII code unit followed by a zero byte.
	for _, align := range [2]int{0, 1} {
		runStart, chars := -1, 0
		var buf []byte
		endRun := func(at int) {
			if runStart >= 0 && chars >= MinLength {
				if len(s.Hits) < MaxCollected {
					s.Hits = append(s.Hits, Hit{Offset: int64(runStart), Enc: "utf16le", Text: string(buf)})
					s.UTF16++
				} else {
					s.Truncated = true
				}
			}
			runStart, chars, buf = -1, 0, buf[:0]
		}
		i := align
		for ; i+1 < len(data); i += 2 {
			if isPrintable(data[i]) && data[i+1] == 0 {
				if runStart < 0 {
					runStart = i
				}
				buf = append(buf, data[i])
				chars++
			} else {
				endRun(i)
			}
		}
		endRun(i)
	}
	sort.SliceStable(s.Hits, func(i, j int) bool { return s.Hits[i].Offset < s.Hits[j].Offset })
	return s
}

// Summarize converts a scan into the report form: a bounded sample, with
// invalid UTF-8 impossible by construction (ASCII only) and long strings cut.
func (s *Scan) Summarize(sectionOf func(off int64) string) models.StringsInfo {
	out := models.StringsInfo{MinLength: MinLength, Total: len(s.Hits), ASCII: s.ASCII, UTF16: s.UTF16, Truncated: s.Truncated, Shown: []models.StringHit{}}
	for _, h := range s.Hits {
		if len(out.Shown) >= MaxShown {
			out.Truncated = true
			break
		}
		out.Shown = append(out.Shown, models.StringHit{Offset: h.Offset, Encoding: h.Enc, Text: clip(h.Text), Section: sectionOf(h.Offset)})
	}
	return out
}

func clip(s string) string {
	if len(s) <= MaxTextLen {
		return s
	}
	cut := MaxTextLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
