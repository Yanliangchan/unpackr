// Package analysis defines the shared input of the content-analysis modules
// (fingerprinting, packing) and the evidence sink they write to.
package analysis

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Input is everything a detector may look at. Detectors never modify it.
type Input struct {
	Data    []byte
	Family  string // pe | elf | macho
	Bin     *models.Binary
	Scan    *content.Scan
	Entropy *models.EntropyInfo
	Sink    *Sink
}

// Sink collects evidence and hands out stable identifiers.
type Sink struct {
	Evidence []models.Evidence
	module   string
}

// NewSink creates a sink whose evidence is attributed to module.
func NewSink(module string) *Sink { return &Sink{module: module} }

// Add records evidence and returns its id. offset < 0 means "no offset".
func (s *Sink) Add(kind, value string, offset int64, length int64, section, rule, family string) string {
	id := fmt.Sprintf("x%d", len(s.Evidence)+1)
	loc := models.Location{Section: section}
	if offset >= 0 {
		loc.Offset = models.Int64(offset)
		if length > 0 {
			loc.Length = models.Int64(length)
		}
	}
	if len(value) > 200 {
		value = value[:200] + "…"
	}
	s.Evidence = append(s.Evidence, models.Evidence{
		ID: id, Kind: kind, Value: value, Loc: loc,
		Source: models.Source{Module: s.module, Rule: rule}, Family: family,
	})
	return id
}

// SectionAt maps a file offset to the section whose raw data contains it.
func (in *Input) SectionAt(off int64) string {
	if in.Bin == nil {
		return ""
	}
	for _, s := range in.Bin.Sections {
		if s.RawSize > 0 && uint64(off) >= s.RawOffset && uint64(off) < s.RawOffset+s.RawSize {
			return s.Name
		}
	}
	return ""
}

// FindBytes returns the offset of the first occurrence of needle, or -1.
func (in *Input) FindBytes(needle []byte) int64 {
	return int64(bytes.Index(in.Data, needle))
}

// FindRegexp returns the first match (offset and text) or -1.
func (in *Input) FindRegexp(re *regexp.Regexp) (int64, string) {
	loc := re.FindIndex(in.Data)
	if loc == nil {
		return -1, ""
	}
	return int64(loc[0]), string(in.Data[loc[0]:loc[1]])
}

// FindString returns the first extracted string that satisfies match.
func (in *Input) FindString(match func(string) bool) (content.Hit, bool) {
	if in.Scan == nil {
		return content.Hit{}, false
	}
	for _, h := range in.Scan.Hits {
		if match(h.Text) {
			return h, true
		}
	}
	return content.Hit{}, false
}

// HasImport reports whether any import (case-insensitive library or function
// name) matches name exactly.
func (in *Input) HasImport(name string) bool {
	if in.Bin == nil {
		return false
	}
	for _, im := range in.Bin.Imports {
		if equalFold(im.Library, name) {
			return true
		}
		for _, f := range im.Functions {
			if f.Name == name {
				return true
			}
		}
	}
	return false
}

// ImportCount is the total number of imported symbols.
func (in *Input) ImportCount() int {
	n := 0
	if in.Bin != nil {
		for _, im := range in.Bin.Imports {
			n += len(im.Functions)
		}
	}
	return n
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 32
		}
		if 'A' <= y && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}
