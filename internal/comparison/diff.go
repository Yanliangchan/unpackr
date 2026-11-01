// Package comparison computes the structured difference between two analysed
// files. It works on reports only, so it applies equally to an original and
// its unpacked layer and to two unrelated samples.
package comparison

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MaxListed bounds each list in the output.
const MaxListed = 200

func ref(r *models.Report) models.FileRef {
	return models.FileRef{Name: r.File.Name, SHA256: r.File.Hashes.SHA256, Size: r.File.Size}
}

// Diff compares a with b.
func Diff(a, b *models.Report) *models.Comparison {
	c := &models.Comparison{FileA: ref(a), FileB: ref(b), Notes: []string{},
		Header: []models.Change{}, SectionChanges: []models.SectionDiff{}, Entropy: []models.Change{},
		Packing: []models.Change{}, Fingerprint: []models.Change{}, Strings: []models.Change{}}
	c.Identical = a.File.Hashes.SHA256 == b.File.Hashes.SHA256
	if c.Identical {
		c.Notes = append(c.Notes, "the files have identical SHA-256 hashes; any reported difference comes from analysis settings")
	}
	if a.File.Size != b.File.Size {
		c.Header = append(c.Header, models.Change{Field: "file size", A: fmt.Sprint(a.File.Size), B: fmt.Sprint(b.File.Size)})
	}
	ba, bb := a.Binary, b.Binary
	if ba == nil || bb == nil {
		if ba == nil && bb == nil {
			c.Notes = append(c.Notes, "no executable structure was parsed for either file")
		} else {
			c.Notes = append(c.Notes, "only one of the files has parsed executable structure; structural comparison is partial")
		}
	}
	if ba != nil && bb != nil {
		chg := func(field, x, y string) {
			if x != y {
				c.Header = append(c.Header, models.Change{Field: field, A: x, B: y})
			}
		}
		chg("format", ba.Format, bb.Format)
		chg("architecture", ba.Arch, bb.Arch)
		chg("kind", ba.Kind, bb.Kind)
		chg("header timestamp", ba.CompiledAt, bb.CompiledAt)
		chg("image base", hex(ba.ImageBase), hex(bb.ImageBase))
		if ba.Entry != nil && bb.Entry != nil {
			chg("entry point (RVA)", hex(ba.Entry.RVA), hex(bb.Entry.RVA))
			chg("entry point section", ba.Entry.Section, bb.Entry.Section)
		}
		chg("import hash", ba.ImportHash, bb.ImportHash)
		overlay := func(b *models.Binary) string {
			if b.Overlay == nil {
				return "none"
			}
			return fmt.Sprintf("%d bytes", b.Overlay.Size)
		}
		chg("overlay", overlay(ba), overlay(bb))

		sa, sb := sectionMap(ba), sectionMap(bb)
		c.Sections = setDiff(keys(sa), keys(sb))
		for _, n := range keys(sa) {
			y, ok := sb[n]
			if !ok {
				continue
			}
			x := sa[n]
			var ch []models.Change
			add := func(f, p, q string) {
				if p != q {
					ch = append(ch, models.Change{Field: f, A: p, B: q})
				}
			}
			add("virtual size", hex(x.VirtualSize), hex(y.VirtualSize))
			add("raw size", hex(x.RawSize), hex(y.RawSize))
			add("permissions", x.Perms, y.Perms)
			add("virtual address", hex(x.VirtualAddress), hex(y.VirtualAddress))
			if len(ch) > 0 {
				c.SectionChanges = append(c.SectionChanges, models.SectionDiff{Name: n, Changes: ch})
			}
		}
		c.Libraries = setDiff(libs(ba), libs(bb))
		c.Imports = setDiff(funcs(ba), funcs(bb))
		c.Exports = setDiff(exps(ba), exps(bb))
	}

	aa, ab := a.Analysis, b.Analysis
	if aa != nil && ab != nil {
		if d := fmt.Sprintf("%.3f", aa.Entropy.File); d != fmt.Sprintf("%.3f", ab.Entropy.File) {
			c.Entropy = append(c.Entropy, models.Change{Field: "whole file", A: d, B: fmt.Sprintf("%.3f", ab.Entropy.File)})
		}
		ea, eb := map[string]float64{}, map[string]float64{}
		for _, s := range aa.Entropy.Sections {
			ea[s.Name] = s.Entropy
		}
		for _, s := range ab.Entropy.Sections {
			eb[s.Name] = s.Entropy
		}
		for _, n := range keysF(ea) {
			if y, ok := eb[n]; ok && fmt.Sprintf("%.2f", ea[n]) != fmt.Sprintf("%.2f", y) {
				c.Entropy = append(c.Entropy, models.Change{Field: "section " + n, A: fmt.Sprintf("%.3f", ea[n]), B: fmt.Sprintf("%.3f", y)})
			}
		}
		pk := func(p models.PackingAssessment) string {
			if p.Family != "" {
				return p.State + " (" + p.Family + ")"
			}
			return p.State
		}
		if pk(aa.Packing) != pk(ab.Packing) {
			c.Packing = append(c.Packing, models.Change{Field: "packing state", A: pk(aa.Packing), B: pk(ab.Packing)})
		}
		top := func(hs []models.Hypothesis) string {
			if len(hs) == 0 {
				return "none identified"
			}
			return fmt.Sprintf("%s (%s)", hs[0].Name, hs[0].Confidence)
		}
		for _, f := range []struct {
			name string
			x, y []models.Hypothesis
		}{{"language", aa.Fingerprint.Languages, ab.Fingerprint.Languages}, {"compiler", aa.Fingerprint.Compilers, ab.Fingerprint.Compilers}, {"runtime", aa.Fingerprint.Runtimes, ab.Fingerprint.Runtimes}} {
			if top(f.x) != top(f.y) {
				c.Fingerprint = append(c.Fingerprint, models.Change{Field: f.name, A: top(f.x), B: top(f.y)})
			}
		}
		c.Capabilities = setDiff(capIDs(aa), capIDs(ab))
		c.Indicators = setDiff(indicators(aa), indicators(ab))
		if aa.Strings.Total != ab.Strings.Total {
			c.Strings = append(c.Strings, models.Change{Field: "strings found", A: fmt.Sprint(aa.Strings.Total), B: fmt.Sprint(ab.Strings.Total)})
		}
	} else if aa != nil || ab != nil {
		c.Notes = append(c.Notes, "content analysis is missing for one file; entropy, packing, fingerprint, capability and indicator comparison was skipped")
	}
	if a.Analysis != nil && b.Analysis != nil {
		sim := similarity.Structural(a, b)
		c.Similarity = &sim
	}
	return c
}

func hex(v uint64) string { return fmt.Sprintf("0x%x", v) }

func sectionMap(b *models.Binary) map[string]models.Section {
	m := map[string]models.Section{}
	for _, s := range b.Sections {
		if _, dup := m[s.Name]; !dup {
			m[s.Name] = s
		}
	}
	return m
}

func keys(m map[string]models.Section) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysF(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func libs(b *models.Binary) []string {
	var out []string
	for _, im := range b.Imports {
		out = append(out, strings.ToLower(im.Library))
	}
	out = append(out, b.Libraries...)
	return out
}

func funcs(b *models.Binary) []string {
	var out []string
	for _, im := range b.Imports {
		for _, f := range im.Functions {
			n := f.Name
			if f.ByOrdinal {
				n = fmt.Sprintf("#%d", f.Ordinal)
			}
			out = append(out, strings.ToLower(im.Library)+"!"+n)
		}
	}
	return out
}

func exps(b *models.Binary) []string {
	var out []string
	for _, e := range b.Exports {
		out = append(out, e.Name)
	}
	return out
}

func capIDs(a *models.Analysis) []string {
	var out []string
	for _, c := range a.Capabilities {
		out = append(out, c.ID)
	}
	return out
}

func indicators(a *models.Analysis) []string {
	var out []string
	for _, i := range a.Indicators {
		out = append(out, i.Type+": "+i.Value)
	}
	return out
}

// setDiff returns items unique to each side, sorted and bounded.
func setDiff(a, b []string) models.SetDiff {
	sa, sb := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		sa[x] = true
	}
	for _, x := range b {
		sb[x] = true
	}
	d := models.SetDiff{OnlyA: []string{}, OnlyB: []string{}}
	for x := range sa {
		if !sb[x] {
			d.OnlyA = append(d.OnlyA, x)
		}
	}
	for x := range sb {
		if !sa[x] {
			d.OnlyB = append(d.OnlyB, x)
		}
	}
	sort.Strings(d.OnlyA)
	sort.Strings(d.OnlyB)
	if len(d.OnlyA) > MaxListed {
		d.OnlyA, d.Truncated = d.OnlyA[:MaxListed], true
	}
	if len(d.OnlyB) > MaxListed {
		d.OnlyB, d.Truncated = d.OnlyB[:MaxListed], true
	}
	return d
}
