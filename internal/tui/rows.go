// Package tui is the interactive `inspect` view. Its model is a plain
// Bubble Tea model with no I/O of its own, so it is tested by feeding it
// messages. Everything it shows comes from a report that has already been
// sanitised by reporting.Sanitized; the model never prints raw sample text.
package tui

import (
	"fmt"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// row is one selectable line in a tab.
type row struct {
	key      string   // stable id: finding id, evidence id, ...
	line     string   // one-line summary shown in the list
	detail   string   // text shown in the detail pane
	evidence []string // evidence ids this row points to
	findings []string // finding ids that cite this row (evidence tab)
	search   string   // lower-cased text matched by the filter
}

type tab struct {
	name string
	rows []row
}

func buildTabs(r *models.Report) []tab {
	return []tab{
		{"Summary", summaryRows(r)},
		{"Findings", findingRows(r)},
		{"Evidence", evidenceRows(r)},
		{"Indicators", indicatorRows(r)},
		{"Capabilities", capabilityRows(r)},
		{"Structure", structureRows(r)},
	}
}

func mk(key, line, detail string, ev ...string) row {
	return row{key: key, line: line, detail: detail, evidence: ev, search: strings.ToLower(key + " " + line + " " + detail)}
}

func off(l models.Location) string {
	s := ""
	if l.Offset != nil {
		s = fmt.Sprintf("0x%x", *l.Offset)
		if l.Length != nil {
			s += fmt.Sprintf("+%d", *l.Length)
		}
	}
	if l.Section != "" {
		if s != "" {
			s += " "
		}
		s += "in " + l.Section
	}
	if l.Path != "" {
		s += " " + l.Path
	}
	if s == "" {
		return "-"
	}
	return s
}

func summaryRows(r *models.Report) []row {
	var out []row
	add := func(k, v string) {
		if v != "" {
			out = append(out, mk(k, fmt.Sprintf("%-12s %s", k, v), k+": "+v))
		}
	}
	add("File", r.File.Name)
	add("Size", fmt.Sprintf("%d bytes", r.File.Size))
	add("SHA-256", r.File.Hashes.SHA256)
	add("MD5", r.File.Hashes.MD5)
	if id := r.Identification; id != nil {
		add("Type", id.Primary)
	}
	if b := r.Binary; b != nil {
		add("Format", b.Format)
		add("Arch", b.Arch)
		add("Kind", b.Kind)
	}
	if a := r.Analysis; a != nil {
		p := a.Packing
		v := p.State
		if p.Family != "" {
			v += " (" + p.Family + ")"
		}
		add("Packing", fmt.Sprintf("%s, %s confidence", v, p.Confidence))
		add("Packing why", p.Rationale)
		for _, n := range p.Notes {
			add("Note", n)
		}
		if a.Fuzzy.SSDeep != "" {
			add("ssdeep", a.Fuzzy.SSDeep)
		}
		if a.Fuzzy.TLSH != "" {
			add("TLSH", a.Fuzzy.TLSH)
		}
		add("Entropy", fmt.Sprintf("%.3f bits/byte", a.Entropy.File))
	}
	if r.Unpack != nil {
		add("Unpack", r.Unpack.Status+": "+r.Unpack.Message)
	}
	counts := map[models.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	add("Findings", fmt.Sprintf("%d high, %d medium, %d low, %d info", counts[models.SeverityHigh], counts[models.SeverityMedium], counts[models.SeverityLow], counts[models.SeverityInfo]))
	for _, w := range r.Warnings {
		add("Warning", w.Message)
	}
	for _, n := range r.NotRun {
		add("Not run", n)
	}
	return out
}

func findingRows(r *models.Report) []row {
	var out []row
	for _, f := range r.Findings {
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n%s  |  %s  |  %s confidence  |  %s\n\n%s\n", f.Title, f.Severity, f.Class, f.Confidence, f.Category, f.Summary)
		if f.Rationale != "" {
			fmt.Fprintf(&b, "\nWhy this confidence: %s\n", f.Rationale)
		}
		if f.Action != "" {
			fmt.Fprintf(&b, "\nSuggested next step: %s\n", f.Action)
		}
		if len(f.Attack) > 0 {
			fmt.Fprintf(&b, "\nATT&CK (consistent with, not proven): %s\n", strings.Join(f.Attack, ", "))
		}
		if len(f.Dissent) > 0 {
			fmt.Fprintf(&b, "\nDisagreement: %s\n", strings.Join(f.Dissent, "; "))
		}
		if len(f.EvidenceID) > 0 {
			fmt.Fprintf(&b, "\nEvidence: %s   (press e to open it)\n", strings.Join(f.EvidenceID, ", "))
		}
		rw := mk(f.ID, fmt.Sprintf("%-13s %-11s %s", f.Severity, f.Confidence, f.Title), b.String(), f.EvidenceID...)
		rw.search += " " + strings.ToLower(string(f.Severity)+" "+f.Category+" "+string(f.Class))
		out = append(out, rw)
	}
	return out
}

func evidenceRows(r *models.Report) []row {
	cited := map[string][]string{}
	for _, f := range r.Findings {
		for _, id := range f.EvidenceID {
			cited[id] = append(cited[id], f.ID)
		}
	}
	var out []row
	for _, e := range r.Evidence {
		var b strings.Builder
		fmt.Fprintf(&b, "%s  (%s)\n%s\n\nValue: %s\n", e.ID, e.Kind, off(e.Loc), e.Value)
		fmt.Fprintf(&b, "Found by: %s", e.Source.Module)
		if e.Source.Rule != "" {
			fmt.Fprintf(&b, " rule %s", e.Source.Rule)
		}
		if e.Source.Engine != "" {
			fmt.Fprintf(&b, " engine %s", e.Source.Engine)
		}
		b.WriteString("\n")
		if e.Family != "" {
			fmt.Fprintf(&b, "Independence family: %s\n", e.Family)
		}
		if c := cited[e.ID]; len(c) > 0 {
			fmt.Fprintf(&b, "\nCited by findings: %s   (press f to open them)\n", strings.Join(c, ", "))
		}
		rw := mk(e.ID, fmt.Sprintf("%-5s %-12s %s", e.ID, e.Kind, oneLine(e.Value, 70)), b.String())
		rw.findings = cited[e.ID]
		out = append(out, rw)
	}
	return out
}

func indicatorRows(r *models.Report) []row {
	if r.Analysis == nil {
		return nil
	}
	var out []row
	for _, i := range r.Analysis.Indicators {
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %s\n\nSeen %d time(s); first at 0x%x", i.Type, i.Value, i.Count, i.Offset)
		if i.Section != "" {
			fmt.Fprintf(&b, " in %s", i.Section)
		}
		fmt.Fprintf(&b, ", encoding %s\n", i.Encoding)
		if i.Note != "" {
			fmt.Fprintf(&b, "\n%s\n", i.Note)
		}
		b.WriteString("\nA string that looks like an indicator is not proof that the sample uses it.\n")
		out = append(out, mk(i.Type+":"+i.Value, fmt.Sprintf("%-12s %s", i.Type, oneLine(i.Value, 80)), b.String()))
	}
	return out
}

func capabilityRows(r *models.Report) []row {
	if r.Analysis == nil {
		return nil
	}
	var out []row
	for _, c := range r.Analysis.Capabilities {
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n%s  |  %s confidence  |  %s\n\n%s\n", c.Name, c.Severity, c.Confidence, c.Category, c.Summary)
		fmt.Fprintf(&b, "\nSupport: %s (an inference from what the file references, not observed behaviour)\n", strings.Join(c.EvidenceKinds, ", "))
		if c.Rationale != "" {
			fmt.Fprintf(&b, "\nWhy this confidence: %s\n", c.Rationale)
		}
		for _, s := range c.Signals {
			fmt.Fprintf(&b, "  - [%s] %s\n", s.Strength, s.Detail)
		}
		if c.Caveat != "" {
			fmt.Fprintf(&b, "\nCaveat: %s\n", c.Caveat)
		}
		if len(c.Attack) > 0 {
			fmt.Fprintf(&b, "\nATT&CK: %s\n", strings.Join(c.Attack, ", "))
		}
		var ev []string
		for _, s := range c.Signals {
			ev = append(ev, s.Evidence...)
		}
		out = append(out, mk(c.ID, fmt.Sprintf("%-13s %-11s %s", c.Severity, c.Confidence, c.Name), b.String(), ev...))
	}
	return out
}

func structureRows(r *models.Report) []row {
	if r.Binary == nil {
		return nil
	}
	ent := map[string]float64{}
	if r.Analysis != nil {
		for _, s := range r.Analysis.Entropy.Sections {
			ent[s.Name] = s.Entropy
		}
	}
	var out []row
	for _, s := range r.Binary.Sections {
		e := "-"
		if v, ok := ent[s.Name]; ok {
			e = fmt.Sprintf("%.2f", v)
		}
		d := fmt.Sprintf("%s\nfile offset 0x%x, %d bytes on disk\nvirtual address 0x%x, %d bytes in memory\npermissions %s, entropy %s\n", s.Name, s.RawOffset, s.RawSize, s.VirtualAddress, s.VirtualSize, s.Perms, e)
		out = append(out, mk("sec:"+s.Name, fmt.Sprintf("%-18s %-4s raw 0x%08x %9d  entropy %s", s.Name, s.Perms, s.RawOffset, s.RawSize, e), d))
	}
	for _, im := range r.Binary.Imports {
		names := make([]string, 0, len(im.Functions))
		for _, f := range im.Functions {
			n := f.Name
			if f.ByOrdinal {
				n = fmt.Sprintf("#%d (by ordinal)", f.Ordinal)
			}
			names = append(names, n)
		}
		out = append(out, mk("imp:"+im.Library, fmt.Sprintf("import %-24s %d function(s)", im.Library, len(im.Functions)), im.Library+"\n\n"+strings.Join(names, "\n")+"\n"))
	}
	if o := r.Binary.Overlay; o != nil {
		out = append(out, mk("overlay", fmt.Sprintf("overlay at 0x%x, %d bytes", o.Offset, o.Size), fmt.Sprintf("Data after the last section: %d bytes at 0x%x.\n", o.Size, o.Offset)))
	}
	return out
}

func oneLine(s string, n int) string {
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
