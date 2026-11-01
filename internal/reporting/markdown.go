package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// mdCell makes text safe inside a Markdown table cell: sample text can hold
// pipes, newlines, HTML and Markdown syntax.
func mdCell(s string) string {
	s = clean(s)
	r := strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "`", "'", "[", `\[`, "]", `\]`, "*", `\*`, "_", `\_`, "#", `\#`, "!", `\!`)
	return r.Replace(s)
}

// mdText is mdCell for running text.
func mdText(s string) string { return mdCell(s) }

// mdCode wraps text in a code span long enough to contain any backtick run.
func mdCode(s string) string {
	// Angle brackets and "](" are softened even inside code spans, so a
	// renderer that mishandles code spans still cannot be handed markup or a
	// link from a hostile file.
	s = strings.NewReplacer("\n", " ", "\r", " ", "<", "\u2039", ">", "\u203a", "](", "] (").Replace(clean(s))
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + s + pad + fence
}

type mdw struct {
	w   io.Writer
	err error
}

func (m *mdw) p(format string, a ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format, a...)
	}
}

func (m *mdw) table(header []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	m.p("| %s |\n|%s\n", strings.Join(header, " | "), strings.Repeat(" --- |", len(header)))
	for _, r := range rows {
		m.p("| %s |\n", strings.Join(r, " | "))
	}
	m.p("\n")
}

// Markdown writes a report as GitHub-flavoured Markdown.
func Markdown(w io.Writer, r *models.Report) error {
	r = sanitized(r, true)
	m := &mdw{w: w}
	m.p("# UNPACKR report: %s\n\n", mdText(r.File.Name))
	m.p("*Static analysis. UNPACKR %s, %s, offline, schema %s, profile %s, %s. The sample was never executed. Network text is defanged, and angle brackets in quoted sample text appear as ‹ ›.*\n\n",
		version.Version, version.Platform(), mdText(r.SchemaVersion), mdText(r.Profile), r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	mdBody(m, r, 2)
	return m.err
}

func h(level int, s string) string { return strings.Repeat("#", level) + " " + s }

func mdBody(m *mdw, r *models.Report, lvl int) {
	m.p("%s\n\n", h(lvl, "Executive summary"))
	for _, s := range Summary(r) {
		m.p("- %s\n", mdText(s))
	}
	c := SeverityCounts(r)
	m.p("\nFindings by severity: high %d, medium %d, low %d, informational %d.\n\n", c[models.SeverityHigh], c[models.SeverityMedium], c[models.SeverityLow], c[models.SeverityInfo])

	m.p("%s\n\n", h(lvl, "File metadata and hashes"))
	m.table([]string{"Property", "Value"}, [][]string{
		{"Name", mdCell(r.File.Name)}, {"Size", fmt.Sprintf("%d bytes", r.File.Size)},
		{"SHA-256", mdCode(r.File.Hashes.SHA256)}, {"SHA-1", mdCode(r.File.Hashes.SHA1)}, {"MD5", mdCode(r.File.Hashes.MD5)},
	})
	if id := r.Identification; id != nil {
		m.p("Format: **%s**%s. Scores are structural validity out of 100, not probabilities.\n\n", mdText(id.Primary), map[bool]string{true: " (satisfies more than one format family)", false: ""}[id.Polyglot])
	}

	if a := r.Analysis; a != nil {
		m.p("%s\n\n", h(lvl, "Technical fingerprint"))
		for _, set := range []struct {
			name string
			hs   []models.Hypothesis
		}{{"Language", a.Fingerprint.Languages}, {"Compiler", a.Fingerprint.Compilers}, {"Runtime", a.Fingerprint.Runtimes}} {
			if len(set.hs) == 0 {
				m.p("- **%s:** no indicators found\n", set.name)
				continue
			}
			for i, hy := range set.hs {
				label := set.name
				if i > 0 {
					label = "  or"
				}
				d := ""
				if hy.Detail != "" {
					d = " — " + mdText(hy.Detail)
				}
				m.p("- **%s:** %s%s (%s confidence). %s\n", label, mdText(hy.Name), d, mdText(string(hy.Confidence)), mdText(hy.Rationale))
			}
		}
		m.p("\n%s\n\n", h(lvl, "Packing and obfuscation"))
		fam := ""
		if a.Packing.Family != "" {
			fam = " (" + mdText(a.Packing.Family) + ")"
		}
		m.p("**%s**%s, %s confidence. %s\n\n", mdText(a.Packing.State), fam, mdText(string(a.Packing.Confidence)), mdText(a.Packing.Rationale))
		var rows [][]string
		for _, s := range a.Packing.Signals {
			rows = append(rows, []string{mdCell(s.Strength), mdCell(s.Detail), mdCell(strings.Join(s.Evidence, ", "))})
		}
		m.table([]string{"Strength", "Signal", "Evidence"}, rows)
		m.p("Entropy: whole file %.3f bits/byte. Entropy is a measurement and never decides a packing verdict alone.\n\n", a.Entropy.File)
	}

	if b := r.Binary; b != nil {
		m.p("%s\n\n", h(lvl, "File structure"))
		m.p("%s, %s, %d-bit, %s-endian, %s.\n\n", mdText(b.Format), mdText(b.Arch), b.Bits, b.Endian, mdText(b.Kind))
		if b.Entry != nil {
			sec := b.Entry.Section
			if sec == "" {
				sec = "not inside any section"
			}
			m.p("Entry point: RVA 0x%x, VA 0x%x, %s.\n\n", b.Entry.RVA, b.Entry.VA, mdText(sec))
		}
		var rows [][]string
		for _, s := range b.Sections {
			rows = append(rows, []string{mdCell(s.Name), fmt.Sprintf("0x%x", s.VirtualAddress), fmt.Sprintf("0x%x", s.VirtualSize), fmt.Sprintf("0x%x", s.RawOffset), fmt.Sprintf("0x%x", s.RawSize), mdCell(s.Perms)})
		}
		m.table([]string{"Section", "Virtual address", "Virtual size", "Raw offset", "Raw size", "Perms"}, rows)
		total := 0
		for _, im := range b.Imports {
			total += len(im.Functions)
		}
		if len(b.Imports) > 0 {
			m.p("Imports: %d symbols from %d libraries.\n\n", total, len(b.Imports))
			rows = nil
			for _, im := range b.Imports {
				rows = append(rows, []string{mdCell(im.Library), fmt.Sprint(len(im.Functions))})
			}
			m.table([]string{"Library", "Symbols"}, rows)
		}
		if len(b.Anomalies) > 0 {
			m.p("Parser anomalies:\n\n")
			for _, an := range b.Anomalies {
				m.p("- %s\n", mdText(an))
			}
			m.p("\n")
		}
	}

	if a := r.Analysis; a != nil {
		m.p("%s\n\n", h(lvl, "Capabilities (inferred)"))
		m.p("> Inferred from what the file references. The sample was not executed, so nothing here is observed behaviour.\n\n")
		var rows [][]string
		for _, c := range a.Capabilities {
			rows = append(rows, []string{mdCell(c.Name), mdCell(c.Category), mdCell(string(c.Confidence)), mdCell(strings.Join(c.Attack, ", ")), mdCell(c.Summary)})
		}
		if len(rows) == 0 {
			m.p("None inferred.\n\n")
		}
		m.table([]string{"Capability", "Category", "Confidence", "ATT&CK", "Summary"}, rows)

		m.p("%s\n\n", h(lvl, "Structural anomalies"))
		if len(a.Anomalies) == 0 {
			m.p("None found.\n\n")
		}
		for _, an := range a.Anomalies {
			m.p("- **%s** (%s): %s", mdText(an.Title), mdText(string(an.Severity)), mdText(an.Why))
			if an.Benign != "" {
				m.p(" *Common and harmless in: %s*", mdText(an.Benign))
			}
			m.p("\n")
		}
		m.p("\n%s\n\n", h(lvl, "Indicators"))
		m.p("> Strings found in the file; presence does not show use or contact. Network indicators are defanged.\n\n")
		rows = nil
		for _, i := range a.Indicators {
			rows = append(rows, []string{mdCell(i.Type), mdCode(Defang(i.Type, i.Value)), fmt.Sprint(i.Count), fmt.Sprintf("0x%x", i.Offset), mdCell(i.Note)})
		}
		if len(rows) == 0 {
			m.p("None found.\n\n")
		}
		m.table([]string{"Type", "Value (defanged)", "Count", "Offset", "Note"}, rows)
		m.p("Strings: %d found (%d ASCII, %d UTF-16). See the JSON report for the sample.\n\n", a.Strings.Total, a.Strings.ASCII, a.Strings.UTF16)
		if len(a.Yara) > 0 {
			rows = nil
			for _, y := range a.Yara {
				rows = append(rows, []string{mdCell(y.Rule), mdCell(y.Status), mdCell(y.Description)})
			}
			m.p("YARA-X matches (only `tested` rules count as evidence):\n\n")
			m.table([]string{"Rule", "Status", "Description"}, rows)
		}
		for _, e := range a.Engines {
			m.p("- Engine %s %s: %s %s\n", mdText(e.Name), mdText(e.Version), mdText(e.Status), mdText(e.Detail))
		}
		m.p("\n")
	}

	if r.Unpack != nil || r.Extraction != nil {
		m.p("%s\n\n", h(lvl, "Payloads: unpacking and extraction"))
		if u := r.Unpack; u != nil {
			m.p("Unpacking: **%s**. %s (supported: %s; not a generic unpacker)\n\n", mdText(u.Status), mdText(u.Message), mdText(strings.Join(u.Supported, ", ")))
		}
		for _, art := range r.Artifacts {
			m.p("Unpacked layer by %s %s: SHA-256 %s, %d bytes.\n\n", mdText(art.Tool), mdText(art.ToolVersion), mdCode(art.Hashes.SHA256), art.Size)
			var rows [][]string
			for _, v := range art.Validation {
				rows = append(rows, []string{mdCell(v.Name), map[bool]string{true: "pass", false: "FAIL"}[v.Passed], mdCell(v.Detail)})
			}
			m.table([]string{"Validation", "Result", "Detail"}, rows)
			if art.Comparison != nil {
				mdComparison(m, art.Comparison, lvl+1)
			}
		}
		if e := r.Extraction; e != nil {
			m.p("Extraction: **%s**. %s (supported: %s). Extracted files were never executed.\n\n", mdText(e.Status), mdText(e.Message), mdText(strings.Join(e.Supported, ", ")))
			var rows [][]string
			for _, en := range e.Entries {
				sha := en.SHA256
				if len(sha) > 16 {
					sha = sha[:16]
				}
				rows = append(rows, []string{mdCell(en.TypeName), mdCell(en.Name), fmt.Sprintf("0x%x", en.Offset), fmt.Sprint(en.Size), mdCell(en.Format), mdCode(sha), mdCell(en.Skipped)})
			}
			m.table([]string{"Type", "Entry", "Offset", "Size", "Content", "SHA-256", "Skipped"}, rows)
		}
	}

	m.p("%s\n\n", h(lvl, "Findings"))
	m.p("Class: *observation* (read from the file), *inference* (derived by a named rule), *hypothesis* (weakly supported). Confidence is ordinal and is not a probability.\n\n")
	var rows [][]string
	for _, f := range r.Findings {
		rows = append(rows, []string{mdCell(f.Title), mdCell(string(f.Class)), mdCell(string(f.Severity)), mdCell(string(f.Confidence)), mdCell(f.Rationale), mdCell(strings.Join(f.EvidenceID, ", "))})
	}
	m.table([]string{"Finding", "Class", "Severity", "Confidence", "Why this confidence", "Evidence"}, rows)

	m.p("%s\n\n", h(lvl, "Evidence"))
	rows = nil
	ev := append([]models.Evidence(nil), r.Evidence...)
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].ID < ev[j].ID })
	for _, e := range ev {
		off := ""
		if e.Loc.Offset != nil {
			off = fmt.Sprintf("0x%x", *e.Loc.Offset)
		}
		rows = append(rows, []string{mdCell(e.ID), mdCell(e.Kind), mdCode(e.Value), off, mdCell(e.Loc.Section), mdCell(e.Source.Module + " " + e.Source.Rule)})
	}
	if len(rows) == 0 {
		m.p("No evidence records.\n\n")
	}
	m.table([]string{"Id", "Kind", "Value", "File offset", "Section", "Source"}, rows)

	m.p("%s\n\n", h(lvl, "Recommendations"))
	for i, s := range Recommendations(r) {
		m.p("%d. %s\n", i+1, mdText(s))
	}
	m.p("\n%s\n\n", h(lvl, "Limits of this report"))
	if len(r.NotRun) > 0 {
		m.p("Stages not available in this build (their absence is not a clean result):\n\n")
		for _, n := range r.NotRun {
			m.p("- %s\n", mdText(n))
		}
		m.p("\n")
	}
	for _, w := range r.Warnings {
		m.p("- Warning, %s: %s\n", mdText(w.Module), mdText(w.Message))
	}
	rows = nil
	for _, mod := range r.Modules {
		sb := "n/a"
		if mod.Sandbox != nil {
			sb = mod.Sandbox.Level
		}
		rows = append(rows, []string{mdCell(mod.Name), mdCell(mod.Status), fmt.Sprint(mod.DurationMS), mdCell(sb)})
	}
	m.p("\n")
	m.table([]string{"Module", "Status", "Time (ms)", "Sandbox"}, rows)
	for _, art := range r.Artifacts {
		if art.Report != nil {
			m.p("---\n\n%s\n\n", h(lvl, "Unpacked layer report: "+mdText(art.Report.File.Name)))
			mdBody(m, art.Report, lvl+1)
		}
	}
}

func mdComparison(m *mdw, c *models.Comparison, lvl int) {
	m.p("%s\n\n", h(lvl, "Differences"))
	var rows [][]string
	for _, x := range c.Header {
		rows = append(rows, []string{mdCell(x.Field), mdCell(x.A), mdCell(x.B)})
	}
	for _, sd := range c.SectionChanges {
		for _, x := range sd.Changes {
			rows = append(rows, []string{mdCell("section " + sd.Name + " " + x.Field), mdCell(x.A), mdCell(x.B)})
		}
	}
	for _, grp := range [][]models.Change{c.Entropy, c.Packing, c.Fingerprint, c.Strings} {
		for _, x := range grp {
			rows = append(rows, []string{mdCell(x.Field), mdCell(x.A), mdCell(x.B)})
		}
	}
	m.table([]string{"Property", "First", "Second"}, rows)
	for _, s := range []struct {
		name string
		d    models.SetDiff
	}{{"Sections", c.Sections}, {"Imported libraries", c.Libraries}, {"Imported functions", c.Imports}, {"Exports", c.Exports}, {"Capabilities", c.Capabilities}, {"Indicators", c.Indicators}} {
		if len(s.d.OnlyA) == 0 && len(s.d.OnlyB) == 0 {
			continue
		}
		m.p("- **%s** only in first (%d): %s\n- **%s** only in second (%d): %s\n", s.name, len(s.d.OnlyA), mdText(strings.Join(limit(s.d.OnlyA, 30), ", ")), s.name, len(s.d.OnlyB), mdText(strings.Join(limit(s.d.OnlyB, 30), ", ")))
	}
	if sm := c.Similarity; sm != nil {
		m.p("\n**Similarity** (measurements, not probabilities; none is evidence of a shared origin):")
		if sm.HasTLSH {
			m.p(" TLSH distance %d;", sm.TLSHDistance)
		}
		if sm.HasSSDeep {
			m.p(" ssdeep %d;", sm.SSDeepScore)
		}
		if sm.HasOverlap {
			m.p(" structural overlap %.2f;", sm.Overlap)
		}
		m.p("\n\n")
		var rows [][]string
		for _, comp := range sm.Components {
			rows = append(rows, []string{mdCell(comp.Name), fmt.Sprintf("%.3f", comp.Score), fmt.Sprintf("%.2f", comp.Weight), mdCell(comp.Note)})
		}
		m.table([]string{"Component", "Score", "Weight", "How"}, rows)
	}
	for _, n := range c.Notes {
		m.p("\n*%s*\n", mdText(n))
	}
	m.p("\n")
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string(nil), in[:n]...), fmt.Sprintf("… (+%d)", len(in)-n))
}
