package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func safe(s string) string { return terminal.Sanitize(s) }

// renderReport prints one report in the human-readable layout. Every string
// that originates from the sample passes through Sanitize.
func renderReport(w io.Writer, r *models.Report, verbose bool, st terminal.Style) {
	h := func(t string) { _, _ = fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan(t))) }
	kv := func(k, v string) { _, _ = fmt.Fprintf(w, "  %-10s %s\n", k, v) }

	h("Stage 01 · File identification")
	kv("File", fmt.Sprintf("%s (%d bytes)", safe(r.File.Name), r.File.Size))
	kv("SHA256", r.File.Hashes.SHA256)
	kv("SHA1", r.File.Hashes.SHA1)
	kv("MD5", r.File.Hashes.MD5)
	if verbose {
		kv("Path", safe(r.File.Path))
	}
	if r.Identification == nil {
		kv("Format", st.Red("identification failed — see warnings"))
	} else {
		for _, f := range r.Findings {
			if f.Category != "identification" {
				continue
			}
			label := "Format"
			if f.ID == "ident.polyglot" {
				label = "Note"
			}
			kv(label, fmt.Sprintf("%s  %s", safe(strings.TrimPrefix(f.Title, "Format: ")), st.Dim("["+string(f.Class)+", confidence: "+string(f.Confidence)+"]")))
			fmt.Fprintf(w, "  %-10s %s\n", "", st.Dim(safe(f.Summary)))
			if verbose {
				fmt.Fprintf(w, "  %-10s why: %s\n", "", safe(f.Rationale))
				for _, id := range f.EvidenceID {
					for _, e := range r.Evidence {
						if e.ID == id {
							loc := ""
							if e.Loc.Offset != nil {
								loc = fmt.Sprintf("offset 0x%x", *e.Loc.Offset)
								if e.Loc.Length != nil {
									loc += fmt.Sprintf(" len %d", *e.Loc.Length)
								}
							}
							fmt.Fprintf(w, "  %-10s · %s  %s\n", "", safe(e.Value), st.Dim(loc))
						}
					}
				}
			}
			if f.Action != "" {
				fmt.Fprintf(w, "  %-10s next: %s\n", "", safe(f.Action))
			}
		}
		if verbose {
			for _, c := range r.Identification.Candidates {
				if c.Score < 50 {
					fmt.Fprintf(w, "  %-10s candidate %-28s score %d/100\n", "", safe(c.Format), c.Score)
				}
			}
		}
	}

	if r.Known != nil {
		renderKnown(w, r.Known, verbose, st)
	}
	if r.Binary != nil {
		renderBinary(w, r.Binary, verbose, st)
	}
	if r.Analysis != nil {
		renderAnalysis(w, r, verbose, st)
	}
	if r.Unpack != nil {
		renderUnpack(w, r, verbose, st)
	}
	if r.Extraction != nil {
		renderExtraction(w, r.Extraction, verbose, st)
	}

	if len(r.Warnings) > 0 {
		h("Warnings")
		for _, wn := range r.Warnings {
			fmt.Fprintf(w, "  %s %s: %s\n", st.Yellow("!"), wn.Module, safe(wn.Message))
		}
	}

	h("Not available in this build")
	fmt.Fprintf(w, "  %s\n", st.Dim("These stages did not run. Their absence is not a clean result."))
	for _, n := range r.NotRun {
		fmt.Fprintf(w, "  - %s\n", n)
	}

	if verbose {
		h("Modules")
		for _, m := range r.Modules {
			sb := "n/a"
			if m.Sandbox != nil {
				sb = m.Sandbox.Level
				if m.Sandbox.Level == "full" {
					sb += fmt.Sprintf(" (landlock abi %d, seccomp, no_new_privs, rlimit)", m.Sandbox.LandlockABI)
				}
			}
			fmt.Fprintf(w, "  %-16s %-7s %4d ms  sandbox: %s\n", m.Name, m.Status, m.DurationMS, sb)
		}
	}
}

// renderTable prints the consolidated batch result.
func renderTable(w io.Writer, reps []*models.Report, errs map[string]error, st terminal.Style) {
	fmt.Fprintf(w, "%s\n", st.Bold(fmt.Sprintf("%-44s %-24s %-16s %s", "FILE", "FORMAT", "SHA256", "STATUS")))
	for _, r := range reps {
		format, status := "?", "ok"
		if r.Identification != nil {
			format = r.Identification.Primary
		} else {
			status = "failed"
		}
		for _, wn := range r.Warnings {
			if wn.Module == "sandbox" {
				status = "ok (reduced sandbox)"
			}
		}
		fmt.Fprintf(w, "%-44s %-24s %-16s %s\n", clip(safe(r.File.Path), 44), clip(safe(format), 24), r.File.Hashes.SHA256[:16], status)
	}
	for p, e := range errs {
		fmt.Fprintf(w, "%-44s %-24s %-16s %s\n", clip(safe(p), 44), "-", "-", st.Red("error: "+safe(e.Error())))
	}
	fmt.Fprintf(w, "\n%d analysed, %d failed\n", len(reps), len(errs))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}

func repeat(s string, n int) string { return strings.Repeat(s, n) }

func renderBinary(w io.Writer, b *models.Binary, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Executable structure")))
	kv := func(k, v string) { fmt.Fprintf(w, "  %-10s %s\n", k, v) }
	kv("Format", fmt.Sprintf("%s, %s, %d-bit, %s-endian, %s", safe(b.Format), safe(b.Arch), b.Bits, b.Endian, b.Kind))
	if b.Entry != nil {
		e := fmt.Sprintf("RVA 0x%x  VA 0x%x", b.Entry.RVA, b.Entry.VA)
		if b.Entry.Section != "" {
			e += "  in " + safe(b.Entry.Section)
		} else {
			e += "  " + st.Yellow("(not inside any section)")
		}
		if verbose && b.Entry.FileOffset != nil {
			e += fmt.Sprintf("  file offset 0x%x", *b.Entry.FileOffset)
		}
		kv("Entry", e)
	}
	if b.CompiledAt != "" {
		kv("Timestamp", b.CompiledAt+" "+st.Dim("(header value; trivially forged)"))
	}
	if b.ImportHash != "" {
		kv("Imphash", b.ImportHash)
	}
	if len(b.Slices) > 0 {
		kv("Slices", safe(b.Attributes["architectures"]))
	}
	if verbose {
		keys := make([]string, 0, len(b.Attributes))
		for k := range b.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			kv(safe(k), safe(b.Attributes[k]))
		}
	}
	table := func(title string, secs []models.Section) {
		if len(secs) == 0 {
			return
		}
		fmt.Fprintf(w, "\n  %s\n", st.Bold(title))
		fmt.Fprintf(w, "  %-26s %-12s %-10s %-10s %-10s %s\n", "name", "virt addr", "virt size", "raw off", "raw size", "perm")
		for _, s := range secs {
			perm := s.Perms
			if perm == "rwx" {
				perm = st.Red(perm)
			}
			fmt.Fprintf(w, "  %-26s 0x%-10x 0x%-8x 0x%-8x 0x%-8x %s\n", clip(safe(s.Name), 26), s.VirtualAddress, s.VirtualSize, s.RawOffset, s.RawSize, perm)
		}
	}
	table("Sections", b.Sections)
	table("Segments (loader view)", b.Segments)
	for i, sl := range b.Slices {
		fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Slice %d: %s", i+1, safe(sl.Arch))))
		table("  Segments", sl.Segments)
	}

	if len(b.Libraries) > 0 {
		fmt.Fprintf(w, "\n  %s\n", st.Bold("Linked libraries"))
		for _, l := range b.Libraries {
			fmt.Fprintf(w, "  - %s\n", safe(l))
		}
	}
	if len(b.Imports) > 0 {
		total := 0
		for _, im := range b.Imports {
			total += len(im.Functions)
		}
		fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Imports: %d symbols from %d libraries", total, len(b.Imports))))
		for _, im := range b.Imports {
			tag := ""
			if im.Delay {
				tag = " (delay-load)"
			}
			fmt.Fprintf(w, "  %-36s %d%s\n", clip(safe(im.Library), 36), len(im.Functions), tag)
			if verbose {
				for _, f := range im.Functions {
					name := f.Name
					if f.ByOrdinal {
						name = fmt.Sprintf("#%d", f.Ordinal)
					}
					fmt.Fprintf(w, "      %s\n", safe(name))
				}
			}
		}
	}
	if dn := b.DotNet; dn != nil {
		renderDotNet(w, dn, verbose, st)
	}
	if len(b.Exports) > 0 {
		fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Exports: %d", len(b.Exports))))
		if verbose {
			for _, e := range b.Exports {
				fmt.Fprintf(w, "      %s  rva 0x%x\n", safe(e.Name), e.RVA)
			}
		}
	}
	if b.Overlay != nil {
		fmt.Fprintf(w, "\n  Overlay    %d bytes at file offset 0x%x (data after the last section; not necessarily malicious)\n", b.Overlay.Size, b.Overlay.Offset)
	}
	if b.Truncated {
		fmt.Fprintf(w, "  %s\n", st.Yellow("only the first part of this large file was parsed"))
	}
	if len(b.Anomalies) > 0 {
		fmt.Fprintf(w, "\n  %s\n", st.Bold("Parser anomalies"))
		for _, a := range b.Anomalies {
			fmt.Fprintf(w, "  %s %s\n", st.Yellow("!"), safe(a))
		}
	}
}

func confTag(c models.Confidence, st terminal.Style) string {
	return st.Dim("[" + string(c) + " confidence]")
}

func renderHyps(w io.Writer, label string, hs []models.Hypothesis, verbose bool, st terminal.Style) {
	if len(hs) == 0 {
		fmt.Fprintf(w, "  %-10s %s\n", label, st.Dim("no indicators found"))
		return
	}
	for i, h := range hs {
		l := ""
		if i == 0 {
			l = label
		} else {
			l = "  or"
		}
		name := safe(h.Name)
		if h.Detail != "" {
			name += " — " + safe(h.Detail)
		}
		fmt.Fprintf(w, "  %-10s %s  %s\n", l, name, confTag(h.Confidence, st))
		if verbose {
			fmt.Fprintf(w, "  %-10s why: %s\n", "", safe(h.Rationale))
			for _, sg := range h.Signals {
				fmt.Fprintf(w, "  %-10s · [%s] %s\n", "", sg.Strength, safe(sg.Detail))
			}
		}
	}
}

func renderAnalysis(w io.Writer, r *models.Report, verbose bool, st terminal.Style) {
	a := r.Analysis
	h := func(t string) { fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan(t))) }

	h("Stage 02 · Technical fingerprint")
	renderHyps(w, "Language", a.Fingerprint.Languages, verbose, st)
	renderHyps(w, "Compiler", a.Fingerprint.Compilers, verbose, st)
	renderHyps(w, "Runtime", a.Fingerprint.Runtimes, verbose, st)

	h("Stage 03 · Packing and obfuscation")
	state := a.Packing.State
	switch state {
	case models.PackConfirmed, models.PackLikely:
		state = st.Red(state)
	case models.PackUnknown, models.PackObfuscated:
		state = st.Yellow(state)
	default:
		state = st.Green(state)
	}
	line := state
	if a.Packing.Family != "" {
		line += "  " + safe(a.Packing.Family)
	}
	fmt.Fprintf(w, "  %-10s %s  %s\n", "State", line, confTag(a.Packing.Confidence, st))
	fmt.Fprintf(w, "  %-10s %s\n", "", st.Dim(safe(a.Packing.Rationale)))
	for _, n := range a.Packing.Notes {
		fmt.Fprintf(w, "  %-10s %s\n", "", st.Dim(safe(n)))
	}
	for _, sg := range a.Packing.Signals {
		fmt.Fprintf(w, "  %-10s · [%s] %s\n", "", sg.Strength, safe(sg.Detail))
		if verbose {
			for _, id := range sg.Evidence {
				for _, e := range r.Evidence {
					if e.ID == id && e.Loc.Offset != nil {
						fmt.Fprintf(w, "  %-10s     %s\n", "", st.Dim(fmt.Sprintf("evidence %s at file offset 0x%x", id, *e.Loc.Offset)))
					}
				}
			}
		}
	}
	for i, d := range a.Decoded {
		if i == 8 {
			fmt.Fprintf(w, "  %-10s … and %d more recovered strings (see the report)\n", "", len(a.Decoded)-i)
			break
		}
		how := d.Method
		if d.Key != "" {
			how += " key " + d.Key
		}
		fmt.Fprintf(w, "  %-10s ⟲ recovered at 0x%x (%s): %s\n", "Hidden", d.Offset, how, safe(head(d.Text, 100)))
	}
	fmt.Fprintf(w, "  %-10s %.3f bits/byte over the whole file", "Entropy", a.Entropy.File)
	if a.Entropy.Overlay != nil {
		fmt.Fprintf(w, ", overlay %.3f", *a.Entropy.Overlay)
	}
	fmt.Fprintln(w)
	if verbose {
		for _, s := range a.Entropy.Sections {
			fmt.Fprintf(w, "  %-10s %-18s %.3f  %s\n", "", clip(safe(s.Name), 18), s.Entropy, s.Perms)
		}
	}

	renderYara(w, a, verbose, st)

	h("Stage 04 · Static intelligence")
	fmt.Fprintf(w, "  %-10s %d found (%d ASCII, %d UTF-16); showing %d in JSON output\n", "Strings", a.Strings.Total, a.Strings.ASCII, a.Strings.UTF16, len(a.Strings.Shown))
	renderCapabilities(w, a, verbose, st)
	renderAnomalies(w, a, verbose, st)
	if len(a.Indicators) == 0 {
		fmt.Fprintf(w, "  %-10s %s\n", "Indicators", st.Dim("none found"))
		return
	}
	limit := 8
	if verbose {
		limit = len(a.Indicators)
	}
	byType := map[string][]models.Indicator{}
	var types []string
	for _, i := range a.Indicators {
		if _, ok := byType[i.Type]; !ok {
			types = append(types, i.Type)
		}
		byType[i.Type] = append(byType[i.Type], i)
	}
	sort.Strings(types)
	for _, t := range types {
		list := byType[t]
		fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("%s (%d)", t, len(list))))
		for n, i := range list {
			if n >= limit {
				fmt.Fprintf(w, "      … %d more (use -v)\n", len(list)-n)
				break
			}
			extra := ""
			if i.Count > 1 {
				extra += fmt.Sprintf(" x%d", i.Count)
			}
			if i.Note != "" {
				extra += " — " + i.Note
			}
			fmt.Fprintf(w, "      %s  %s\n", safe(i.Value), st.Dim(fmt.Sprintf("@0x%x%s", i.Offset, extra)))
		}
	}
	fmt.Fprintf(w, "\n  %s\n", st.Dim("Indicators are strings found in the file. They do not show that the sample uses or contacts them."))
}

func renderCapabilities(w io.Writer, a *models.Analysis, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n  %s\n", st.Bold("Capabilities"))
	fmt.Fprintf(w, "  %s\n", st.Dim("Inferred from what the file references. The sample was not run, so none of this is observed behaviour."))
	if len(a.Capabilities) == 0 {
		fmt.Fprintf(w, "  %s\n", st.Dim("none inferred"))
		return
	}
	cat := ""
	for _, c := range a.Capabilities {
		if c.Category != cat {
			cat = c.Category
			fmt.Fprintf(w, "\n  %s\n", st.Cyan(safe(cat)))
		}
		atk := ""
		if len(c.Attack) > 0 {
			atk = "  ATT&CK " + strings.Join(c.Attack, ", ")
		}
		fmt.Fprintf(w, "    %s %s  %s%s\n", st.Yellow("•"), safe(c.Name), confTag(c.Confidence, st), st.Dim(atk))
		var flow []string
		for _, s := range c.Chain {
			if len(s.APIs) > 0 {
				flow = append(flow, safe(s.APIs[0]))
			}
		}
		if strings.HasPrefix(c.ID, "exfil") {
			for _, s := range c.Chain {
				fmt.Fprintf(w, "        %s: %s\n", safe(s.Label), safe(strings.Join(s.APIs, ", ")))
			}
		} else if len(flow) > 1 {
			fmt.Fprintf(w, "        %s  %s\n", strings.Join(flow, " → "), st.Dim("("+strings.Join(c.EvidenceKinds, ", ")+")"))
		} else if len(flow) == 1 {
			fmt.Fprintf(w, "        %s  %s\n", flow[0], st.Dim("("+strings.Join(c.EvidenceKinds, ", ")+")"))
		}
		if verbose {
			fmt.Fprintf(w, "        why: %s\n", safe(c.Rationale))
			for _, s := range c.Chain {
				fmt.Fprintf(w, "        | %-22s %s [%s]\n", safe(s.Label), safe(strings.Join(s.APIs, ", ")), s.Source)
			}
			for _, sg := range c.Signals {
				if strings.Contains(sg.ID, ".string") || strings.Contains(sg.ID, ".constant") {
					fmt.Fprintf(w, "        · [%s] %s\n", sg.Strength, safe(sg.Detail))
				}
			}
			if c.Caveat != "" {
				fmt.Fprintf(w, "        note: %s\n", safe(c.Caveat))
			}
		}
	}
}

func renderAnomalies(w io.Writer, a *models.Analysis, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Structural anomalies (%d)", len(a.Anomalies))))
	if len(a.Anomalies) == 0 {
		fmt.Fprintf(w, "  %s\n", st.Dim("none found"))
		return
	}
	for _, an := range a.Anomalies {
		mark := st.Dim("·")
		switch an.Severity {
		case models.SeverityHigh:
			mark = st.Red("!")
		case models.SeverityMedium:
			mark = st.Yellow("!")
		}
		fmt.Fprintf(w, "    %s %s\n", mark, safe(an.Title))
		fmt.Fprintf(w, "        %s\n", st.Dim(safe(an.Why)))
		if verbose && an.Benign != "" {
			fmt.Fprintf(w, "        common and harmless in: %s\n", safe(an.Benign))
		}
	}
}

func renderUnpack(w io.Writer, r *models.Report, verbose bool, st terminal.Style) {
	u := r.Unpack
	fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Unpacking")))
	status := u.Status
	switch u.Status {
	case "unpacked":
		status = st.Green(status)
	case "failed", "rejected":
		status = st.Red(status)
	default:
		status = st.Yellow(status)
	}
	fmt.Fprintf(w, "  %-10s %s\n", "Status", status)
	fmt.Fprintf(w, "  %-10s %s\n", "", safe(u.Message))
	if u.Tool != "" {
		tv := u.Tool
		if u.ToolVersion != "" {
			tv += " " + u.ToolVersion
		}
		fmt.Fprintf(w, "  %-10s %s\n", "Tool", safe(tv))
	}
	fmt.Fprintf(w, "  %-10s %s\n", "Supported", st.Dim(strings.Join(u.Supported, ", ")+" (no other packer is unpacked; this is not a generic unpacker)"))
	for _, a := range r.Artifacts {
		fmt.Fprintf(w, "\n  %s\n", st.Bold("Unpacked layer"))
		fmt.Fprintf(w, "  %-10s %s\n", "File", safe(a.Path))
		fmt.Fprintf(w, "  %-10s %d bytes, mode 0600, never executed\n", "Size", a.Size)
		fmt.Fprintf(w, "  %-10s %s\n", "SHA256", a.Hashes.SHA256)
		for _, c := range a.Validation {
			mark := st.Green("✓")
			if !c.Passed {
				mark = st.Red("✗")
			}
			d := ""
			if c.Detail != "" {
				d = st.Dim("  " + safe(c.Detail))
			}
			if verbose || !c.Passed {
				fmt.Fprintf(w, "  %s %s%s\n", mark, safe(c.Name), d)
			}
		}
		if !verbose {
			fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("%d validation checks passed (-v lists them)", len(a.Validation))))
		}
		if a.Comparison != nil {
			renderComparison(w, a.Comparison, verbose, st, "packed", "unpacked")
		}
		if a.Report != nil {
			fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Analysis of the unpacked layer")))
			renderReport(w, a.Report, verbose, st)
		}
	}
}

func renderComparison(w io.Writer, c *models.Comparison, verbose bool, st terminal.Style, nameA, nameB string) {
	fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Differences (%s -> %s)", nameA, nameB)))
	any := false
	line := func(label string, ch []models.Change) {
		for _, x := range ch {
			any = true
			fmt.Fprintf(w, "    %-26s %s  ->  %s\n", strings.TrimSpace(label+" "+safe(x.Field)), safe(x.A), safe(x.B))
		}
	}
	line("", c.Header)
	for _, sd := range c.SectionChanges {
		for _, x := range sd.Changes {
			any = true
			fmt.Fprintf(w, "    section %-14s %s: %s  ->  %s\n", safe(sd.Name), safe(x.Field), safe(x.A), safe(x.B))
		}
	}
	set := func(label string, d models.SetDiff, limit int) {
		show := func(side string, items []string) {
			if len(items) == 0 {
				return
			}
			any = true
			n := len(items)
			if !verbose && n > limit {
				items = items[:limit]
			}
			fmt.Fprintf(w, "    %-22s %s %d: %s", label, side, n, safe(strings.Join(items, ", ")))
			if n > len(items) {
				fmt.Fprintf(w, " … (+%d, use -v)", n-len(items))
			}
			fmt.Fprintln(w)
		}
		show("only in "+nameA, d.OnlyA)
		show("only in "+nameB, d.OnlyB)
	}
	set("sections", c.Sections, 12)
	set("libraries", c.Libraries, 12)
	set("imported functions", c.Imports, 8)
	set("exports", c.Exports, 8)
	set("capabilities", c.Capabilities, 12)
	set("indicators", c.Indicators, 6)
	line("entropy", c.Entropy)
	line("", c.Packing)
	line("fingerprint", c.Fingerprint)
	line("", c.Strings)
	if sm := c.Similarity; sm != nil {
		any = true
		var parts []string
		if sm.HasTLSH {
			parts = append(parts, fmt.Sprintf("TLSH distance %d (%s)", sm.TLSHDistance, similarity.TLSHLabel(sm.TLSHDistance)))
		}
		if sm.HasSSDeep {
			parts = append(parts, fmt.Sprintf("ssdeep %d (%s)", sm.SSDeepScore, similarity.SSDeepLabel(sm.SSDeepScore)))
		}
		if sm.HasOverlap {
			parts = append(parts, fmt.Sprintf("structural overlap %.2f", sm.Overlap))
		}
		if len(parts) == 0 {
			parts = append(parts, "not enough data to compare")
		}
		fmt.Fprintf(w, "    %-26s %s\n", "similarity", strings.Join(parts, "; "))
		if verbose {
			for _, comp := range sm.Components {
				fmt.Fprintf(w, "      %-12s %.3f (weight %.2f)  %s\n", comp.Name, comp.Score, comp.Weight, st.Dim(safe(comp.Note)))
			}
		}
		fmt.Fprintf(w, "    %s\n", st.Dim("measurements, not probabilities; none is evidence of a shared origin"))
	}
	for _, n := range c.Notes {
		fmt.Fprintf(w, "    %s\n", st.Dim(safe(n)))
	}
	if !any {
		fmt.Fprintf(w, "    %s\n", st.Dim("no differences found in the compared properties"))
	}
}

func renderYara(w io.Writer, a *models.Analysis, verbose bool, st terminal.Style) {
	for _, e := range a.Engines {
		line := e.Status
		switch e.Status {
		case "used":
			line = st.Green("used")
		case "missing", "skipped":
			line = st.Yellow(e.Status)
		case "failed":
			line = st.Red("failed")
		}
		v := ""
		if e.Version != "" {
			v = " " + e.Version
		}
		d := ""
		if e.Detail != "" {
			d = st.Dim("  " + safe(e.Detail))
		}
		fmt.Fprintf(w, "  %-10s %s%s: %s%s\n", "Engine", safe(e.Name), v, line, d)
	}
	if len(a.Yara) == 0 {
		return
	}
	fmt.Fprintf(w, "  %-10s %d rule(s) matched; only \"tested\" rules count as evidence\n", "YARA-X", len(a.Yara))
	for _, m := range a.Yara {
		tag := m.Status
		switch m.Status {
		case "tested":
			tag = st.Green(tag)
		default:
			tag = st.Yellow(tag)
		}
		off := ""
		if verbose && len(m.Matches) > 0 {
			off = st.Dim(fmt.Sprintf("  @0x%x", m.Matches[0].Offset))
		}
		fmt.Fprintf(w, "  %-10s · %s [%s] %s%s\n", "", safe(m.Rule), tag, safe(m.Description), off)
	}
}

func renderExtraction(w io.Writer, e *models.Extraction, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Extraction")))
	status := e.Status
	switch e.Status {
	case "extracted":
		status = st.Green(status)
	case "failed", "rejected":
		status = st.Red(status)
	default:
		status = st.Yellow(status)
	}
	fmt.Fprintf(w, "  %-10s %s\n", "Status", status)
	fmt.Fprintf(w, "  %-10s %s\n", "", safe(e.Message))
	fmt.Fprintf(w, "  %-10s %s\n", "Supported", st.Dim(strings.Join(e.Supported, ", ")+" (no other container is extracted)"))
	if e.Status != "extracted" {
		return
	}
	fmt.Fprintf(w, "  %-10s %s, archive at file offset 0x%x, %d bytes\n", "Archive", safe(e.ArchiveFormat), e.ArchiveOffset, e.ArchiveLength)
	fmt.Fprintf(w, "  %-10s %s %s\n", "Output", safe(e.Dir), st.Dim("(files mode 0600, never executed)"))
	for _, n := range e.Notes {
		fmt.Fprintf(w, "  %-10s %s\n", "Note", st.Dim(safe(n)))
	}
	fmt.Fprintf(w, "\n  %-11s %-44s %10s  %-14s %s\n", "type", "entry", "size", "content", "sha256")
	shown := 0
	skipped := 0
	for _, en := range e.Entries {
		if en.Skipped != "" {
			skipped++
			continue
		}
		if !verbose && shown >= 15 {
			continue
		}
		shown++
		hash := en.SHA256
		if len(hash) > 12 {
			hash = hash[:12]
		}
		fmt.Fprintf(w, "  %-11s %-44s %10d  %-14s %s  %s\n", safe(en.TypeName), clip(safe(en.Name), 44), en.Size, clip(safe(en.Format), 14), hash, st.Dim(fmt.Sprintf("@0x%x", en.Offset)))
	}
	if total := len(e.Entries) - skipped; total > shown {
		fmt.Fprintf(w, "  … %d more (use -v)\n", total-shown)
	}
	if skipped > 0 {
		fmt.Fprintf(w, "\n  %s\n", st.Bold(fmt.Sprintf("Skipped entries (%d)", skipped)))
		for _, en := range e.Entries {
			if en.Skipped != "" {
				fmt.Fprintf(w, "  %s %s: %s\n", st.Yellow("!"), clip(safe(en.Name), 50), safe(en.Skipped))
			}
		}
	}
}

func renderKnown(w io.Writer, k *models.KnownSample, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Seen before")))
	fmt.Fprintf(w, "  %-10s first seen %s, analysed %d time(s) before, last on %s\n", "History", k.FirstSeen, k.TimesSeen, k.LastSeen)
	if l := k.Last; l != nil {
		line := fmt.Sprintf("UNPACKR %s (%s): packing %s", safe(l.ToolVersion), safe(l.Profile), safe(orDash(l.PackingState)))
		if l.PackingFamily != "" {
			line += " (" + safe(l.PackingFamily) + ")"
		}
		if l.Language != "" {
			line += ", " + safe(l.Language)
		}
		fmt.Fprintf(w, "  %-10s %s; %d findings (%d high, %d medium)\n", "Last time", line, l.Findings, l.High, l.Medium)
	}
	if len(k.Cases) > 0 {
		fmt.Fprintf(w, "  %-10s %s\n", "Cases", safe(strings.Join(k.Cases, ", ")))
	}
	if k.ToolChange != "" {
		fmt.Fprintf(w, "  %-10s %s %s\n", "Tool", safe(k.ToolChange), st.Dim("(results may differ because the analysis changed, not the file)"))
	}
	if k.Changes != nil {
		any := len(k.Changes.Packing)+len(k.Changes.Fingerprint)+len(k.Changes.Capabilities.OnlyA)+len(k.Changes.Capabilities.OnlyB)+len(k.Changes.Indicators.OnlyA)+len(k.Changes.Indicators.OnlyB) > 0
		if !any {
			fmt.Fprintf(w, "  %-10s %s\n", "Changes", st.Dim("no change in packing, fingerprint, capabilities or indicators since last time"))
		} else {
			renderComparison(w, k.Changes, verbose, st, "before", "now")
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// head shortens s to at most n runes, marking the cut.
func head(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func renderDotNet(w io.Writer, dn *models.DotNet, verbose bool, st terminal.Style) {
	fmt.Fprintf(w, "\n  %s\n", st.Bold(".NET assembly"))
	id := safe(dn.AssemblyName)
	if dn.AssemblyVersion != "" {
		id += " " + safe(dn.AssemblyVersion)
	}
	fmt.Fprintf(w, "  %-12s %s   metadata %s   %s\n", "Assembly", id, safe(dn.MetadataVersion), safe(strings.Join(dn.Flags, ", ")))
	fmt.Fprintf(w, "  %-12s %d types, %d methods, %d fields, %d member references, %d P/Invoke declarations, %d resources\n", "Contents",
		dn.Counts["TypeDef"], dn.Counts["MethodDef"], dn.Counts["Field"], dn.Counts["MemberRef"], len(dn.PInvokes), len(dn.Resources))
	if dn.Names.Total > 0 {
		fmt.Fprintf(w, "  %-12s %d names: %d unreadable, %d of one or two characters\n", "Names", dn.Names.Total, dn.Names.NonPrintable, dn.Names.Tiny)
	}
	limit := 8
	if verbose {
		limit = 1 << 30
	}
	if len(dn.AssemblyRefs) > 0 {
		fmt.Fprintf(w, "  %-12s", "References")
		for i, r := range dn.AssemblyRefs {
			if i >= limit {
				fmt.Fprintf(w, " … %d more", len(dn.AssemblyRefs)-i)
				break
			}
			fmt.Fprintf(w, " %s;", safe(r))
		}
		fmt.Fprintln(w)
	}
	for i, p := range dn.PInvokes {
		if i >= limit {
			fmt.Fprintf(w, "  %-12s … %d more\n", "", len(dn.PInvokes)-i)
			break
		}
		fmt.Fprintf(w, "  %-12s %s!%s\n", "P/Invoke", safe(p.Module), safe(p.Function))
	}
	for i, r := range dn.Resources {
		if i >= limit {
			break
		}
		kind := r.Kind
		if kind == "" {
			kind = "data"
		}
		fmt.Fprintf(w, "  %-12s %s (%d bytes, %s, entropy %.2f)\n", "Resource", safe(clip(r.Name, 48)), r.Size, kind, r.Entropy)
	}
}
