package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

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

	if r.Binary != nil {
		renderBinary(w, r.Binary, verbose, st)
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
	fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan("Stage 02 · Executable structure")))
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
