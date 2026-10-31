package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func safe(s string) string { return terminal.Sanitize(s) }

// renderReport prints one report in the human-readable layout. Every string
// that originates from the sample passes through Sanitize.
func renderReport(w io.Writer, r *models.Report, verbose bool, st terminal.Style) {
	h := func(t string) { fmt.Fprintf(w, "\n%s\n", st.Bold(st.Cyan(t))) }
	kv := func(k, v string) { fmt.Fprintf(w, "  %-10s %s\n", k, v) }

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
