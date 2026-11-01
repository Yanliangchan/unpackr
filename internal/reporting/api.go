package reporting

import (
	"fmt"
	"html/template"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Formats are the report formats this package can write.
var Formats = []string{"html", "markdown", "csv"}

// Valid reports whether f is a supported report format.
func Valid(f string) bool {
	for _, x := range Formats {
		if x == f {
			return true
		}
	}
	return false
}

// Single writes the report for one file. CSV is the indicator list.
func Single(w io.Writer, format string, r *models.Report) error {
	switch format {
	case "html":
		return HTML(w, r)
	case "markdown":
		return Markdown(w, r)
	case "csv":
		return IOCsv(w, []*models.Report{r})
	}
	return fmt.Errorf("unsupported report format %q", format)
}

func sanitizeAll(reps []*models.Report, defang bool) []*models.Report {
	out := make([]*models.Report, len(reps))
	for i, r := range reps {
		out[i] = sanitized(r, defang)
	}
	return out
}

type batchData struct {
	Tool, Plat string
	Now        string
	Rows       []SummaryRow
	Pages      []page
}

// Batch writes a consolidated report for several files. CSV is the summary
// table; use Single with CSV per file for indicators.
func Batch(w io.Writer, format string, reps []*models.Report, errs map[string]string) error {
	reps = sanitizeAll(reps, format != "csv")
	errs = sanitizeErrs(errs, format != "csv")
	switch format {
	case "html":
		d := batchData{Tool: version.Version, Plat: version.Platform(), Now: time.Now().UTC().Format("2006-01-02 15:04:05 MST"), Rows: rows(reps, errs)}
		for _, r := range reps {
			d.Pages = append(d.Pages, page{R: r, Tool: d.Tool, Plat: d.Plat})
		}
		return tmpl.ExecuteTemplate(w, "bpage", d)
	case "markdown":
		m := &mdw{w: w}
		m.p("# UNPACKR batch report\n\n*Static analysis of %d file(s). UNPACKR %s, %s. No sample was executed.*\n\n", len(reps)+len(errs), version.Version, version.Platform())
		var tr [][]string
		for _, r := range rows(reps, errs) {
			if r.Error != "" {
				tr = append(tr, []string{mdCell(r.Name), "", "", "", "", "", "", "", "", "", "ERROR: " + mdCell(r.Error)})
				continue
			}
			tr = append(tr, []string{mdCell(r.Name), mdCode(r.SHA256), mdCell(r.Format), mdCell(r.Packing), mdCell(r.Language), fmt.Sprint(r.High), fmt.Sprint(r.Medium), fmt.Sprint(r.Capabilities), fmt.Sprint(r.Indicators), fmt.Sprint(r.Anomalies), ""})
		}
		m.table([]string{"File", "SHA-256", "Format", "Packing", "Language", "High", "Medium", "Capabilities", "Indicators", "Anomalies", "Error"}, tr)
		for _, r := range reps {
			m.p("## %s\n\n", mdText(r.File.Name))
			for _, s := range Summary(r) {
				m.p("- %s\n", mdText(s))
			}
			m.p("\n")
		}
		return m.err
	case "csv":
		return SummaryCSV(w, reps, errs)
	}
	return fmt.Errorf("unsupported report format %q", format)
}

type compareData struct {
	Tool, Plat    string
	Now           string
	First, Second *models.Report
	C             *models.Comparison
}

// Compare writes a comparison of two analysed files.
func Compare(w io.Writer, format string, first, second *models.Report, c *models.Comparison) error {
	first, second, c = sanitized(first, format != "csv"), sanitized(second, format != "csv"), sanitizedComparison(c, format != "csv")
	switch format {
	case "html":
		return tmpl.ExecuteTemplate(w, "cpage", compareData{Tool: version.Version, Plat: version.Platform(), Now: time.Now().UTC().Format("2006-01-02 15:04:05 MST"), First: first, Second: second, C: c})
	case "markdown":
		m := &mdw{w: w}
		m.p("# UNPACKR comparison\n\n*Static analysis. UNPACKR %s, %s. No sample was executed.*\n\n", version.Version, version.Platform())
		m.table([]string{"", "Name", "SHA-256", "Size"}, [][]string{
			{"First", mdCell(first.File.Name), mdCode(first.File.Hashes.SHA256), fmt.Sprint(first.File.Size)},
			{"Second", mdCell(second.File.Name), mdCode(second.File.Hashes.SHA256), fmt.Sprint(second.File.Size)},
		})
		if c.Identical {
			m.p("The files are byte-for-byte identical (same SHA-256).\n\n")
		}
		mdComparison(m, c, 2)
		return m.err
	case "csv":
		return SummaryCSV(w, []*models.Report{first, second}, nil)
	}
	return fmt.Errorf("unsupported report format %q", format)
}

func init() {
	template.Must(tmpl.Parse(htmlExtra))
}

const htmlExtra = `{{define "bpage"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>UNPACKR batch report</title><style>` + cssBlock + `</style></head><body>
<header class="top"><div class="wrap"><h1>UNPACKR <span class="tag">Know What's Inside.</span></h1>
<div class="tag">Batch report &middot; UNPACKR {{.Tool}} &middot; {{.Plat}} &middot; offline &middot; {{.Now}}</div></div></header>
<main class="wrap"><section><h2>Summary ({{len .Rows}} files)</h2>
<p class="note">Static analysis only: no sample was executed. Per-file detail is in the JSON reports (--output-dir) or in a single-file HTML report.</p>
<table><tr><th>File</th><th>SHA-256</th><th>Format</th><th>Packing</th><th>Language</th><th>High</th><th>Medium</th><th>Capabilities</th><th>Indicators</th><th>Anomalies</th></tr>
{{range .Rows}}<tr><td>{{clean .Name}}</td>{{if .Error}}<td colspan="9" class="sev-high">error: {{clean .Error}}</td>{{else}}<td class="mono">{{short .SHA256}}</td><td>{{clean .Format}}</td><td>{{clean .Packing}}</td><td>{{clean .Language}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.Capabilities}}</td><td>{{.Indicators}}</td><td>{{.Anomalies}}</td>{{end}}</tr>{{end}}</table></section>
{{range .Pages}}<section><details><summary>{{clean .R.File.Name}}</summary><ul class="tight">{{range .Summary}}<li>{{.}}</li>{{end}}</ul></details></section>{{end}}
</main><footer class="wrap">Generated by UNPACKR {{.Tool}}. Self-contained; no network requests.</footer></body></html>{{end}}

{{define "cpage"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>UNPACKR comparison</title><style>` + cssBlock + `</style></head><body>
<header class="top"><div class="wrap"><h1>UNPACKR <span class="tag">Know What's Inside.</span></h1>
<div class="tag">Comparison &middot; UNPACKR {{.Tool}} &middot; {{.Plat}} &middot; offline &middot; {{.Now}}</div></div></header>
<main class="wrap"><section><h2>Files</h2>
<table><tr><th></th><th>Name</th><th>SHA-256</th><th>Size</th></tr>
<tr><td>First</td><td>{{clean .First.File.Name}}</td><td class="mono">{{.First.File.Hashes.SHA256}}</td><td>{{.First.File.Size}}</td></tr>
<tr><td>Second</td><td>{{clean .Second.File.Name}}</td><td class="mono">{{.Second.File.Hashes.SHA256}}</td><td>{{.Second.File.Size}}</td></tr></table>
{{if .C.Identical}}<p>The files are byte-for-byte identical (same SHA-256).</p>{{end}}</section>
<section><h2>Differences</h2>{{template "cmp" .C}}</section></main>
<footer class="wrap">Generated by UNPACKR {{.Tool}}. Static analysis; self-contained; no network requests.</footer></body></html>{{end}}`

// extFormat maps a file extension to a report format.
func ExtFormat(path string) (string, bool) {
	l := strings.ToLower(path)
	switch {
	case strings.HasSuffix(l, ".html"), strings.HasSuffix(l, ".htm"):
		return "html", true
	case strings.HasSuffix(l, ".md"), strings.HasSuffix(l, ".markdown"):
		return "markdown", true
	case strings.HasSuffix(l, ".csv"):
		return "csv", true
	}
	return "", false
}

func sanitizeErrs(errs map[string]string, defang bool) map[string]string {
	out := make(map[string]string, len(errs))
	for k, v := range errs {
		if defang {
			out[safeText(k)] = safeText(v)
		} else {
			out[k] = v
		}
	}
	return out
}

// sanitizedComparison copies a comparison through the same string filter as a
// report by wrapping it in a throwaway report-shaped value.
func sanitizedComparison(c *models.Comparison, defang bool) *models.Comparison {
	fn := safeText
	if !defang {
		fn = func(s string) string { return s }
	}
	out := reflect.New(reflect.TypeOf(*c))
	copyValue(out.Elem(), reflect.ValueOf(*c), fn)
	return out.Interface().(*models.Comparison)
}

// Sanitized returns a deep copy of r that is safe to print to a terminal:
// control and escape bytes are made visible and bidirectional overrides are
// neutralised. With defang, network-looking text is also defanged. The
// original report is not modified.
func Sanitized(r *models.Report, defang bool) *models.Report { return sanitized(r, defang) }
