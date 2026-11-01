package reporting

import (
	"fmt"
	"html/template"
	"io"
	"reflect"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func sanitizedCase(c *models.CaseReport) *models.CaseReport {
	out := reflect.New(reflect.TypeOf(*c))
	copyValue(out.Elem(), reflect.ValueOf(*c), safeText)
	return out.Interface().(*models.CaseReport)
}

// Case writes an investigation report in html, markdown or csv (csv is the
// shared-indicator table).
func Case(w io.Writer, format string, c *models.CaseReport) error {
	switch format {
	case "html":
		return caseTmpl.ExecuteTemplate(w, "casepage", struct {
			C          *models.CaseReport
			Tool, Plat string
		}{sanitizedCase(c), version.Version, version.Platform()})
	case "markdown":
		return caseMarkdown(w, sanitizedCase(c))
	case "csv":
		return caseCSV(w, c)
	}
	return fmt.Errorf("unsupported report format %q", format)
}

func caseMarkdown(w io.Writer, c *models.CaseReport) error {
	m := &mdw{w: w}
	m.p("# Case %s\n\n", mdText(c.Name))
	m.p("*UNPACKR %s. Status: %s. Opened %s. Generated %s. Static analysis only; network text is defanged.*\n\n", version.Version, mdText(c.Status), mdText(c.CreatedAt), mdText(c.Generated))
	if c.Description != "" {
		m.p("%s\n\n", mdText(c.Description))
	}
	m.p("## Samples (%d)\n\n", len(c.Samples))
	var rows [][]string
	for _, s := range c.Samples {
		rows = append(rows, []string{mdCell(s.Name), mdCode(s.SHA256), mdCell(s.Format), mdCell(s.Packing), mdCell(s.Language), fmt.Sprint(s.High), fmt.Sprint(s.Medium), mdCell(s.LastSeen)})
	}
	m.table([]string{"File", "SHA-256", "Format", "Packing", "Language", "High", "Medium", "Last analysed"}, rows)
	m.p("## Indicators shared across the case\n\n")
	rows = nil
	for _, i := range c.Indicators {
		rows = append(rows, []string{mdCell(i.Type), mdCode(Defang(i.Type, i.Value)), fmt.Sprint(len(i.Samples))})
	}
	if len(rows) == 0 {
		m.p("None recorded.\n\n")
	}
	m.table([]string{"Type", "Value (defanged)", "Samples"}, rows)
	m.p("## Notes\n\n")
	if len(c.Notes) == 0 {
		m.p("None.\n\n")
	}
	for _, n := range c.Notes {
		about := ""
		if n.SHA256 != "" {
			about = " (" + mdCode(n.SHA256[:min(12, len(n.SHA256))]) + ")"
		}
		m.p("- **%s**%s: %s\n", mdText(n.At), about, mdText(n.Body))
	}
	m.p("\n## Timeline\n\n")
	rows = nil
	for _, e := range c.Timeline {
		sha := ""
		if e.SHA256 != "" {
			sha = mdCode(e.SHA256[:min(12, len(e.SHA256))])
		}
		rows = append(rows, []string{mdCell(e.At), mdCell(e.Kind), sha, mdCell(e.Detail)})
	}
	m.table([]string{"When (UTC)", "Event", "Sample", "Detail"}, rows)
	return m.err
}

func caseCSV(w io.Writer, c *models.CaseReport) error {
	c = sanitizedCaseRaw(c)
	var sb strings.Builder
	sb.WriteString("type,value,defanged,samples\n")
	for _, i := range c.Indicators {
		fmt.Fprintf(&sb, "%s,%s,%s,%d\n", csvQuote(i.Type), csvQuote(i.Value), csvQuote(Defang(i.Type, i.Value)), len(i.Samples))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

func sanitizedCaseRaw(c *models.CaseReport) *models.CaseReport {
	out := reflect.New(reflect.TypeOf(*c))
	copyValue(out.Elem(), reflect.ValueOf(*c), func(s string) string { return csvCellSafe(s) })
	return out.Interface().(*models.CaseReport)
}

func csvCellSafe(s string) string { return csvCell(s) }

func csvQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

var caseTmpl = template.Must(template.New("case").Funcs(template.FuncMap{
	"defang": Defang,
	"short":  func(s string) string { return s[:min(12, len(s))] },
}).Parse(`{{define "casepage"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>UNPACKR case: {{.C.Name}}</title><style>` + cssBlock + `</style></head><body>
<header class="top"><div class="wrap"><h1>UNPACKR <span class="tag">Know What's Inside.</span></h1>
<div class="tag">Case report &middot; UNPACKR {{.Tool}} &middot; {{.Plat}} &middot; {{.C.Generated}}</div></div></header>
<main class="wrap">
<section><h2>Case {{.C.Name}} <span class="chip">{{.C.Status}}</span></h2><p>{{.C.Description}}</p><p class="note">Opened {{.C.CreatedAt}}. Static analysis only: no sample was executed. Network indicators are defanged.</p></section>
<section><h2>Samples ({{len .C.Samples}})</h2>
<table><tr><th>File</th><th>SHA-256</th><th>Format</th><th>Packing</th><th>Language</th><th>High</th><th>Medium</th><th>Last analysed</th></tr>
{{range .C.Samples}}<tr><td>{{.Name}}</td><td class="mono">{{.SHA256}}</td><td>{{.Format}}</td><td>{{.Packing}}</td><td>{{.Language}}</td><td>{{.High}}</td><td>{{.Medium}}</td><td>{{.LastSeen}}</td></tr>{{end}}</table></section>
<section><h2>Indicators</h2>{{if not .C.Indicators}}<p>None recorded.</p>{{else}}
<p class="note">Strings found in the samples; presence does not show use or contact. Values shared by several samples are the useful ones.</p>
<table><tr><th>Type</th><th>Value (defanged)</th><th>Samples</th></tr>{{range .C.Indicators}}<tr><td>{{.Type}}</td><td class="mono">{{defang .Type .Value}}</td><td>{{len .Samples}}</td></tr>{{end}}</table>{{end}}</section>
<section><h2>Notes</h2>{{if not .C.Notes}}<p>None.</p>{{end}}<ul class="tight">{{range .C.Notes}}<li><strong>{{.At}}</strong>{{if .SHA256}} <span class="mono">{{short .SHA256}}</span>{{end}}: {{.Body}}</li>{{end}}</ul></section>
<section><h2>Timeline</h2><table><tr><th>When (UTC)</th><th>Event</th><th>Sample</th><th>Detail</th></tr>
{{range .C.Timeline}}<tr><td>{{.At}}</td><td>{{.Kind}}</td><td class="mono">{{if .SHA256}}{{short .SHA256}}{{end}}</td><td>{{.Detail}}</td></tr>{{end}}</table></section>
</main><footer class="wrap">Generated by UNPACKR {{.Tool}}. Self-contained; no network requests.</footer></body></html>{{end}}`))
