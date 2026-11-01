package reporting

import (
	"fmt"
	"html/template"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MaxHTMLStrings bounds the strings table; the JSON report has the full sample.
const MaxHTMLStrings = 500

var reAttack = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

type page struct {
	R      *models.Report
	P      string // id prefix so nested reports do not collide
	Nested bool
	Tool   string
	Plat   string
}

func (p page) Summary() []string               { return Summary(p.R) }
func (p page) Recs() []string                  { return Recommendations(p.R) }
func (p page) Counts() map[models.Severity]int { return SeverityCounts(p.R) }
func (p page) Strings() []models.StringHit {
	if p.R.Analysis == nil {
		return nil
	}
	s := p.R.Analysis.Strings.Shown
	if len(s) > MaxHTMLStrings {
		s = s[:MaxHTMLStrings]
	}
	return s
}
func (p page) Nest(r *models.Report) page {
	return page{R: r, P: p.P + "n-", Nested: true, Tool: p.Tool, Plat: p.Plat}
}

var funcs = template.FuncMap{
	"clean":  clean,
	"defang": Defang,
	"hex":    func(v uint64) string { return fmt.Sprintf("0x%x", v) },
	"hex64":  func(v int64) string { return fmt.Sprintf("0x%x", v) },
	"join":   strings.Join,
	"lower":  strings.ToLower,
	"add":    func(a, b int) int { return a + b },
	"sev":    func(s models.Severity) string { return string(s) },
	"conf":   func(c models.Confidence) string { return string(c) },
	"attack": func(id string) bool { return reAttack.MatchString(id) },
	"offset": func(l models.Location) string {
		if l.Offset == nil {
			return ""
		}
		return fmt.Sprintf("0x%x", *l.Offset)
	},
	"short": func(s string) string {
		if len(s) > 16 {
			return s[:16]
		}
		return s
	},
	"sorted": func(m map[string]string) []string {
		k := make([]string, 0, len(m))
		for key := range m {
			k = append(k, key)
		}
		sort.Strings(k)
		return k
	},
	"ev": func(r *models.Report, id string) models.Evidence {
		for _, e := range r.Evidence {
			if e.ID == id {
				return e
			}
		}
		return models.Evidence{ID: id}
	},
	"deref":   func(p *int64) int64 { return *p },
	"derefF":  func(p *float64) float64 { return *p },
	"attr":    func(b *models.Binary, k string) string { return b.Attributes[k] },
	"replace": func(s, old, new string) string { return strings.ReplaceAll(s, old, new) },
	"dict2":   func(name string, set models.SetDiff) map[string]any { return map[string]any{"Name": name, "Set": set} },
	"hypsArg": func(p string, hs []models.Hypothesis) map[string]any { return map[string]any{"P": p, "H": hs} },
	"importTotal": func(b *models.Binary) int {
		n := 0
		for _, im := range b.Imports {
			n += len(im.Functions)
		}
		return n
	},
	"pct": func(a, b int64) int {
		if b == 0 {
			return 0
		}
		return int(a * 100 / b)
	},
}

var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(htmlPage + htmlBody))

// HTML writes a complete, self-contained report. It makes no network
// requests, runs no script, and loads no external resources.
func HTML(w io.Writer, r *models.Report) error {
	r = sanitized(r, true)
	return tmpl.ExecuteTemplate(w, "page", page{R: r, Tool: version.Version, Plat: version.Platform()})
}

const cssBlock = `
:root{--bg:#f7f8fa;--card:#fff;--ink:#1c2230;--muted:#5b6578;--line:#dfe3ea;--accent:#1d5fd1;--high:#b3261e;--med:#9a5b00;--low:#2b6a2b;--info:#4a5568;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#10141c;--card:#171c27;--ink:#e6e9f0;--muted:#9aa4b8;--line:#2a3243;--accent:#7aa7ff;--high:#ff8a80;--med:#ffc266;--low:#8fd18f;--info:#aab4c8;--chip:#222a3a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow-wrap:anywhere}
header.top{padding:20px 16px;border-bottom:1px solid var(--line);background:var(--card)}
.wrap{max-width:1100px;margin:0 auto;padding:0 16px}
h1{margin:0;font-size:22px;letter-spacing:.04em}
.tag{color:var(--muted);font-size:13px}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;margin:10px 0 0;font-size:13px}
nav a{color:var(--accent);text-decoration:none}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:16px 0;padding:14px 16px}
section.nested{border-left:4px solid var(--accent)}
h2{font-size:17px;margin:0 0 10px}
h3{font-size:14px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
table{border-collapse:collapse;width:100%;font-size:13px;display:block;overflow-x:auto}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{font-weight:600;color:var(--muted);white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.chip{display:inline-block;padding:1px 8px;border-radius:10px;background:var(--chip);font-size:12px;margin:0 4px 2px 0}
.sev-high{color:var(--high);font-weight:600}.sev-medium{color:var(--med);font-weight:600}.sev-low{color:var(--low)}.sev-informational{color:var(--info)}
.conf-definitive,.conf-high{color:var(--low);font-weight:600}.conf-medium{color:var(--med)}.conf-low,.conf-speculative{color:var(--muted)}
.state{display:inline-block;padding:2px 10px;border-radius:4px;font-weight:600;background:var(--chip)}
.note{color:var(--muted);font-size:13px}
.warn{border-left:3px solid var(--med);padding:4px 10px;background:var(--chip);margin:6px 0}
details{margin:6px 0}summary{cursor:pointer;color:var(--accent)}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:0}dl.kv dt{color:var(--muted)}dl.kv dd{margin:0;word-break:break-all}
ul.tight{margin:4px 0 4px 18px;padding:0}
footer{color:var(--muted);font-size:12px;padding:10px 0 30px}
@media print{body{background:#fff;color:#000;font-size:11pt}header.top,section{background:#fff;border-color:#bbb}nav{display:none}section{break-inside:avoid-page}a{color:#000;text-decoration:none}details>summary{display:none}table{display:table}}
`

const htmlPage = `{{define "page"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="generator" content="UNPACKR {{.Tool}}">
<title>UNPACKR report: {{clean .R.File.Name}}</title>
<style>` + cssBlock + `</style></head><body>
<header class="top"><div class="wrap">
<h1>UNPACKR <span class="tag">Know What's Inside.</span></h1>
<div class="tag">Static analysis report &middot; UNPACKR {{.Tool}} &middot; {{.Plat}} &middot; offline &middot; schema {{.R.SchemaVersion}} &middot; {{.R.StartedAt.Format "2006-01-02 15:04:05 MST"}} &middot; profile {{.R.Profile}}</div>
<nav><a href="#summary">Summary</a><a href="#file">File</a><a href="#fingerprint">Fingerprint</a><a href="#packing">Packing</a><a href="#structure">Structure</a><a href="#capabilities">Capabilities</a><a href="#anomalies">Anomalies</a><a href="#indicators">Indicators</a><a href="#payloads">Payloads</a><a href="#findings">Findings</a><a href="#evidence">Evidence</a><a href="#recommendations">Recommendations</a><a href="#limits">Limits</a></nav>
</div></header>
<main class="wrap">{{template "body" .}}</main>
<footer class="wrap">Generated by UNPACKR {{.Tool}}. Static analysis: the sample was never executed. This file is self-contained and makes no network requests.</footer>
</body></html>{{end}}`

const htmlBody = `{{define "body"}}{{$p := .P}}{{$r := .R}}
<section id="{{$p}}summary"{{if .Nested}} class="nested"{{end}}>
<h2>{{if .Nested}}Unpacked layer: {{clean $r.File.Name}}{{else}}Executive summary{{end}}</h2>
<ul class="tight">{{range .Summary}}<li>{{.}}</li>{{end}}</ul>
<p>{{range $k, $v := .Counts}}<span class="chip sev-{{sev $k}}">{{$v}} {{sev $k}}</span>{{end}}</p>
</section>

<section id="{{$p}}file"><h2>File metadata and hashes</h2>
<dl class="kv">
<dt>Name</dt><dd>{{clean $r.File.Name}}</dd>
<dt>Size</dt><dd>{{$r.File.Size}} bytes</dd>
<dt>SHA-256</dt><dd class="mono">{{$r.File.Hashes.SHA256}}</dd>
<dt>SHA-1</dt><dd class="mono">{{$r.File.Hashes.SHA1}}</dd>
<dt>MD5</dt><dd class="mono">{{$r.File.Hashes.MD5}}</dd>
{{with $r.Binary}}{{if .ImportHash}}<dt>Import hash</dt><dd class="mono">{{.ImportHash}}</dd>{{end}}{{end}}
</dl>
{{with $r.Identification}}
<h3>Format identification</h3>
<p>Primary: <strong>{{clean .Primary}}</strong>{{if .Polyglot}} <span class="warn">satisfies more than one format family</span>{{end}}. The score is structural validity out of 100, not a probability.</p>
<details><summary>{{len .Candidates}} candidate(s) with the checks behind them</summary>
<table><tr><th>Format</th><th>Score</th><th>Checks</th></tr>
{{range .Candidates}}<tr><td>{{clean .Format}}</td><td>{{.Score}}</td><td>{{range .Checks}}<span class="chip">{{if .Passed}}pass{{else}}fail{{end}}: {{clean .Name}} @ {{hex64 .Offset}}</span>{{end}}</td></tr>{{end}}
</table></details>{{end}}
</section>

{{with $r.Analysis}}
<section id="{{$p}}fingerprint"><h2>Technical fingerprint</h2>
<p class="note">Ranked hypotheses with the signals behind each. C and C++ binaries from the same toolchain cannot always be told apart, so both stay listed.</p>
<h3>Language</h3>{{template "hyps" hypsArg $p .Fingerprint.Languages}}
<h3>Compiler</h3>{{template "hyps" hypsArg $p .Fingerprint.Compilers}}
<h3>Runtime</h3>{{template "hyps" hypsArg $p .Fingerprint.Runtimes}}
</section>

<section id="{{$p}}packing"><h2>Packing and obfuscation</h2>
<p><span class="state">{{.Packing.State}}</span>{{if .Packing.Family}} <strong>{{clean .Packing.Family}}</strong>{{end}} <span class="conf-{{conf .Packing.Confidence}}">{{conf .Packing.Confidence}} confidence</span></p>
<p class="note">{{clean .Packing.Rationale}}</p>
{{range .Packing.Notes}}<p class="warn">{{clean .}}</p>{{end}}
{{if .Packing.Signals}}<table><tr><th>Strength</th><th>Signal</th><th>Evidence</th></tr>
{{range .Packing.Signals}}<tr><td>{{.Strength}}</td><td>{{clean .Detail}}</td><td>{{range .Evidence}}<a href="#{{$p}}ev-{{.}}">{{.}}</a> {{end}}</td></tr>{{end}}</table>{{end}}
<h3>Entropy (bits per byte)</h3>
<p>Whole file {{printf "%.3f" .Entropy.File}}{{with .Entropy.Overlay}}, overlay {{printf "%.3f" (derefF .)}}{{end}}. Entropy is a measurement; compressed, encrypted and legitimate data all score high, and it never decides a packing verdict alone.</p>
{{if .Entropy.Sections}}<table><tr><th>Section</th><th>Entropy</th><th>Permissions</th><th>Raw offset</th><th>Bytes</th></tr>
{{range .Entropy.Sections}}<tr><td>{{clean .Name}}</td><td>{{printf "%.3f" .Entropy}}</td><td>{{.Perms}}</td><td>{{hex .Offset}}</td><td>{{.Size}}</td></tr>{{end}}</table>{{end}}
</section>
{{end}}

{{with $r.Binary}}
<section id="{{$p}}structure"><h2>File structure</h2>
<dl class="kv"><dt>Format</dt><dd>{{clean .Format}}, {{clean .Arch}}, {{.Bits}}-bit, {{.Endian}}-endian, {{.Kind}}</dd>
{{with .Entry}}<dt>Entry point</dt><dd>RVA {{hex .RVA}}, VA {{hex .VA}}{{if .Section}} in {{clean .Section}}{{else}} <span class="warn">not inside any section</span>{{end}}{{if .FileOffset}}, file offset {{hex64 (deref .FileOffset)}}{{end}}</dd>{{end}}
{{if .CompiledAt}}<dt>Header timestamp</dt><dd>{{.CompiledAt}} <span class="note">(a header value; easily forged)</span></dd>{{end}}
{{with .Overlay}}<dt>Overlay</dt><dd>{{.Size}} bytes at file offset {{hex64 .Offset}}</dd>{{end}}
{{range sorted .Attributes}}<dt>{{clean .}}</dt><dd>{{clean (attr $.R.Binary .)}}</dd>{{end}}
</dl>
{{if .Sections}}<h3>Sections</h3><table><tr><th>Name</th><th>Virtual address</th><th>Virtual size</th><th>Raw offset</th><th>Raw size</th><th>Permissions</th></tr>
{{range .Sections}}<tr><td>{{clean .Name}}</td><td>{{hex .VirtualAddress}}</td><td>{{hex .VirtualSize}}</td><td>{{hex .RawOffset}}</td><td>{{hex .RawSize}}</td><td{{if eq .Perms "rwx"}} class="sev-high"{{end}}>{{.Perms}}</td></tr>{{end}}</table>{{end}}
{{if .Segments}}<h3>Segments (loader view)</h3><table><tr><th>Name</th><th>Virtual address</th><th>Virtual size</th><th>Raw offset</th><th>Raw size</th><th>Permissions</th></tr>
{{range .Segments}}<tr><td>{{clean .Name}}</td><td>{{hex .VirtualAddress}}</td><td>{{hex .VirtualSize}}</td><td>{{hex .RawOffset}}</td><td>{{hex .RawSize}}</td><td>{{.Perms}}</td></tr>{{end}}</table>{{end}}
{{if .Libraries}}<h3>Linked libraries</h3><p>{{range .Libraries}}<span class="chip">{{clean .}}</span>{{end}}</p>{{end}}
{{if .Imports}}<h3>Imports ({{importTotal .}} symbols from {{len .Imports}} libraries)</h3>
{{range .Imports}}<details><summary>{{clean .Library}} ({{len .Functions}}){{if .Delay}} delay-load{{end}}</summary><p class="mono">{{range .Functions}}{{if .ByOrdinal}}#{{.Ordinal}}{{else}}{{clean .Name}}{{end}}<br>{{end}}</p></details>{{end}}{{end}}
{{if .Exports}}<h3>Exports ({{len .Exports}})</h3><details><summary>show</summary><table><tr><th>Name</th><th>Ordinal</th><th>RVA</th></tr>{{range .Exports}}<tr><td>{{clean .Name}}{{if .Forwarder}} &rarr; {{clean .Forwarder}}{{end}}</td><td>{{.Ordinal}}</td><td>{{hex .RVA}}</td></tr>{{end}}</table></details>{{end}}
{{if .Anomalies}}<h3>Parser anomalies</h3><ul class="tight">{{range .Anomalies}}<li>{{clean .}}</li>{{end}}</ul>{{end}}
</section>
{{end}}

{{with $r.Analysis}}
<section id="{{$p}}capabilities"><h2>Capabilities (inferred)</h2>
<p class="warn">Inferred from what the file references. The sample was not executed, so nothing here is observed behaviour. An imported API shows the file may ask for something, not that the code runs, reaches it, or succeeds.</p>
{{if not .Capabilities}}<p>None inferred.</p>{{end}}
{{range .Capabilities}}<details open><summary><strong>{{clean .Name}}</strong> &middot; {{clean .Category}} &middot; <span class="conf-{{conf .Confidence}}">{{conf .Confidence}} confidence</span> &middot; severity if true <span class="sev-{{sev .Severity}}">{{sev .Severity}}</span></summary>
<p>{{clean .Summary}}</p>
{{if .Attack}}<p>ATT&amp;CK: {{range .Attack}}{{if attack .}}<a href="https://attack.mitre.org/techniques/{{replace . "." "/"}}/" rel="noopener noreferrer">{{.}}</a> {{end}}{{end}}</p>{{end}}
{{if .Chain}}<table><tr><th>Stage</th><th>APIs</th><th>Source</th></tr>{{range .Chain}}<tr><td>{{clean .Label}}</td><td class="mono">{{clean (join .APIs ", ")}}</td><td>{{.Source}}</td></tr>{{end}}</table>{{end}}
<p class="note">Evidence kinds: {{join .EvidenceKinds ", "}}. {{clean .Rationale}}</p>
{{if .Caveat}}<p class="note">Common and harmless in: {{clean .Caveat}}</p>{{end}}
</details>{{end}}
</section>

<section id="{{$p}}anomalies"><h2>Structural anomalies</h2>
{{if not .Anomalies}}<p>None found.</p>{{end}}
{{range .Anomalies}}<details open><summary class="sev-{{sev .Severity}}">{{clean .Title}}</summary><p>{{clean .Why}}</p>{{if .Benign}}<p class="note">Common and harmless in: {{clean .Benign}}</p>{{end}}</details>{{end}}
</section>

<section id="{{$p}}indicators"><h2>Indicators</h2>
<p class="warn">These are strings found in the file. Their presence does not show that the sample uses or contacts them. Network indicators are defanged (hxxp, [.]) so they cannot be clicked or resolved by accident.</p>
{{if not .Indicators}}<p>None found.</p>{{else}}
<table><tr><th>Type</th><th>Value (defanged)</th><th>Count</th><th>Offset</th><th>Encoding</th><th>Note</th></tr>
{{range .Indicators}}<tr><td>{{.Type}}</td><td class="mono">{{clean (defang .Type .Value)}}</td><td>{{.Count}}</td><td>{{hex64 .Offset}}</td><td>{{.Encoding}}</td><td>{{clean .Note}}</td></tr>{{end}}</table>{{end}}
<h3>Strings</h3>
<p class="note">{{.Strings.Total}} strings found ({{.Strings.ASCII}} ASCII, {{.Strings.UTF16}} UTF-16). The first {{len $.Strings}} are listed below; the JSON report holds up to {{len .Strings.Shown}} (a bounded sample in file order).</p>
<details><summary>show strings</summary><table><tr><th>Offset</th><th>Enc</th><th>Section</th><th>String</th></tr>
{{range $.Strings}}<tr><td>{{hex64 .Offset}}</td><td>{{.Encoding}}</td><td>{{clean .Section}}</td><td class="mono">{{clean .Text}}</td></tr>{{end}}</table></details>
{{if .Yara}}<h3>YARA-X matches</h3><p class="note">Only rules marked tested count as evidence; experimental and analyst rules are listed for review.</p>
<table><tr><th>Rule</th><th>Status</th><th>Category</th><th>Description</th></tr>{{range .Yara}}<tr><td>{{clean .Rule}}</td><td>{{.Status}}</td><td>{{clean .Category}}</td><td>{{clean .Description}}</td></tr>{{end}}</table>{{end}}
<h3>Engines</h3><ul class="tight">{{range .Engines}}<li>{{clean .Name}} {{clean .Version}}: {{.Status}}{{if .Detail}} &mdash; {{clean .Detail}}{{end}}</li>{{end}}</ul>
</section>
{{end}}

<section id="{{$p}}payloads"><h2>Payloads: unpacking and extraction</h2>
{{if and (not $r.Unpack) (not $r.Extraction)}}<p>Neither unpacking (-u) nor extraction (-x) was requested.</p>{{end}}
{{with $r.Unpack}}<h3>Unpacking</h3><p><span class="state">{{.Status}}</span> {{clean .Message}}</p><p class="note">Supported packers: {{join .Supported ", "}}. This is not a generic unpacker.</p>{{end}}
{{range $r.Artifacts}}<h3>Unpacked layer</h3>
<dl class="kv"><dt>Tool</dt><dd>{{clean .Tool}} {{clean .ToolVersion}}</dd><dt>SHA-256</dt><dd class="mono">{{.Hashes.SHA256}}</dd><dt>Size</dt><dd>{{.Size}} bytes</dd><dt>Stored at</dt><dd class="mono">{{clean .Path}}</dd></dl>
<table><tr><th>Validation check</th><th>Result</th><th>Detail</th></tr>{{range .Validation}}<tr><td>{{clean .Name}}</td><td>{{if .Passed}}pass{{else}}FAIL{{end}}</td><td>{{clean .Detail}}</td></tr>{{end}}</table>
{{with .Comparison}}{{template "cmp" .}}{{end}}{{end}}
{{with $r.Extraction}}<h3>Extraction</h3><p><span class="state">{{.Status}}</span> {{clean .Message}}</p>
<p class="note">Supported containers: {{join .Supported ", "}}. Extracted files are mode 0600 and were never executed.</p>
{{if eq .Status "extracted"}}<dl class="kv"><dt>Archive</dt><dd>{{clean .ArchiveFormat}} at file offset {{hex64 .ArchiveOffset}}, {{.ArchiveLength}} bytes</dd><dt>Output</dt><dd class="mono">{{clean .Dir}}</dd></dl>
<table><tr><th>Type</th><th>Entry</th><th>Offset</th><th>Size</th><th>Content</th><th>SHA-256</th><th>Skipped</th></tr>
{{range .Entries}}<tr><td>{{clean .TypeName}}</td><td>{{clean .Name}}</td><td>{{hex64 .Offset}}</td><td>{{.Size}}</td><td>{{clean .Format}}</td><td class="mono">{{short .SHA256}}</td><td>{{clean .Skipped}}</td></tr>{{end}}</table>{{end}}{{end}}
</section>

<section id="{{$p}}findings"><h2>Findings</h2>
<p class="note">Class: an <em>observation</em> was read from the file, an <em>inference</em> was derived by a named rule, a <em>hypothesis</em> is weakly supported. Confidence is ordinal (speculative, low, medium, high, definitive) and says how well the evidence supports the statement; it is not a probability.</p>
<table><tr><th>Finding</th><th>Class</th><th>Severity</th><th>Confidence</th><th>Why this confidence</th><th>Evidence</th></tr>
{{range $r.Findings}}<tr><td><strong>{{clean .Title}}</strong><br><span class="note">{{clean .Summary}}</span>{{if .Attack}}<br>{{range .Attack}}<span class="chip">{{clean .}}</span>{{end}}{{end}}</td><td>{{.Class}}</td><td class="sev-{{sev .Severity}}">{{sev .Severity}}</td><td class="conf-{{conf .Confidence}}">{{conf .Confidence}}</td><td>{{clean .Rationale}}</td><td>{{range .EvidenceID}}<a href="#{{$p}}ev-{{.}}">{{.}}</a> {{end}}</td></tr>{{end}}</table>
</section>

<section id="{{$p}}evidence"><h2>Evidence</h2>
{{if not $r.Evidence}}<p>No evidence records.</p>{{else}}
<table><tr><th>Id</th><th>Kind</th><th>Value</th><th>File offset</th><th>Section</th><th>Source</th></tr>
{{range $r.Evidence}}<tr id="{{$p}}ev-{{.ID}}"><td>{{.ID}}</td><td>{{.Kind}}</td><td class="mono">{{clean .Value}}</td><td>{{offset .Loc}}</td><td>{{clean .Loc.Section}}</td><td>{{clean .Source.Module}} {{clean .Source.Rule}}</td></tr>{{end}}</table>{{end}}
</section>

<section id="{{$p}}recommendations"><h2>Recommendations</h2><ol>{{range .Recs}}<li>{{.}}</li>{{end}}</ol></section>

<section id="{{$p}}limits"><h2>Limits of this report</h2>
{{if $r.NotRun}}<p class="warn">Stages not available in this build. Their absence is not a clean result:</p><ul class="tight">{{range $r.NotRun}}<li>{{clean .}}</li>{{end}}</ul>{{end}}
{{if $r.Warnings}}<h3>Warnings</h3><ul class="tight">{{range $r.Warnings}}<li>{{clean .Module}}: {{clean .Message}}</li>{{end}}</ul>{{end}}
<h3>Modules run</h3><table><tr><th>Module</th><th>Status</th><th>Time (ms)</th><th>Sandbox</th></tr>
{{range $r.Modules}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.DurationMS}}</td><td>{{if .Sandbox}}{{.Sandbox.Level}}{{else}}n/a{{end}}</td></tr>{{end}}</table>
</section>

{{range $r.Artifacts}}{{with .Report}}{{template "body" ($.Nest .)}}{{end}}{{end}}
{{end}}

{{define "hyps"}}{{$p := .P}}{{if not .H}}<p class="note">No indicators found.</p>{{end}}{{range .H}}<details open><summary><strong>{{clean .Name}}</strong>{{if .Detail}} &mdash; {{clean .Detail}}{{end}} &middot; <span class="conf-{{conf .Confidence}}">{{conf .Confidence}} confidence</span></summary>
<p class="note">{{clean .Rationale}}</p>
<ul class="tight">{{range .Signals}}<li>[{{.Strength}}] {{clean .Detail}} {{range .Evidence}}<a href="#{{$p}}ev-{{.}}">{{.}}</a> {{end}}</li>{{end}}</ul></details>{{end}}{{end}}

{{define "cmp"}}<h3>Differences</h3>
{{if .Header}}<table><tr><th>Property</th><th>First</th><th>Second</th></tr>{{range .Header}}<tr><td>{{clean .Field}}</td><td>{{clean .A}}</td><td>{{clean .B}}</td></tr>{{end}}</table>{{end}}
{{if or .Sections.OnlyA .Sections.OnlyB}}<p>Sections only in first: {{clean (join .Sections.OnlyA ", ")}}<br>Sections only in second: {{clean (join .Sections.OnlyB ", ")}}</p>{{end}}
{{if .SectionChanges}}<table><tr><th>Section</th><th>Property</th><th>First</th><th>Second</th></tr>{{range .SectionChanges}}{{$n := .Name}}{{range .Changes}}<tr><td>{{clean $n}}</td><td>{{.Field}}</td><td>{{clean .A}}</td><td>{{clean .B}}</td></tr>{{end}}{{end}}</table>{{end}}
{{template "setrow" dict2 "Imported libraries" .Libraries}}{{template "setrow" dict2 "Imported functions" .Imports}}{{template "setrow" dict2 "Exports" .Exports}}{{template "setrow" dict2 "Capabilities" .Capabilities}}{{template "setrow" dict2 "Indicators" .Indicators}}
{{if or .Entropy .Packing .Fingerprint .Strings}}<table><tr><th>Property</th><th>First</th><th>Second</th></tr>{{range .Entropy}}<tr><td>entropy {{clean .Field}}</td><td>{{.A}}</td><td>{{.B}}</td></tr>{{end}}{{range .Packing}}<tr><td>{{clean .Field}}</td><td>{{clean .A}}</td><td>{{clean .B}}</td></tr>{{end}}{{range .Fingerprint}}<tr><td>{{clean .Field}}</td><td>{{clean .A}}</td><td>{{clean .B}}</td></tr>{{end}}{{range .Strings}}<tr><td>{{clean .Field}}</td><td>{{.A}}</td><td>{{.B}}</td></tr>{{end}}</table>{{end}}
{{with .Similarity}}<h3>Similarity</h3><p class="note">Measurements, not probabilities; none is evidence of a shared origin.{{if .HasTLSH}} TLSH distance {{.TLSHDistance}}.{{end}}{{if .HasSSDeep}} ssdeep score {{.SSDeepScore}}.{{end}}{{if .HasOverlap}} Weighted structural overlap {{printf "%.2f" .Overlap}}.{{end}}</p>
{{if .Components}}<table><tr><th>Component</th><th>Score</th><th>Weight</th><th>How</th></tr>{{range .Components}}<tr><td>{{clean .Name}}</td><td>{{printf "%.3f" .Score}}</td><td>{{printf "%.2f" .Weight}}</td><td>{{clean .Note}}</td></tr>{{end}}</table>{{end}}{{end}}
{{range .Notes}}<p class="note">{{clean .}}</p>{{end}}{{end}}

{{define "setrow"}}{{if or .Set.OnlyA .Set.OnlyB}}<details><summary>{{.Name}}: {{len .Set.OnlyA}} only in first, {{len .Set.OnlyB}} only in second{{if .Set.Truncated}} (lists truncated){{end}}</summary>
<p class="mono">First only: {{clean (join .Set.OnlyA ", ")}}<br><br>Second only: {{clean (join .Set.OnlyB ", ")}}</p></details>{{end}}{{end}}
`
