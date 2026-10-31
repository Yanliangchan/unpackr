package reporting

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// csvCell neutralises spreadsheet formula injection: a cell that starts with
// =, +, -, @, tab or carriage return would be evaluated by Excel or
// LibreOffice, and indicator text comes from hostile files.
func csvCell(s string) string {
	s = textutil.Sanitize(s)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// IOCsv writes the indicators of a report: one row per indicator, with the
// raw value, a defanged value, and the file it came from.
func IOCsv(w io.Writer, reps []*models.Report) error {
	reps = sanitizeAll(reps, false)
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"file_sha256", "file_name", "type", "value", "defanged", "count", "offset", "encoding", "section", "note"}); err != nil {
		return err
	}
	for _, r := range reps {
		if r.Analysis == nil {
			continue
		}
		for _, i := range r.Analysis.Indicators {
			row := []string{r.File.Hashes.SHA256, csvCell(r.File.Name), i.Type, csvCell(i.Value), csvCell(Defang(i.Type, i.Value)),
				fmt.Sprint(i.Count), fmt.Sprintf("0x%x", i.Offset), i.Encoding, csvCell(i.Section), csvCell(i.Note)}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// SummaryRow is one line of a batch summary.
type SummaryRow struct {
	Name, SHA256, Format, Arch, Packing, Language, Compiler     string
	Findings, High, Medium, Capabilities, Indicators, Anomalies int
	Error                                                       string
}

func rows(reps []*models.Report, errs map[string]string) []SummaryRow {
	var out []SummaryRow
	for _, r := range reps {
		row := SummaryRow{Name: r.File.Name, SHA256: r.File.Hashes.SHA256, Findings: len(r.Findings)}
		if r.Identification != nil {
			row.Format = r.Identification.Primary
		}
		if r.Binary != nil {
			row.Arch = r.Binary.Arch
		}
		for _, f := range r.Findings {
			switch f.Severity {
			case models.SeverityHigh:
				row.High++
			case models.SeverityMedium:
				row.Medium++
			}
		}
		if a := r.Analysis; a != nil {
			row.Packing = a.Packing.State
			if a.Packing.Family != "" {
				row.Packing += " (" + a.Packing.Family + ")"
			}
			if len(a.Fingerprint.Languages) > 0 {
				row.Language = a.Fingerprint.Languages[0].Name
			}
			if len(a.Fingerprint.Compilers) > 0 {
				row.Compiler = a.Fingerprint.Compilers[0].Name
			}
			row.Capabilities, row.Indicators, row.Anomalies = len(a.Capabilities), len(a.Indicators), len(a.Anomalies)
		}
		out = append(out, row)
	}
	var names []string
	for n := range errs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, SummaryRow{Name: n, Error: errs[n]})
	}
	return out
}

// SummaryCSV writes one row per analysed file.
func SummaryCSV(w io.Writer, reps []*models.Report, errs map[string]string) error {
	reps = sanitizeAll(reps, false)
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"name", "sha256", "format", "architecture", "packing", "language", "compiler", "findings", "high", "medium", "capabilities", "indicators", "anomalies", "error"}); err != nil {
		return err
	}
	for _, r := range rows(reps, errs) {
		rec := []string{csvCell(r.Name), r.SHA256, csvCell(r.Format), csvCell(r.Arch), csvCell(r.Packing), csvCell(r.Language), csvCell(r.Compiler),
			fmt.Sprint(r.Findings), fmt.Sprint(r.High), fmt.Sprint(r.Medium), fmt.Sprint(r.Capabilities), fmt.Sprint(r.Indicators), fmt.Sprint(r.Anomalies), csvCell(r.Error)}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
