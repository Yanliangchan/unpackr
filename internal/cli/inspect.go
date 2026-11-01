package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/reporting"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// maxReportJSON bounds a report file read for inspection.
const maxReportJSON = 64 << 20

func newInspectCmd(g *globals) *cobra.Command {
	c := &cobra.Command{
		Use:   "inspect <file | report.json>",
		Short: "Browse an analysis interactively",
		Long: `Open an interactive view of an analysis: summary, findings, evidence,
indicators, capabilities and structure, with search and links from each finding
to the evidence behind it.

The argument is either a file to analyse (the same analysis as -i) or a JSON
report saved earlier with -o report.json. Nothing is executed. Text taken from
the sample is shown with control and escape bytes made visible.

It needs an interactive terminal; for scripts use -o report.json instead.`,
		Args: cobra.ExactArgs(1),
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if !terminal.IsTTY(os.Stdin) || !terminal.IsTTY(os.Stdout) {
			return usagef("inspect needs an interactive terminal; use -o report.html or --format json for non-interactive output")
		}
		rep, err := g.inspectReport(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		color := terminal.ColorEnabled(os.Stdout, g.noColor)
		return runInspectHelper(rep, color)
	}
	return c
}

// inspectReport returns the report to show: a saved JSON report, or a fresh
// analysis of the given file.
func (g *globals) inspectReport(ctx context.Context, path string) (*models.Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, usagef("%s is not a regular file", path)
	}
	if strings.EqualFold(extOf(path), ".json") {
		return loadReportJSON(path)
	}
	cfg, err := g.loadConfig()
	if err != nil {
		return nil, err
	}
	rep, err := engine.Analyze(ctx, path, engine.Options{Config: cfg, Profile: engine.ProfileInfo, UserRuleDir: userRuleDir()})
	if err != nil {
		return nil, err
	}
	g.remember(cfg, []*models.Report{rep})
	return rep, nil
}

func extOf(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && !strings.ContainsAny(p[i:], `/\`) {
		return p[i:]
	}
	return ""
}

// loadReportJSON reads a report written by this tool. The file is untrusted
// input: it is size-limited and every string is sanitised before display.
func loadReportJSON(path string) (*models.Report, error) {
	f, err := os.Open(path) //nolint:gosec // path chosen by the user
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	data, err := io.ReadAll(io.LimitReader(f, maxReportJSON+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReportJSON {
		return nil, fmt.Errorf("%s is larger than %d MiB; not a report this tool wrote", path, maxReportJSON>>20)
	}
	var r models.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s is not a UNPACKR JSON report: %w", path, err)
	}
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("%s has no schema_version; it is not a UNPACKR report", path)
	}
	return &r, nil
}

// helperName is the viewer executable installed next to unpackr.
const helperName = "unpackr-inspect"

// findHelper locates the viewer beside the running executable. PATH is not
// searched: a planted program must not be able to receive the report.
func findHelper() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = real
	}
	p := filepath.Join(filepath.Dir(exe), helperName)
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("the interactive viewer %s was not found next to %s (it is installed with the package; build it with `make build`)", helperName, filepath.Base(exe))
	}
	return p, nil
}

// runInspectHelper sanitises the report and hands it to the viewer over an
// inherited pipe. The viewer gets the terminal but opens no files.
func runInspectHelper(rep *models.Report, color bool) error {
	helper, err := findHelper()
	if err != nil {
		return err
	}
	data, err := json.Marshal(reporting.Sanitized(rep, false))
	if err != nil {
		return err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(helper) //nolint:gosec // fixed sibling executable resolved above
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{pr}
	cmd.Env = os.Environ()
	if color {
		cmd.Env = append(cmd.Env, "UNPACKR_COLOR=1")
	}
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return err
	}
	_ = pr.Close()
	go func() {
		_, _ = pw.Write(data)
		_ = pw.Close()
	}()
	return cmd.Wait()
}
