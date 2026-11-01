// Package cli wires the command line. It contains no analysis logic.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/assets"
	"github.com/Yanliangchan/unpackr/internal/artvault"
	"github.com/Yanliangchan/unpackr/internal/comparison"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/reporting"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

type globals struct {
	configPath string
	noBanner   bool
	banner     string
	quiet      bool
	noColor    bool
	threads    int
	timeout    time.Duration
	offline    bool
	requireSB  bool
	noDB       bool
	verbose    bool
	flags      Flags
}

// userRuleDir is where analysts keep their own YARA rules.
func userRuleDir() string {
	if d := config.Dir(); d != "" {
		return filepath.Join(d, "rules")
	}
	return ""
}

func customArtDir() string {
	if d := config.Dir(); d != "" {
		return filepath.Join(d, "artvault", "custom")
	}
	return ""
}

func (g *globals) loadConfig() (config.Config, error) {
	cfg, err := config.Load(g.configPath)
	if err != nil {
		return cfg, err
	}
	if g.threads > 0 {
		cfg.Threads = g.threads
	}
	if g.timeout > 0 {
		cfg.TimeoutSeconds = int(g.timeout.Seconds())
		if cfg.TimeoutSeconds < 1 {
			cfg.TimeoutSeconds = 1
		}
	}
	if g.requireSB {
		cfg.RequireSandbox = true
	}
	return cfg, cfg.Validate()
}

// maybeBanner prints the startup banner to stderr when appropriate: only for
// interactive terminals, never when output is machine-readable or suppressed.
func (g *globals) maybeBanner(cmd *cobra.Command, cfg config.Config, machineOutput bool) {
	sel := g.banner
	if sel == "" {
		sel = cfg.Banner
	}
	if g.noBanner || g.quiet || machineOutput || sel == "off" || !terminal.IsTTY(os.Stderr) {
		return
	}
	v, _, err := artvault.Load(assets.ArtVault, "artvault", customArtDir())
	if err != nil {
		return
	}
	state := config.StateDir()
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	b, err := v.Pick(sel, artvault.LastShown(state), rnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "banner: %v\n", err)
		return
	}
	artvault.RememberShown(state, b.ID)
	st := terminal.Style{On: terminal.ColorEnabled(os.Stderr, g.noColor)}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(os.Stderr, format, a...) }
	depth := artvault.DepthNone
	if st.On {
		depth = artvault.DetectDepth()
	}
	p("\n%s\n\n", artvault.Paint(b, "", depth))
	p("%s %s  |  %s  |  offline  |  ArtVault #%s\n", st.Bold(version.Name), version.Version, version.Platform(), b.ID)
	p("%s\n", st.Dim(version.Tagline+"  "+repeat("-", 30)))
}

// NewRoot builds the command tree.
func NewRoot() *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:   "unpackr [flags] <file|directory>...",
		Short: "Binary intelligence and static malware analysis toolkit",
		Long: version.Name + " — " + version.Tagline + `

Analyses executables statically. Samples are never executed.

  unpackr -i sample.exe          full static analysis (default when only a path is given)
  unpackr -q ./samples/          quick triage of a directory
  unpackr -i sample.exe -o r.json   write a JSON report

Run 'unpackr doctor' to check the sandbox and optional tools.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			return g.run(cmd, args)
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &UsageError{Msg: err.Error()} })
	root.SetVersionTemplate(version.Name + " {{.Version}} (" + version.Platform() + ")\n")

	pf := root.PersistentFlags()
	pf.StringVar(&g.configPath, "config", "", "configuration file (default $XDG_CONFIG_HOME/unpackr/config.yaml)")
	pf.BoolVar(&g.noBanner, "no-banner", false, "do not show the startup banner")
	pf.StringVar(&g.banner, "banner", "", "banner selection: random, an id such as 003, or a category")
	pf.BoolVar(&g.quiet, "quiet", false, "suppress banner and progress; print only results")
	pf.BoolVar(&g.noColor, "no-color", false, "disable colour")

	f := root.Flags()
	fl := &g.flags
	f.BoolVarP(&fl.Info, "info", "i", false, "full static analysis")
	f.BoolVarP(&fl.Quick, "quick", "q", false, "fast triage; accepts directories")
	f.BoolVarP(&fl.Deep, "deep", "d", false, "extended analysis (not implemented in this build)")
	f.BoolVarP(&fl.Verbose, "verbose", "v", false, "show technical evidence")
	f.BoolVarP(&fl.Unpack, "unpack", "u", false, "unpack supported packers (UPX) and analyse the result; needs upx installed")
	f.BoolVarP(&fl.Extract, "extract", "x", false, "extract embedded content (PyInstaller bundles; ZIP/RAR/7z/CAB archives appended to an executable, needs 7-Zip) without running it")
	f.BoolVarP(&fl.Reverse, "reverse", "r", false, "use reverse-engineering integrations (not implemented in this build)")
	f.BoolVarP(&fl.Compare, "compare", "c", false, "compare two files: header, sections, imports, entropy, packing, capabilities, indicators")
	f.StringVarP(&fl.Output, "output", "o", "", "write a report; format inferred from the extension (.json .html .md .csv)")
	f.StringVar(&fl.Format, "format", "", "output format: terminal, json, html, markdown, csv (csv is the indicator list, or the summary table for several files)")
	f.StringVar(&fl.OutputDir, "output-dir", "", "directory for per-file JSON reports in batch mode")
	f.StringVar(&fl.Modules, "modules", "", "comma-separated modules to run (available: identification, structure)")
	f.IntVar(&g.threads, "threads", 0, "concurrent analyses for batches (default from config)")
	f.DurationVar(&g.timeout, "timeout", 0, "per-worker time limit, e.g. 90s (default from config)")
	f.BoolVar(&g.offline, "offline", true, "never use the network (always true in this build)")
	f.BoolVar(&g.noDB, "no-db", false, "do not read or write the local sample database")
	f.BoolVar(&g.requireSB, "require-sandbox", false, "refuse to analyse unless workers are fully sandboxed")

	root.AddCommand(newDoctorCmd(g), newArtCmd(g), newDBCmd(g), newCaseCmd(g), newSimilarCmd(g), newInspectCmd(g), newYaraCmd(g))
	root.AddCommand(newGenCmd(g, root))
	return root
}

func (g *globals) run(cmd *cobra.Command, args []string) error {
	plan, err := BuildPlan(g.flags, args)
	if err != nil {
		return err
	}
	cfg, err := g.loadConfig()
	if err != nil {
		return err
	}
	machine := plan.Format != "terminal" && plan.OutputFile == ""
	g.maybeBanner(cmd, cfg, machine)

	if plan.Mode == ModeCompare {
		return g.runCompare(cmd, plan, cfg, machine)
	}
	files, err := collectInputs(plan.Paths, cfg.MaxBatchFiles)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no regular files found in %v", plan.Paths)
	}
	profile := engine.ProfileInfo
	switch {
	case plan.Mode == ModeQuick:
		profile = engine.ProfileQuick
	case plan.Deep:
		profile = engine.ProfileDeep
	}
	opts := engine.Options{Config: cfg, Profile: profile, Modules: plan.Modules, Unpack: plan.Unpack, Extract: plan.Extract, ArtifactDir: plan.OutputDir, UserRuleDir: userRuleDir(), Reverse: plan.Reverse}

	ctx, stop := signalContext()
	defer stop()

	out := cmd.OutOrStdout()
	st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
	single := len(files) == 1 && len(plan.Paths) == 1 && !isDir(plan.Paths[0])

	if !g.quiet && !machine && len(files) > 1 && terminal.IsTTY(os.Stderr) {
		fmt.Fprintf(os.Stderr, "analysing %d files with %d workers...\n", len(files), cfg.Threads)
	}
	reps, errs := analyzeAll(ctx, files, opts, cfg.Threads)
	if ctx.Err() != nil {
		return fmt.Errorf("interrupted")
	}

	g.remember(cfg, reps)

	if plan.OutputDir != "" {
		if err := writePerFile(plan.OutputDir, reps); err != nil {
			return err
		}
	}
	render := func(w io.Writer, format string) error {
		if format == "json" {
			return encode(w, reportPayload(reps, errs, single))
		}
		if single && len(reps) == 1 {
			return reporting.Single(w, format, reps[0])
		}
		return reporting.Batch(w, format, reps, errStrings(errs))
	}
	if plan.OutputFile != "" {
		if err := writeFile(plan.OutputFile, func(w io.Writer) error { return render(w, plan.OutputFmt) }); err != nil {
			return err
		}
	}

	switch {
	case machine:
		if err := render(out, plan.Format); err != nil {
			return err
		}
	case single && len(reps) == 1:
		if !g.quiet || plan.OutputFile == "" {
			renderReport(out, reps[0], plan.Verbose, st)
		}
	default:
		renderTable(out, reps, errs, st)
		if plan.Verbose {
			for _, r := range reps {
				fmt.Fprintf(out, "\n%s\n", st.Bold(safe(r.File.Path)))
				renderReport(out, r, true, st)
			}
		}
	}
	if plan.OutputFile != "" && !machine && !g.quiet {
		fmt.Fprintf(os.Stderr, "report written to %s\n", plan.OutputFile)
	}
	if len(errs) > 0 {
		for p, e := range errs {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", terminal.Sanitize(p), e)
		}
		return fmt.Errorf("%d file(s) could not be analysed", len(errs))
	}
	return nil
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// BatchReport is the JSON shape for more than one input.
type BatchReport struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          models.ToolMeta   `json:"tool"`
	Reports       []*models.Report  `json:"reports"`
	Errors        map[string]string `json:"errors"`
}

func reportPayload(reps []*models.Report, errs map[string]error, single bool) any {
	if single && len(reps) == 1 {
		return reps[0]
	}
	b := BatchReport{SchemaVersion: models.SchemaVersion, Reports: reps, Errors: map[string]string{}}
	if b.Reports == nil {
		b.Reports = []*models.Report{}
	}
	b.Tool = models.ToolMeta{Name: "unpackr", Version: version.Version, Platform: version.Platform(), Offline: true}
	for p, e := range errs {
		b.Errors[p] = e.Error()
	}
	return b
}

func encode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	return enc.Encode(v)
}

func writeJSON(path string, v any) error {
	return writeFile(path, func(w io.Writer) error { return encode(w, v) })
}

// writeFile creates path (BuildPlan has already refused an input path) and
// fills it with fn. A failure removes the partial file.
func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func errStrings(errs map[string]error) map[string]string {
	m := make(map[string]string, len(errs))
	for k, v := range errs {
		m[k] = v.Error()
	}
	return m
}

func writePerFile(dir string, reps []*models.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, r := range reps {
		// Named by content hash: never derived from the sample's own name.
		if err := writeJSON(filepath.Join(dir, r.File.Hashes.SHA256+".json"), r); err != nil {
			return err
		}
	}
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signalNotify()
}

// CompareReport is the JSON shape of -c.
type CompareReport struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          models.ToolMeta    `json:"tool"`
	First         *models.Report     `json:"first"`
	Second        *models.Report     `json:"second"`
	Comparison    *models.Comparison `json:"comparison"`
}

func (g *globals) runCompare(cmd *cobra.Command, plan Plan, cfg config.Config, machine bool) error {
	for _, p := range plan.Paths {
		if isDir(p) {
			return usagef("-c/--compare compares two files, but %s is a directory", p)
		}
	}
	ctx, stop := signalContext()
	defer stop()
	opts := engine.Options{Config: cfg, Profile: engine.ProfileInfo, Modules: plan.Modules}
	reps, errs := analyzeAll(ctx, plan.Paths, opts, 2)
	if len(errs) > 0 || len(reps) != 2 {
		for p, e := range errs {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", terminal.Sanitize(p), e)
		}
		return fmt.Errorf("both files must be analysable to compare them")
	}
	first, second := reps[0], reps[1] // results keep argument order
	cmp := comparison.Diff(first, second)
	payload := CompareReport{SchemaVersion: models.SchemaVersion, First: first, Second: second, Comparison: cmp,
		Tool: models.ToolMeta{Name: "unpackr", Version: version.Version, Platform: version.Platform(), Offline: true}}
	renderCmp := func(w io.Writer, format string) error {
		if format == "json" {
			return encode(w, payload)
		}
		return reporting.Compare(w, format, first, second, cmp)
	}
	if plan.OutputFile != "" {
		if err := writeFile(plan.OutputFile, func(w io.Writer) error { return renderCmp(w, plan.OutputFmt) }); err != nil {
			return err
		}
	}
	out := cmd.OutOrStdout()
	if machine {
		return renderCmp(out, plan.Format)
	}
	st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
	fmt.Fprintf(out, "%s\n", st.Bold(st.Cyan("Comparison")))
	fmt.Fprintf(out, "  %-10s %s  %s\n", "First", safe(first.File.Name), first.File.Hashes.SHA256)
	fmt.Fprintf(out, "  %-10s %s  %s\n", "Second", safe(second.File.Name), second.File.Hashes.SHA256)
	if cmp.Identical {
		fmt.Fprintf(out, "  %s\n", st.Green("the files are byte-for-byte identical (same SHA-256)"))
	}
	renderComparison(out, cmp, plan.Verbose, st, "first", "second")
	if plan.OutputFile != "" && !g.quiet {
		fmt.Fprintf(os.Stderr, "report written to %s\n", plan.OutputFile)
	}
	return nil
}
