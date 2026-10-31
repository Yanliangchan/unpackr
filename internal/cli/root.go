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
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/engine"
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
	flags      Flags
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
	p("\n%s\n\n", st.Cyan(b.Text()))
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
	f.BoolVarP(&fl.Unpack, "unpack", "u", false, "attempt supported unpacking (not implemented in this build)")
	f.BoolVarP(&fl.Extract, "extract", "x", false, "extract embedded content (not implemented in this build)")
	f.BoolVarP(&fl.Reverse, "reverse", "r", false, "use reverse-engineering integrations (not implemented in this build)")
	f.BoolVarP(&fl.Compare, "compare", "c", false, "compare two files (not implemented in this build)")
	f.StringVarP(&fl.Output, "output", "o", "", "write a report; format inferred from the extension (.json)")
	f.StringVar(&fl.Format, "format", "", "output format: terminal, json (html, markdown, csv are not implemented yet)")
	f.StringVar(&fl.OutputDir, "output-dir", "", "directory for per-file JSON reports in batch mode")
	f.StringVar(&fl.Modules, "modules", "", "comma-separated modules to run (available: identification)")
	f.IntVar(&g.threads, "threads", 0, "concurrent analyses for batches (default from config)")
	f.DurationVar(&g.timeout, "timeout", 0, "per-worker time limit, e.g. 90s (default from config)")
	f.BoolVar(&g.offline, "offline", true, "never use the network (always true in this build)")
	f.BoolVar(&g.requireSB, "require-sandbox", false, "refuse to analyse unless workers are fully sandboxed")

	root.AddCommand(newDoctorCmd(g), newArtCmd(g))
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
	machine := plan.Format == "json" && plan.OutputFile == ""
	g.maybeBanner(cmd, cfg, machine)

	files, err := collectInputs(plan.Paths, cfg.MaxBatchFiles)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no regular files found in %v", plan.Paths)
	}
	profile := engine.ProfileInfo
	if plan.Mode == ModeQuick {
		profile = engine.ProfileQuick
	}
	opts := engine.Options{Config: cfg, Profile: profile}

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

	if plan.OutputDir != "" {
		if err := writePerFile(plan.OutputDir, reps); err != nil {
			return err
		}
	}
	if plan.OutputFile != "" {
		if err := writeJSON(plan.OutputFile, reportPayload(reps, errs, single)); err != nil {
			return err
		}
	}

	switch {
	case machine:
		if err := encode(out, reportPayload(reps, errs, single)); err != nil {
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := encode(f, v); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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
