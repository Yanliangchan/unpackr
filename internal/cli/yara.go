package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/internal/yara"
	"github.com/Yanliangchan/unpackr/internal/yarasuggest"
)

func newYaraCmd(g *globals) *cobra.Command {
	c := &cobra.Command{
		Use:   "yara",
		Short: "Draft and test YARA rules",
		Long: `Helpers for writing YARA rules.

  yara suggest <file>   analyse a file and draft a candidate rule from what is
                        specific to it, then test the draft
  yara test <rule>      check that a rule compiles, matches a sample, and how
                        many files in a directory of clean files it matches

Rules are tested with YARA-X (yr), inside the same sandbox as the other external
tools. A draft is a starting point: it is never loaded as a built-in rule, and
rules you load yourself are shown in reports but never counted as evidence.`,
	}
	c.AddCommand(newYaraSuggestCmd(g), newYaraTestCmd(g))
	return c
}

func newYaraSuggestCmd(g *globals) *cobra.Command {
	var name, out string
	var against []string
	var maxStrings int
	var imphash bool
	c := &cobra.Command{
		Use:   "suggest <file>",
		Short: "Draft a candidate YARA rule from a sample",
		Long: `Analyses the file and drafts a rule from its most specific features: strings
recovered from an encoded form (written with the xor modifier), indicators, and
unusual long strings. Library and compiler boilerplate is left out, and nothing
is written when there is too little to go on.

The draft is then tested: it must compile and match the sample, and --against
DIR (repeatable) counts how many files in a directory of known-clean files it
also matches. Without --against the false-positive risk is unknown and the
output says so.`,
		Args: usageArgs(cobra.ExactArgs(1)),
	}
	c.Flags().StringVar(&name, "name", "", "rule name (default: derived from the SHA-256)")
	c.Flags().StringArrayVar(&against, "against", nil, "directory of clean files to test the draft against (repeatable)")
	c.Flags().IntVar(&maxStrings, "max-strings", 8, "most strings to put in the rule")
	c.Flags().BoolVar(&imphash, "imphash", false, "PE only: add an alternative that matches the import hash (broad; see the warning it prints)")
	c.Flags().StringVarP(&out, "output", "o", "", "write the rule to this .yar file (an existing file is not overwritten)")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := g.loadConfig()
		if err != nil {
			return err
		}
		ctx, stop := signalContext()
		defer stop()
		rep, err := engine.Analyze(ctx, args[0], engine.Options{Config: cfg, Profile: engine.ProfileInfo})
		if err != nil {
			return err
		}
		sug, err := yarasuggest.Build(rep, yarasuggest.Options{Name: name, MaxStrings: maxStrings, Imphash: imphash, Version: version.Version})
		if err != nil {
			var ne *yarasuggest.ErrNotEnough
			if errors.As(err, &ne) {
				fmt.Fprintln(cmd.ErrOrStderr(), "No rule drafted:", terminal.Sanitize(ne.Reason))
				fmt.Fprintln(cmd.ErrOrStderr(), "Try `unpackr -d` on the file, or unpack it first (-u), then suggest again.")
				return fmt.Errorf("not enough distinctive features")
			}
			return err
		}
		st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
		w := cmd.OutOrStdout()
		fmt.Fprintln(w, sug.Rule)

		fmt.Fprintf(w, "%s\n", st.Bold("Why these strings"))
		for _, f := range sug.Features {
			fmt.Fprintf(w, "  %s  %s (%s)\n", f.ID, terminal.Sanitize(clipHead(f.Text, 70)), terminal.Sanitize(f.Why))
		}
		if len(sug.Dropped) > 0 {
			fmt.Fprintf(w, "%s\n", st.Bold("Left out"))
			for i, d := range sug.Dropped {
				if i == 6 && !g.verbose {
					fmt.Fprintf(w, "  … and %d more (use -v)\n", len(sug.Dropped)-i)
					break
				}
				fmt.Fprintf(w, "  %s: %s\n", terminal.Sanitize(clipHead(d.Text, 50)), terminal.Sanitize(d.Why))
			}
		}
		for _, wmsg := range sug.Warnings {
			fmt.Fprintf(w, "%s %s\n", st.Yellow("!"), terminal.Sanitize(wmsg))
		}

		verdict, werr := testAndReport(ctx, w, st, cfg.WorkerMemoryMB, sug.Rule, args[0], against, time.Duration(cfg.TimeoutSeconds)*time.Second)
		if out != "" {
			if err := writeRuleFile(out, sug.Rule); err != nil {
				return err
			}
			fmt.Fprintf(w, "Written to %s\n", terminal.Sanitize(out))
		}
		if werr != nil {
			return werr
		}
		_ = verdict
		return nil
	}
	return c
}

func newYaraTestCmd(g *globals) *cobra.Command {
	var sample string
	var against []string
	c := &cobra.Command{
		Use:   "test <rule.yar>",
		Short: "Test a YARA rule against a sample and a directory of clean files",
		Args:  usageArgs(cobra.ExactArgs(1)),
	}
	c.Flags().StringVar(&sample, "sample", "", "a file the rule should match")
	c.Flags().StringArrayVar(&against, "against", nil, "directory of clean files the rule should not match (repeatable)")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := g.loadConfig()
		if err != nil {
			return err
		}
		data, err := readBounded(args[0], yara.MaxRuleBytes)
		if err != nil {
			return err
		}
		ctx, stop := signalContext()
		defer stop()
		st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
		_, werr := testAndReport(ctx, cmd.OutOrStdout(), st, cfg.WorkerMemoryMB, string(data), sample, against, time.Duration(cfg.TimeoutSeconds)*time.Second)
		return werr
	}
	return c
}

// testAndReport runs the rule tests and prints what they found. It returns an
// error (so the exit status is non-zero) when the rule does not compile, does
// not match its sample, or matches clean files.
func testAndReport(ctx context.Context, w io.Writer, st terminal.Style, memMB int64, rule, samplePath string, against []string, timeout time.Duration) (string, error) {
	fmt.Fprintf(w, "%s\n", st.Bold("Tests"))
	mem := uint64(memMB) << 20
	tool, err := yara.Locate(ctx, "", mem)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		fmt.Fprintf(w, "  %s YARA-X (yr) is not installed, so the rule was NOT compiled or tested. Install it, then run `unpackr yara test`.\n", st.Yellow("!"))
		return "untested", nil
	case errors.Is(err, worker.ErrExecSandbox):
		fmt.Fprintf(w, "  %s the sandbox could not be fully established, so nothing was tested (%s)\n", st.Yellow("!"), terminal.Sanitize(err.Error()))
		return "untested", nil
	case err != nil:
		return "", err
	}
	var sample io.Reader
	if samplePath != "" {
		f, err := os.Open(samplePath) //nolint:gosec // path chosen by the user
		if err != nil {
			return "", err
		}
		defer f.Close() //nolint:errcheck // read only
		sample = f
	}
	res, err := yara.TestRule(ctx, tool, rule, sample, yara.TestOptions{Timeout: timeout, MemoryBytes: mem, ControlDirs: against})
	if err != nil {
		return "", err
	}
	bad := false
	if !res.Compiled {
		fmt.Fprintf(w, "  %s does not compile:\n    %s\n", st.Red("✗"), indent(terminal.Sanitize(res.CompileError)))
		return "invalid", errors.New("the rule does not compile")
	}
	fmt.Fprintf(w, "  %s compiles with YARA-X %s\n", st.Green("✓"), terminal.Sanitize(tool.Version))
	if res.SampleTested {
		if res.MatchedSample {
			fmt.Fprintf(w, "  %s matches the sample\n", st.Green("✓"))
		} else {
			bad = true
			fmt.Fprintf(w, "  %s does NOT match the sample it was drafted from\n", st.Red("✗"))
		}
	}
	if len(against) == 0 {
		fmt.Fprintf(w, "  %s not tested against any clean files: the false-positive risk is unknown. Use --against DIR with a directory of files you know are clean.\n", st.Yellow("!"))
	} else {
		note := ""
		if res.ControlTruncated {
			note = fmt.Sprintf(" (counting stopped at %d files)", yara.MaxControlFiles)
		}
		if res.ControlMatchN == 0 {
			fmt.Fprintf(w, "  %s matches none of %d clean file(s)%s. This lowers, and does not remove, the risk of false positives.\n", st.Green("✓"), res.ControlFiles, note)
		} else {
			bad = true
			fmt.Fprintf(w, "  %s matches %d of %d clean file(s)%s, so it is too broad:\n", st.Red("✗"), res.ControlMatchN, res.ControlFiles, note)
			for _, m := range res.ControlMatches {
				fmt.Fprintf(w, "      %s\n", terminal.Sanitize(m))
			}
		}
	}
	if bad {
		return "failed", errors.New("the rule failed its tests")
	}
	return "ok", nil
}

func indent(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n    ") }

func clipHead(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func writeRuleFile(path, rule string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // rule files are meant to be shared
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; not overwriting it", path)
		}
		return err
	}
	if _, err := f.WriteString(rule); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readBounded(path string, max int) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path chosen by the user
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s is larger than %d KiB; not a rule file this tool will test", path, max>>10)
	}
	return b, nil
}
