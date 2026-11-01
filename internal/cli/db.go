package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/internal/cases"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/database"
	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/reporting"
	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// openDB opens the local database, or returns nil when it is disabled. Errors
// are returned so commands that need the database can say why.
func (g *globals) openDB(cfg config.Config) (*database.DB, error) {
	if g.noDB || !cfg.UseDatabase {
		return nil, nil
	}
	p := cfg.DatabasePath
	if p == "" {
		p = database.DefaultPath()
	}
	return database.Open(p)
}

// needDB is for commands that cannot work without the database.
func (g *globals) needDB() (*database.DB, error) {
	cfg, err := g.loadConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.UseDatabase {
		return nil, errors.New("the local database is disabled (use_database: false)")
	}
	p := cfg.DatabasePath
	if p == "" {
		p = database.DefaultPath()
	}
	return database.Open(p)
}

// remember annotates reports with what the database already knew, then
// records them. Failures are warnings: the analysis itself is never lost.
func (g *globals) remember(cfg config.Config, reps []*models.Report) {
	db, err := g.openDB(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: local database unavailable: %s\n", terminal.Sanitize(err.Error()))
		return
	}
	if db == nil {
		return
	}
	defer db.Close() //nolint:errcheck // best effort at exit
	for _, r := range reps {
		if err := db.Annotate(r); err != nil {
			fmt.Fprintf(os.Stderr, "warning: reading the local database: %s\n", terminal.Sanitize(err.Error()))
		}
	}
	for _, r := range reps {
		if err := db.Record(r); err != nil {
			fmt.Fprintf(os.Stderr, "warning: recording in the local database: %s\n", terminal.Sanitize(err.Error()))
			return
		}
	}
}

func newDBCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "db", Short: "Inspect the local sample database", Long: "UNPACKR remembers analysed files (hashes and reports, never the samples) in a local SQLite file. Disable with use_database: false or --no-db."}
	var kind string
	c.AddCommand(
		&cobra.Command{Use: "path", Short: "Print the database location", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.loadConfig()
			if err != nil {
				return err
			}
			p := cfg.DatabasePath
			if p == "" {
				p = database.DefaultPath()
			}
			fmt.Fprintln(cmd.OutOrStdout(), p)
			return nil
		}},
		&cobra.Command{Use: "stats", Short: "Show what is stored", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := g.needDB()
			if err != nil {
				return err
			}
			defer db.Close() //nolint:errcheck // read-only command
			s, err := db.Stats()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Database   %s (%d bytes)\nSamples    %d\nAnalyses   %d\nIndicators %d distinct\nCases      %d\n", terminal.Sanitize(s.Path), s.Bytes, s.Samples, s.Analyses, s.Indicators, s.Cases)
			return nil
		}},
	)
	find := &cobra.Command{Use: "find <value>", Short: "Find samples sharing a value (indicator, imphash, rule, capability ...)", Args: usageArgs(cobra.ExactArgs(1)), RunE: func(cmd *cobra.Command, args []string) error {
		db, err := g.needDB()
		if err != nil {
			return err
		}
		defer db.Close() //nolint:errcheck // read-only command
		refs, err := db.Find(kind, args[0])
		if err != nil {
			return usagef("%v", err)
		}
		out := cmd.OutOrStdout()
		if len(refs) == 0 {
			fmt.Fprintln(out, "no stored sample matches")
			return nil
		}
		for _, r := range refs {
			fmt.Fprintf(out, "%s  %-22s %-14s seen %dx, last %s  %s\n", r.SHA256, clip(safe(r.Format), 22), clip(safe(r.Packing), 14), r.TimesSeen, r.LastSeen, safe(r.Name))
		}
		return nil
	}}
	find.Flags().StringVar(&kind, "kind", "ioc", "what to match: ioc, hash, imphash, section-layout, yara, capability, attack, packer, language, or indicator:<type>")
	forget := &cobra.Command{Use: "forget <sha256>", Short: "Delete a sample and its stored analyses", Args: usageArgs(cobra.ExactArgs(1)), RunE: func(cmd *cobra.Command, args []string) error {
		db, err := g.needDB()
		if err != nil {
			return err
		}
		defer db.Close() //nolint:errcheck // short command
		sha, err := cases.ResolveSample(db, args[0])
		if err != nil {
			return usagef("%v", err)
		}
		ok, err := db.Forget(sha)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "forgot %s: %t\n", sha, ok)
		return nil
	}}
	c.AddCommand(find, forget)
	return c
}

func newCaseCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "case", Short: "Manage investigations: samples, notes and a timeline", Long: "A case groups analysed samples, analyst notes and an automatic timeline in the local database."}
	with := func(fn func(cmd *cobra.Command, db *database.DB, args []string) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			db, err := g.needDB()
			if err != nil {
				return err
			}
			defer db.Close() //nolint:errcheck // short command
			return fn(cmd, db, args)
		}
	}
	userErr := func(err error) error {
		if errors.Is(err, cases.ErrNoCase) || errors.Is(err, cases.ErrNoSample) {
			return usagef("%v", err)
		}
		return err
	}

	c.AddCommand(&cobra.Command{Use: "new <name> [description...]", Short: "Open a case", Args: usageArgs(cobra.MinimumNArgs(1)),
		RunE: with(func(cmd *cobra.Command, db *database.DB, a []string) error {
			if err := cases.New(db, a[0], strings.Join(a[1:], " ")); err != nil {
				return usagef("%v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "opened case %s\n", a[0])
			return nil
		})})
	c.AddCommand(&cobra.Command{Use: "list", Short: "List cases", Args: usageArgs(cobra.NoArgs),
		RunE: with(func(cmd *cobra.Command, db *database.DB, _ []string) error {
			cs, err := cases.List(db)
			if err != nil {
				return err
			}
			for _, x := range cs {
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-7s %3d samples  %s  %s\n", safe(x.Name), x.Status, x.Samples, x.CreatedAt, clip(safe(x.Description), 60))
			}
			if len(cs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no cases yet; try: unpackr case new <name>")
			}
			return nil
		})})
	add := &cobra.Command{Use: "add <case> <file|sha256-prefix>...", Short: "Add samples to a case (files are analysed first)", Args: usageArgs(cobra.MinimumNArgs(2))}
	add.RunE = with(func(cmd *cobra.Command, db *database.DB, a []string) error {
		cfg, err := g.loadConfig()
		if err != nil {
			return err
		}
		for _, arg := range a[1:] {
			sha := ""
			if st, serr := os.Stat(arg); serr == nil && st.Mode().IsRegular() {
				rep, aerr := engine.Analyze(context.Background(), arg, engine.Options{Config: cfg, Profile: engine.ProfileInfo})
				if aerr != nil {
					return fmt.Errorf("%s: %w", terminal.Sanitize(arg), aerr)
				}
				if err := db.Annotate(rep); err != nil {
					return err
				}
				if err := db.Record(rep); err != nil {
					return err
				}
				sha = rep.File.Hashes.SHA256
			} else {
				sha, err = cases.ResolveSample(db, arg)
				if err != nil {
					return userErr(fmt.Errorf("%s: %w", terminal.Sanitize(arg), err))
				}
			}
			if err := cases.AddSample(db, a[0], sha); err != nil {
				return userErr(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s to %s\n", sha[:16], a[0])
		}
		return nil
	})
	c.AddCommand(add)
	var noteSample string
	note := &cobra.Command{Use: "note <case> <text...>", Short: "Add an analyst note", Args: usageArgs(cobra.MinimumNArgs(2))}
	note.Flags().StringVar(&noteSample, "sample", "", "SHA-256 prefix of the sample the note is about")
	note.RunE = with(func(cmd *cobra.Command, db *database.DB, a []string) error {
		sha := ""
		if noteSample != "" {
			s, err := cases.ResolveSample(db, noteSample)
			if err != nil {
				return userErr(err)
			}
			sha = s
		}
		if err := cases.AddNote(db, a[0], sha, strings.Join(a[1:], " ")); err != nil {
			return userErr(err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "note added")
		return nil
	})
	c.AddCommand(note)
	for _, st := range []string{"close", "reopen"} {
		st := st
		status := map[string]string{"close": "closed", "reopen": "open"}[st]
		c.AddCommand(&cobra.Command{Use: st + " <case>", Short: strings.ToUpper(st[:1]) + st[1:] + " a case", Args: usageArgs(cobra.ExactArgs(1)),
			RunE: with(func(cmd *cobra.Command, db *database.DB, a []string) error {
				if err := cases.SetStatus(db, a[0], status); err != nil {
					return userErr(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "case %s is %s\n", a[0], status)
				return nil
			})})
	}
	c.AddCommand(&cobra.Command{Use: "search <words>", Short: "Search notes", Args: usageArgs(cobra.MinimumNArgs(1)),
		RunE: with(func(cmd *cobra.Command, db *database.DB, a []string) error {
			hits, err := cases.Search(db, strings.Join(a, " "))
			if err != nil {
				return usagef("%v", err)
			}
			for _, h := range hits {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s\n", safe(h.Case), h.At, clip(safe(strings.ReplaceAll(h.Body, "\n", " ")), 100))
			}
			if len(hits) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no notes match")
			}
			return nil
		})})
	c.AddCommand(&cobra.Command{Use: "timeline <case>", Short: "Show the case timeline", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: with(func(cmd *cobra.Command, db *database.DB, a []string) error {
			r, err := cases.BuildReport(db, a[0])
			if err != nil {
				return userErr(err)
			}
			for _, e := range r.Timeline {
				sha := ""
				if e.SHA256 != "" {
					sha = e.SHA256[:12]
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %-14s %-12s %s\n", e.At, safe(e.Kind), sha, safe(e.Detail))
			}
			return nil
		})})
	var out, format string
	rep := &cobra.Command{Use: "report <case>", Short: "Write a case report (html, markdown, csv or json)", Args: usageArgs(cobra.ExactArgs(1))}
	rep.Flags().StringVarP(&out, "output", "o", "", "write to a file; the format follows the extension")
	rep.Flags().StringVar(&format, "format", "", "markdown (default), html, csv or json")
	rep.RunE = with(func(cmd *cobra.Command, db *database.DB, a []string) error {
		r, err := cases.BuildReport(db, a[0])
		if err != nil {
			return userErr(err)
		}
		f := format
		if f == "" && out != "" {
			if ef, ok := reporting.ExtFormat(out); ok {
				f = ef
			} else if strings.HasSuffix(strings.ToLower(out), ".json") {
				f = "json"
			}
		}
		if f == "" {
			f = "markdown"
		}
		emit := func(w io.Writer) error {
			if f == "json" {
				return encode(w, r)
			}
			return reporting.Case(w, f, r)
		}
		if out == "" {
			return emit(cmd.OutOrStdout())
		}
		if err := writeFile(filepath.Clean(out), emit); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "case report written to %s\n", out)
		return nil
	})
	c.AddCommand(rep)
	return c
}

func newSimilarCmd(g *globals) *cobra.Command {
	var limit int
	c := &cobra.Command{Use: "similar <file|sha256-prefix>", Short: "Find stored samples that resemble a file",
		Long: "Compares a file with every sample in the local database using TLSH and ssdeep, then a documented structural overlap (imports, sections, strings, indicators, capabilities, import hash). Distances and overlaps are shown as measured; none is a probability or evidence of a shared family. See docs/SIMILARITY.md.",
		Args: usageArgs(cobra.ExactArgs(1))}
	c.Flags().IntVar(&limit, "limit", 10, "how many results to show")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		db, err := g.needDB()
		if err != nil {
			return err
		}
		defer db.Close() //nolint:errcheck // short command
		cfg, err := g.loadConfig()
		if err != nil {
			return err
		}
		var rep *models.Report
		if st, serr := os.Stat(args[0]); serr == nil && st.Mode().IsRegular() {
			rep, err = engine.Analyze(context.Background(), args[0], engine.Options{Config: cfg, Profile: engine.ProfileInfo})
			if err != nil {
				return err
			}
			if aerr := db.Annotate(rep); aerr != nil {
				return aerr
			}
			if rerr := db.Record(rep); rerr != nil {
				return rerr
			}
		} else {
			sha, rerr := cases.ResolveSample(db, args[0])
			if rerr != nil {
				return usagef("%v", rerr)
			}
			if rep, err = db.LoadReport(sha); err != nil {
				return err
			}
		}
		hits, err := db.Similar(rep, limit)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
		fmt.Fprintf(out, "%s %s\n", st.Bold("Similar to"), safe(rep.File.Name)+"  "+rep.File.Hashes.SHA256)
		if len(hits) == 0 {
			fmt.Fprintln(out, "no stored sample resembles this file (the database may simply not hold related samples yet)")
			return nil
		}
		fmt.Fprintf(out, "%s\n", st.Dim("TLSH: lower is closer. ssdeep: higher is closer. Overlap: weighted structural overlap, 0 to 1, shown only with 3 or more comparable properties. None is a probability or evidence of shared origin."))
		for _, h := range hits {
			s := h.Similarity
			t, ss, ov := "TLSH n/a", "ssdeep n/a", "overlap n/a"
			if s.HasTLSH {
				t = fmt.Sprintf("TLSH %d (%s)", s.TLSHDistance, similarityLabelT(s.TLSHDistance))
			}
			if s.HasSSDeep {
				ss = fmt.Sprintf("ssdeep %d", s.SSDeepScore)
			}
			if s.HasOverlap {
				ov = fmt.Sprintf("overlap %.2f", s.Overlap)
			}
			fmt.Fprintf(out, "\n%s  %s\n  %s | %s | %s", h.SHA256[:16], safe(h.Name), t, ss, ov)
			if len(h.Shared) > 0 {
				fmt.Fprintf(out, "\n  shares: %s", strings.Join(h.Shared, ", "))
			}
			fmt.Fprintln(out)
			if g.verbose {
				for _, comp := range s.Components {
					fmt.Fprintf(out, "    %-12s %.3f (weight %.2f)  %s\n", comp.Name, comp.Score, comp.Weight, st.Dim(comp.Note))
				}
			}
		}
		return nil
	}
	c.Flags().BoolVarP(&g.verbose, "verbose", "v", false, "show each overlap component")
	return c
}

func similarityLabelT(d int) string { return similarity.TLSHLabel(d) }
