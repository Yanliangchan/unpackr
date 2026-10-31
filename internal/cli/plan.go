package cli

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/safety"
)

// Mode is the primary action. Exactly one applies.
type Mode int

const (
	ModeInfo Mode = iota
	ModeQuick
	ModeCompare
)

func (m Mode) String() string { return [...]string{"info", "quick", "compare"}[m] }

// Flags are the parsed command-line options relevant to planning.
type Flags struct {
	Info, Quick, Compare      bool
	Deep, Verbose             bool
	Unpack, Extract, Reverse  bool
	Output, Format, OutputDir string
	Modules                   string
	Quiet                     bool
}

// Plan is a validated request.
type Plan struct {
	Mode       Mode
	Paths      []string
	Verbose    bool
	Unpack     bool
	Format     string // terminal | json
	OutputFile string
	OutputFmt  string // format of OutputFile
	OutputDir  string
	Modules    []string
}

// KnownModules lists the values accepted by --modules in this build.
var KnownModules = []string{"identification", "structure", "analysis", "signatures"}

var allFormats = []string{"terminal", "json", "html", "markdown", "csv"}

func formatFromExt(path string) (string, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json", true
	case ".html", ".htm":
		return "html", true
	case ".md", ".markdown":
		return "markdown", true
	case ".csv":
		return "csv", true
	}
	return "", false
}

// BuildPlan validates flag combinations. It is a pure function so the whole
// grammar can be tested without running anything. Usage errors are reported
// before "not implemented" so that a malformed command line is always
// diagnosed first.
func BuildPlan(f Flags, args []string) (Plan, error) {
	var p Plan
	modes := 0
	for _, b := range []bool{f.Info, f.Quick, f.Compare} {
		if b {
			modes++
		}
	}
	if modes > 1 {
		return p, usagef("-i/--info, -q/--quick and -c/--compare are mutually exclusive")
	}
	switch {
	case f.Compare:
		p.Mode = ModeCompare
	case f.Quick:
		p.Mode = ModeQuick
	default:
		p.Mode = ModeInfo // also the default when only a path is given
	}
	if len(args) == 0 {
		return p, usagef("no input path given")
	}
	if p.Mode == ModeCompare && len(args) != 2 {
		return p, usagef("-c/--compare takes exactly two files, got %d", len(args))
	}
	if f.Quick && f.Deep {
		return p, usagef("-q/--quick and -d/--deep contradict each other")
	}
	if p.Mode == ModeCompare && (f.Deep || f.Unpack || f.Extract || f.Reverse) {
		return p, usagef("-c/--compare only combines with -v, -o and --format")
	}
	p.Paths = args
	p.Verbose = f.Verbose
	p.Unpack = f.Unpack

	p.Format = f.Format
	if p.Format == "" {
		p.Format = "terminal"
	}
	valid := false
	for _, v := range allFormats {
		if v == p.Format {
			valid = true
		}
	}
	if !valid {
		return p, usagef("unknown --format %q (valid: %s)", p.Format, strings.Join(allFormats, ", "))
	}
	if f.Output != "" {
		ext, ok := formatFromExt(f.Output)
		if !ok && f.Format == "" {
			return p, usagef("cannot infer an output format from %q: use .json, .html, .md or .csv, or pass --format", f.Output)
		}
		if f.Format != "" {
			ext = f.Format
		}
		p.OutputFile, p.OutputFmt = f.Output, ext
		for _, in := range args {
			if safety.SameFile(in, f.Output) {
				return p, usagef("refusing to write the report over the input file %s", in)
			}
		}
	}
	p.OutputDir = f.OutputDir

	if f.Modules != "" {
		for _, m := range strings.Split(f.Modules, ",") {
			m = strings.TrimSpace(m)
			ok := false
			for _, k := range KnownModules {
				ok = ok || k == m
			}
			if !ok {
				return p, usagef("unknown module %q (available in this build: %s)", m, strings.Join(KnownModules, ", "))
			}
			p.Modules = append(p.Modules, m)
		}
		sort.Strings(p.Modules)
	}

	// Valid commands that this build cannot honour.
	switch {
	case f.Deep:
		return p, &NotImplementedError{"-d/--deep (extended analysis)"}
	case f.Extract:
		return p, &NotImplementedError{"-x/--extract"}
	case f.Reverse:
		return p, &NotImplementedError{"-r/--reverse"}
	}
	for _, fm := range []string{p.Format, p.OutputFmt} {
		if fm != "" && fm != "terminal" && fm != "json" {
			return p, &NotImplementedError{"the " + fm + " report format"}
		}
	}
	if p.OutputFmt == "terminal" {
		return p, usagef("-o needs a file format (json), not terminal")
	}
	return p, nil
}
