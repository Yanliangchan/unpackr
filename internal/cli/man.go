package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Yanliangchan/unpackr/internal/version"
)

// roff escapes text for a man page: backslashes, leading dots and quotes.
func roff(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, ".") || strings.HasPrefix(l, "'") {
			lines[i] = `\&` + l
		}
	}
	return strings.Join(lines, "\n")
}

func flagLine(f *pflag.Flag) string {
	var b strings.Builder
	if f.Shorthand != "" {
		fmt.Fprintf(&b, `\fB\-%s\fR, `, f.Shorthand)
	}
	fmt.Fprintf(&b, `\fB\-\-%s\fR`, strings.ReplaceAll(f.Name, "-", `\-`))
	if f.Value.Type() != "bool" {
		fmt.Fprintf(&b, ` \fI%s\fR`, roff(strings.ToUpper(f.Value.Type())))
	}
	return b.String()
}

// WriteMan writes the manual page for the command tree. It is generated from
// the live command definitions, so it cannot describe a flag that does not
// exist or omit one that does.
func WriteMan(w io.Writer, root *cobra.Command, date string) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p(".TH UNPACKR 1 %q \"UNPACKR %s\" \"User Commands\"\n", date, version.Version)
	p(".SH NAME\nunpackr \\- binary intelligence and static malware analysis toolkit\n")
	p(".SH SYNOPSIS\n.B unpackr\n[\\fIflags\\fR] \\fIfile\\fR|\\fIdirectory\\fR...\n.br\n.B unpackr\n\\fB\\-c\\fR \\fIfirst\\fR \\fIsecond\\fR\n.br\n.B unpackr\n\\fIcommand\\fR [\\fIargs\\fR]\n")
	p(".SH DESCRIPTION\n")
	p("%s\n", roff("UNPACKR analyses executables statically and offline: it identifies the file by its content, parses its structure, estimates how it was built, assesses packing, infers capabilities from what the file references, extracts indicators, and can unpack UPX and extract PyInstaller bundles. Samples are never executed.")+"\n.PP\n"+
		roff("Every finding carries evidence and an ordinal confidence. Capabilities are inferences from references, not observed behaviour; confidence is not a probability."))
	p(".SH OPTIONS\n")
	flags := []*pflag.Flag{}
	seen := map[string]bool{}
	add := func(f *pflag.Flag) {
		if !seen[f.Name] {
			seen[f.Name] = true
			flags = append(flags, f)
		}
	}
	root.Flags().VisitAll(add)
	root.PersistentFlags().VisitAll(add)
	sort.SliceStable(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	for _, f := range flags {
		if f.Hidden || f.Name == "help" {
			continue
		}
		p(".TP\n%s\n%s\n", flagLine(f), roff(f.Usage))
	}
	p(".SH COMMANDS\n")
	cmds := root.Commands()
	sort.SliceStable(cmds, func(i, j int) bool { return cmds[i].Name() < cmds[j].Name() })
	for _, c := range cmds {
		if c.Hidden || c.Name() == "help" {
			continue
		}
		p(".TP\n\\fB%s\\fR\n%s\n", roff(c.Use), roff(c.Short))
		subs := c.Commands()
		sort.SliceStable(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		for _, s := range subs {
			if s.Hidden {
				continue
			}
			p(".RS\n.TP\n\\fB%s %s\\fR\n%s\n.RE\n", roff(c.Name()), roff(s.Use), roff(s.Short))
		}
	}
	p(".SH EXIT STATUS\n.TP\n.B 0\nSuccess.\n.TP\n.B 1\nAn input could not be analysed.\n.TP\n.B 2\nUsage error.\n.TP\n.B 4\nA valid request that this build does not implement.\n")
	p(".SH FILES\n.TP\n.I $XDG_CONFIG_HOME/unpackr/config.yaml\nConfiguration.\n.TP\n.I $XDG_CONFIG_HOME/unpackr/rules/\nAnalyst YARA rules (never counted as evidence).\n.TP\n.I $XDG_CONFIG_HOME/unpackr/artvault/custom/\nCustom banners.\n.TP\n.I $XDG_DATA_HOME/unpackr/db.json\nLocal sample memory: hashes, reports and notes, never samples.\n")
	p(".SH SECURITY\n%s\n", roff("Every analysed file is treated as hostile. Parsing and external tools run in separate processes that confine themselves with Landlock and seccomp before touching input; if confinement cannot be established the tool is not run. Run `unpackr doctor` to see what the current system provides. Extracted and unpacked files are written without execute permission and are never run. Reports defang network indicators and sanitise every string taken from a sample."))
	p(".SH SEE ALSO\nupx(1), yr(1), capa(1), ghidra(1)\n.PP\nFull documentation: /usr/share/doc/unpackr/\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func newGenCmd(g *globals, root *cobra.Command) *cobra.Command {
	var dir, date string
	c := &cobra.Command{Use: "gen-packaging --dir DIR", Hidden: true, Short: "Write the man page and shell completions (used by the package build)", Args: usageArgs(cobra.NoArgs)}
	c.Flags().StringVar(&dir, "dir", "", "output directory")
	c.Flags().StringVar(&date, "date", "1970-01-01", "date for the man page header (use SOURCE_DATE_EPOCH for reproducible builds)")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if dir == "" {
			return usagef("--dir is required")
		}
		return genPackaging(root, dir, date)
	}
	return c
}
