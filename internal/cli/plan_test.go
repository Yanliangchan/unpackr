package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildPlanGrammar(t *testing.T) {
	type tc struct {
		name  string
		f     Flags
		args  []string
		usage bool
		notim bool
		mode  Mode
	}
	cases := []tc{
		{name: "path only defaults to info", args: []string{"a"}, mode: ModeInfo},
		{name: "-i", f: Flags{Info: true}, args: []string{"a"}, mode: ModeInfo},
		{name: "-q with several paths", f: Flags{Quick: true}, args: []string{"a", "b", "d/"}, mode: ModeQuick},
		{name: "-v modifies presentation only", f: Flags{Info: true, Verbose: true}, args: []string{"a"}, mode: ModeInfo},
		{name: "no path", f: Flags{Info: true}, usage: true},
		{name: "modes conflict", f: Flags{Info: true, Quick: true}, args: []string{"a"}, usage: true},
		{name: "compare needs two", f: Flags{Compare: true}, args: []string{"a"}, usage: true},
		{name: "compare three", f: Flags{Compare: true}, args: []string{"a", "b", "c"}, usage: true},
		{name: "compare with two files", f: Flags{Compare: true}, args: []string{"a", "b"}, mode: ModeCompare},
		{name: "quick and deep contradict", f: Flags{Quick: true, Deep: true}, args: []string{"a"}, usage: true},
		{name: "deep unimplemented", f: Flags{Deep: true}, args: []string{"a"}, notim: true},
		{name: "unpack is valid with info", f: Flags{Unpack: true}, args: []string{"a"}, mode: ModeInfo},
		{name: "unpack with quick", f: Flags{Unpack: true, Quick: true}, args: []string{"a"}, mode: ModeQuick},
		{name: "extract is valid", f: Flags{Extract: true}, args: []string{"a"}, mode: ModeInfo},
		{name: "reverse unimplemented", f: Flags{Reverse: true}, args: []string{"a"}, notim: true},
		{name: "compare with unpack is a usage error first", f: Flags{Compare: true, Unpack: true}, args: []string{"a", "b"}, usage: true},
		{name: "html unimplemented", f: Flags{Output: "r.html"}, args: []string{"a"}, notim: true},
		{name: "markdown unimplemented", f: Flags{Output: "r.md"}, args: []string{"a"}, notim: true},
		{name: "unknown extension", f: Flags{Output: "r.txt"}, args: []string{"a"}, usage: true},
		{name: "unknown extension with --format json", f: Flags{Output: "r.txt", Format: "json"}, args: []string{"a"}, mode: ModeInfo},
		{name: "bad --format", f: Flags{Format: "xml"}, args: []string{"a"}, usage: true},
		{name: "json output", f: Flags{Output: "r.json"}, args: []string{"a"}, mode: ModeInfo},
		{name: "unknown module", f: Flags{Modules: "imports"}, args: []string{"a"}, usage: true},
		{name: "known module", f: Flags{Modules: "identification"}, args: []string{"a"}, mode: ModeInfo},
	}
	for _, c := range cases {
		p, err := BuildPlan(c.f, c.args)
		var u *UsageError
		var n *NotImplementedError
		switch {
		case c.usage:
			if !errors.As(err, &u) {
				t.Errorf("%s: want usage error, got %v", c.name, err)
			}
		case c.notim:
			if !errors.As(err, &n) {
				t.Errorf("%s: want not-implemented, got %v", c.name, err)
			}
		default:
			if err != nil {
				t.Errorf("%s: unexpected %v", c.name, err)
			} else if p.Mode != c.mode {
				t.Errorf("%s: mode %v", c.name, p.Mode)
			}
		}
	}
}

func TestReportNeverOverwritesInput(t *testing.T) {
	in := filepath.Join(t.TempDir(), "sample.json")
	_ = os.WriteFile(in, []byte("{}"), 0o600)
	_, err := BuildPlan(Flags{Output: in}, []string{in})
	var u *UsageError
	if !errors.As(err, &u) {
		t.Fatalf("report over input must be refused, got %v", err)
	}
}

func TestExitCodes(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(&UsageError{"x"}) != 2 || ExitCode(&NotImplementedError{"x"}) != 4 || ExitCode(errors.New("x")) != 1 {
		t.Fatal("exit code mapping")
	}
}
