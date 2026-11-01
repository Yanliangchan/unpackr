package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestManListsEachFlagOnce(t *testing.T) {
	root := NewRoot()
	var b bytes.Buffer
	if err := WriteMan(&b, root, "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	root.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == "help" {
			return
		}
		needle := `\-\-` + strings.ReplaceAll(f.Name, "-", `\-`)
		if n := strings.Count(out, ".TP\n\\fB"); n == 0 {
			t.Fatal("no option entries")
		}
		if c := strings.Count(out, needle+`\fR`) + strings.Count(out, needle+`\fP`); c > 1 {
			t.Errorf("flag %s listed %d times", f.Name, c)
		}
	})
}
