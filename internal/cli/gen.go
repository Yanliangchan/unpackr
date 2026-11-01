package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// genPackaging writes unpackr.1 and the bash, zsh and fish completions.
func genPackaging(root *cobra.Command, dir, date string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(name string, fn func(f *os.File) error) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	if err := write("unpackr.1", func(f *os.File) error { return WriteMan(f, root, date) }); err != nil {
		return err
	}
	if err := write("unpackr.bash", func(f *os.File) error { return root.GenBashCompletionV2(f, true) }); err != nil {
		return err
	}
	if err := write("_unpackr", func(f *os.File) error { return root.GenZshCompletion(f) }); err != nil {
		return err
	}
	return write("unpackr.fish", func(f *os.File) error { return root.GenFishCompletion(f, true) })
}
