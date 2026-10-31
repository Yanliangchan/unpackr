package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/assets"
	"github.com/Yanliangchan/unpackr/internal/artvault"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/terminal"
)

func loadVault() (*artvault.Vault, []error, error) {
	return artvault.Load(assets.ArtVault, "artvault", customArtDir())
}

func newArtCmd(g *globals) *cobra.Command {
	art := &cobra.Command{Use: "art", Short: "Browse the ArtVault banner library"}
	art.AddCommand(
		&cobra.Command{Use: "list", Short: "List all banners", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
			v, warns, err := loadVault()
			if err != nil {
				return err
			}
			fav := map[string]bool{}
			for _, f := range artvault.Favourites(config.Dir()) {
				fav[f] = true
			}
			out := cmd.OutOrStdout()
			for _, b := range v.All() {
				star := " "
				if fav[b.ID] {
					star = "*"
				}
				fmt.Fprintf(out, "%s %-12s %-12s %s\n", star, terminal.Sanitize(b.ID), terminal.Sanitize(b.Category), terminal.Sanitize(b.Title))
			}
			for _, w := range warns {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", w)
			}
			return nil
		}},
		&cobra.Command{Use: "show <id>", Short: "Display one banner", Args: usageArgs(cobra.ExactArgs(1)), RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := loadVault()
			if err != nil {
				return err
			}
			b, ok := v.Get(args[0])
			if !ok {
				return usagef("no banner with id %q (try 'unpackr art list')", args[0])
			}
			fmt.Fprintln(cmd.OutOrStdout(), b.Text())
			return nil
		}},
		&cobra.Command{Use: "categories", Short: "List banner categories", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
			v, _, err := loadVault()
			if err != nil {
				return err
			}
			m := v.Categories()
			names := make([]string, 0, len(m))
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintf(cmd.OutOrStdout(), "%-14s %d\n", terminal.Sanitize(n), m[n])
			}
			return nil
		}},
		&cobra.Command{Use: "favourite <id>", Aliases: []string{"favorite"}, Short: "Mark a banner as a favourite", Args: usageArgs(cobra.ExactArgs(1)), RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := loadVault()
			if err != nil {
				return err
			}
			if _, ok := v.Get(args[0]); !ok {
				return usagef("no banner with id %q", args[0])
			}
			return artvault.AddFavourite(config.Dir(), args[0])
		}},
		&cobra.Command{Use: "favourites", Aliases: []string{"favorites"}, Short: "List favourite banners", Args: usageArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
			for _, f := range artvault.Favourites(config.Dir()) {
				fmt.Fprintln(cmd.OutOrStdout(), terminal.Sanitize(f))
			}
			return nil
		}},
	)
	return art
}
