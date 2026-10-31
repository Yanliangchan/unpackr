// Command unpackr is a static binary-analysis toolkit.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Yanliangchan/unpackr/internal/cli"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/internal/worker"

	_ "github.com/Yanliangchan/unpackr/internal/engine" // registers worker tasks
)

func main() {
	// A worker is this same binary re-executed; it must confine itself before
	// doing anything else, so this check precedes all other work.
	if worker.IsWorker() {
		worker.Serve()
	}
	root := cli.NewRoot()
	if err := root.Execute(); err != nil {
		var u *cli.UsageError
		if errors.As(err, &u) {
			fmt.Fprintf(os.Stderr, "unpackr: %s\nTry 'unpackr --help'.\n", terminal.Sanitize(err.Error()))
		} else {
			fmt.Fprintf(os.Stderr, "unpackr: %s\n", terminal.Sanitize(err.Error()))
		}
		os.Exit(cli.ExitCode(err))
	}
}
