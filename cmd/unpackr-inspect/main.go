// Command unpackr-inspect is the interactive viewer started by `unpackr
// inspect`. It is a separate executable so that the terminal UI library (which
// probes the terminal when it is linked in) stays out of the main binary.
//
// It reads one already-sanitised JSON report from file descriptor 3, shows it,
// and opens no files itself. Run it through `unpackr inspect`.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Yanliangchan/unpackr/internal/tui"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

const reportFD = 3

// maxReport bounds what the helper will read from the parent.
const maxReport = 128 << 20

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "unpackr-inspect:", err)
		os.Exit(1)
	}
}

func run() error {
	in := os.NewFile(reportFD, "report")
	if in == nil {
		return fmt.Errorf("this program is started by `unpackr inspect`")
	}
	data, err := io.ReadAll(io.LimitReader(in, maxReport+1))
	_ = in.Close()
	if err != nil {
		return fmt.Errorf("no report on descriptor %d (run it through `unpackr inspect`): %w", reportFD, err)
	}
	if len(data) > maxReport {
		return fmt.Errorf("report larger than %d MiB", maxReport>>20)
	}
	var r models.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("report is not valid: %w", err)
	}
	return tui.Run(&r, os.Getenv("UNPACKR_COLOR") == "1")
}
