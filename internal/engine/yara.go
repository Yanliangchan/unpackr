package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/Yanliangchan/unpackr/assets/rules"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/internal/yara"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// runYara scans the sample with YARA-X when it is installed and selected. It
// never fails the analysis: the outcome is reported as engine status.
func runYara(ctx context.Context, f *os.File, size int64, o Options) ([]models.YaraMatch, models.EngineStatus) {
	eng := models.EngineStatus{Name: "YARA-X"}
	if !wants(o.Modules, "signatures") {
		eng.Status, eng.Detail = "skipped", "not selected with --modules"
		return nil, eng
	}
	mem := uint64(o.Config.WorkerMemoryMB) << 20
	tool, err := yara.Locate(ctx, o.YaraName, mem)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		eng.Status, eng.Detail = "missing", "YARA-X (`yr`) is not installed; only native signatures were used. Install it from your package manager or https://github.com/VirusTotal/yara-x"
		return nil, eng
	case err != nil:
		eng.Status = "failed"
		if errors.Is(err, worker.ErrExecSandbox) {
			eng.Detail = "not run: it could not be fully sandboxed (" + textutil.Sanitize(err.Error()) + ")"
		} else {
			eng.Detail = textutil.Sanitize(err.Error())
		}
		return nil, eng
	}
	res, err := yara.Scan(ctx, tool, io.NewSectionReader(f, 0, size), yara.Options{
		Builtin: rules.FS, BuiltinDir: ".", UserRuleDir: o.UserRuleDir,
		Timeout: time.Duration(o.Config.TimeoutSeconds) * time.Second, MemoryBytes: mem,
	})
	if err != nil {
		eng.Status, eng.Version, eng.Detail = "failed", tool.Version, textutil.Sanitize(err.Error())
		return nil, eng
	}
	return res.Matches, res.Engine
}
