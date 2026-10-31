package unpacking

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// UPXOptions bound one unpack run.
type UPXOptions struct {
	Timeout        time.Duration
	MemoryBytes    uint64
	MaxOutputBytes uint64
}

// UPXRun is the raw outcome of the tool.
type UPXRun struct {
	OutPath  string
	ExitCode int
	Stderr   string
	Duration time.Duration
}

// RunUPX decompresses in (a copy inside workDir) to out (also inside workDir)
// with `upx -d`. UPX parses untrusted data in C++, so it runs only in the exec
// worker. A tool failure is an ordinary outcome (ExitCode != 0), not an error.
func RunUPX(ctx context.Context, t *Tool, workDir, in, out string, o UPXOptions) (*UPXRun, error) {
	spec := t.Spec(workDir, []string{"-d", "-q", "-o", out, in}, o.MemoryBytes, o.MaxOutputBytes)
	res, err := worker.RunExec(ctx, spec, o.Timeout)
	if err != nil {
		return nil, err
	}
	return &UPXRun{OutPath: out, ExitCode: res.ExitCode, Stderr: res.Stderr + res.Stdout, Duration: res.Duration}, nil
}

// FailureHint turns UPX's complaint into advice. The tool's text is untrusted
// and is sanitised before it is shown.
func FailureHint(stderr string) string {
	s := strings.ToLower(stderr)
	line := textutil.Sanitize(strings.TrimSpace(firstNonEmpty(stderr)))
	if len(line) > 200 {
		line = line[:200]
	}
	switch {
	case strings.Contains(s, "notpacked"), strings.Contains(s, "not packed"):
		return "upx reports the file is not packed (" + line + ")"
	case strings.Contains(s, "cantunpack"), strings.Contains(s, "can't unpack"), strings.Contains(s, "cannot unpack"), strings.Contains(s, "not supported"):
		return "upx recognised the file but cannot unpack it: it may use a newer UPX format than this UPX build, or have been modified to defeat `upx -d` (" + line + ")"
	case strings.Contains(s, "newer"), strings.Contains(s, "version"):
		return "upx cannot handle this file's format version; try a newer UPX (" + line + ")"
	}
	return "upx failed: " + line
}

func firstNonEmpty(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			return l
		}
	}
	return ""
}

// CheckOutput applies the file-level checks to a produced file: it must be a
// regular, non-empty file within the size and expansion limits.
func CheckOutput(inSize int64, outPath string, maxBytes uint64, maxRatio float64) ([]models.ValidationCheck, int64) {
	var checks []models.ValidationCheck
	st, err := os.Lstat(outPath)
	if err != nil {
		return []models.ValidationCheck{{Name: "output file exists", Passed: false, Detail: err.Error()}}, 0
	}
	regular := st.Mode().IsRegular()
	checks = append(checks, models.ValidationCheck{Name: "output is a regular file", Passed: regular, Detail: st.Mode().String()})
	checks = append(checks, models.ValidationCheck{Name: "output is not empty", Passed: st.Size() > 0, Detail: fmt.Sprintf("%d bytes", st.Size())})
	checks = append(checks, models.ValidationCheck{Name: "output within size limit", Passed: st.Size() >= 0 && uint64(st.Size()) <= maxBytes, Detail: fmt.Sprintf("%d bytes, limit %d", st.Size(), maxBytes)})
	ratio := 0.0
	if inSize > 0 {
		ratio = float64(st.Size()) / float64(inSize)
	}
	checks = append(checks, models.ValidationCheck{Name: "expansion ratio within limit (decompression-bomb guard)", Passed: ratio <= maxRatio, Detail: fmt.Sprintf("%.1fx, limit %.0fx", ratio, maxRatio)})
	return checks, st.Size()
}

// WorkDir creates a private temporary directory (mode 0700).
func WorkDir() (string, error) {
	d, err := os.MkdirTemp("", "unpackr-work-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(d, 0o700); err != nil {
		_ = os.RemoveAll(d)
		return "", err
	}
	return filepath.Clean(d), nil
}

// AllPassed reports whether every check passed.
func AllPassed(cs []models.ValidationCheck) bool {
	for _, c := range cs {
		if !c.Passed {
			return false
		}
	}
	return true
}
