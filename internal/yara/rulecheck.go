package yara

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
)

// Limits for testing a rule.
const (
	MaxRuleBytes     = 256 << 10
	MaxControlFiles  = 20000
	maxListedMatches = 50
)

// TestOptions control one rule test.
type TestOptions struct {
	Timeout     time.Duration
	MemoryBytes uint64
	// ControlDirs are directories of files believed clean. They are read in
	// place, read-only, by the sandboxed scanner; nothing is copied or run.
	ControlDirs []string
}

// TestResult is what testing a rule found.
type TestResult struct {
	Compiled     bool
	CompileError string
	// SampleTested is true when a sample was supplied; MatchedSample says
	// whether the rule matched it.
	SampleTested  bool
	MatchedSample bool
	// ControlFiles counts the regular files in the control directories and
	// ControlMatches lists those the rule matched (relative paths, capped).
	ControlFiles     int
	ControlMatches   []string
	ControlMatchN    int
	ControlTruncated bool
	Duration         time.Duration
}

// TestRule checks that a rule compiles, optionally that it matches a sample,
// and optionally how many files in control directories it matches. All scanning
// is done by yr inside the exec sandbox.
func TestRule(ctx context.Context, t *unpacking.Tool, rule string, sample io.Reader, o TestOptions) (*TestResult, error) {
	start := time.Now()
	if len(rule) == 0 || len(rule) > MaxRuleBytes {
		return nil, fmt.Errorf("rule is empty or larger than %d KiB", MaxRuleBytes>>10)
	}
	res := &TestResult{}
	work, err := unpacking.WorkDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir

	rulePath := filepath.Join(work, "rule.yar")
	if err := writeNew(rulePath, strings.NewReader(rule)); err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	run := func(args []string, extraRO ...string) (*worker.ExecResult, error) {
		spec := t.Spec(work, args, o.MemoryBytes, 1<<20)
		spec.ReadOnly = append(spec.ReadOnly, extraRO...)
		r, err := worker.RunExec(ctx, spec, o.Timeout)
		return r, err
	}

	chk, err := run([]string{"check", rulePath})
	if err != nil {
		return nil, err
	}
	if chk.ExitCode != 0 {
		res.CompileError = textutil.Sanitize(clip(firstLines(chk.Stderr+chk.Stdout), 800))
		res.Duration = time.Since(start)
		return res, nil
	}
	res.Compiled = true

	scanArgs := []string{"scan", "-o", "ndjson", "--disable-console-logs", "-w"}
	if sample != nil {
		target := filepath.Join(work, "target.bin")
		if err := writeNew(target, sample); err != nil {
			return nil, fmt.Errorf("staging sample: %w", err)
		}
		r, err := run(append(append([]string{}, scanArgs...), rulePath, target))
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			return nil, fmt.Errorf("yr exited with status %d: %s", r.ExitCode, firstLines(r.Stderr))
		}
		res.SampleTested = true
		res.MatchedSample = len(matchedPaths(r.Stdout)) > 0
	}

	for _, dir := range o.ControlDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("control path %q is not a directory", dir)
		}
		n, trunc := countFiles(abs, MaxControlFiles-res.ControlFiles)
		res.ControlFiles += n
		res.ControlTruncated = res.ControlTruncated || trunc
		r, err := run(append(append([]string{}, scanArgs...), "-r", rulePath, abs), abs)
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			return nil, fmt.Errorf("yr exited with status %d: %s", r.ExitCode, firstLines(r.Stderr))
		}
		for _, p := range matchedPaths(r.Stdout) {
			res.ControlMatchN++
			if len(res.ControlMatches) < maxListedMatches {
				rel, rerr := filepath.Rel(abs, p)
				if rerr != nil {
					rel = p
				}
				res.ControlMatches = append(res.ControlMatches, textutil.Sanitize(clip(rel, 200)))
			}
		}
	}
	res.Duration = time.Since(start)
	return res, nil
}

// matchedPaths returns the target of each ndjson line that has at least one
// rule. The output comes from a process that parsed hostile data, so lines are
// decoded strictly and ignored when malformed.
func matchedPaths(out string) []string {
	var paths []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var v struct {
			Path  string            `json:"path"`
			Rules []json.RawMessage `json:"rules"`
		}
		if json.Unmarshal([]byte(l), &v) != nil || len(v.Rules) == 0 {
			continue
		}
		paths = append(paths, v.Path)
	}
	return paths
}

// countFiles counts regular files below dir without following symlinks.
func countFiles(dir string, limit int) (int, bool) {
	n := 0
	truncated := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if n++; n >= limit {
				truncated = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return n, truncated
}
