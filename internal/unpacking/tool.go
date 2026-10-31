// Package unpacking drives external unpackers. Every tool runs in the exec
// worker: confined by Landlock and seccomp, with write access to a private
// work directory only, no network, a memory limit and a wall-clock timeout.
// The tool's input is always a copy; the sample is never handed over.
package unpacking

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/worker"
)

// Tool is a located external program.
type Tool struct {
	Name    string
	Path    string // absolute, symlinks resolved
	Version string
	loader  string
}

var reVersion = regexp.MustCompile(`(?i)\bupx\s+v?(\d+\.\d+(?:\.\d+)?)`)

// Locate finds name on PATH and resolves it. A missing tool is reported with
// exec.ErrNotFound so callers can give installation guidance.
func Locate(name string) (*Tool, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(real)
	if err != nil {
		return nil, err
	}
	t := &Tool{Name: name, Path: abs}
	if f, err := elf.Open(abs); err == nil {
		for _, pr := range f.Progs {
			if pr.Type == elf.PT_INTERP {
				buf := make([]byte, pr.Filesz)
				if _, err := pr.ReadAt(buf, 0); err == nil {
					l := strings.TrimRight(string(buf), "\x00")
					if r, err := filepath.EvalSymlinks(l); err == nil {
						t.loader = r
					} else {
						t.loader = l
					}
				}
			}
		}
		_ = f.Close()
	}
	return t, nil
}

// Spec builds the confinement for running the tool with args in workDir.
func (t *Tool) Spec(workDir string, args []string, memBytes, maxFile uint64) worker.ExecSpec {
	exe := []string{t.Path}
	if t.loader != "" {
		exe = append(exe, t.loader)
	}
	var ro []string
	for _, d := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		if _, err := os.Stat(d); err == nil {
			ro = append(ro, d)
		}
	}
	var files []string
	if _, err := os.Stat("/etc/ld.so.cache"); err == nil {
		files = append(files, "/etc/ld.so.cache")
	}
	return worker.ExecSpec{
		Exe: t.Path, Args: args, WorkDir: workDir, ExecFiles: exe, ReadOnly: ro, ReadFiles: files,
		Env:              []string{"PATH=", "LC_ALL=C", "TMPDIR=" + workDir, "HOME=" + workDir},
		MemoryLimitBytes: memBytes, MaxFileBytes: maxFile,
	}
}

// ProbeVersion asks the tool for its version inside the sandbox.
func (t *Tool) ProbeVersion(ctx context.Context, workDir string, memBytes uint64) error {
	res, err := worker.RunExec(ctx, t.Spec(workDir, []string{"--version"}, memBytes, 1<<20), 20*time.Second)
	if err != nil {
		return err
	}
	if m := reVersion.FindStringSubmatch(res.Stdout + res.Stderr); m != nil {
		t.Version = m[1]
		return nil
	}
	return fmt.Errorf("could not read a version from %s output", t.Name)
}
