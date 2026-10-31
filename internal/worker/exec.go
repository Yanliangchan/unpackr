package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Yanliangchan/unpackr/internal/safety"
)

// ExecMode is the value of EnvVar that selects the exec worker.
const ExecMode = "exec"

// exitSandbox is the exit status the exec worker uses when it refused to run
// the tool because it could not confine itself.
const exitSandbox = 97

// ExecSpec describes an external tool to run under confinement.
type ExecSpec struct {
	Exe  string   `json:"exe"`  // absolute path, symlinks already resolved
	Args []string `json:"args"` // argv[1:]
	Env  []string `json:"env"`
	// WorkDir is the only writable location.
	WorkDir string `json:"work_dir"`
	// ExecFiles are the files that may be executed: the tool and its loader.
	ExecFiles []string `json:"exec_files"`
	// ReadOnly lists directories the tool may read but not execute from
	// (shared libraries).
	ReadOnly         []string `json:"read_only"`
	ReadFiles        []string `json:"read_files"`
	MemoryLimitBytes uint64   `json:"memory_limit_bytes"`
	MaxFileBytes     uint64   `json:"max_file_bytes"`
}

// ExecResult is what the tool produced.
type ExecResult struct {
	Stdout, Stderr string
	ExitCode       int
	Duration       time.Duration
}

// ErrExecSandbox is returned when the tool was not run because the worker
// could not be fully confined. The tool never runs unconfined.
var ErrExecSandbox = errors.New("external tool not run: the sandbox could not be fully established")

// serveExec confines the process and replaces it with the tool. It never
// returns on success. Any failure to confine is fatal: the tool must not run
// with less protection than requested.
func serveExec() {
	var spec ExecSpec
	if err := readFrame(os.Stdin, &spec); err != nil {
		fmt.Fprintln(os.Stderr, "unpackr-exec: bad request:", err)
		os.Exit(2)
	}
	st := safety.ApplySandbox(safety.SandboxOptions{
		MemoryLimitBytes: spec.MemoryLimitBytes,
		MaxFileSizeBytes: spec.MaxFileBytes,
		WritableDirs:     []string{spec.WorkDir},
		AllowExec:        true,
		ExecFiles:        spec.ExecFiles,
		ReadOnlyNoExec:   spec.ReadOnly,
		ReadFiles:        spec.ReadFiles,
	})
	if st.Level != safety.LevelFull {
		fmt.Fprintf(os.Stderr, "unpackr-exec: sandbox %s: %s\n", st.Level, st.Detail)
		os.Exit(exitSandbox)
	}
	argv := append([]string{spec.Exe}, spec.Args...)
	err := syscall.Exec(spec.Exe, argv, spec.Env) //nolint:gosec // exe is resolved and confined by Landlock
	fmt.Fprintln(os.Stderr, "unpackr-exec: exec failed:", err)
	os.Exit(126)
}

// RunExec runs spec in an exec worker with a wall-clock timeout. Output is
// captured and size-capped. The tool's output is untrusted data.
func RunExec(ctx context.Context, spec ExecSpec, timeout time.Duration) (*ExecResult, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, self)
	cmd.Env = []string{EnvVar + "=" + ExecMode}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	out, errb := &cappedBuffer{max: 1 << 20}, &cappedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start exec worker: %w", err)
	}
	werr := writeFrame(stdin, spec)
	_ = stdin.Close()
	waitErr := cmd.Wait()
	res := &ExecResult{Stdout: out.buf.String(), Stderr: errb.buf.String(), Duration: time.Since(start)}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s killed after %s: %w", spec.Exe, timeout, ctx.Err())
	}
	if werr != nil {
		return res, werr
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		res.ExitCode = 0
	case errors.As(waitErr, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return res, waitErr
	}
	if res.ExitCode == exitSandbox && bytes.Contains(errb.buf.Bytes(), []byte("unpackr-exec: sandbox")) {
		return res, fmt.Errorf("%w: %s", ErrExecSandbox, firstLine(res.Stderr))
	}
	return res, nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
