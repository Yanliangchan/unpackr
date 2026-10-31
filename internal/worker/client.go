package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Options configure one worker invocation.
type Options struct {
	// Exe is the binary to re-execute. Defaults to the running executable.
	Exe string
	// Timeout is a hard wall-clock limit. The whole process group is killed.
	Timeout time.Duration
	// MemoryLimitBytes is applied inside the worker as RLIMIT_AS.
	MemoryLimitBytes uint64
	// WritableDirs lists the directories the worker may write (extraction).
	WritableDirs []string
	// RequireSandbox makes a result with less than full confinement an error.
	RequireSandbox bool
}

// Result is a decoded worker response.
type Result struct {
	Sandbox  models.SandboxStatus
	Raw      json.RawMessage
	Stderr   string
	Duration time.Duration
}

// ErrSandbox is returned when full confinement was required but not achieved.
var ErrSandbox = errors.New("worker could not be fully sandboxed")

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// Run executes task in a fresh sandboxed worker. input may be nil for tasks
// that read nothing.
func Run(ctx context.Context, task string, params any, input *os.File, size int64, o Options) (*Result, error) {
	exe := o.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		rawParams = b
	}
	if input == nil {
		size = -1
	}

	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = []string{EnvVar + "=1"} // scrubbed environment
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	if input != nil {
		cmd.ExtraFiles = []*os.File{input}
	}
	var out, errb = &cappedBuffer{max: MaxFrame + 8}, &cappedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}
	werr := writeFrame(stdin, Request{Task: task, Params: rawParams, InputSize: size, MemoryLimitBytes: o.MemoryLimitBytes, WritableDirs: o.WritableDirs})
	_ = stdin.Close()
	waitErr := cmd.Wait()
	res := &Result{Stderr: errb.buf.String(), Duration: time.Since(start)}

	if ctx.Err() != nil {
		return res, fmt.Errorf("worker %q killed after %s: %w", task, o.Timeout, ctx.Err())
	}
	var resp Response
	if rerr := readFrame(&out.buf, &resp); rerr != nil {
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			rerr = fmt.Errorf("no response (worker exit: %v; stderr: %q)", waitErr, trim(res.Stderr))
		}
		return res, fmt.Errorf("worker %q: %w", task, rerr)
	}
	if werr != nil && !errors.Is(werr, syscall.EPIPE) {
		return res, werr
	}
	res.Sandbox, res.Raw = resp.Sandbox, resp.Result
	if o.RequireSandbox && resp.Sandbox.Level != "full" {
		return res, fmt.Errorf("%w: %s", ErrSandbox, resp.Sandbox.Level+" ("+resp.Sandbox.Detail+")")
	}
	if !resp.OK {
		return res, fmt.Errorf("worker %q failed: %s", task, trim(resp.Error))
	}
	return res, nil
}

func trim(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
