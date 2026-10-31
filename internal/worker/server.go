package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/Yanliangchan/unpackr/internal/safety"
)

// Handler runs inside the sandboxed worker. in is the sample.
type Handler func(ctx context.Context, in io.ReaderAt, size int64, params json.RawMessage) (any, error)

var handlers = map[string]Handler{}

// Register adds a task handler. Call from init().
func Register(task string, h Handler) { handlers[task] = h }

// IsWorker reports whether this process was started as a worker.
func IsWorker() bool { v := os.Getenv(EnvVar); return v == "1" || v == ExecMode }

// Serve runs the worker protocol and never returns to the caller's main.
// Main (and TestMain in packages that use workers) calls it first thing when
// IsWorker is true.
func Serve() {
	if os.Getenv(EnvVar) == ExecMode {
		serveExec()
	}
	os.Exit(serve(os.Stdin, os.Stdout))
}

func serve(stdin io.Reader, stdout io.Writer) (code int) {
	var req Request
	if err := readFrame(stdin, &req); err != nil {
		fmt.Fprintln(os.Stderr, "worker: bad request:", err)
		return 2
	}
	// Confine before any untrusted byte is read.
	st := safety.ApplySandbox(safety.SandboxOptions{MemoryLimitBytes: req.MemoryLimitBytes})
	resp := Response{Sandbox: st}

	defer func() {
		if r := recover(); r != nil {
			resp = Response{Sandbox: st, Error: fmt.Sprintf("worker panic: %v\n%s", r, debug.Stack())}
			_ = writeFrame(stdout, resp)
			code = 3
		}
	}()

	h, ok := handlers[req.Task]
	if !ok {
		resp.Error = "unknown task " + req.Task
		_ = writeFrame(stdout, resp)
		return 2
	}
	var in io.ReaderAt
	if req.InputSize >= 0 {
		f := os.NewFile(uintptr(InputFD), "input")
		if f != nil {
			in = f
		}
	}
	res, err := h(context.Background(), in, req.InputSize, req.Params)
	if err != nil {
		resp.Error = err.Error()
	} else if b, merr := json.Marshal(res); merr != nil {
		resp.Error = "marshal result: " + merr.Error()
	} else {
		resp.OK, resp.Result = true, b
	}
	if err := writeFrame(stdout, resp); err != nil {
		fmt.Fprintln(os.Stderr, "worker: write:", err)
		return 2
	}
	return 0
}
