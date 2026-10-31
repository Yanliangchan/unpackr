// Package worker implements isolated, short-lived helper processes. The
// orchestrator re-executes its own binary with UNPACKR_WORKER=1; the child
// confines itself (see safety.ApplySandbox), reads one request frame from
// stdin and writes one response frame to stdout. The input file is passed as
// an inherited read-only descriptor so the child needs no filesystem access.
//
// Everything a worker returns is untrusted data: the client enforces size
// limits and decodes strictly.
package worker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// EnvVar marks a process as a worker.
const EnvVar = "UNPACKR_WORKER"

// InputFD is the descriptor number of the sample inside the worker (stdin,
// stdout and stderr occupy 0-2, so the first ExtraFiles entry is 3).
const InputFD = 3

// MaxFrame bounds every frame in either direction.
const MaxFrame = 16 << 20

// Request is sent by the orchestrator. It is trusted.
type Request struct {
	Task             string          `json:"task"`
	Params           json.RawMessage `json:"params,omitempty"`
	InputSize        int64           `json:"input_size"`
	MemoryLimitBytes uint64          `json:"memory_limit_bytes"`
	// WritableDirs are the only locations the worker may write. Normally
	// empty; extraction tasks get one private directory.
	WritableDirs []string `json:"writable_dirs,omitempty"`
}

// Response is returned by the worker. It is untrusted.
type Response struct {
	OK      bool                 `json:"ok"`
	Error   string               `json:"error,omitempty"`
	Sandbox models.SandboxStatus `json:"sandbox"`
	Result  json.RawMessage      `json:"result,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("frame of %d bytes exceeds limit", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

var errFrameTooLarge = errors.New("frame exceeds size limit")

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return errFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
