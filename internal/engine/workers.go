package engine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"github.com/Yanliangchan/unpackr/internal/identification"
	"github.com/Yanliangchan/unpackr/internal/worker"
)

// Task names understood by workers.
const (
	TaskIdentify = "identify"
	TaskSelfTest = "selftest"
)

func init() {
	worker.Register(TaskIdentify, func(ctx context.Context, in io.ReaderAt, size int64, _ json.RawMessage) (any, error) {
		return identification.Identify(in, size), nil
	})
	worker.Register(TaskSelfTest, func(ctx context.Context, _ io.ReaderAt, _ int64, _ json.RawMessage) (any, error) {
		return SelfTest(), nil
	})
}

// SelfTestResult records which forbidden actions the sandboxed worker could
// still perform. Every field should read "denied" in a fully confined worker.
type SelfTestResult struct {
	ReadEtcPasswd string `json:"read_etc_passwd"`
	WriteTemp     string `json:"write_temp"`
	NetworkDial   string `json:"network_dial"`
}

// SelfTest is run inside a worker and attempts the actions the sandbox is
// supposed to prevent. It touches nothing permanently.
func SelfTest() SelfTestResult {
	r := SelfTestResult{}
	state := func(err error) string {
		if err == nil {
			return "ALLOWED"
		}
		return "denied"
	}
	_, err := os.ReadFile("/etc/passwd")
	r.ReadEtcPasswd = state(err)
	p := os.TempDir() + "/.unpackr-selftest"
	err = os.WriteFile(p, []byte("x"), 0o600)
	if err == nil {
		os.Remove(p)
	}
	r.WriteTemp = state(err)
	c, err := net.DialTimeout("tcp", "127.0.0.1:9", 500*time.Millisecond)
	if err == nil {
		c.Close()
	}
	r.NetworkDial = state(err)
	return r
}
