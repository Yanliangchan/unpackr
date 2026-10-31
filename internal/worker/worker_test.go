package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func init() {
	Register("echo", func(ctx context.Context, in io.ReaderAt, size int64, p json.RawMessage) (any, error) {
		b := make([]byte, size)
		_, _ = in.ReadAt(b, 0)
		return map[string]any{"data": string(b)}, nil
	})
	Register("probe", func(ctx context.Context, in io.ReaderAt, size int64, p json.RawMessage) (any, error) {
		out := map[string]string{}
		if _, err := os.ReadFile("/etc/passwd"); err == nil {
			out["read_etc_passwd"] = "ALLOWED"
		} else {
			out["read_etc_passwd"] = "denied"
		}
		if _, err := net.DialTimeout("tcp", "127.0.0.1:9", time.Second); err == nil {
			out["net"] = "ALLOWED"
		} else {
			out["net"] = "denied"
		}
		if err := os.WriteFile(os.TempDir()+"/unpackr-worker-test", []byte("x"), 0o600); err == nil {
			_ = os.Remove(os.TempDir() + "/unpackr-worker-test")
			out["write_tmp"] = "ALLOWED"
		} else {
			out["write_tmp"] = "denied"
		}
		return out, nil
	})
	Register("write", func(ctx context.Context, in io.ReaderAt, size int64, p json.RawMessage) (any, error) {
		var targets []string
		_ = json.Unmarshal(p, &targets)
		out := map[string]string{}
		for _, t := range targets {
			if err := os.WriteFile(t, []byte("x"), 0o600); err == nil {
				out[t] = "WRITTEN"
			} else {
				out[t] = "denied"
			}
		}
		return out, nil
	})
	Register("panic", func(ctx context.Context, in io.ReaderAt, size int64, p json.RawMessage) (any, error) {
		var m map[string]int
		m["x"] = 1 //nolint:staticcheck // deliberate nil-map panic
		return nil, nil
	})
	Register("spin", func(ctx context.Context, in io.ReaderAt, size int64, p json.RawMessage) (any, error) {
		for { //nolint:staticcheck // deliberate busy loop to test the kill path
		}
	})
}

func TestMain(m *testing.M) {
	if IsWorker() {
		Serve()
	}
	os.Exit(m.Run())
}

func tmpInput(t *testing.T, data string) (*os.File, int64) {
	t.Helper()
	p := t.TempDir() + "/in"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, int64(len(data))
}

func TestEchoThroughInheritedFD(t *testing.T) {
	f, n := tmpInput(t, "hello sample")
	res, err := Run(context.Background(), "echo", nil, f, n, Options{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Data string }
	_ = json.Unmarshal(res.Raw, &out)
	if out.Data != "hello sample" {
		t.Fatalf("got %q", out.Data)
	}
}

func TestSandboxConfinesWorker(t *testing.T) {
	res, err := Run(context.Background(), "probe", nil, nil, 0, Options{Timeout: 20 * time.Second, MemoryLimitBytes: 4 << 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sandbox: %+v", res.Sandbox)
	if res.Sandbox.Level != "full" {
		t.Skipf("kernel does not provide full confinement here: %+v", res.Sandbox)
	}
	var out map[string]string
	_ = json.Unmarshal(res.Raw, &out)
	for k, v := range out {
		if v != "denied" {
			t.Errorf("%s: %s (sandbox did not confine)", k, v)
		}
	}
}

func TestPanicIsContained(t *testing.T) {
	_, err := Run(context.Background(), "panic", nil, nil, 0, Options{Timeout: 20 * time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHangIsKilled(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), "spin", nil, nil, 0, Options{Timeout: 1500 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

func TestRequireSandboxFailsClosed(t *testing.T) {
	// Without a memory limit the sandbox level is "partial", so a caller that
	// requires full confinement must get ErrSandbox rather than a result.
	_, err := Run(context.Background(), "probe", nil, nil, 0, Options{Timeout: 20 * time.Second, RequireSandbox: true})
	if !errors.Is(err, ErrSandbox) {
		t.Fatalf("expected ErrSandbox, got %v", err)
	}
}

func TestUnknownTask(t *testing.T) {
	if _, err := Run(context.Background(), "nope", nil, nil, 0, Options{Timeout: 20 * time.Second}); err == nil {
		t.Fatal("expected error")
	}
}

func TestWritableDirIsTheOnlyWritableLocation(t *testing.T) {
	allowed, denied := t.TempDir(), t.TempDir()
	targets := []string{filepath.Join(allowed, "ok"), filepath.Join(denied, "no"), "/tmp/unpackr-worker-escape"}
	res, err := Run(context.Background(), "write", targets, nil, 0, Options{Timeout: 20 * time.Second, MemoryLimitBytes: 4 << 30, WritableDirs: []string{allowed}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sandbox.Level != "full" {
		t.Skipf("full confinement unavailable: %+v", res.Sandbox)
	}
	var out map[string]string
	if err := json.Unmarshal(res.Raw, &out); err != nil {
		t.Fatal(err)
	}
	if out[targets[0]] != "WRITTEN" || out[targets[1]] != "denied" || out[targets[2]] != "denied" {
		t.Fatalf("%v", out)
	}
	os.Remove("/tmp/unpackr-worker-escape") //nolint:errcheck // cleanup if the sandbox failed
}
