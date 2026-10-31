package fixtures

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

const helloSrc = `package main

import "fmt"

func main() { fmt.Println("fixture") }
`

var (
	mu    sync.Mutex
	built = map[string]string{}
	dir   string
)

// GoBinary cross-compiles a trivial, harmless Go program for the given target
// and returns the path. It is the source of realistic ELF, Mach-O and PE
// samples without committing binaries. The test is skipped when the Go
// toolchain is unavailable. The binary is never executed.
func GoBinary(t testing.TB, goos, goarch string) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	key := goos + "/" + goarch
	if p, ok := built[key]; ok {
		return p
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available to build fixtures")
	}
	if dir == "" {
		dir, err = os.MkdirTemp("", "unpackr-fixtures")
		if err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(dir, "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(helloSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fixture\n\ngo 1.21\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, fmt.Sprintf("fixture_%s_%s", goos, goarch))
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = filepath.Join(dir, "src")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fixture for %s: %v\n%s", key, err, b)
	}
	built[key] = out
	return out
}
