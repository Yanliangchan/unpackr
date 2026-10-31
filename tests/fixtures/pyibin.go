package fixtures

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

const pyiScript = `import json, sys
print(json.dumps({"hello": "fixture", "argv": len(sys.argv)}))
`

var (
	pyiOnce sync.Once
	pyiPath string
	pyiErr  error
)

// PyInstallerBinary builds a real one-file PyInstaller executable from a
// trivial script and returns its path. It is skipped when PyInstaller is not
// installed (it takes a while, so the result is cached per test process). The
// binary is never executed.
func PyInstallerBinary(t testing.TB) string {
	t.Helper()
	exe, err := exec.LookPath("pyinstaller")
	if err != nil {
		t.Skip("pyinstaller not installed")
	}
	pyiOnce.Do(func() {
		dir, err := os.MkdirTemp("", "unpackr-pyi")
		if err != nil {
			pyiErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "hello.py"), []byte(pyiScript), 0o600); err != nil {
			pyiErr = err
			return
		}
		cmd := exec.Command(exe, "--onefile", "--name", "hello_pyi", "--distpath", filepath.Join(dir, "dist"),
			"--workpath", filepath.Join(dir, "work"), "--specpath", dir, filepath.Join(dir, "hello.py")) //nolint:gosec // fixed test tool
		if b, err := cmd.CombinedOutput(); err != nil {
			pyiErr = &buildError{err: err, out: string(b)}
			return
		}
		pyiPath = filepath.Join(dir, "dist", "hello_pyi")
	})
	if pyiErr != nil {
		t.Fatal(pyiErr)
	}
	return pyiPath
}

type buildError struct {
	err error
	out string
}

func (b *buildError) Error() string { return "pyinstaller: " + b.err.Error() + "\n" + b.out }
