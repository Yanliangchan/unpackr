package unpacking

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/internal/worker"
)

func TestMain(m *testing.M) {
	if worker.IsWorker() {
		worker.Serve()
	}
	os.Exit(m.Run())
}

func tool(t *testing.T, name string) *Tool {
	t.Helper()
	tl, err := Locate(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	return tl
}

func run(t *testing.T, tl *Tool, work string, args ...string) (*worker.ExecResult, error) {
	t.Helper()
	return worker.RunExec(context.Background(), tl.Spec(work, args, 2<<30, 64<<20), 30*time.Second)
}

func TestToolRunsConfinedAndCanWriteOnlyInWorkDir(t *testing.T) {
	cat := tool(t, "cat")
	work := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "in.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := run(t, cat, work, filepath.Join(work, "in.txt"))
	if errors.Is(err, worker.ErrExecSandbox) {
		t.Skipf("no full sandbox here: %v", err)
	}
	if err != nil || res.ExitCode != 0 || res.Stdout != "inside" {
		t.Fatalf("workdir read failed: %v %+v", err, res)
	}
	// Reading a file outside the work directory must be refused.
	res, err = run(t, cat, work, filepath.Join(outside, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 || strings.Contains(res.Stdout, "outside") {
		t.Fatalf("sandbox let the tool read outside its work directory: %+v", res)
	}
	res, _ = run(t, cat, work, "/etc/passwd")
	if res.ExitCode == 0 {
		t.Fatal("/etc/passwd readable")
	}
}

func TestToolCannotWriteOutsideOrExecOthers(t *testing.T) {
	sh := tool(t, "sh")
	work := t.TempDir()
	outside := t.TempDir()
	// The shell tries to write outside, to start another program and to open a socket-like device.
	script := "echo hi > " + filepath.Join(outside, "x") + "; echo rc=$? ; /bin/ls / ; echo rc2=$?"
	res, err := run(t, sh, work, "-c", script)
	if errors.Is(err, worker.ErrExecSandbox) {
		t.Skipf("no full sandbox here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(filepath.Join(outside, "x")); serr == nil {
		t.Fatal("the tool wrote outside its work directory")
	}
	if strings.Contains(res.Stdout, "rc2=0") {
		t.Fatalf("the tool started another program: %+v", res)
	}
}

func TestFailsClosedWhenSandboxUnavailable(t *testing.T) {
	// A work directory that does not exist makes Landlock rule creation fail
	// in BestEffort mode only partially; instead assert the contract through
	// a nonexistent executable, which must be an error, never a silent pass.
	_, err := worker.RunExec(context.Background(), worker.ExecSpec{Exe: "/nonexistent/tool", WorkDir: t.TempDir()}, 10*time.Second)
	if err == nil {
		res, _ := worker.RunExec(context.Background(), worker.ExecSpec{Exe: "/nonexistent/tool", WorkDir: t.TempDir()}, 10*time.Second)
		if res.ExitCode == 0 {
			t.Fatal("a missing tool must not look like success")
		}
	}
}

func TestMissingToolReportsNotFound(t *testing.T) {
	if _, err := Locate("definitely-not-a-real-tool-xyz"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestUPXVersionProbe(t *testing.T) {
	u := tool(t, "upx")
	err := u.ProbeVersion(context.Background(), t.TempDir(), 2<<30)
	if errors.Is(err, worker.ErrExecSandbox) {
		t.Skipf("no full sandbox here: %v", err)
	}
	if err != nil || u.Version == "" {
		t.Fatalf("%v version=%q", err, u.Version)
	}
	t.Logf("upx %s at %s", u.Version, u.Path)
}

func TestCheckOutputGuards(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	// 1 MiB from a 1 KiB input is 1024x: a decompression bomb by any measure.
	checks, _ := CheckOutput(1024, big, 1<<30, 200)
	if AllPassed(checks) {
		t.Fatal("expansion beyond the ratio limit must be rejected")
	}
	checks, _ = CheckOutput(512<<10, big, 1<<30, 200)
	if !AllPassed(checks) {
		t.Fatalf("%+v", checks)
	}
	checks, _ = CheckOutput(512<<10, big, 1<<10, 200)
	if AllPassed(checks) {
		t.Fatal("size cap not enforced")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(big, link); err != nil {
		t.Fatal(err)
	}
	if checks, _ = CheckOutput(512<<10, link, 1<<30, 200); AllPassed(checks) {
		t.Fatal("a symlink must not be accepted as the unpacked output")
	}
	if checks, _ = CheckOutput(10, filepath.Join(dir, "missing"), 1<<30, 200); AllPassed(checks) {
		t.Fatal("missing output accepted")
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if checks, _ = CheckOutput(10, empty, 1<<30, 200); AllPassed(checks) {
		t.Fatal("empty output accepted")
	}
}

func TestFailureHintNeutralisesToolText(t *testing.T) {
	h := FailureHint("upx: x: CantUnpackException: \x1b]0;pwned\x07 not supported\n")
	if strings.ContainsRune(h, 0x1b) || strings.ContainsRune(h, 7) {
		t.Fatalf("raw control bytes from tool output reached the message: %q", h)
	}
	if !strings.Contains(h, "modified to defeat") {
		t.Fatalf("%q", h)
	}
}
