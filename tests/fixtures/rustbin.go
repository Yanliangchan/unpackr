package fixtures

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const rustSrc = `fn main() {
    let v: Vec<u32> = (0..3).collect();
    println!("{:?}", v);
    if v.len() > 9 {
        panic!("boom");
    }
}
`

// RustBinary compiles a trivial, harmless Rust program for the host and
// returns its path. The test is skipped when rustc is not installed. The
// binary is never executed.
func RustBinary(t testing.TB) string {
	t.Helper()
	rustc, err := exec.LookPath("rustc")
	if err != nil {
		t.Skip("rustc not installed")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.rs")
	if err := os.WriteFile(src, []byte(rustSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "hello_rs")
	if b, err := exec.Command(rustc, "-O", "-o", out, src).CombinedOutput(); err != nil { //nolint:gosec // fixed test tool
		t.Fatalf("rustc: %v\n%s", err, b)
	}
	return out
}
