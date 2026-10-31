package fixtures

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// PackWithUPX compresses src with the host's UPX into a new file and returns
// its path. The test is skipped when UPX is not installed. UPX is only used
// to build a harmless test input from a harmless program.
func PackWithUPX(t testing.TB, src string, extra ...string) string {
	t.Helper()
	upx, err := exec.LookPath("upx")
	if err != nil {
		t.Skip("upx not installed")
	}
	out := filepath.Join(t.TempDir(), "packed_"+filepath.Base(src))
	args := append([]string{"-q", "--best"}, extra...)
	args = append(args, "-o", out, src)
	if b, err := exec.Command(upx, args...).CombinedOutput(); err != nil { //nolint:gosec // fixed test tool
		t.Fatalf("upx: %v\n%s", err, b)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	return out
}
