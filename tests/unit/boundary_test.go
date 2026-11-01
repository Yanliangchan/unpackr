// Package unit holds repository-wide architectural checks.
package unit

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const mod = "github.com/Yanliangchan/unpackr/"

// touchSources reads every Go file so that the test cache is invalidated when
// any source changes: `go list` runs in a subprocess the cache cannot see.
func touchSources(t *testing.T) {
	t.Helper()
	_ = filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "go.mod")) {
			_, _ = os.ReadFile(p)
		}
		return nil
	})
}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	touchSources(t)
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", mod+pkg)
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", pkg, err, out)
	}
	return strings.Fields(string(out))
}

func mustNotImport(t *testing.T, pkg string, forbidden ...string) {
	t.Helper()
	for _, d := range deps(t, pkg) {
		for _, f := range forbidden {
			if d == mod+f {
				t.Errorf("%s must not depend on %s", pkg, f)
			}
		}
	}
}

// The analysis engine must not know about presentation, banners or the CLI.
func TestEngineIsIndependentOfPresentation(t *testing.T) {
	mustNotImport(t, "internal/engine", "internal/terminal", "internal/cli", "internal/artvault", "assets")
	mustNotImport(t, "internal/identification", "internal/terminal", "internal/cli", "internal/artvault", "internal/engine")
}

// ArtVault stays independent of the analysis engine.
func TestArtVaultIsIndependentOfEngine(t *testing.T) {
	mustNotImport(t, "internal/artvault", "internal/engine", "internal/worker", "internal/identification", "internal/cli", "internal/safety")
}

// The data model depends on nothing in this project.
func TestModelsHaveNoProjectDependencies(t *testing.T) {
	for _, d := range deps(t, "pkg/models") {
		if strings.HasPrefix(d, mod) && d != mod+"pkg/models" {
			t.Errorf("pkg/models imports %s", d)
		}
	}
}

// No network packages outside the sandbox self-test and the standard library
// pulled in transitively by the toolchain: the product is offline-first.
func TestNoHTTPClientInBinary(t *testing.T) {
	for _, d := range deps(t, "cmd/unpackr") {
		if d == "net/http" {
			t.Errorf("the binary links net/http; the product must not contain an HTTP client")
		}
	}
}

// External-tool and comparison code is analysis logic, not presentation.
func TestUnpackingAndComparisonAreIndependentOfPresentation(t *testing.T) {
	for _, p := range []string{"internal/unpacking", "internal/comparison", "internal/worker", "internal/capabilities", "internal/anomalies", "internal/packing", "internal/fingerprint"} {
		mustNotImport(t, p, "internal/terminal", "internal/cli", "internal/artvault")
	}
}

// Reports are built from the data model only: no terminal code, no artwork,
// no analysis engine.
func TestReportingOnlyDependsOnTheModel(t *testing.T) {
	mustNotImport(t, "internal/reporting", "internal/terminal", "internal/cli", "internal/artvault", "internal/engine", "internal/worker", "assets")
}

// The database and case code is storage, not presentation, and the engine
// must never depend on it.
func TestStorageBoundaries(t *testing.T) {
	mustNotImport(t, "internal/database", "internal/terminal", "internal/cli", "internal/artvault", "internal/engine", "internal/reporting")
	mustNotImport(t, "internal/cases", "internal/terminal", "internal/cli", "internal/artvault", "internal/engine")
	mustNotImport(t, "internal/engine", "internal/database", "internal/cases")
}
