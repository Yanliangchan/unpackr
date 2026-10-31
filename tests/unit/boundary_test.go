// Package unit holds repository-wide architectural checks.
package unit

import (
	"os/exec"
	"strings"
	"testing"
)

const mod = "github.com/Yanliangchan/unpackr/"

func deps(t *testing.T, pkg string) []string {
	t.Helper()
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
