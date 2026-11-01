package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectRefusesWithoutATerminal(t *testing.T) {
	root := NewRoot()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs([]string{"inspect", "whatever"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
	if ExitCode(err) != ExitUsage {
		t.Fatalf("exit code %d", ExitCode(err))
	}
}

func TestLoadReportJSONRejectsForeignAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadReportJSON(write("notjson.json", "hello")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := loadReportJSON(write("other.json", `{"x":1}`)); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("a JSON file that is not a report must be refused: %v", err)
	}
	r, err := loadReportJSON(write("ok.json", `{"schema_version":"1","file":{"name":"a"},"findings":[],"evidence":[]}`))
	if err != nil || r.File.Name != "a" {
		t.Errorf("valid report refused: %v", err)
	}
}

func TestViewerIsNotFoundOnPATH(t *testing.T) {
	// A planted unpackr-inspect earlier on PATH must never be used.
	dir := t.TempDir()
	p := filepath.Join(dir, helperName)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := findHelper()
	if err == nil && filepath.Dir(got) == dir {
		t.Fatalf("resolved the helper from PATH: %s", got)
	}
}
