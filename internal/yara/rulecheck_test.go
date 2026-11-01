package yara

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
)

func tester(t *testing.T) *unpacking.Tool {
	t.Helper()
	tool, err := Locate(context.Background(), "yr", 2<<30)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("yr (YARA-X) not installed")
		}
		if errors.Is(err, worker.ErrExecSandbox) {
			t.Skipf("no full sandbox here: %v", err)
		}
		t.Fatal(err)
	}
	return tool
}

const goodRule = `rule t { strings: $a = "needle-in-haystack" condition: $a }`

func TestRuleCompileErrorsAreReportedNotFatal(t *testing.T) {
	tool := tester(t)
	r, err := TestRule(context.Background(), tool, `rule bad { strings: $a = "x" condition: $b }`, nil, TestOptions{MemoryBytes: 2 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if r.Compiled || !strings.Contains(r.CompileError, "unknown pattern") {
		t.Fatalf("%+v", r)
	}
}

func TestRuleMatchesItsSampleAndControls(t *testing.T) {
	tool := tester(t)
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("clean1.bin", "nothing here")
	write("clean2.bin", "still nothing")
	write("sub/clean3.bin", "deeper nothing")
	write("sub/unlucky.bin", "contains needle-in-haystack by accident")

	sample := []byte("MZ.. the sample has needle-in-haystack inside")
	r, err := TestRule(context.Background(), tool, goodRule, bytes.NewReader(sample), TestOptions{MemoryBytes: 2 << 30, ControlDirs: []string{dir}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Compiled || !r.SampleTested || !r.MatchedSample {
		t.Fatalf("%+v", r)
	}
	if r.ControlFiles != 4 || r.ControlMatchN != 1 || len(r.ControlMatches) != 1 || r.ControlMatches[0] != filepath.Join("sub", "unlucky.bin") {
		t.Fatalf("controls: %+v", r)
	}

	// A rule that misses its own sample is reported as such.
	miss, err := TestRule(context.Background(), tool, goodRule, strings.NewReader("different bytes"), TestOptions{MemoryBytes: 2 << 30})
	if err != nil || !miss.Compiled || !miss.SampleTested || miss.MatchedSample {
		t.Fatalf("%+v %v", miss, err)
	}
}

func TestControlDirMustBeADirectoryAndIsNotModified(t *testing.T) {
	tool := tester(t)
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TestRule(context.Background(), tool, goodRule, nil, TestOptions{MemoryBytes: 2 << 30, ControlDirs: []string{f}}); err == nil {
		t.Error("a file is not a control directory")
	}
	dir := t.TempDir()
	body := []byte("needle-in-haystack")
	p := filepath.Join(dir, "a")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	if _, err := TestRule(context.Background(), tool, goodRule, nil, TestOptions{MemoryBytes: 2 << 30, ControlDirs: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, body) || !before.ModTime().Equal(after.ModTime()) {
		t.Error("the control file was changed")
	}
}

func TestOversizedOrEmptyRulesAreRefused(t *testing.T) {
	tool := tester(t)
	for _, rule := range []string{"", strings.Repeat("a", MaxRuleBytes+1)} {
		if _, err := TestRule(context.Background(), tool, rule, nil, TestOptions{MemoryBytes: 2 << 30}); err == nil {
			t.Errorf("rule of %d bytes accepted", len(rule))
		}
	}
}

func TestMalformedScannerOutputIsIgnored(t *testing.T) {
	out := "not json\n{\"path\":\"a\",\"rules\":[{\"identifier\":\"r\"}]}\n{\"path\":\"b\",\"rules\":[]}\n{broken\n"
	got := matchedPaths(out)
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("%v", got)
	}
}
