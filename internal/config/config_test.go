package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(s), 0o600)
	return p
}

func TestDefaultsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	if _, err := Load(write(t, "tiemout_seconds: 5\n")); err == nil {
		t.Fatal("typo accepted")
	}
}

func TestOverrideAndValidation(t *testing.T) {
	c, err := Load(write(t, "threads: 2\nrequire_sandbox: true\n"))
	if err != nil || c.Threads != 2 || !c.RequireSandbox {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Load(write(t, "threads: 0\n")); err == nil {
		t.Fatal("zero threads accepted")
	}
}

func TestMissingImplicitFileIsFine(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := Load(""); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("/nonexistent/x.yaml"); err == nil {
		t.Fatal("explicit missing file must error")
	}
}
