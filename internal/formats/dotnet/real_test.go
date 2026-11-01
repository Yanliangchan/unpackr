package dotnet

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realAssembly loads a genuine managed assembly shipped as test data with the
// saferwall/pe module, and maps RVAs using the standard library's PE reader so
// the metadata reader is checked against an independent view of the file.
func realAssembly(t *testing.T, name string) ([]byte, uint32, uint32, Mapper) {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/saferwall/pe").Output()
	if err != nil {
		t.Skip("module directory not available")
	}
	path := filepath.Join(strings.TrimSpace(string(out)), "test", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("sample not available: " + name)
	}
	f, err := pe.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only test file
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = oh.DataDirectory[14]
	case *pe.OptionalHeader64:
		dir = oh.DataDirectory[14]
	}
	m := func(rva uint32) (int, bool) {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+max(s.VirtualSize, s.Size) {
				return int(rva - s.VirtualAddress + s.Offset), true
			}
		}
		return 0, false
	}
	return data, dir.VirtualAddress, dir.Size, m
}

func TestRealMixedModeAssembly(t *testing.T) {
	data, rva, size, m := realAssembly(t, "pspluginwkr.dll")
	d, err := Parse(data, rva, size, m)
	if err != nil {
		t.Fatal(err)
	}
	if d.AssemblyName != "pspluginwkr" || d.AssemblyVersion != "1.0.0.0" || d.MetadataVersion != "v2.0.50727" {
		t.Errorf("identity wrong: %+v", d)
	}
	want := map[string]int{"TypeDef": 169, "MethodDef": 434, "Field": 325, "MemberRef": 256, "AssemblyRef": 5, "ImplMap": 51}
	for k, v := range want {
		if d.Counts[k] != v {
			t.Errorf("%s = %d, want %d", k, d.Counts[k], v)
		}
	}
	got := strings.Join(d.AssemblyRefs, "|")
	for _, ref := range []string{"mscorlib 2.0.0.0", "System 2.0.0.0", "System.Management.Automation 1.0.0.0"} {
		if !strings.Contains(got, ref) {
			t.Errorf("missing assembly reference %q in %s", ref, got)
		}
	}
	if len(d.Anomalies) != 0 {
		t.Errorf("a normal assembly should have no anomalies: %v", d.Anomalies)
	}
}

func TestRealReferenceAssembly(t *testing.T) {
	data, rva, size, m := realAssembly(t, "mscorlib.dll")
	d, err := Parse(data, rva, size, m)
	if err != nil {
		t.Fatal(err)
	}
	if d.AssemblyName != "mscorlib" || d.MetadataVersion != "v4.0.30319" || d.Counts["AssemblyRef"] != 30 {
		t.Errorf("%+v", d)
	}
}

// Truncating or damaging a real assembly anywhere must never panic or hang.
func TestHostileMutationsOfARealAssembly(t *testing.T) {
	data, rva, size, m := realAssembly(t, "pspluginwkr.dll")
	for cut := 0; cut < len(data); cut += len(data)/257 + 1 {
		_, _ = Parse(data[:cut], rva, size, m)
	}
	for i := 0; i < 3000; i++ {
		c := append([]byte(nil), data...)
		// damage bytes inside the metadata and CLR header regions
		o, _ := m(rva)
		for j := 0; j < 6; j++ {
			pos := o + (i*7919+j*104729)%max(int(size)+60000, 1)
			if pos < len(c) {
				c[pos] ^= byte(1 + i%255)
			}
		}
		_, _ = Parse(c, rva, size, m)
	}
}
