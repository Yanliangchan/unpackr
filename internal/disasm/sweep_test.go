package disasm

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// Ordinary compiled code must not trigger any of the three idioms. This runs
// the sweep over a sample of the host's own executables (a few dozen megabytes
// of real x86-64 code) and expects silence. It skips where there is nothing to
// sweep, and in -short mode.
func TestOrdinarySystemCodeIsQuiet(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	var paths []string
	for _, dir := range []string{"/usr/bin", "/usr/lib/x86_64-linux-gnu"} {
		m, _ := filepath.Glob(filepath.Join(dir, "*"))
		paths = append(paths, m...)
	}
	files, code := 0, 0
	for _, path := range paths {
		if files >= 120 {
			break
		}
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 20<<20 {
			continue
		}
		f, err := elf.Open(path)
		if err != nil {
			continue
		}
		var regs []Region
		if f.Machine == elf.EM_X86_64 {
			for _, s := range f.Sections {
				if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type != elf.SHT_NOBITS {
					if b, err := s.Data(); err == nil {
						regs = append(regs, Region{Name: s.Name, Offset: int64(s.Offset), Code: b})
					}
				}
			}
		}
		_ = f.Close()
		if len(regs) == 0 {
			continue
		}
		files++
		d := Analyze(regs, 64)
		code += d.Bytes
		if len(d.Sites) != 0 {
			t.Errorf("%s: %+v", path, d.Sites[0])
		}
	}
	if files == 0 {
		t.Skip("no x86-64 executables on this host")
	}
	t.Logf("swept %d files, %d MB of code, no sites", files, code>>20)
}
