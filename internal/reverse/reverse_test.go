package reverse

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func TestMain(m *testing.M) {
	if worker.IsWorker() {
		worker.Serve()
	}
	os.Exit(m.Run())
}

func tool(t *testing.T) *unpacking.Tool {
	t.Helper()
	tl, err := Locate(context.Background(), 2<<30)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("radare2 not installed")
		}
		if errors.Is(err, worker.ErrExecSandbox) {
			t.Skipf("no full sandbox here: %v", err)
		}
		t.Fatal(err)
	}
	return tl
}

func runOn(t *testing.T, path, family string, apis []API) (callers map[string][]string, functions int, entry string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read only
	res, err := Run(context.Background(), tool(t), f, family, apis, Options{Timeout: 90 * time.Second, MemoryBytes: 2 << 30})
	if err != nil {
		t.Fatal(err)
	}
	callers = map[string][]string{}
	for _, c := range res.CallSites {
		callers[c.API] = append(callers[c.API], c.Function+"/"+c.Kind)
	}
	return callers, res.Functions, res.Entry
}

func TestELFCallSitesAreResolved(t *testing.T) {
	callers, n, entry := runOn(t, fixtures.LinuxNetworkProgram(t), "elf", []API{{Name: "socket"}, {Name: "connect"}, {Name: "execl"}, {Name: "no_such_import"}})
	for _, api := range []string{"socket", "connect", "execl"} {
		if !contains(callers[api], "main/call") {
			t.Errorf("%s: %v", api, callers[api])
		}
	}
	if len(callers["no_such_import"]) != 0 {
		t.Errorf("an import that is not there has callers: %v", callers["no_such_import"])
	}
	if n < 2 || entry != "entry0" {
		t.Errorf("functions=%d entry=%q", n, entry)
	}
}

func TestPECallSitesAreResolved(t *testing.T) {
	callers, n, _ := runOn(t, fixtures.WindowsImportsProgram(t), "pe", []API{
		{Name: "CreateProcessA", Library: "KERNEL32.dll"}, {Name: "VirtualAlloc", Library: "KERNEL32.dll"},
		{Name: "LoadLibraryA", Library: "KERNEL32.dll"}, {Name: "GetProcAddress", Library: "KERNEL32.dll"},
		{Name: "MessageBoxA", Library: "USER32.dll"},
	})
	for _, api := range []string{"CreateProcessA", "VirtualAlloc", "LoadLibraryA", "GetProcAddress"} {
		if !contains(callers[api], "main/call") {
			t.Errorf("%s: %v", api, callers[api])
		}
	}
	if len(callers["MessageBoxA"]) != 0 {
		t.Errorf("MessageBoxA is only resolved at run time and is not imported: %v", callers["MessageBoxA"])
	}
	if n < 5 {
		t.Errorf("functions=%d", n)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestUnsafeImportNamesNeverReachTheCommandScript(t *testing.T) {
	hostile := []string{"x; !echo owned", "a|b", "a`id`", "a b", "a\nb", "a>b", "a~b", "$(id)", "a&&b", "", strings_repeat("a", 129), "a'b", `a"b`, "a\\b", "?e boom"}
	for _, name := range hostile {
		if f, ok := flagFor(API{Name: name}, "elf"); ok {
			t.Errorf("name %q was accepted as %q", name, f)
		}
		if f, ok := flagFor(API{Name: "ok", Library: name}, "pe"); ok && name != "" {
			t.Errorf("library %q was accepted as %q", name, f)
		}
	}
	for _, good := range []string{"socket", "CreateProcessA", "_ZN3foo3barEv", "__libc_start_main", "sym.x", "a$b"} {
		if _, ok := flagFor(API{Name: good}, "elf"); !ok {
			t.Errorf("safe name %q rejected", good)
		}
	}
	if _, ok := flagFor(API{Name: "x"}, "macho"); ok {
		t.Error("formats that were not verified must not be looked up")
	}
	// Whatever the names, the script contains only the fixed commands and flags.
	s := script([]string{"sym.imp.socket", "sym.imp.KERNEL32.dll_VirtualAlloc"}, "abcd1234abcd1234")
	if strings.Count(s, ";") != 1+1+6+2*2 || strings.ContainsAny(s, "!|`\n&<>") {
		t.Errorf("unexpected script: %s", s)
	}
}

func strings_repeat(s string, n int) string { return strings.Repeat(s, n) }

// radare2's own sandbox mode must switch off the shell escape, so a command that
// somehow reached it still could not run a program. (The -S flag looked like the
// way to ask for it and, in 5.5.0, is not: this test is what showed that.)
func TestSandboxModeDisablesTheShellEscape(t *testing.T) {
	r2, err := exec.LookPath("radare2")
	if err != nil {
		t.Skip("radare2 not installed")
	}
	out, _ := exec.Command(r2, "-q", "-N", "-c", "e cfg.sandbox=true;!echo SHELL_RAN_MARKER", "-").CombinedOutput() //nolint:gosec // fixed test tool
	if strings.Contains(string(out), "SHELL_RAN_MARKER") {
		t.Fatalf("the shell escape ran with cfg.sandbox=true: %s", out)
	}
	// Control: without -S the same command does run, so the test can fail.
	out, _ = exec.Command(r2, "-q", "-N", "-c", "!echo SHELL_RAN_MARKER", "-").CombinedOutput() //nolint:gosec // fixed test tool
	if !strings.Contains(string(out), "SHELL_RAN_MARKER") {
		t.Skip("this radare2 does not run the shell escape even without the sandbox setting; the control cannot fail")
	}
}

const tok = "feedfacefeedface"

func mk(k string) string { return marker(tok, k) }

var sampleOutput = "\x1b[2K" + mk("I") + "\n{\"arch\":\"x86\"}\n" + mk("E") + "\n[{\"vaddr\":4384,\"paddr\":4384,\"baddr\":0,\"type\":\"program\"}]\n" + mk("F") + "\n" +
	"0x00001120    1 38           entry0\n0x00001149    7 120 -> 118   sym.main\n0x00001200    1 10           sym.helper one\n" +
	"garbage line\n0xzz    1 2 bad\n0x00001300   -1 5 negative\n" +
	mk("X0") + "\n\x1b[2K[{\"from\":4658,\"type\":\"CALL\",\"opcode\":\"call sym.imp.socket\",\"fcn_addr\":4617,\"fcn_name\":\"sym.main\"},{\"from\":4900,\"type\":\"CODE\",\"fcn_addr\":0,\"name\":\"sym.thunk+4\"},{\"from\":5000,\"type\":\"WEIRD\",\"fcn_addr\":4617,\"fcn_name\":\"sym.main\"}]\n" +
	mk("X1") + "\n[]\n"

func TestParseIsStrictAndBounded(t *testing.T) {
	res := newResult()
	if err := parse(res, sampleOutput, tok, []API{{Name: "socket"}, {Name: "connect"}}, []string{"sym.imp.socket", "sym.imp.connect"}); err != nil {
		t.Fatal(err)
	}
	if res.Functions != 3 || res.Entry != "entry0" {
		t.Errorf("functions=%d entry=%q (junk lines must be ignored)", res.Functions, res.Entry)
	}
	if res.Largest[0].Name != "sym.main" || res.Largest[0].Size != 120 {
		t.Errorf("largest: %+v", res.Largest)
	}
	if len(res.CallSites) != 3 {
		t.Fatalf("call sites: %+v", res.CallSites)
	}
	kinds := map[string]bool{}
	for _, c := range res.CallSites {
		kinds[c.Kind] = true
	}
	if !kinds["call"] || !kinds["jump"] || !kinds["data"] {
		t.Errorf("kinds: %v", kinds)
	}
	if res.CallSites[0].Function != "main" {
		t.Errorf("the sym. prefix should be dropped: %+v", res.CallSites[0])
	}
	if err := parse(newResult(), "no markers at all", tok, nil, nil); err == nil {
		t.Error("output without a function listing must be an error")
	}
	// Control characters in names are neutralised.
	evil := mk("F") + "\n0x00001000 1 10 sym.\x1b]0;owned\x07name\n" + mk("I") + "\n" + mk("E") + "\n[]\n"
	r := newResult()
	if err := parse(r, evil, tok, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.Largest) == 1 && strings.ContainsAny(r.Largest[0].Name, "\x1b\x07") {
		t.Errorf("escape bytes survived: %q", r.Largest[0].Name)
	}
	// A name inside the file cannot fake a section break: markers carry this run's token.
	forged := mk("F") + "\n0x00001000 1 10 real\n0x00001010 1 10 UNPACKR0000000000000000ENDX0\n" + mk("E") + "\n[]\n"
	r2 := newResult()
	if err := parse(r2, forged, tok, nil, nil); err != nil || r2.Functions != 2 {
		t.Errorf("a forged marker must be an ordinary (odd) name, not a section break: %v %+v", err, r2)
	}
}
