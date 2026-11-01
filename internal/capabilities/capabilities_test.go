package capabilities

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func pe(imports map[string][]string, extra string) *analysis.Input {
	b := &models.Binary{Format: "PE32+", Attributes: map[string]string{}}
	for lib, fns := range imports {
		im := models.Import{Library: lib}
		for _, f := range fns {
			im.Functions = append(im.Functions, models.ImportFn{Name: f})
		}
		b.Imports = append(b.Imports, im)
	}
	data := []byte(extra)
	return &analysis.Input{Data: data, Family: "pe", Bin: b, Scan: content.ExtractStrings(data), Sink: analysis.NewSink("t")}
}

func find(caps []models.Capability, id string) *models.Capability {
	for i := range caps {
		if caps[i].ID == id {
			return &caps[i]
		}
	}
	return nil
}

func TestInjectionChainFromImports(t *testing.T) {
	in := pe(map[string][]string{"KERNEL32.dll": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}}, "")
	c := find(Detect(in, models.PackUnpacked), "inject.classic")
	if c == nil {
		t.Fatal("injection chain not reported")
	}
	if len(c.Chain) != 4 || c.Chain[0].Source != KindImported {
		t.Fatalf("chain %+v", c.Chain)
	}
	if c.Attack[0] != "T1055" || c.Severity != models.SeverityHigh {
		t.Fatalf("%+v", c)
	}
	// An import chain alone is a moderate signal: low confidence, never high.
	if c.Confidence == models.ConfidenceHigh || c.Confidence == models.ConfidenceDefinitive {
		t.Fatalf("overconfident: %s", c.Confidence)
	}
	for _, want := range []string{"consistent with", "not that the behaviour occurs"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("summary lacks %q: %s", want, c.Summary)
		}
	}
	if !strings.Contains(c.Caveat, "Debuggers") {
		t.Errorf("benign context missing: %q", c.Caveat)
	}
}

func TestPartialChainBelowThresholdIsNotReported(t *testing.T) {
	in := pe(map[string][]string{"KERNEL32.dll": {"VirtualAllocEx", "WriteProcessMemory"}}, "")
	if c := find(Detect(in, models.PackUnpacked), "inject.classic"); c != nil {
		t.Fatalf("two of four groups must not be reported: %+v", c)
	}
}

func TestDynamicResolutionIsStringReferenced(t *testing.T) {
	in := pe(map[string][]string{"KERNEL32.dll": {"GetProcAddress", "LoadLibraryA"}},
		"\x00OpenProcess\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00")
	c := find(Detect(in, models.PackUnpacked), "inject.classic")
	if c == nil {
		t.Fatal("names stored as strings should still be noticed")
	}
	if len(c.EvidenceKinds) != 1 || c.EvidenceKinds[0] != KindStringReferenced {
		t.Fatalf("kinds %v", c.EvidenceKinds)
	}
	if !strings.Contains(c.Summary, "names as strings") {
		t.Fatalf("%s", c.Summary)
	}
}

func TestCommonSingleAPIsStaySpeculative(t *testing.T) {
	in := pe(map[string][]string{"KERNEL32.dll": {"CreateProcessW", "IsDebuggerPresent"}}, "")
	caps := Detect(in, models.PackUnpacked)
	for _, id := range []string{"exec.process", "evasion.debugger"} {
		c := find(caps, id)
		if c == nil {
			t.Fatalf("%s missing", id)
		}
		if c.Confidence != models.ConfidenceSpeculative {
			t.Errorf("%s: %s; single common API must stay speculative", id, c.Confidence)
		}
	}
}

func TestPackedFileLowersImportBasedConfidence(t *testing.T) {
	imps := map[string][]string{"WS2_32.dll": {"WSAStartup", "socket", "connect", "send", "recv"}}
	un := find(Detect(pe(imps, ""), models.PackUnpacked), "network.client.winsock")
	pk := find(Detect(pe(imps, ""), models.PackConfirmed), "network.client.winsock")
	if un == nil || pk == nil {
		t.Fatal("missing")
	}
	order := map[models.Confidence]int{models.ConfidenceSpeculative: 0, models.ConfidenceLow: 1, models.ConfidenceMedium: 2, models.ConfidenceHigh: 3}
	if order[pk.Confidence] >= order[un.Confidence] && un.Confidence != models.ConfidenceSpeculative {
		t.Fatalf("packed %s should be below unpacked %s", pk.Confidence, un.Confidence)
	}
	if !strings.Contains(pk.Caveat, "packed") {
		t.Fatal("packed caveat missing")
	}
}

func TestExfiltrationIsOnlyACooccurrenceNote(t *testing.T) {
	in := pe(map[string][]string{
		"WININET.dll": {"InternetOpenA", "InternetConnectA", "HttpSendRequestA"},
		"GDI32.dll":   {"BitBlt", "CreateCompatibleDC", "CreateCompatibleBitmap", "GetDIBits"},
		"USER32.dll":  {"GetDC"},
	}, "")
	caps := Detect(in, models.PackUnpacked)
	c := find(caps, "exfil.possible")
	if c == nil {
		t.Fatal("co-occurrence not noted")
	}
	if c.Confidence != models.ConfidenceSpeculative {
		t.Fatalf("exfiltration must be speculative, got %s", c.Confidence)
	}
	if !strings.Contains(c.Summary, "not evidence that data leaves") {
		t.Fatalf("%s", c.Summary)
	}
	if find(Detect(pe(map[string][]string{"WININET.dll": {"InternetOpenA", "InternetConnectA", "HttpSendRequestA"}}, ""), models.PackUnpacked), "exfil.possible") != nil {
		t.Fatal("network alone must not suggest exfiltration")
	}
}

func TestCryptoConstants(t *testing.T) {
	sbox := []byte{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}
	data := append(append([]byte("padding"), sbox...), []byte("more")...)
	in := &analysis.Input{Data: data, Family: "pe", Bin: &models.Binary{Format: "PE32", Attributes: map[string]string{}}, Scan: content.ExtractStrings(data), Sink: analysis.NewSink("t")}
	c := find(Detect(in, models.PackUnpacked), "crypto.constants")
	if c == nil || c.Confidence != models.ConfidenceMedium || c.EvidenceKinds[0] != KindStructural {
		t.Fatalf("%+v", c)
	}
	if len(c.Attack) != 0 {
		t.Fatal("no ATT&CK technique maps to merely containing a cipher; do not invent one")
	}
}

func TestPOSIXSymbolsIncludingMachOUnderscore(t *testing.T) {
	for _, tc := range []struct {
		family, fmt string
		names       []string
	}{{"elf", "ELF64", []string{"socket", "connect", "getaddrinfo"}}, {"macho", "Mach-O 64-bit", []string{"_socket", "_connect", "_getaddrinfo"}}} {
		b := &models.Binary{Format: tc.fmt, Attributes: map[string]string{}, Imports: []models.Import{{Library: "libc"}}}
		for _, n := range tc.names {
			b.Imports[0].Functions = append(b.Imports[0].Functions, models.ImportFn{Name: n})
		}
		in := &analysis.Input{Data: []byte("x"), Family: tc.family, Bin: b, Scan: content.ExtractStrings([]byte("x")), Sink: analysis.NewSink("t")}
		if find(Detect(in, models.PackUnpacked), "network.client.posix") == nil {
			t.Errorf("%s: network client not found", tc.family)
		}
		if find(Detect(in, models.PackUnpacked), "network.client.winsock") != nil {
			t.Errorf("%s: Windows rule applied to a non-PE", tc.family)
		}
	}
}

func TestStringPatternsAreCaseInsensitive(t *testing.T) {
	in := pe(nil, "\x00VSSADMIN Delete Shadows /all /quiet\x00")
	c := find(Detect(in, models.PackUnpacked), "file.inhibit-recovery")
	if c == nil || c.Attack[0] != "T1490" {
		t.Fatalf("%+v", c)
	}
	if c.Confidence != models.ConfidenceMedium {
		t.Fatalf("one exact command string is a strong signal alone: medium, got %s", c.Confidence)
	}
}

// Rule hygiene: the wording and metadata rules of this package, enforced.
func TestRuleHygiene(t *testing.T) {
	attack := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	forbidden := []string{" steals", " injects ", " executes", " calls ", "performs", " will ", " does ", " is malicious", "malware"}
	ids := map[string]bool{}
	for _, r := range Rules {
		if ids[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		ids[r.ID] = true
		if r.Name == "" || r.Category == "" || r.Summary == "" {
			t.Errorf("%s: incomplete metadata", r.ID)
		}
		if len(r.Groups) == 0 && len(r.Strings) == 0 && len(r.Bytes) == 0 {
			t.Errorf("%s: rule matches nothing", r.ID)
		}
		for _, a := range r.Attack {
			if !attack.MatchString(a) {
				t.Errorf("%s: malformed ATT&CK id %q", r.ID, a)
			}
		}
		low := " " + strings.ToLower(r.Summary) + " "
		for _, f := range forbidden {
			if strings.Contains(low, f) {
				t.Errorf("%s: summary %q uses declarative behaviour wording %q", r.ID, r.Summary, f)
			}
		}
		if len(r.Groups) > 0 && r.Complete == "" {
			t.Errorf("%s: Complete strength unset", r.ID)
		}
		if r.Need > len(r.Groups) {
			t.Errorf("%s: Need exceeds group count", r.ID)
		}
		if r.Benign == "" {
			t.Errorf("%s: every rule must say where the pattern is harmless", r.ID)
		}
		for _, p := range r.Strings {
			if p.Strength != "weak" && p.Strength != "moderate" && p.Strength != "strong" {
				t.Errorf("%s: bad strength %q", r.ID, p.Strength)
			}
		}
	}
}

func FuzzDetect(f *testing.F) {
	f.Add([]byte("OpenProcess\x00vssadmin delete shadows"))
	f.Fuzz(func(t *testing.T, b []byte) {
		in := &analysis.Input{Data: b, Family: "pe", Bin: &models.Binary{Format: "PE32", Attributes: map[string]string{}}, Scan: content.ExtractStrings(b), Sink: analysis.NewSink("t")}
		Detect(in, models.PackUnpacked)
	})
}

func TestManagedCodeRules(t *testing.T) {
	mk := func(refs ...string) *analysis.Input {
		fns := make([]models.ImportFn, len(refs))
		for i, r := range refs {
			fns[i] = models.ImportFn{Name: r}
		}
		b := &models.Binary{Format: "PE32", Imports: []models.Import{{Library: ".NET references", Functions: fns}}}
		return &analysis.Input{Family: "pe", Bin: b, Sink: analysis.NewSink("t"), Scan: &content.Scan{}}
	}
	has := func(caps []models.Capability, id string) bool {
		for _, c := range caps {
			if c.ID == id {
				return true
			}
		}
		return false
	}
	got := Detect(mk("Assembly.Load", "Process.Start", "WebClient.DownloadString", "Convert.FromBase64String", "Aes.CreateDecryptor"), models.PackUnpacked)
	for _, id := range []string{"dotnet.reflective-load", "dotnet.process", "dotnet.download", "dotnet.decode-decrypt"} {
		if !has(got, id) {
			t.Errorf("missing %s in %+v", id, got)
		}
	}
	// Half of a two-part pattern is not the pattern.
	if got := Detect(mk("Convert.FromBase64String"), models.PackUnpacked); has(got, "dotnet.decode-decrypt") {
		t.Error("base64 decoding alone must not be reported as decode-and-decrypt")
	}
	// Names that only look similar are not matches.
	if got := Detect(mk("MyProcess.Start", "Assembly.GetName"), models.PackUnpacked); has(got, "dotnet.process") || has(got, "dotnet.reflective-load") {
		t.Errorf("lookalike names matched: %+v", got)
	}
	for _, c := range Detect(mk("Assembly.LoadFrom"), models.PackUnpacked) {
		if c.ID == "dotnet.reflective-load" && c.Confidence == models.ConfidenceDefinitive {
			t.Error("an inference from a reference can never be definitive")
		}
	}
}
