// Package fingerprint estimates how an executable was built: language,
// compiler and runtime. Each answer is a ranked list of hypotheses with the
// signals behind them, because several toolchains leave the same traces and
// compiled C and C++ in particular cannot always be told apart.
package fingerprint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/confidence"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

type hyp struct {
	name, detail string
	signals      []models.Signal
	contra       int
}

type builder struct {
	in        *analysis.Input
	languages map[string]*hyp
	compilers map[string]*hyp
	runtimes  map[string]*hyp
}

func (b *builder) get(m map[string]*hyp, name string) *hyp {
	h, ok := m[name]
	if !ok {
		h = &hyp{name: name}
		m[name] = h
	}
	return h
}

func (b *builder) sig(h *hyp, id, detail, strength, family string, ev ...string) {
	h.signals = append(h.signals, models.Signal{ID: id, Detail: detail, Strength: strength, Family: family, Evidence: ev})
}

var (
	reGoVersion  = regexp.MustCompile(`^go1\.\d{1,2}(?:\.\d{1,2})?(?:rc\d+|beta\d+)?$`)
	reRustPath   = regexp.MustCompile(`/rustc/([0-9a-f]{40})/`)
	reGCCComment = regexp.MustCompile(`GCC: \([^)]*\) [0-9][0-9.]*`)
	reClang      = regexp.MustCompile(`(?:Ubuntu |Debian |Apple )?clang version [0-9][0-9.]*`)
	reMSVCRT     = regexp.MustCompile(`(?i)^(?:vcruntime\d+(?:_\d+)?|msvcp\d+(?:_\d+)?|msvcr\d+|ucrtbase|api-ms-win-crt-[a-z-]+-l\d+-\d+-\d+)\.dll$`)
	rePyDLL      = regexp.MustCompile(`(?i)^python3\d*\.dll$`)
)

// Detect inspects in and returns ranked hypotheses.
func Detect(in *analysis.Input) models.Fingerprint {
	b := &builder{in: in, languages: map[string]*hyp{}, compilers: map[string]*hyp{}, runtimes: map[string]*hyp{}}
	if in.Bin != nil {
		b.goLang()
		b.rustLang()
		b.dotnet()
		b.python()
		b.delphi()
		b.vb6()
		b.msvc()
		b.gccClang()
		b.apple()
	}
	b.java()
	b.yara()
	b.cFamilyAlternatives()
	return models.Fingerprint{
		Languages: rank(b.languages),
		Compilers: rank(b.compilers),
		Runtimes:  rank(b.runtimes),
	}
}

func rank(m map[string]*hyp) []models.Hypothesis {
	var out []models.Hypothesis
	for _, h := range m {
		c, why := confidence.Derive(h.signals, h.contra)
		out = append(out, models.Hypothesis{Name: h.name, Detail: h.detail, Confidence: c, Rationale: why, Signals: h.signals})
	}
	order := map[models.Confidence]int{models.ConfidenceHigh: 4, models.ConfidenceMedium: 3, models.ConfidenceLow: 2, models.ConfidenceSpeculative: 1}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Confidence] != order[out[j].Confidence] {
			return order[out[i].Confidence] > order[out[j].Confidence]
		}
		return out[i].Name < out[j].Name
	})
	if out == nil {
		out = []models.Hypothesis{}
	}
	return out
}

func (b *builder) goLang() {
	in := b.in
	lang := b.get(b.languages, "Go")
	if off := in.FindBytes([]byte("\xff Go buildinf:")); off >= 0 {
		ev := in.Sink.Add("signature", "Go build information header", off, 14, in.SectionAt(off), "fingerprint/go/buildinfo", "go:buildinfo")
		b.sig(lang, "lang.go.buildinfo", "Go build information header present", "strong", "go:buildinfo", ev)
	}
	for _, s := range in.Bin.Sections {
		switch s.Name {
		case ".gopclntab", "__gopclntab", ".go.buildinfo", "__go_buildinfo", ".note.go.buildid", ".typelink", "__typelink":
			ev := in.Sink.Add("section", "Go runtime section "+s.Name, int64(s.RawOffset), int64(s.RawSize), s.Name, "fingerprint/go/section", "go:sections")
			b.sig(lang, "lang.go.section", "section "+s.Name+" is created by the Go linker", "moderate", "go:sections", ev)
			goto versioned
		}
	}
	if h, ok := in.FindString(func(t string) bool {
		return strings.HasPrefix(t, "runtime.gopanic") || strings.HasPrefix(t, "runtime.goexit")
	}); ok {
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/go/symbols", "go:symbols")
		b.sig(lang, "lang.go.symbol", "Go runtime symbol names present", "moderate", "go:symbols", ev)
	}
versioned:
	if len(lang.signals) == 0 {
		delete(b.languages, "Go")
		return
	}
	if h, ok := in.FindString(func(t string) bool { return reGoVersion.MatchString(t) }); ok {
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/go/version", "go:version")
		lang.detail = "toolchain " + h.Text
		b.sig(lang, "lang.go.version", "toolchain version string "+h.Text, "moderate", "go:version", ev)
		comp := b.get(b.compilers, "Go toolchain (gc)")
		comp.detail = h.Text
		b.sig(comp, "comp.go.version", "version string "+h.Text, "strong", "go:version", ev)
		b.sig(comp, "comp.go.buildinfo", "Go build information present", "moderate", "go:buildinfo", lang.signals[0].Evidence...)
	} else {
		comp := b.get(b.compilers, "Go toolchain (gc)")
		b.sig(comp, "comp.go.lang", "binary is Go", "moderate", "go:lang", lang.signals[0].Evidence...)
	}
	b.sig(b.get(b.runtimes, "Go runtime (statically linked)"), "rt.go", "Go binaries embed their own runtime", "moderate", "go:lang", lang.signals[0].Evidence...)
}

func (b *builder) rustLang() {
	in := b.in
	var sigs []models.Signal
	if off, m := in.FindRegexp(reRustPath); off >= 0 {
		ev := in.Sink.Add("string", m, off, int64(len(m)), in.SectionAt(off), "fingerprint/rust/path", "rust:path")
		sigs = append(sigs, models.Signal{ID: "lang.rust.path", Detail: "standard-library source path embedded (panic location)", Strength: "strong", Family: "rust:path", Evidence: []string{ev}})
	}
	if h, ok := in.FindString(func(t string) bool {
		return strings.Contains(t, "rust_begin_unwind") || strings.Contains(t, "core::panicking") || strings.Contains(t, "rust_eh_personality")
	}); ok {
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/rust/symbols", "rust:symbols")
		sigs = append(sigs, models.Signal{ID: "lang.rust.symbols", Detail: "Rust runtime symbol present", Strength: "moderate", Family: "rust:symbols", Evidence: []string{ev}})
	}
	if len(sigs) == 0 {
		return
	}
	lang := b.get(b.languages, "Rust")
	lang.signals = sigs
	comp := b.get(b.compilers, "rustc (LLVM)")
	comp.signals = append(comp.signals, sigs...)
	if off, m := in.FindRegexp(reRustPath); off >= 0 {
		comp.detail = "built with a rustc whose commit is " + reRustPath.FindStringSubmatch(m)[1][:12] + " (version not derivable from the hash alone)"
	}
}

func (b *builder) dotnet() {
	in := b.in
	if in.Bin.Attributes["has_clr_header"] != "true" {
		return
	}
	lang := b.get(b.languages, ".NET (C#, VB.NET or F# - not distinguished)")
	ev := in.Sink.Add("header", "CLR runtime header present in the PE data directories", -1, 0, "", "fingerprint/dotnet/clr", "dotnet:clr")
	b.sig(lang, "lang.dotnet.clr", "CLR header present: the file contains managed code", "strong", "dotnet:clr", ev)
	if in.HasImport("_CorExeMain") || in.HasImport("_CorDllMain") {
		ev2 := in.Sink.Add("imports", "mscoree.dll entry import", -1, 0, "", "fingerprint/dotnet/mscoree", "dotnet:import")
		b.sig(lang, "lang.dotnet.import", "imports the CLR entry stub from mscoree.dll", "moderate", "dotnet:import", ev2)
	}
	rt := b.get(b.runtimes, ".NET (CLR / .NET Framework or modern .NET)")
	rt.signals = append(rt.signals, lang.signals...)
	if h, ok := in.FindString(func(t string) bool {
		return strings.HasPrefix(t, ".NETFramework,Version=") || strings.HasPrefix(t, ".NETCoreApp,Version=")
	}); ok {
		ev3 := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/dotnet/target", "dotnet:target")
		rt.detail = "target " + h.Text
		b.sig(rt, "rt.dotnet.target", "target framework attribute "+h.Text, "strong", "dotnet:target", ev3)
	}
}

func (b *builder) python() {
	in := b.in
	if off := in.FindBytes([]byte("MEI\x0c\x0b\x0a\x0b\x0e")); off >= 0 {
		lang := b.get(b.languages, "Python (bundled with PyInstaller)")
		ev := in.Sink.Add("signature", "PyInstaller archive cookie", off, 8, in.SectionAt(off), "fingerprint/pyinstaller/cookie", "pyi:cookie")
		b.sig(lang, "lang.python.pyinstaller", "PyInstaller CArchive cookie present", "strong", "pyi:cookie", ev)
		rt := b.get(b.runtimes, "Embedded CPython interpreter")
		b.sig(rt, "rt.pyinstaller", "PyInstaller bundles a Python interpreter", "strong", "pyi:cookie", ev)
		if h, ok := in.FindString(func(t string) bool {
			return strings.HasPrefix(t, "python3") && (strings.HasSuffix(t, ".dll") || strings.Contains(t, ".so"))
		}); ok {
			ev2 := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/pyinstaller/lib", "pyi:lib")
			rt.detail = h.Text
			b.sig(rt, "rt.python.lib", "interpreter library name "+h.Text, "moderate", "pyi:lib", ev2)
		}
	}
	for _, im := range in.Bin.Imports {
		if rePyDLL.MatchString(im.Library) {
			lang := b.get(b.languages, "Python (embedding or bundling an interpreter)")
			ev := in.Sink.Add("imports", "imports "+im.Library, -1, 0, "", "fingerprint/python/dll", "py:dll")
			b.sig(lang, "lang.python.dll", "links "+im.Library, "moderate", "py:dll", ev)
		}
	}
	if h, ok := in.FindString(func(t string) bool { return strings.Contains(t, "Nuitka") && len(t) < 200 }); ok {
		lang := b.get(b.languages, "Python (compiled with Nuitka)")
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/nuitka", "nuitka:str")
		b.sig(lang, "lang.python.nuitka", "Nuitka marker string", "moderate", "nuitka:str", ev)
	}
}

func (b *builder) delphi() {
	in := b.in
	if in.Bin.Family() != "pe" {
		return
	}
	var sigs []models.Signal
	if len(in.Bin.Sections) > 0 && in.Bin.Sections[0].Name == "CODE" {
		ev := in.Sink.Add("section", "first section is named CODE", int64(in.Bin.Sections[0].RawOffset), 0, "CODE", "fingerprint/delphi/section", "delphi:section")
		sigs = append(sigs, models.Signal{ID: "lang.delphi.section", Detail: "section layout CODE/DATA/BSS used by Borland and Embarcadero linkers", Strength: "moderate", Family: "delphi:section", Evidence: []string{ev}})
	}
	if h, ok := in.FindString(func(t string) bool {
		return strings.Contains(t, "Software\\Borland\\Delphi") || strings.Contains(t, "Embarcadero") || t == "TObject" || strings.Contains(t, "This program must be run under Win32")
	}); ok {
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/delphi/string", "delphi:string")
		sigs = append(sigs, models.Signal{ID: "lang.delphi.string", Detail: "Delphi/Embarcadero runtime string", Strength: "moderate", Family: "delphi:string", Evidence: []string{ev}})
	}
	if len(sigs) == 0 {
		return
	}
	b.get(b.languages, "Delphi / Object Pascal").signals = sigs
	b.get(b.compilers, "Borland / Embarcadero Delphi compiler").signals = sigs
}

func (b *builder) vb6() {
	in := b.in
	if in.HasImport("MSVBVM60.DLL") || in.HasImport("MSVBVM50.DLL") {
		ev := in.Sink.Add("imports", "imports the Visual Basic 5/6 runtime", -1, 0, "", "fingerprint/vb6/runtime", "vb6:import")
		h := b.get(b.languages, "Visual Basic 5/6")
		b.sig(h, "lang.vb6", "links MSVBVM50/60.DLL", "strong", "vb6:import", ev)
		b.sig(b.get(b.runtimes, "Visual Basic 6 runtime (MSVBVM60)"), "rt.vb6", "links MSVBVM60.DLL", "strong", "vb6:import", ev)
	}
}

func (b *builder) msvc() {
	in := b.in
	if in.Bin.Family() != "pe" {
		return
	}
	var cpp bool
	var libs []string
	for _, im := range in.Bin.Imports {
		if reMSVCRT.MatchString(im.Library) {
			libs = append(libs, strings.ToLower(im.Library))
			if strings.HasPrefix(strings.ToLower(im.Library), "msvcp") {
				cpp = true
			}
		}
	}
	rich := in.Bin.Attributes["rich_header"] == "true"
	if len(libs) == 0 && !rich {
		return
	}
	comp := b.get(b.compilers, "Microsoft Visual C/C++")
	if rich {
		ev := in.Sink.Add("header", "Rich header present (linker-recorded build tool list)", -1, 0, "", "fingerprint/msvc/rich", "msvc:rich")
		b.sig(comp, "comp.msvc.rich", "Rich header, written only by Microsoft's linker", "strong", "msvc:rich", ev)
	}
	if len(libs) > 0 {
		sort.Strings(libs)
		ev := in.Sink.Add("imports", strings.Join(libs, ", "), -1, 0, "", "fingerprint/msvc/crt", "msvc:crt")
		b.sig(comp, "comp.msvc.crt", "links the Microsoft C runtime ("+libs[0]+")", "moderate", "msvc:crt", ev)
		rt := b.get(b.runtimes, "Microsoft Visual C++ / Universal C runtime")
		b.sig(rt, "rt.msvc.crt", "links "+strings.Join(libs, ", "), "moderate", "msvc:crt", ev)
	}
	if lv := in.Bin.Attributes["linker_version"]; lv != "" {
		comp.detail = "linker version " + lv
	}
	if cpp {
		ev := in.Sink.Add("imports", "msvcp*.dll (C++ standard library)", -1, 0, "", "fingerprint/msvc/cpp", "msvc:cpp")
		b.sig(b.get(b.languages, "C++"), "lang.cpp.msvcp", "links the C++ standard library runtime", "moderate", "msvc:cpp", ev)
	}
}

func (b *builder) gccClang() {
	in := b.in
	if _, ok := in.FindString(func(t string) bool {
		return strings.HasPrefix(t, "Mingw-w64 runtime failure") || strings.Contains(t, "libgcc_s_") || strings.Contains(t, "__mingw_")
	}); ok && in.Bin.Family() == "pe" {
		h, _ := in.FindString(func(t string) bool {
			return strings.HasPrefix(t, "Mingw-w64 runtime failure") || strings.Contains(t, "libgcc_s_") || strings.Contains(t, "__mingw_")
		})
		ev := in.Sink.Add("string", h.Text, h.Offset, int64(len(h.Text)), in.SectionAt(h.Offset), "fingerprint/mingw/runtime", "mingw:str")
		b.sig(b.get(b.compilers, "GCC (MinGW-w64)"), "comp.mingw", "MinGW runtime string", "strong", "mingw:str", ev)
	}
	if off, m := in.FindRegexp(reGCCComment); off >= 0 {
		ev := in.Sink.Add("string", m, off, int64(len(m)), in.SectionAt(off), "fingerprint/gcc/comment", "gcc:comment")
		c := b.get(b.compilers, "GCC")
		c.detail = strings.TrimPrefix(m, "GCC: ")
		b.sig(c, "comp.gcc.comment", ".comment-style GCC version string", "strong", "gcc:comment", ev)
	}
	if off, m := in.FindRegexp(reClang); off >= 0 {
		ev := in.Sink.Add("string", m, off, int64(len(m)), in.SectionAt(off), "fingerprint/clang/version", "clang:comment")
		c := b.get(b.compilers, "Clang / LLVM")
		c.detail = m
		b.sig(c, "comp.clang.version", "clang version string", "strong", "clang:comment", ev)
	}
	// Dynamic C++ standard library linkage.
	for _, l := range in.Bin.Libraries {
		if strings.HasPrefix(l, "libstdc++") || strings.HasPrefix(l, "libc++") {
			ev := in.Sink.Add("imports", "links "+l, -1, 0, "", "fingerprint/cpp/stdlib", "cpp:stdlib")
			b.sig(b.get(b.languages, "C++"), "lang.cpp.stdlib", "links the C++ standard library "+l, "moderate", "cpp:stdlib", ev)
		}
	}
}

func (b *builder) apple() {
	in := b.in
	if in.Bin.Family() != "macho" {
		return
	}
	bin := in.Bin
	if len(bin.Slices) > 0 {
		bin = &bin.Slices[0]
	}
	for _, l := range bin.Libraries {
		switch {
		case strings.Contains(l, "libswiftCore"):
			ev := in.Sink.Add("imports", "links "+l, -1, 0, "", "fingerprint/swift/lib", "swift:lib")
			b.sig(b.get(b.languages, "Swift"), "lang.swift", "links the Swift standard library", "strong", "swift:lib", ev)
		case strings.Contains(l, "libobjc"):
			ev := in.Sink.Add("imports", "links "+l, -1, 0, "", "fingerprint/objc/lib", "objc:lib")
			b.sig(b.get(b.languages, "Objective-C"), "lang.objc", "links the Objective-C runtime", "moderate", "objc:lib", ev)
		}
	}
}

func (b *builder) java() {
	in := b.in
	if len(in.Data) >= 4 && string(in.Data[:4]) == "\xca\xfe\xba\xbe" && in.Family == "java" {
		ev := in.Sink.Add("header", "Java class file magic", 0, 4, "", "fingerprint/java/class", "java:class")
		b.sig(b.get(b.languages, "Java (JVM bytecode)"), "lang.java.class", "class file magic", "strong", "java:class", ev)
	}
}

// cFamilyAlternatives keeps C and C++ honest: native binaries from the same
// toolchain look alike, so when a C-family compiler is indicated and neither
// language is established both stay on the list as alternatives.
func (b *builder) cFamilyAlternatives() {
	hasCompiler := false
	for n := range b.compilers {
		if strings.Contains(n, "Visual C") || strings.Contains(n, "GCC") || strings.Contains(n, "Clang") {
			hasCompiler = true
		}
	}
	if !hasCompiler {
		return
	}
	if b.languages["C++"] == nil {
		c := b.get(b.languages, "C++")
		c.detail = "cannot be excluded: compiled C and C++ are not reliably distinguishable"
		b.sig(c, "lang.cpp.alt", "same toolchains compile both languages", "weak", "c-family")
	}
	cc := b.get(b.languages, "C")
	cc.detail = "cannot be excluded: compiled C and C++ are not reliably distinguishable"
	b.sig(cc, "lang.c.alt", "a C-family compiler is indicated and no C++ runtime was found", "weak", "c-family")
	if b.languages["C++"] != nil && len(b.languages["C++"].signals) > 1 {
		cc.contra = 1
	}
	if cl := b.languages["C++"]; cl != nil && cl.detail == "" {
		cl.detail = fmt.Sprintf("%d supporting signal(s)", len(cl.signals))
	}
}

// yara folds tested YARA-X matches into the hypotheses. A rule that reads the
// same bytes as a native detector shares its family, so agreement between
// engines is shown without being counted as independent corroboration.
func (b *builder) yara() {
	for cat, m := range map[string]map[string]*hyp{"language": b.languages, "compiler": b.compilers, "runtime": b.runtimes} {
		for _, ym := range b.in.TestedYara(cat) {
			fam := ym.Family
			if fam == "" {
				fam = "yara:" + ym.Rule
			}
			ev := b.in.YaraEvidence(ym, fam)
			h := b.get(m, ym.Name)
			h.signals = analysis.MergeSignal(h.signals, models.Signal{
				ID: "fp.yara." + ym.Rule, Detail: ym.Description + " (YARA-X rule " + ym.Rule + ")", Strength: ym.Strength, Family: fam, Evidence: []string{ev},
			}, "also matched by YARA-X rule "+ym.Rule)
		}
	}
}
