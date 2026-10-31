# UNPACKR — Technical Architecture Review

Status: **proposal for approval. Nothing here is implemented.**

## 0. How to read this document

**Evidence caveat.** The tool assessments below come from working knowledge of
these projects, not from a live audit. This environment could not reach
upstream repositories, so licences, release cadence, maintenance status and
version numbers are **unverified**. Every such claim is tagged `[V]` and must
be confirmed in a verification spike (section 19, milestone 0) before a dependency
is adopted. Where a recommendation depends on a `[V]` item, a fallback is named.

**Priorities** (as mandated): accuracy > capability > robustness on hostile
input > extensibility > performance > offline > UX > implementation cost.

**Position changes from the first proposal.** Several earlier choices were
convenience-driven and are reversed here:

| Earlier proposal | Revised | Reason |
|---|---|---|
| Pure-Go, `CGO_ENABLED=0`, stdlib parsers | Go orchestrator plus isolated engine workers in several languages | Best parsers, rule engines and decompilers are not Go |
| Own rule format for everything | Three rule layers on existing formats (YARA, capa rules, coded detectors) | Large community rule corpora exist; a new format starts with none |
| Hand-write PE reader | Start from a pefile-compatible Go parser, differential-test against pefile and LIEF | Accuracy on malformed files comes from mimicking the loader plus test oracles, not from a fresh implementation |
| Own fuzzy hash | Established algorithms (ssdeep, TLSH, imphash family) plus our own structural similarity | A new fuzzy hash has no validation history |
| Reporting before unpacking | Neither first: artifact-graph engine first | Unpacking changes the data model |

---

## 1. Recommended system architecture

### 1.1 Shape

```
                    ┌──────────────────────────────────────────┐
                    │  unpackr (Go)  CLI · TUI · reports · DB   │
                    │  orchestrator · artifact graph · findings │
                    └───────────────┬──────────────────────────┘
                                    │ typed requests/results (JSON over stdio, schema-versioned)
        ┌───────────────┬───────────┴───────┬────────────────┬───────────────┐
        ▼               ▼                   ▼                ▼               ▼
  native Go core   Rule worker        Format/extract     RE workers      Emulation worker
  (parsers, hash,  (YARA-X, capa      workers            (Rizin, Ghidra  (OPT-IN, off by
  strings, entropy rules, DIE)        (unblob, 7z, UPX,  headless, ILSpy, default; see 7.4)
  carving, disasm                     pyinstaller, .NET  Binja optional)
  lite)                               tools)
```

Core principles:

1. **Go owns orchestration, data model, and everything that must always work.**
   The tool is useful with zero optional engines installed.
2. **Anything that parses hostile data in an unsafe language, or is heavy, runs
   out of process** in a worker with its own temp dir, resource limits, seccomp
   and timeout (section 13). A crash in LIEF, Ghidra or libyara never takes down
   the orchestrator or corrupts a report.
3. **Multiple independent engines are run and reconciled** where accuracy
   matters (parsing, packer ID, strings). Disagreement is itself a reported
   finding, not something silently resolved.
4. **The unit of analysis is an Artifact, not a file.** A sample, its unpacked
   layers, extracted resources and carved payloads form a directed graph;
   every analysis runs per artifact and results link through edges
   ("unpacked-from", "extracted-from at offset", "decrypted-with").
5. **Facts, inferences, hypotheses are separate types** (section 6).

### 1.2 Decision: orchestrator language and process model

| | Recommended: Go orchestrator + process-isolated polyglot workers | Alt A: pure Go | Alt B: Python orchestrator (like Assemblyline/CAPE) | Alt C: Rust core |
|---|---|---|---|---|
| Accuracy | Best of each ecosystem | Limited by Go parser/rule ecosystem | Best library access | Strong parsers (goblin/object), good YARA-X access |
| Hostile-input safety | Orchestrator memory-safe; unsafe code sandboxed | Memory-safe | Memory-safe orchestrator, native libs in-process | Memory-safe |
| Startup/idle cost | ~ms | ~ms | 100–400 ms import cost | ~ms |
| Distribution | Single binary core; extras optional | Single binary | Needs venv/pip; poor air-gap story | Single binary |
| Ecosystem fit for TUI/CLI | Excellent | Excellent | Fair | Good |
| Complexity | Highest (IPC contracts, worker management) | Lowest | Medium | High (smaller RE ecosystem) |

Why it wins: it is the only option that keeps a fast, single-binary,
air-gap-friendly core while still reaching YARA-X, capa, LIEF, Ghidra, unblob
and ILSpy at full capability. Pure Go caps accuracy; Python orchestration costs
startup time and distribution simplicity and puts parsing in-process.
Rust-for-core is credible (best long-term for parsers) but forfeits Bubble Tea
and Go's concurrency ergonomics for small gain, since parsers can be added as
Rust workers later if Go parsers prove inadequate. **Revisit trigger:** if
fuzzing shows Go parser performance or correctness is a bottleneck, move that
single parser to a Rust worker; the worker boundary makes this cheap.

---

## 2. Build-versus-integrate decision matrix

Legend: **N** native Go in core · **W** isolated worker (bundled in package) ·
**X** external, optional, detected at runtime · **D** development/test oracle only.

| Component | Strongest options considered | Decision | Role |
|---|---|---|---|
| PE parsing | pefile (Py), LIEF (C++), saferwall/pe (Go port of pefile) `[V]`, goblin (Rust), Go `debug/pe` | saferwall/pe as base, extended (N); pefile + LIEF as differential oracles (D) and cross-check worker (X) | N + D |
| ELF parsing | LIEF, readelf/binutils, goblin, Go `debug/elf` | N: tolerant layer over `debug/elf` with program-header-only fallback; LIEF/readelf as oracles | N + D |
| Mach-O parsing | blacktop/go-macho `[V]`, LIEF, Go `debug/macho`, ipsw | N: go-macho as base, extended; LIEF oracle | N + D |
| .NET metadata | dnlib (C#), dnfile (Py), ECMA-335 direct | N: own ECMA-335 table reader (well-specified, bounded); dnlib/ILSpy for decompilation | N + X |
| Java class/JAR | Go stdlib zip + own classfile reader, jadx, CFR | N: classfile reader; X: CFR/jadx | N + X |
| Signature engine (packers, compilers, families) | YARA, YARA-X, DIE signature DB, custom | **YARA-X** as the signature engine (W), DIE (`diec`) as second opinion (X) | W + X |
| Capability detection | capa (+ capa-rules), custom, YARA | N: evaluator for capa-rules' *static* feature subset (imports, strings, sections, characteristics); X: full capa for disassembly-based features | N + X |
| String extraction | Go scan, FLOSS, binary refinery | N: fast ASCII/UTF-8/UTF-16 scan; X: FLOSS for stack/tight/decoded strings | N + X |
| Disassembly (light) | golang.org/x/arch, Capstone, Zydis, iced | N: x/arch for bounded entry-stub inspection; W: Capstone or iced when more accuracy needed `[V]` | N + W |
| Function discovery, xrefs, CFG | Rizin, radare2, Ghidra, Binary Ninja, angr, IDA | W: Rizin (fast); X: Ghidra headless (deep); X: Binary Ninja if licensed | W/X |
| Decompilation | Ghidra decompiler, rz-ghidra, RetDec, Binary Ninja HLIL, Hex-Rays | X: Ghidra headless primary; rz-ghidra fast path; RetDec fallback only `[V]` | X |
| .NET decompilation | ILSpy (`ilspycmd`), dnSpyEx, dnlib+de4dot | X: ilspycmd; de4dot for deobfuscation when applicable | X |
| Python-packaged | pyinstxtractor(-ng), pycdc, decompyle3, uncompyle6 | N: PyInstaller CArchive reader (spec is stable); X: pycdc/decompyle3 for bytecode | N + X |
| UPX unpack | upx -d | W: bundled upx; native validation of result | W |
| Generic archive/firmware/container extraction | unblob, Binwalk (Rust v3 `[V]`), 7-Zip, libarchive | W: 7-Zip + libarchive-class tools; X: unblob (strongest sandboxed-extraction framework) | W + X |
| Generic unpacking (non-UPX) | Emulation (speakeasy, Qiling, unipacker, Unicorn), per-packer unpackers | X, **opt-in**, see 7.4 | X |
| Config extraction | CAPE parsers, malduck, RATDecoders, binary refinery, MWCP | X: plugin interface; native: format-specific parsers for families we can test | X |
| Fuzzy hashing | ssdeep, TLSH, sdhash, imphash/rich/authentihash/telfhash/symhash | Integrate established algorithms (section 9) | N (Go ports) |
| Storage | SQLite, DuckDB, Postgres, bbolt/Badger | SQLite + content-addressed blob store (section 10) | N |
| Dynamic analysis | CAPE, Cuckoo, Triage | Out of scope; export formats (STIX/MISP/CAPE-style JSON) only | — |

Overlap and gaps: parsing is covered redundantly (pefile/LIEF/DIE/Rizin) with
inconsistent output; capa, DIE, FLOSS, YARA, unblob, ILSpy and Ghidra each solve
one slice in different formats with no shared evidence model; Assemblyline
and CAPE are server platforms, not local CLIs. **UNPACKR's defensible gap is
(a) a unified evidence/artifact model across engines, (b) cross-engine
disagreement detection, (c) a fast offline CLI that treats unpacked layers as
first-class, and (d) explanation of why a verdict was reached.**

---

## 3. Recommended tools, libraries, engines

**Core dependencies (bundled in the `.deb`, always available)**

| Tool | Why core | Licence implication `[V]` |
|---|---|---|
| Go 1.24+ stdlib, cobra, bubbletea/lipgloss | CLI/TUI | permissive |
| YARA-X (`yr` binary, Rust) | Best signature engine, memory-safe, active VirusTotal development | BSD-3 |
| UPX | Only reliable UPX unpacker | GPL-2+ with exception: ship as separate executable, include source offer |
| 7-Zip / p7zip | Broad container support | LGPL + unRAR restriction: exclude unRAR code |
| SQLite | Storage | public domain |

**Strongly recommended extras (separate package `unpackr-extras` plus `doctor` guidance)**

| Tool | Provides |
|---|---|
| Rizin (+ rz-ghidra) | Fast function/xref/CFG, quick decompile |
| Ghidra (headless, PyGhidra scripts) | Deep decompilation, data-type recovery |
| capa + capa-rules | Disassembly-backed capability detection |
| FLOSS | Obfuscated/stack/decoded strings |
| Detect It Easy (`diec`) | Second-opinion packer/compiler ID |
| LIEF, pefile (Python) | Cross-check parser worker |
| unblob | Sandboxed container/firmware extraction |
| ilspycmd, de4dot | .NET decompilation and deobfuscation |
| pycdc / decompyle3 | Python bytecode |
| Capstone or iced | Accurate disassembly for worker tasks |

**Optional / licensed:** Binary Ninja (headless licence), IDA (no headless in free edition: not supportable), emulation stack (speakeasy / Qiling / Unicorn) under 7.4.

GPL and AGPL components are always invoked as separate processes (never linked
into the Go binary), which keeps the core's own licence unconstrained. Packaging
must ship licence texts and source-offer notices. Because the user ranked
licensing last, bundling is acceptable; the `.deb` records each third-party
component, version and licence in `/usr/share/doc/unpackr/THIRD-PARTY.md`.

---

## 4. File format support strategy

**Principle: format is determined by content, with a ranked list of hypotheses,
not a single label.** Polyglots, appended data, truncated files, and type
confusion are first-class outcomes.

Pipeline for identification:
1. Magic/structure probes run in parallel (PE, ELF, Mach-O/fat, COFF, a.out,
   Java class/JAR, DEX/APK, WebAssembly, MSI/OLE, script shebangs, archives, ...).
2. Each probe returns validity score + the structural checks it passed.
3. Multiple valid probes → polyglot finding; both parse trees are kept.

Depth per format (full parsing, not "headers only"; the earlier "limited first
release" for Mach-O is **rejected**, see decision D2):

| Format | Parsed |
|---|---|
| PE/PE+/COFF | All directories incl. delay/bound imports, exports and forwarders, resources (tree + typed decoding of version info, manifests, icons, strings), relocations, TLS, load config (CFG/SEH), debug (CodeView/PDB path, POGO, REPRO), Rich header, Authenticode (PKCS#7, timestamps, cert chain, signature validity), CLR header, overlay, section/layout anomalies, loader-accurate vs file-literal views |
| ELF | Both views: segment-only and section-based; dynamic, symbols, versioning, notes (build-id, ABI, Go build info), relocations, init/fini arrays, interpreter, RPATH, GNU hash; sections-stripped files must still analyse |
| Mach-O | fat/universal; all load commands; segments/sections; dyld info and chained fixups; symbols and indirect symbols; code signature (CodeDirectory, entitlements, CMS); LC_BUILD_VERSION; Objective-C/Swift metadata (later within the milestone) |
| .NET | Metadata streams and tables, assembly refs, resources, IL method bodies sizes, obfuscator markers |
| Java | class constant pool, methods, JAR manifest, nested JAR |
| Containers | zip, 7z, tar, cab, ISO, NSIS, Inno, PyInstaller, Nuitka onefile, Go/Rust embedded data, AppImage, MSI |
| Scripts | PowerShell, VBS, JS, batch, shell, Python source (detection, de-obfuscation hints) |

Each parser exposes two outputs: **normalised model** (format-neutral section/
import/export/resource tables) and **raw model** (every field, with offset).
All reads are bounds-checked; every anomaly is a typed `Warning` with offset.

---

## 5. Analysis pipeline and module boundaries

### 5.1 Artifact graph

```go
type Artifact struct {
    ID       string          // content-derived (sha256 of bytes)
    Parent   *Edge           // how it came to exist
    Layers   []Layer         // for formats with views (raw file, loader-mapped, decrypted)
    Reports  map[string]any  // per-module outputs, namespaced
}
type Edge struct {
    Kind   string  // unpacked-by | extracted-from | carved-at | decoded-by
    Tool   string  // exact tool + version
    Offset *int64
    Path   string  // path inside archive
}
```

Recursion is bounded (depth, total bytes, count, ratio), cycles impossible
(content-addressed, repeats deduplicated).

### 5.2 Module contract

```go
type Module interface {
    Info() ModuleInfo                        // name, version, cost class, requires, produces
    Run(ctx context.Context, a *Artifact, env *Env) (ModuleResult, error)
}
```
- Modules declare `requires`/`produces`; the scheduler builds a DAG and runs
  independent modules in parallel with a bounded worker pool.
- Cost classes: `instant` (<10 ms), `fast` (<500 ms), `heavy`, `external`.
  Profiles select by class.
- A failure yields a `ModuleResult` with status and warning; analysis continues.
- Worker-backed modules use the same interface; the adapter hides IPC.

### 5.3 Stages (logical order; execution is DAG-parallel)

identify → parse → fingerprint (language/compiler/runtime) → signatures →
packing assessment → strings → resources/payloads → capabilities →
indicators/config → anomalies → correlation → recommendations. Unpack/extract
re-enters the graph with new artifacts.

### 5.4 Interface boundaries

`engine` imports no presentation. `reporting` consumes only the serialised
`Report`. Workers only speak the wire schema (versioned protobuf-free JSON with
a strict schema and size limits). A boundary test (`go list`-based) enforces
this in CI.

---

## 6. Finding, Evidence, and confidence models

### 6.1 Epistemic classes (non-negotiable)

| Class | Meaning | Example | May state |
|---|---|---|---|
| **Observation** | Directly read from bytes by a parser; reproducible | `.text` raw size 0x1200 at 0x400; imports `WriteProcessMemory` | fact, with offset |
| **Inference** | Derived from observations by a named rule | "Import triad consistent with remote-process injection" | "indicates/consistent with", never "does" |
| **Hypothesis** | Plausible but weakly supported or heuristic | "Likely custom packer: high-entropy RWX section and stub-sized entry" | "possible" |

Runtime behaviour is **never** a class here. No finding says an API was called.
Capability findings use the wording policy: *"imports X, Y, Z, consistent with
..."*. A lint test rejects reports whose capability findings use declarative
runtime phrasing.

### 6.2 Schema

```go
type Finding struct {
    ID          string
    Rule        RuleRef          // pack, version, source file, hash of rule
    Class       Class            // observation | inference | hypothesis
    Category    string
    Title       string
    Summary     string
    Severity    Severity         // informational | low | medium | high (impact if true)
    Confidence  Confidence       // see 6.3
    Evidence    []EvidenceRef    // ids into the evidence table
    Attack      []AttackTechnique
    Artifact    string
    Action      string           // recommended next step
    Dissent     []Dissent        // engines/rules that disagree
}
type Evidence struct {
    ID     string
    Kind   string               // import|section|string|header|signature-hit|overlay|resource|asm
    Value  any
    Loc    Location             // file offset, RVA, VA, section, length, artifact-relative path
    Source Source               // module + engine + version + rule id
    Family string               // evidence-family for independence accounting
    Raw    []byte               // truncated bytes, capped
}
```

### 6.3 Confidence

Not a fabricated percentage. Ordinal: `speculative < low < medium < high < definitive`.
Computed by a published rubric:

- `definitive`: only when a validated artifact proves it (UPX unpack succeeded and
  re-parsed; PyInstaller TOC parsed and entries extracted).
- Otherwise derived from the number of **independent evidence families** (e.g. a
  signature hit and an unrelated structural property are independent; two
  signatures matching the same bytes are one family), and from signature
  specificity class (exact vs generic).
- Contradicting evidence lowers confidence and populates `Dissent`.
- Rubric lives in `docs/CONFIDENCE.md`, is covered by tests, and every finding
  prints the rationale on `-v`.

### 6.4 Packing state

`unpacked | likely-packed | confirmed-packed | unknown`, plus `protector-family`
and `unpack-support`. "Confirmed" requires a signature plus a structural
corroboration, or a successful unpack. Entropy is only a feature; there is a
test asserting entropy alone cannot produce either "packed" state.

---

## 7. Detection rules and intelligence architecture

### 7.1 Decision D1 — shared rule format?

**Recommendation: no single format. Layered rule systems unified at the output
(Signal → Finding), not at the syntax.**

| Layer | Format | Used for | Why |
|---|---|---|---|
| L1 byte/structure signatures | YARA (via YARA-X), with PE/ELF modules and pe-specific conditions | packers, protectors, compilers, runtimes, installers, config markers, family rules | Huge existing corpora (public packer/compiler/family rule sets), analyst familiarity, highly optimised |
| L2 capability rules | capa rule YAML (static-feature subset natively; full via capa) | capability and ATT&CK/MBC mapping | Existing maintained rules with ATT&CK/MBC metadata |
| L3 structural/heuristic detectors | Go code with declarative thresholds in YAML | anomalies, packing heuristics, polyglots | These need parsed-model access and arithmetic that neither YARA nor capa expresses cleanly |
| L4 correlation | Small declarative YAML (signals in, finding out) | combining independent signals, confidence | Our unique logic, and the only part where a custom format is justified |

Alternatives rejected: (a) a single custom YAML for everything — forfeits
existing corpora and needs us to re-create DIE's and YARA's rule libraries,
accuracy cost large; (b) YARA only — cannot express "section 2 is RWX and the
entry point is outside .text and import count < 5" across parsers without
heavy module reliance, and has no capability semantics.
Trade-off accepted: four systems to maintain. Mitigation: all emit `Signal`s
into one bus; the correlation layer sees only Signals.

Rule provenance: each rule pack is versioned, hashed, listed in `unpackr doctor`;
reports record exact rule-pack hashes so results are reproducible.
Rule updates are offline: signed archives imported by `unpackr rules import`.
Rule quality gates: every shipped rule needs positive and negative fixtures or
is tagged `experimental` and excluded from default confidence boosts.

### 7.2 Signals

```go
type Signal struct { Kind, Name string; Strength Strength; Evidence []EvidenceRef; Family string }
```
Correlation rules combine signals, e.g. packing = f(signature-hit, section-shape,
entry-point-location, import-sparseness, overlay-structure), each with weight
classes, not magic numbers; weights are stored with the rule and justified.

### 7.3 API relationship mapper

Behaviour groups are L2/L4 rules over imports, delay imports and resolved
strings (GetProcAddress targets, API hashes where decodable via dictionary).
Each result states: *imported*, *string-referenced*, or *call-referenced*
(only if disassembly confirms a call site). Output never uses "calls" without
call-site evidence.

### 7.4 Emulation: policy decision (needs approval, see section 20)

Tools like FLOSS (vivisect), speakeasy, Qiling and unipacker emulate sample
code in a software CPU. That is **not host execution** but it is outside
"purely static". Recommendation: allowed only with explicit `--emulate`, runs
in a locked-down worker (no network, seccomp, memory/time limits, no
filesystem outside temp), results labelled `emulated`, never merged silently
into static results. Default and `-i/-d/-r` remain emulation-free except FLOSS
decoding when the user passes `-r --floss` (clearly documented). This unlocks
generic unpacking and decoded-string recovery, which are major accuracy gains.

---

## 8. Unpacking and extraction strategy

Tiered, with honest support levels reported per sample:

| Tier | Mechanism | Examples | Validation |
|---|---|---|---|
| 1 Deterministic | Format-specific reversal | UPX, PyInstaller, NSIS/Inno, self-extracting zip/7z/RAR, Nuitka onefile, .NET single-file bundle, AppImage, Go embed | Output re-parses, sizes plausible, hashes new, entry/imports sane |
| 2 Container carving | Signature carve + structural validation | embedded PE/ELF/zip/OLE/RTF payloads, resource-embedded files, overlay data | Parse-verified before reporting |
| 3 Known-packer unpackers | Specific external tools | ASPack-class static unpackers, de4dot for .NET | Same validation |
| 4 Generic (opt-in) | Emulation / dump-on-OEP heuristics | custom packers, simple crypters | Labelled `emulated`, confidence capped |
| 5 Unsupported | Reported as unsupported with recommended manual workflow | Themida, VMProtect | no unpacking claim |

Safe extraction: every container extraction runs in a worker with: output
root jail (`openat2(RESOLVE_BENEATH)` or path canonicalisation), symlink/
hardlink/device rejection, ratio/size/count/depth limits, mode 0600, no exec
bit, timestamps neutralised, names sanitised with original name preserved in
metadata. unblob is preferred for complex containers because it already
addresses extraction hardening.

The original sample is never modified; unpacked output is new artifacts with
edges. Analysis then recurses automatically (bounded).

---

## 9. Fingerprinting and similarity

### 9.1 Decision D3 — own fuzzy hash?

**Recommendation: do not invent a fuzzy hash. Integrate established ones, and
build a documented, feature-based similarity engine on top.**

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Own CTPH-style hash | Full control | No validation history; ecosystem incompatibility; risk of misleading scores | Reject |
| ssdeep (CTPH) | Ubiquitous in malware tooling (VT, MISP); pure-Go ports exist `[V]` | Weak on small/high-entropy data; known evasion | Include for interoperability |
| TLSH | Better distance semantics, resistant to some evasion; Go port `[V]` | Needs ≥50 bytes with variance; different scale | Include |
| sdhash | Strong on some corpora | Heavy, less tooled | Optional |
| Structural hashes | imphash, import-name hash, Rich hash, section-layout hash, authentihash, telfhash (ELF), symhash (Mach-O), TypeRef/TypeDef hash (.NET), icon dhash, resource hash, Go build-ID/buildinfo hash | Format-aware, explainable | Core |
| Code-level | Basic-block/function normalised hashes via disassembly; Ghidra BSim; radare/Rizin signatures; Diaphora-style | Highest accuracy for related-code detection; needs disassembly | Optional, extras |

### 9.2 Similarity engine

Per-component similarity (Jaccard over import sets, normalised string-hash
sets, section tuples, resource hashes; TLSH/ssdeep distance; structural-hash
equality) with **each component reported separately**. A combined score is shown
only when ≥ N components are comparable and is documented as a weighted mean
with fixed published weights; otherwise no score. Calibration: weights are
validated on labelled benign and malware-adjacent corpora (legitimate
families/versions) and the measured precision/recall is published in
`docs/SIMILARITY.md`. No family attribution from similarity alone.

Local indexing: MinHash/LSH over feature sets stored in SQLite for sub-linear
lookup across large local corpora; TLSH via a vantage-point or LSH index.

---

## 10. Database and case management

### 10.1 Decision D5 — storage

| | Recommended: SQLite (metadata/relations/FTS) + content-addressed blob store | Alt: Postgres | Alt: DuckDB | Alt: KV (bbolt/Badger) | Alt: Graph DB |
|---|---|---|---|---|---|
| Local, offline, zero-admin | ✔ | ✘ (server) | ✔ | ✔ | ✘ |
| Relational pivoting (IOC→samples→cases) | ✔ | ✔ | ✔ | ✘ | ✔ |
| Full-text on notes/strings | FTS5 | ✔ | partial | ✘ | partial |
| Concurrent writers | single-writer WAL, adequate for a CLI | ✔ | single process | ✔ | ✔ |
| Analytics over large corpora | adequate | ✔ | ✔✔ | ✘ | – |
| Multi-analyst | via export/sync | ✔ | ✘ | ✘ | ✔ |

SQLite wins for a local-first CLI. Postgres is the answer for team deployment,
so the data layer sits behind a repository interface with SQLite as the one
shipped implementation and a documented export (STIX 2.1, MISP, JSON-L) for
team platforms. DuckDB can later query exported Parquet for corpus analytics.

Driver: if the core stays `CGO_ENABLED=0`, use `ncruces/go-sqlite3` or
`modernc.org/sqlite` `[V]`. If the orchestrator accepts cgo (see D6), `mattn/go-sqlite3`
is faster. Recommendation: stay CGO-free; benchmark both pure-Go drivers.

### 10.2 Layout

- `$XDG_DATA_HOME/unpackr/db.sqlite` WAL, `foreign_keys=ON`, migrations embedded.
- `blobs/sha256/ab/cd/<hash>.zst`: reports and extracted artifacts, compressed,
  deduplicated. Samples themselves are stored only by explicit opt-in
  (`--keep-sample`), default is hash and report only (avoids holding live malware).
- Tables: `artifacts(sha256 pk,...)`, `analyses(id, artifact, tool_ver, ruleset_hash, profile, report_blob)`,
  `edges`, `findings`, `evidence`, `indicators(type,value,first/last seen)`,
  `features(artifact, kind, hash)` for similarity, `cases`, `case_artifacts`,
  `notes` (FTS5), `timeline_events`, `tags`, `rule_packs`.
- Analyses are immutable and versioned; re-analysis stores a new row, enabling
  "what changed since last time (tool version, rules, results)" diffs.
- Case folders optionally mirror to disk (`case.yaml` + artifacts) for sharing.

---

## 11. ArtVault architecture

Kept strictly independent of the engine (separate package, no imports from
engine/reporting). Banners are embedded plain-text assets with a header block
(`id`, `category`, `title`, `author`, `notes`). Validation at build time and at
load: ≤80 columns, ≤24 rows, ASCII (curated Unicode box subset allowed for
custom), control bytes/ESC rejected, size cap. Selection: random, non-repeating
across launches (state file), selectable by id/category. Banner and progress
render to **stderr** only when stderr is a TTY; they never enter stdout or file
output. Content bar: each banner must be original and technically accurate;
`docs/ARTVAULT.md` documents provenance and a review checklist. Target ≥60
distinct compositions across the categories in the brief, delivered in
batches so quality review can keep pace. Custom directory:
`~/.config/unpackr/artvault/custom/`.

---

## 12. Reporting and output formats

Single canonical `Report` (JSON Schema published, `schema_version`). Renderers:
terminal (stage-grouped, evidence on `-v`), JSON, JSON-Lines for batch,
Markdown, HTML, CSV (IOCs, batch summary), STIX 2.1 and MISP export for IOCs,
YARA candidate-rule export. HTML: one self-contained file, no external
requests, `html/template` escaping, sample-derived strings stripped of control
characters, print stylesheet, collapsible evidence. Terminal: sample-derived
text is sanitised before display (a hostile string cannot inject escape
sequences or spoof the layout). Reports record tool and rule-pack versions
and the `workers` that ran, so a result is reproducible and an unavailable
engine is visible, not silent.

---

## 13. Security and sandboxing model

Threat model: the sample is adversarial and may target the parser, the
extractor, the report renderer, the terminal and the analyst.

1. **No execution.** The sample is only ever read. No `dlopen`, no `exec` of
   sample or extracted content. Verified by canary tests.
2. **Memory-safe orchestrator**; all unsafe-language parsing is in workers.
3. **Worker sandbox (Linux):** separate process; `no_new_privs`; seccomp
   allow-list; user/mount/pid/net namespaces (via bubblewrap or `unshare`)
   where available, degrading with a visible warning where not; read-only
   bind of the input; private tmpfs; cgroup/`rlimit` CPU, memory, file size,
   open files, process count; hard wall-clock timeout; process-group kill.
   Landlock as additional filesystem restriction `[V]`.
4. **Network:** workers have none. The orchestrator makes no network calls.
5. **IPC:** length-prefixed, size-capped JSON; strict schema validation; worker
   output is untrusted data (a compromised worker must not be able to crash or
   inject into the orchestrator or terminal).
6. **Evidence integrity:** input opened read-only, hashed before and after;
   mismatch is fatal. Optional: analyse a private reflink/copy.
7. **Extraction safety:** see section 8.
8. **Supply chain:** pinned, checksummed external tool versions; `doctor` shows
   versions and hashes; no auto-download; bundled binaries verified at build.
9. **Dynamic analysis:** out of scope; any future feature requires a disposable
   isolated VM and is separate from the static CLI.

---

## 14. Performance strategy (decision D10)

Goal: *first useful answer in well under a second, full depth on demand, never
less accurate than the requested profile.*

- **Streaming first pass:** one mmap'd read-only pass computes hashes, entropy
  blocks, string candidates and magic probes concurrently.
- **Progressive profiles** with explicit cost classes: `quick` = instant+fast
  only; `info` adds fast+selected heavy; `deep` all native; `-r` external.
  Profiles never silently downgrade; skipped modules are listed.
- **DAG scheduling** with bounded concurrency and cancellation (`context`).
- **Result cache** keyed by `(sha256, module, module version, rule-pack hash,
  tool version, options)`; re-analysis returns instantly unless inputs changed.
- **Warm workers:** YARA-X rules compiled once and cached on disk; worker pools
  reused for batches; Ghidra project reuse via persistent headless server where
  supported `[V]`.
- **Memory:** mmap for large files; analysis operates on `ReaderAt`, never loads
  whole files; caps on string and resource retention.
- **Benchmarks in CI** with regression thresholds (startup, hash, parse,
  strings, entropy, full analysis, batch).
- Accuracy is never traded for speed implicitly; trade-offs are profile choices
  the user sees.

---

## 15. Testing and validation plan

- **Differential parsing:** every fixture is parsed by our parser, pefile, LIEF,
  and (ELF) readelf; a disagreement report is generated and triaged. This is the
  main accuracy mechanism for parsers.
- **Fuzzing:** Go native fuzz for each parser and the IPC decoder; AFL++/libFuzzer
  for native workers we ship; corpus seeded with malformed-sample generators.
  CI fails on panic, hang, or unbounded allocation.
- **Fixtures:** generated synthetic binaries (exercising odd layouts, overlapping
  sections, zero-length tables, loops in forwarders, huge counts), small benign
  real binaries built from known source with every supported compiler/runtime
  (gcc, clang, MSVC via cross, mingw, Go, Rust, .NET, Python-PyInstaller, Nuitka,
  UPX variants). No malware committed.
- **Detector validation:** every signature/heuristic documents its fixtures and
  is scored on a labelled benign corpus for false positives; precision/recall
  are published in `docs/DETECTION-QUALITY.md`; a detector without evidence is
  labelled `experimental` and excluded from "supported" claims.
- **Safety tests:** canary non-execution, original-unchanged, extraction-escape
  (zip-slip, symlink, device, bomb) tests, sandbox escape attempts, terminal
  injection strings, HTML injection.
- **Contract tests:** worker wire schema; missing-tool behaviour for every
  optional engine; offline operation under network namespace without routes.
- **Golden tests** for report formats; **CLI tests** on the built binary;
  **packaging tests** in clean Kali and Ubuntu containers; ARM64 via QEMU.
- **Regression corpus:** every bug adds a minimised fixture.

---

## 16. Packaging and deployment

- Core: single static Go binary, amd64 and arm64.
- `.deb` packages: `unpackr` (core + bundled YARA-X, UPX, rule pack),
  `unpackr-extras` (metapackage with `Recommends:` / helper installer for
  Rizin, Ghidra, capa, FLOSS, DIE, Python helpers, ilspycmd). Air-gapped
  install supported via a downloadable offline bundle with checksums.
- Python extras in an isolated venv under `/opt/unpackr/venv` (not system
  Python), built offline from vetted wheels; Java/Ghidra located but not bundled.
- Man page, bash/zsh/fish completions, docs, third-party notices.
- Reproducible builds, SBOM (CycloneDX), checksums, signatures.
- `unpackr doctor` reports every engine, version, path, hash, and which
  features that engine enables or disables.
- Makefile targets per the spec; installer script with architecture detection
  and checksum verification; no unrelated system changes.

---

## 17. Major engineering risks

| Risk | Impact | Mitigation |
|---|---|---|
| Polyglot dependency sprawl | Install pain, version drift | Pinned versions, `doctor`, bundled core engines, optional extras, contract tests |
| Parser divergence from the Windows loader | False conclusions on malformed PEs | Loader-accurate vs literal views, differential testing, corpus of loader quirks |
| Worker IPC attack surface | Orchestrator compromise | Strict schema, caps, untrusted-output posture, fuzz IPC |
| Sandbox unavailable (no userns, containers) | Weaker isolation | Detect and warn loudly; allow `--require-sandbox` to fail closed |
| Rule-pack false positives / stale rules | Misleading verdicts | Quality gates, negative corpus, provenance, experimental tier |
| Emulation scope creep | Blurs static guarantee | Opt-in, labelled, isolated, capped confidence |
| Ghidra/Rizin version churn | Broken adapters | Version-gated adapters, JSON contracts, scripts shipped with tool |
| Scope too large | Never ships | Vertical slices with each milestone usable; unimplemented features absent from `--help` |
| Overconfidence in scores | Analyst harm | Ordinal confidence, rubric, evidence-family independence, dissent surfaced |
| Licensing/distribution (GPL bundles, unRAR, Binary Ninja) | Redistribution issues | Process boundaries, notices, exclude unRAR, no bundled proprietary tools |
| Maintenance burden of own parsers | Long-term cost | Reuse upstream bases, keep them thin, rely on oracles |
| Go cgo-free constraint vs. performance | Slower DB/disasm | Benchmarks first; workers absorb heavy compute |

---

## 18. Decisions D1–D10 summarised

| # | Question | Recommendation | Key alternative rejected |
|---|---|---|---|
| D1 | Shared rule format | **No.** YARA + capa-rules + coded detectors, unified at Signal/Finding level; only the correlation layer is custom | One custom YAML for all |
| D2 | Mach-O depth | **Full parsing in one milestone**, built on go-macho `[V]`, LIEF as oracle | Limited headers-only first release |
| D3 | Fuzzy hashing | **Integrate** ssdeep, TLSH, structural hashes; build feature-based similarity; no new fuzzy hash | Custom CTPH |
| D4 | Reporting vs unpacking order | **Artifact-graph engine first**; JSON/terminal reporting and UPX/container extraction land together; HTML later | Reporting-then-unpacking |
| D5 | Storage | **SQLite + CAS blobs**, repository interface for later Postgres | Postgres, DuckDB, KV |
| D6 | Go for everything? | **No.** Go orchestrator; Rust (YARA-X, optionally parsers), Python (capa, FLOSS, LIEF, pefile, unblob), JVM (Ghidra), .NET (ILSpy) as isolated workers | Pure Go; Python or Rust core |
| D7 | Custom PE parser | **Extend a pefile-compatible Go port** `[V]` with own loader-view layer and differential tests; not from scratch, not stdlib-only | `debug/pe`; LIEF only; pefile-in-Python only |
| D8 | RE integration style | **Subprocess workers with JSON contracts**; tiered Rizin → Ghidra → Binary Ninja | Embedded JVM/JNI; language bindings in-process |
| D9 | Native / optional / external | See 2; native = parsing, hashing, strings, entropy, rule evaluation, carving; workers = YARA-X, UPX, 7z, Rizin; optional = Ghidra, capa, FLOSS, ILSpy, unblob, DIE, emulation | — |
| D10 | Speed vs depth | Progressive profiles, one-pass streaming, DAG, result cache, warm workers; user-visible skips | Single fixed pipeline |

**D8 detail.** Subprocess beats bindings/embedding for RE because Ghidra (JVM) and
Rizin (C) crash on hostile inputs and have large memory footprints; process
isolation contains this, simplifies licensing (Ghidra Apache-2, rz GPL/LGPL,
Binary Ninja commercial) and allows version-gating. Cost: IPC overhead and no
shared memory, negligible against decompilation time. Rizin handles fast
triage (seconds); Ghidra handles depth (tens of seconds to minutes, so it runs
only on `-r` and never implicitly). RetDec is a fallback only `[V]`; IDA Free
is unsupported (no headless automation); Binary Ninja is supported when the
user has a licence.

**D7 detail.** Accuracy on hostile PEs is dominated by how closely the parser
follows what the Windows loader accepts, and by consistent handling of
corruption. pefile is the reference for tolerance, LIEF for breadth, and both
disagree in places. Hence: keep a Go base for speed and always-on use, treat
pefile and LIEF as oracles in CI and as optional runtime cross-checks that
raise a `parser-disagreement` finding. Writing a fresh parser is only
justified for pieces the base lacks (loader-mapped view, anomaly catalogue,
Authenticode validation).

---

## 19. Phased implementation roadmap (milestones)

Each milestone leaves the tool usable and ends with tests, a security review, a
performance check, doc updates and an honest list of what remains.

0. **Verification spike (no product code):** confirm every `[V]` item (licences,
   versions, maintenance, Go port quality), build a comparison harness running
   saferwall/pe, pefile, LIEF on a fixture set, prototype a worker over stdio
   with seccomp/bubblewrap, benchmark pure-Go SQLite drivers. Output: updated
   decision record.
1. **Skeleton:** Go module, CLI flag grammar and tests, config, logging,
   `doctor`, artifact-graph and Finding/Evidence types, JSON schema, worker
   framework, hashing, content-based identification, ArtVault loader and the
   first batch of banners, startup behaviour.
2. **Parsing core:** PE (full), ELF (both views), Mach-O (full), COFF/.NET/Java
   metadata, differential harness, fuzz targets.
3. **Intelligence core:** strings, entropy, YARA-X worker and rule pack, language/
   compiler/runtime fingerprinting, packing assessment, anomalies, indicators,
   native capa-subset capabilities, correlation, ATT&CK mapping, terminal and
   JSON output. **First usable release for `unpackr -i`, `-q`, `-d`, `-v`.**
4. **Unpack/extract:** UPX, PyInstaller, container extraction with sandboxed
   workers, carving, recursion and artifact edges, unpacked-vs-original
   comparison, `-c`.
5. **Reporting and batch:** HTML, Markdown, CSV, STIX/MISP, batch with bounded
   concurrency and consolidated report.
6. **Reverse engineering adapters:** Rizin, Ghidra (headless script pack), capa,
   FLOSS, ILSpy, Python bytecode, DIE second-opinion, cross-engine disagreement
   findings.
7. **Investigation:** SQLite store, sample recognition, similarity with
   published calibration, YARA assistant, cases, timeline.
8. **Interactive:** Bubble Tea `inspect` view with search, filtering, evidence
   navigation.
9. **Optional emulation** (pending D-E below), generic unpacking.
10. **Release engineering:** `.deb` for amd64 and arm64, extras package, offline
    bundle, completions, man page, SBOM, reproducible builds, clean Kali and
    Ubuntu verification, external security review.

---

## 20. Decisions requiring your approval

1. **Architecture shape (D6):** approve Go orchestrator + isolated polyglot
   workers, accepting a bundled Rust binary (YARA-X) and an extras package with
   Python/JVM/.NET tools. Alternative: stay CGO-free pure Go with reduced
   capability.
2. **Rule architecture (D1):** approve YARA-X + capa rules + coded detectors,
   with a custom format only for correlation.
3. **Parser strategy (D7):** approve basing PE on a pefile-compatible Go port
   and using pefile/LIEF as oracles, contingent on the spike confirming its
   quality. Fallback: custom parser from scratch.
4. **Mach-O (D2):** full parsing rather than a limited first release.
5. **Fuzzy hashing (D3):** integrate ssdeep + TLSH + structural hashes; no own algorithm.
6. **Sequencing (D4):** artifact-graph first; reporting formats staged after
   unpack/extract as in the roadmap.
7. **Storage (D5):** SQLite + CAS blob store; samples not retained by default.
8. **RE strategy (D8):** subprocess workers; Rizin fast path, Ghidra deep path,
   Binary Ninja optional; IDA Free unsupported.
9. **Emulation policy (7.4):** permit opt-in, isolated emulation (generic
   unpacking, decoded strings), clearly labelled non-static, or exclude it and
   keep UNPACKR strictly static.
10. **Packaging scope:** bundle YARA-X and UPX in the core `.deb`; extras as a
    separate package with an offline bundle. Confirm acceptable footprint.
11. **UNPACKR's own licence** (affects what may be linked rather than spawned).
12. **Verification spike:** approve doing milestone 0 before
    any product code, since several recommendations depend on `[V]` items.
