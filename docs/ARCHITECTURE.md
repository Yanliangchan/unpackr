# UNPACKR — Architecture Proposal

Status: **proposal, awaiting review.** No implementation exists yet. Nothing in
this document is claimed as built.

## 1. Research summary: build vs. integrate

| Tool | Licence | What it teaches us | Decision |
|---|---|---|---|
| Detect It Easy | MIT | Signature scripting for packer/compiler ID | Native: own declarative rule format, no code copied |
| capa | Apache-2.0 | Rule-based capability mapping, ATT&CK tagging | Native: simplified rules over imports/strings/structure. No disassembly-based features initially |
| FLOSS | Apache-2.0 | Decoding obfuscated strings via emulation | Integrate (subprocess), optional |
| pefile | MIT | Tolerant PE parsing, anomaly warnings | Native parser built on Go `debug/pe` plus own tolerant fallback |
| Ghidra | Apache-2.0 | Decompilation | Integrate (headless, subprocess), optional |
| ILSpy (`ilspycmd`) | MIT | .NET decompilation | Integrate (subprocess), optional |
| Binwalk | MIT | Carving embedded content by signature | Native: small carver with strict limits |
| UPX | GPL-2.0+ | Reference unpacker | Integrate via subprocess only (never linked, never bundled) |
| YARA | BSD-3 | Rule syntax | Native rule *generation* and a minimal local matcher. Full YARA engine stays external |
| ssdeep/TLSH | GPL / Apache | Fuzzy hashing | Native implementation of a documented CTPH algorithm, clearly labelled as such |

Principle: re-implement cheap, high-value, well-specified logic (parsing,
signatures, correlation). Delegate mature heavy tools (decompilers, emulation)
to subprocess adapters. GPL tools are never linked or distributed.

## 2. Language, libraries, dependency map

Go 1.24, single static binary, `CGO_ENABLED=0` so amd64 and arm64 cross-compile
trivially.

| Concern | Choice | Reason |
|---|---|---|
| CLI | `spf13/cobra` + `pflag` | Short/long flags, completions (bash/zsh/fish), man page generation |
| TUI | `charmbracelet/bubbletea`, `bubbles`, `lipgloss` | Works over SSH, no GUI |
| Storage | `modernc.org/sqlite` | Pure Go, no CGO, keeps cross-builds simple |
| Config | `gopkg.in/yaml.v3` | Specified |
| Formats | stdlib `debug/pe`, `debug/elf`, `debug/macho`, `archive/zip`, `compress/*` | No dependency; wrapped by tolerant layer |
| HTML | stdlib `html/template` + `embed` | Fully offline, no CDN |
| Tests | stdlib `testing`, native fuzzing | |

Stdlib limits to design around: `debug/pe` rejects many malformed files and
exposes no resources, TLS, relocations, certificates or overlay. We use it for
the happy path and add our own bounds-checked reader (`internal/formats/pe`)
for everything it omits and for malformed input. All reads go through a
bounds-checked `ReaderAt` wrapper so corrupt headers yield warnings, never
panics.

## 3. Command-line specification

Single root command; analysis is flag-driven (Nmap/Binwalk style). Subcommands
exist only for non-analysis utilities.

```
unpackr [flags] <path>...            # path may be a file or directory
unpackr -i <path>                    # full static analysis
unpackr -q <path|dir>                # triage
unpackr -c <a> <b>                   # compare
unpackr doctor | art … | inspect <path> | case … | db … | completion <shell>
```

| Short | Long | Notes |
|---|---|---|
| `-i` | `--info` | Full static profile (default when only a path is given with no mode flag) |
| `-q` | `--quick` | Triage profile; accepts directories |
| `-d` | `--deep` | Modifier; extends the active profile; never invokes decompilers |
| `-v` | `--verbose` | Presentation only; does not change what is analysed |
| `-u` | `--unpack` | Modifier; supported unpackers only |
| `-x` | `--extract` | Modifier; carve/extract into `--output-dir` |
| `-r` | `--reverse` | Modifier; use detected external tools |
| `-c` | `--compare` | Takes exactly two paths |
| `-o` | `--output <file>` | Format inferred from `.json/.html/.md/.csv` |
| `-h` | `--help` | |
| — | `--version` | |

Long-only: `--no-banner`, `--banner <random\|NNN\|category>`, `--offline`,
`--format`, `--modules a,b,c`, `--threads N`, `--timeout D`, `--output-dir`,
`--config`, `--quiet`, `--no-color`.

Parsing rules (documented in COMMANDS.md and enforced by CLI tests):

- Mode flags `-i -q -c` are mutually exclusive; modifiers `-d -v -u -x -r` combine freely.
- Positional paths are accepted before or after flags. `-i` and `-q` are boolean, so `unpackr -i a.exe` and `unpackr a.exe -i` are equivalent. `-c` consumes two positionals.
- `-o` and `--output-dir` take a value; `-o` is validated against the allowed format set before analysis starts.
- Banner suppressed when stdout is not a TTY, or `--format` is machine-readable, or `--quiet`/`--no-banner`. Banner and progress go to stderr, never into report output.
- Exit codes: 0 success, 1 analysis error, 2 usage error, 3 partial result (parser warnings with `--strict`).

## 4. Module map

```
cmd/unpackr/                 main only
internal/
  cli/                       cobra wiring, flag validation, no analysis logic
  config/                    YAML load, defaults, XDG paths
  engine/                    Analyze(ctx, path, Options) -> *models.Report
  pipeline/                  ordered stages, module selection, cancellation
  formats/{pe,elf,macho,dotnet,java,container}/   parsers → models.Binary
  identification/            magic-based type detection, hashes, signature status
  language/  compiler/       independent signal collectors → scored hypotheses
  packing/                   signature + structural heuristics; entropy is one input
  unpacking/                 adapters: upx, pyinstaller, archives
  strings/                   ASCII/UTF-8/UTF-16 extraction with offsets
  resources/                 resource/overlay/embedded-payload inspection
  capabilities/              rules + correlation + ATT&CK mapping
  indicators/                IOC extraction/classification
  fingerprint/               structural fingerprint + similarity
  comparison/                two-report diff
  decompiler/                ghidra, ilspy, floss, pyc adapters
  reporting/                 terminal, json, html, md, csv renderers
  database/                  sqlite sample DB
  cases/                     case management
  safety/                    limits, temp dirs, path guard, subprocess runner
  terminal/                  tty detection, colour, progress
  artvault/                  banners; imports nothing from engine
pkg/models  pkg/rules  pkg/signatures
assets/{artvault,signatures,rules,templates}   (go:embed)
tests/{fixtures,integration,unit,benchmarks}  docs/
```

Dependency rules (checked by a test using `go list`):
`engine` and everything below it must not import `terminal`, `cli`, `artvault`
or `reporting`. `reporting` imports only `pkg/models`. `artvault` imports
nothing internal. External tools are reachable only through `safety.Runner`.

## 5. Core data model (`pkg/models`)

```go
type Finding struct {
    ID          string       // stable rule id, e.g. "pack.upx.sections"
    Category    Category     // identification|fingerprint|packing|capability|anomaly|ioc|payload
    Title       string
    Description string
    Severity    Severity     // info|low|medium|high
    Confidence  Confidence   // low|medium|high, with Rationale string
    Evidence    []Evidence   // what was observed
    Recommended string
    Attack      []string     // ATT&CK technique IDs where applicable
}
type Evidence struct {
    Kind    string // import|section|string|header|signature|resource
    Value   string
    Offset  *int64 // file offset
    RVA     *uint64
    VA      *uint64
    Source  string // module that produced it
}
```

`Report` holds `File`, `Hashes`, `Binary` (format-neutral view: sections,
imports, exports, resources, overlay), `Language`/`Compiler` hypotheses (ranked,
with alternatives), `Packing` (state: unpacked | likely | confirmed | unknown),
`Strings`, `Indicators`, `Capabilities`, `Findings`, `Warnings`, `Tools`
(external tool availability), `Meta` (version, duration, options). It is
JSON-serialisable and is the only thing renderers see.

Verdict discipline:

- Entropy is an input to a score, never a verdict on its own.
- Imported API ≠ executed behaviour; every capability finding carries an
  evidence class: `imported`, `referenced-string`, `structural`. Nothing is
  labelled `observed` because no execution happens.
- C vs C++ is reported as ranked alternatives with confidence.

## 6. Analysis pipeline

Stages mirror an investigation and each is an independently testable module
implementing:

```go
type Module interface {
    Name() string
    Requires() []string          // module names whose output it consumes
    Run(ctx context.Context, in *Input, rep *models.Report) error
}
```

Order: identify → parse format → fingerprint (language/compiler) → packing →
strings → resources/payloads → capabilities/indicators → anomalies →
correlation → recommendations. `--modules` selects a subset (dependencies are
pulled in automatically). A module failure becomes a Warning on the report; it
does not abort the run. Profiles (`quick`, `info`, `deep`) are just module sets
plus limits.

## 7. Security model

- Files are only ever opened read-only and read via `ReaderAt`; no `exec` of
  samples, no loading as libraries, no `mmap` with `PROT_EXEC`. A test builds a
  sample that would write a marker file if run and asserts it never does.
- Hard limits (configurable, with defaults): max file size, max section/
  resource count, max recursion depth for containers, max total extracted
  bytes, max extraction ratio (zip-bomb guard), per-module and global timeouts.
- Extraction: every output path is cleaned and verified to stay inside the
  work directory (rejects `..`, absolute paths, symlinks); extracted files are
  mode 0600, never executable.
- Subprocesses: allow-listed binaries resolved once, explicit argv (no shell),
  scrubbed env, per-run temp dir (0700), timeout, output size cap, process
  group kill on cancel.
- Original sample is hashed before and after; a mismatch is a hard error.
- Report output paths are validated; HTML output escapes all sample-derived
  text via `html/template`; terminal output strips control sequences from
  sample-derived strings.
- Offline-first: the binary makes no network calls. `--offline` is the
  default behaviour and exists to make that explicit and testable.

## 8. Unpacking, extraction, reverse engineering

- UPX: detect by signature; `upx -d` on a copy in a restricted temp dir;
  validate output (parses as same format, sections sane, hash differs);
  re-run analysis on result; diff against original.
- PyInstaller: native reader for the CArchive (cookie `MEI\x0c\x0b\x0a\x0b\x0e`,
  TOC) with size limits; extracts entries, flags `.pyc`. Decompiling bytecode
  is delegated to external tools if present.
- Archives: zip/jar via stdlib; others via signature + optional tools.
- Not claimed: generic unpacking. Unsupported packers are reported as such.
- Adapters for Ghidra headless, `ilspycmd`, FLOSS: detect, check version,
  run with timeout, capture stdout/stderr, validate artefacts. Missing tools
  produce install guidance and a list of unavailable features, never an error.

## 9. Fingerprint and similarity (to be documented in docs)

Fingerprint = hashes + import hash (sorted lower-cased `dll.func`) + section
layout (name, sizes, entropy bucket) + resource type hash + rich-header hash
where present + selected string hash set + packing/compiler tags.
Similarity: Jaccard over import sets, section-name/size tuples and string-hash
sets, combined as a fixed, published weighted mean over components that exist
in both samples; each component score is shown alongside the total. No score
is shown when there is too little data. No family attribution.

## 10. Persistence

SQLite at `~/.local/share/unpackr/unpackr.db` (XDG). Tables: `samples`
(sha256 PK), `analyses` (versioned JSON report + timestamp), `cases`,
`case_samples`, `findings`, `indicators`, `notes`, `timeline`. Schema
migrations are embedded and numbered. Re-encountering a sha256 shows prior
analysis date, case links and a diff of changed characteristics (e.g. newer
rules producing new findings). Database use can be disabled in config.

## 11. ArtVault

Embedded plain-text banners under `assets/artvault/<category>/NNN.txt` with
optional front-matter (title, category, tags). Library enforces ≤ 80 columns,
≤ 20 rows, printable ASCII only (custom art may use a validated UTF-8 subset),
and rejects ESC/control bytes. Selection avoids repeating the previous banner
(last id stored in the state dir). At least 60 original compositions across the
categories in the brief; each is hand-written and reviewed for originality and
technical accuracy. Custom art loaded from `~/.config/unpackr/artvault/custom/`.
`art list|show|categories|favourite|favourites` subcommands.

## 12. Reporting

All renderers consume `models.Report` only. Terminal output is grouped by the
investigation stages with evidence shown under `-v`. HTML is a single
self-contained file (inline CSS/JS, no external requests, print stylesheet).
JSON carries a `schema_version`. Markdown and CSV (IOCs, batch summary) are
derived from the same model. No ANSI or banner content ever reaches a file
report.

## 13. Testing strategy

- Unit tests per module with table-driven cases.
- Fixtures are generated at test time where possible (small synthetic PE/ELF/
  Mach-O writers in `tests/fixtures`), plus a few tiny harmless real binaries
  (e.g. a hello-world compiled with Go, a UPX-packed copy). No malware in the
  repository.
- Malformed-input corpus: truncated, bad offsets, overlapping sections, huge
  counts, wrong extension, Unicode names.
- Native Go fuzz targets for each parser, ensuring no panic/hang.
- Golden-file tests for JSON/Markdown output; CLI tests via the built binary
  (flag combos, exit codes, banner suppression when piped).
- Property tests: sample unchanged after analysis; no sample execution;
  analysis works with network disabled and with every optional tool missing.
- Benchmarks: startup, hashing, PE/ELF parse, strings, entropy, full analysis,
  batch.
- Detector reliability: each packer/compiler signature ships with positive and
  negative fixtures; documentation lists only detectors that have them.

## 14. Packaging

`make build|test|lint|package|install|uninstall|clean`. Cross-compile amd64 and
arm64 with `CGO_ENABLED=0`. `.deb` assembled with `dpkg-deb` (or `nfpm`):
`/usr/bin/unpackr`, `/usr/share/doc/unpackr/`, gzipped man page generated from
cobra, bash/zsh/fish completions in the standard system directories. Package
declares `Suggests:` for upx, ghidra, and similar tools; no maintainer scripts
touching unrelated settings. `install.sh` detects architecture and verifies
SHA256SUMS before installing. Installation on clean Kali and Ubuntu will be
verified in containers in CI.

## 15. Risks

| Risk | Mitigation |
|---|---|
| Go stdlib parsers reject malformed PEs | Own tolerant reader for PE; fuzzing |
| False positives in packer/compiler detection | Multi-signal scoring, confidence + rationale, negative fixtures |
| Fuzzy-hash/similarity misleading | Documented algorithm, per-component scores, thresholds on data volume |
| Scope size | Vertical delivery order below; unfinished features are absent from `--help`, not stubbed |
| Untrusted archive parsing | Limits, fuzzing, path guard |
| ARM64 testing | QEMU in CI |
| Pure-Go SQLite size/perf | Acceptable; DB is optional |

## 16. Delivery plan

Each milestone leaves the tool usable, ends with tests, a security and
performance review, and doc updates.

1. **Foundation** — module, cobra CLI and flag rules, config, logging, ArtVault
   (60 banners) and startup behaviour, identification, hashing, `doctor`,
   `--version`, CLI tests.
2. **Parsing** — PE, ELF, Mach-O models; sections, imports, exports,
   resources; fuzz targets.
3. **Identification** — language/compiler/runtime, packing, entropy, strings.
4. **Intelligence** — capabilities, API correlation, indicators, ATT&CK,
   anomalies, findings.
5. **Reporting** — terminal, JSON, HTML, Markdown; batch mode. (Pulled early
   so the first release is usable: `unpackr -i`, `-d`, `-v`, `-o report.html`,
   `-q dir/`, `doctor`.)
6. **Unpack/extract** — UPX, PyInstaller, archives, re-analysis, compare.
7. **Reverse-engineering adapters** — Ghidra, ILSpy, FLOSS, pyc tools.
8. **Investigation** — SQLite, similarity, YARA assistant, cases, timeline.
9. **Interactive** — `inspect` TUI.
10. **Release** — .deb for amd64/arm64, completions, man page, install script,
    clean Kali/Ubuntu test, security review.

## 17. Open questions for review

1. **Rule format:** one declarative YAML format for packer, compiler and
   capability rules (proposed), or separate formats per engine?
2. **Mach-O depth:** header, load commands and imports only for the first
   release (proposed), with signing metadata later?
3. **Fuzzy hashing:** ship our own documented CTPH implementation (proposed),
   or defer fuzzy hashing until after the first release?
4. **Release order:** is reporting before unpacking (as above) acceptable
   given the first-release acceptance list?
5. **Licence for UNPACKR itself** (MIT, Apache-2.0, GPL-3.0)? Affects what we
   may bundle.
