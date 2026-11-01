# Command reference

This document describes what the **current build** does. Anything not listed as
working is refused with exit code 4 rather than silently ignored.

## Synopsis

```
unpackr [flags] <file|directory>...
unpackr doctor
unpackr art list | show <id> | categories | favourite <id> | favourites
unpackr db path | stats | find <value> [--kind K] | forget <sha256>
unpackr case new|list|add|note|search|timeline|close|reopen|report
unpackr similar <file|sha256-prefix> [--limit N] [-v]
unpackr inspect <file | report.json>
unpackr yara suggest <file> [--against DIR]... [-o rule.yar] | test <rule.yar> [--sample F] [--against DIR]...
unpackr completion bash|zsh|fish
unpackr --version
```

A path may appear before or after flags. A file literally named `doctor`,
`art` or `completion` must be written `./doctor`.

## Flags

| Short | Long | Status | Meaning |
|---|---|---|---|
| `-i` | `--info` | works | Identification, hashes, executable structure. The default when only a path is given |
| `-q` | `--quick` | works | Skips ssdeep, TLSH and the string sketch (listed under `not_run` so an empty hash is never read as "unique"); accepts directories and prints a table |
| `-v` | `--verbose` | works | Show check-level evidence with file offsets, header attributes, every imported/exported symbol, module timings, sandbox detail |
| `-o` | `--output FILE` | works | Write a report; format inferred from `.json`, `.html`, `.md`, `.csv` |
| | `--format` | `terminal`, `json`, `html`, `markdown`, `csv` | Non-terminal formats write only the document to stdout (no banner or progress). `csv` is the indicator list for one file and the summary table for several |
| | `--output-dir DIR` | works | Batch: one `<sha256>.json` per sample |
| | `--modules` | `identification`, `structure`, `analysis` | Run only the named modules (identification always runs). `analysis` covers entropy, strings, indicators, fingerprint and packing |
| | `--threads N` | works | Concurrent analyses in batch mode |
| | `--timeout D` | works | Per-worker time limit, e.g. `90s` |
| | `--config FILE` | works | YAML configuration |
| | `--no-db` | works | Do not read or write the local sample database |
| | `--require-sandbox` | works | Fail instead of analysing with reduced confinement |
| | `--offline` | accepted | Always true; the build has no network code |
| | `--no-banner`, `--banner SEL`, `--quiet`, `--no-color` | works | Presentation |
| `-d` | `--deep` | works for x86/x86-64 | Everything `-i` does, plus a bounded linear disassembly of the executable sections that looks for three obfuscation idioms: PEB module walking, the ror-13 API-name hash loop and control-flow-flattening dispatchers. Other architectures are listed under `not_run` as skipped. See `docs/OBFUSCATION.md` |
| `-u` | `--unpack` | works for UPX | Unpacks UPX-packed files with `upx -d` in a sandbox, validates, analyses and compares the result. Needs `upx` installed. Output goes to `<output-dir>/artifacts/` (default `./unpackr-out/artifacts/`) as `<sha256>.bin`, mode 0600. Other packers report `not-applicable` |
| `-x` | `--extract` | works for PyInstaller and for ZIP/RAR/7z/CAB archives appended to an executable | Extracts into `<output-dir>/artifacts/pyinstaller-<sha256 prefix>/` or `.../overlay-<sha256 prefix>/` (default `./unpackr-out/`). Other files report `not-applicable` |
| `-r` | `--reverse` | works for ELF and PE with radare2 | Asks radare2 (inside the sandbox) which functions reference the imported APIs behind each reported capability, how many functions it finds and which is largest. Without radare2 the run succeeds and `not_run` says so. See the `-r` section below |
| `-c` | `--compare` | works | Exactly two files; shows header, section, import, export, entropy, packing, fingerprint, capability, indicator and string differences. `--format json` / `-o x.json` give the structured comparison |
| `-h` | `--help` | works | |

## Combination rules

- `-i`, `-q` and `-c` are mutually exclusive. With none of them a path implies `-i`.
- `-q` and `-d` contradict each other.
- `-c` takes exactly two paths and combines only with `-v`, `-o` and `--format`.
- A report is never written over its input file.
- Usage errors (exit 2) are detected before "not implemented" (exit 4).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | An input could not be analysed (missing, unreadable, too large, worker failed) |
| 2 | Usage error |
| 4 | Valid request that this build does not implement |

## Banner

Shown on stderr only when stderr is a terminal and neither `--no-banner`,
`--quiet` nor JSON-to-stdout is in effect. `--banner` accepts `random`, an id
such as `003`, a category such as `humour`, or `off`. The previously shown
banner is not repeated when an alternative exists. Custom artwork goes in
`~/.config/unpackr/artvault/custom/*.txt`; files are validated (80x24, printable
ASCII, no control bytes) and invalid ones are ignored with a warning in
`unpackr art list`.

Colour is added when the banner is printed, never stored in the artwork files.
It follows the terminal: 24-bit colour when `COLORTERM` says `truecolor`, the
256-colour palette when `TERM` ends in `256color`, otherwise the 16 ANSI
colours, and none for `NO_COLOR`, `--no-color` or a pipe. Each banner has a
`style` in its front matter (`fire`, `ice`, `matrix`, `sunset`, `toxic`,
`gold`, `plasma`, `ocean`, `rainbow`, `cyan`); banners without one use their
category's style, and custom artwork stays plain cyan unless it names a style.
Try one with `unpackr art show 064 --style matrix`.

## Configuration

`~/.config/unpackr/config.yaml`; unknown keys are errors.

```yaml
threads: 4            # batch concurrency
timeout_seconds: 120  # per worker
max_file_size_mb: 2048
worker_memory_mb: 4096
require_sandbox: false
max_batch_files: 100000
banner: random
```

## Unpacking policy

- Only UPX is supported. A file indicating any other packer reports
  `not-applicable` with the packer named; UNPACKR is not a generic unpacker.
- The external tool never runs unconfined: if Landlock and seccomp cannot be
  fully applied, UPX is not started and the attempt is reported as
  `unavailable`.
- The tool receives a copy of the sample in a private 0700 directory, which is
  deleted afterwards. The original is never opened for writing.
- Output limits: `unpack_max_mb` (default 1024), `unpack_max_ratio` (default
  200x, a decompression-bomb guard), `max_unpack_depth` (default 3).
- A failed or rejected unpack leaves no file behind and does not affect the rest
  of the report.

## Extraction policy

- PyInstaller bundles are extracted by a native reader. A ZIP, RAR, 7z or CAB
  archive that starts within the first 64 KiB of an executable's overlay (a
  dropper's payload, a self-extractor's data) is extracted with a native 7-Zip
  (`7zz`, or `7z` when it is the real executable; Debian's `/usr/bin/7z` is a
  shell wrapper and is skipped in favour of `/usr/lib/7zip/7z`). UNPACKR does
  not extract other archives, resources or installers yet.
- 7-Zip runs in the same confinement as UPX (Landlock, seccomp, no network,
  memory and time limits), on a copy of only the archive bytes. It lists the
  archive first and refuses it when the listed file count or total size passes
  `extract_max_entries` / `extract_max_mb`. The parent then rejects links and
  special files, resets modes to 0600, and hashes every file itself.
- Encrypted archives are reported, never guessed. If 7-Zip cannot extract some
  entries (for example an unsupported RAR method) the rest are kept and the
  failed ones are listed as skipped. The archive comment, where a WinRAR
  self-extractor keeps its command script, is shown as a note.
- The reader runs in a sandboxed worker whose only writable location is one
  private directory. The parent then re-verifies every file before storing it.
- Entry names containing `..` or absolute paths are skipped with a reason, not
  rewritten. Other characters in names are replaced by `_` in file names (the
  original name is kept in the report).
- Limits: `extract_max_mb` (default 1024, total), `extract_max_entries`
  (default 20000); per-entry size 256 MiB and expansion ratio 1000x are fixed.
- Extracted files are mode 0600 and are never executed or loaded.
- Python bytecode is saved with a `.pyc` header for the bundle's Python version
  (3.6 to 3.13). Decompiling it needs an external tool, which UNPACKR does not
  run yet.

## Report formats

| Format | Content |
|---|---|
| `json` | The complete structured report (`schema_version`); raw values |
| `html` | Self-contained page: summary, file and hashes, fingerprint, packing, structure, capabilities, anomalies, indicators, payloads, findings, evidence, recommendations, limits. No script or external resource |
| `markdown` | The same sections as GitHub-flavoured Markdown |
| `csv` | One file: the indicator list (raw value, defanged value, offset, section). Several files: a summary table |

HTML, Markdown and terminal output defang network indicators and sanitise every
string taken from the sample. JSON and the CSV `value` column keep raw values
for tooling; CSV cells beginning with `=`, `+`, `-`, `@`, tab or CR are prefixed
with an apostrophe so spreadsheets do not execute them.

## Local database and cases

- Location: `$XDG_DATA_HOME/unpackr/db.json` (default `~/.local/share/unpackr/`),
  directory 0700, file 0600. Config: `use_database` (default true) and
  `database_path`.
- Stores, per SHA-256: hashes, size, last file name, first/last seen, up to 20
  stored reports (gzip), pivot values (indicators, hosts, import hash, section
  layout, tested YARA rules, capabilities, ATT&CK ids) and links to unpacked
  layers. It never stores sample bytes. Reports contain absolute paths of the
  files as analysed.
- A database problem is a warning, never a failed analysis.
- `db find <value> --kind K`: `ioc` (any indicator or host, default), `hash`
  (SHA-256 prefix), `imphash`, `section-layout`, `yara`, `capability`,
  `attack`, `packer`, `language`, `host`, or `indicator:<type>`.
- `case add` accepts a file (analysed first) or a SHA-256 prefix (at least 6 hex
  characters, unambiguous). Case names: 1-64 characters from letters, digits,
  `.`, `_`, `-`.
- `case report <case> [-o file]`: markdown by default; `.html`, `.csv`, `.json`
  by extension or `--format`.

## inspect

`unpackr inspect <file | report.json>` opens an interactive view with six tabs
(Summary, Findings, Evidence, Indicators, Capabilities, Structure). Keys: tab or
1-6 switch tabs, up/down/pgup/pgdn/g/G move, `/` searches the current tab, `e`
opens the evidence a finding or capability cites, `f` opens the findings that
cite an evidence row, esc clears a search or filter, `?` help, `q` quit.

- The argument is a file to analyse (same analysis as `-i`, recorded in the local
  database like any other run) or a JSON report saved with `-o report.json`.
- It needs an interactive terminal. Otherwise it exits with a usage error and
  points to `-o`/`--format`.
- The viewer is a separate executable, `unpackr-inspect`, installed next to
  `unpackr` and started by it. The terminal UI library probes the terminal for
  its background colour when it is linked into a program, so keeping it out of
  the main binary means ordinary runs and `--version` never emit those queries.
  The helper is found beside the running executable only, never on `PATH`.
  It receives one already-sanitised report over an inherited pipe and opens no
  files. Control and escape bytes in sample text are shown as visible escapes.
- On a terminal that does not answer the colour query, starting `inspect` can
  pause for a few seconds; this comes from the UI library's start-up probe and
  only affects this command.

## yara

`unpackr yara suggest <file>` analyses the file and drafts a candidate rule, then
tests it. `unpackr yara test <rule.yar>` tests any rule.

**What goes into a draft**, best first: strings recovered from an encoded form
(written with YARA's `xor` modifier, which matches them under any single-byte
key), indicators (URLs, domains, public IPs, registry persistence paths,
commands), and long unusual strings. Strings that look like compiler, runtime or
system boilerplate are left out and listed with the reason (`-v` shows all). If
there is anything specific, only specific features are used: padding a rule with
ordinary strings made an earlier version match clean files built with the same
compiler. With nothing specific the draft needs at least three ordinary strings,
otherwise nothing is written ("No rule drafted"). A PE or ELF header check and a
size limit (twice the sample's size, rounded up) are added. `--imphash` adds a
PE import-hash alternative and warns that it is broad. The rule is marked
`status = "experimental"`; it is never loaded as a built-in rule, and rules you
load yourself are shown in reports but never counted as evidence.

**What is tested** (by YARA-X inside the sandbox): that the rule compiles; that it
matches the sample; and, with `--against DIR` (repeatable), how many files in a
directory of known-clean files it also matches. Control files are read in place,
read-only, and never copied or run. A rule that matches clean files, misses its
own sample, or fails to compile exits non-zero. Without `--against` the output
says the false-positive risk is unknown. Passing a clean-file test lowers that
risk; it does not remove it.

**Limits.** Strings come from the first 3,000 extracted strings plus all
indicators and recovered strings. ADD-encoded and multi-byte-key strings cannot be
written as YARA modifiers and are listed as left out. A rule built from a
packed sample describes the packer, so unpack first (`-u`). Without `yr` installed
the rule is drafted but reported as not compiled or tested. `-o` never overwrites
an existing file.

## -r (reverse)

`-r` runs radare2 5.5.0 or later against ELF and PE files and adds a "Reverse
engineering" block: the number of functions it discovers, the function containing
the entry point, the largest functions, and **where each imported API is
referenced** (`call`, `jump` or `data`, with the containing function and address).
That answers what the import table cannot: whether and from where an API is used.
Each reference becomes evidence and a finding, and the capability that rests on the
API gets a note ("radare2: CreateProcessA is called from main").

* Which APIs: those behind a reported capability, most serious first, at most 40.
* Addresses are virtual addresses in radare2's view, not file offsets.
* Findings are observations at medium confidence at most. A reference is found by
  static analysis; it may be in code that never runs, and function discovery in
  packed or obfuscated code is unreliable.
* radare2 runs in the same exec sandbox as the other tools (no network, one
  writable scratch directory, Landlock, seccomp). The script is fixed; only API
  names from the file's import table are placed in it, and only if they match
  `[A-Za-z0-9_.$]` (PE library names `[A-Za-z0-9_.-]`). Others are skipped and
  counted. radare2's own sandbox setting is also on, but it is a second line only:
  testing showed it blocks a leading `!`, pipes and file writes, and does **not**
  stop a `!` inside backticks.
* Section breaks in radare2's output are random per-run tokens, because the output
  contains names taken from the hostile file.
* Not supported: Mach-O (not verified), Rizin (command-compatible but not tested),
  versions other than 5.5.0 (the output formats were checked only on 5.5.0), files
  over 64 MiB, and import names with other characters (C++ and MSVC mangled names).
  Ghidra, capa, FLOSS and ILSpy adapters do not exist.
* `-d` and `-r` can be combined.
