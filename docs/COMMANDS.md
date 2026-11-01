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
| `-d` | `--deep` | **not implemented** | Exit 4 |
| `-u` | `--unpack` | works for UPX | Unpacks UPX-packed files with `upx -d` in a sandbox, validates, analyses and compares the result. Needs `upx` installed. Output goes to `<output-dir>/artifacts/` (default `./unpackr-out/artifacts/`) as `<sha256>.bin`, mode 0600. Other packers report `not-applicable` |
| `-x` | `--extract` | works for PyInstaller | Extracts the bundle into `<output-dir>/artifacts/pyinstaller-<sha256 prefix>/` (default `./unpackr-out/`). Other files report `not-applicable` |
| `-r` | `--reverse` | **not implemented** | Exit 4 |
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

- Only PyInstaller bundles are extracted. UNPACKR does not extract arbitrary
  archives, resources or installers yet.
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

- Location: `$XDG_DATA_HOME/unpackr/db.sqlite` (default `~/.local/share/unpackr/`),
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
