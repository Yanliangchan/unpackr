# Command reference

This document describes what the **current build** does. Anything not listed as
working is refused with exit code 4 rather than silently ignored.

## Synopsis

```
unpackr [flags] <file|directory>...
unpackr doctor
unpackr art list | show <id> | categories | favourite <id> | favourites
unpackr completion bash|zsh|fish
unpackr --version
```

A path may appear before or after flags. A file literally named `doctor`,
`art` or `completion` must be written `./doctor`.

## Flags

| Short | Long | Status | Meaning |
|---|---|---|---|
| `-i` | `--info` | works | Identification, hashes. The default when only a path is given |
| `-q` | `--quick` | works | Same stages as `-i` today; accepts directories and prints a table |
| `-v` | `--verbose` | works | Show check-level evidence with file offsets, module timings, sandbox detail |
| `-o` | `--output FILE` | works for `.json` | Write a report; format inferred from the extension |
| | `--format` | `terminal`, `json` | `json` writes only JSON to stdout |
| | `--output-dir DIR` | works | Batch: one `<sha256>.json` per sample |
| | `--modules` | `identification` only | Select modules |
| | `--threads N` | works | Concurrent analyses in batch mode |
| | `--timeout D` | works | Per-worker time limit, e.g. `90s` |
| | `--config FILE` | works | YAML configuration |
| | `--require-sandbox` | works | Fail instead of analysing with reduced confinement |
| | `--offline` | accepted | Always true; the build has no network code |
| | `--no-banner`, `--banner SEL`, `--quiet`, `--no-color` | works | Presentation |
| `-d` | `--deep` | **not implemented** | Exit 4 |
| `-u` | `--unpack` | **not implemented** | Exit 4 |
| `-x` | `--extract` | **not implemented** | Exit 4 |
| `-r` | `--reverse` | **not implemented** | Exit 4 |
| `-c` | `--compare` | **not implemented** | Exit 4 (after argument validation) |
| | `--format html\|markdown\|csv` | **not implemented** | Exit 4 |
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
