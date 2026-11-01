# UNPACKR

**Know What's Inside.**

[![CI](https://github.com/Yanliangchan/unpackr/actions/workflows/ci.yml/badge.svg)](https://github.com/Yanliangchan/unpackr/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

UNPACKR is an offline command-line tool for the static analysis of
executables. Point it at a PE, ELF or Mach-O file and it tells you what the file
is, how it was built, whether it is packed or obfuscated, what it appears
capable of, and exactly which evidence supports each statement. It is written in
Go, ships as one static binary and **never executes a sample**.

```
$ unpackr -i sample.exe -x

   0000: 4d5a 9000 0300 0000 0400 0000       Know what's inside.
   ...
UNPACKR 0.1.0  |  linux/amd64  |  offline  |  ArtVault #068

File identification
  Format     PE32  [observation, confidence: high]
Executable structure
  Entry      RVA 0x1ea80  in .text
  Imports: 240 symbols from 10 libraries
Extraction
  Status     extracted
             7-Zip 23.01 extracted 2 file(s) from the RAR archive at offset 488960
```

> **Status: early development.** Everything listed below works and is tested.
> Anything that does not exist yet is refused with a clear message rather than
> approximated, and every report lists the analysis stages that were not run, so
> a missing stage can never be mistaken for a clean result.

## Why it is built the way it is

Malware analysis tools tend to make confident statements they cannot back up.
UNPACKR is designed around the opposite rule:

- **Observations are separated from inferences.** Every finding is classed as an
  observation, an inference or a hypothesis, carries a confidence level with its
  reason, and points at the evidence behind it.
- **An imported API is not behaviour.** Capability wording is always
  "references X, consistent with Y", and tests enforce it.
- **Entropy alone never decides.** A packed verdict needs independent signals.
  Only a validated unpack of the file can raise the verdict to *definitive*.
- **Input is hostile.** Parsing and external tools run in separate worker
  processes that confine themselves with Landlock, seccomp-bpf, `no_new_privs`
  and resource limits before touching the file. If confinement cannot be
  established, the tool is not run.
- **Nothing is trusted on the way out.** Every string from a sample goes through
  a sanitiser (control bytes, escape sequences, bidirectional overrides), and
  network-looking text is defanged (`hxxp://`, `[.]`).

## Features

### Identification and structure
- Content-based format identification (PE/PE+, ELF, Mach-O and universal
  binaries, Java class/JAR, ZIP and several container and script types), showing
  the structural checks that justify each result.
- Headers, sections and segments with permissions, entry point mapped to a
  section and file offset, imports, exports, linked libraries, overlay, import
  hash, and the parser's own list of structural anomalies. ELF files with missing
  or damaged section headers still parse. The parsers are checked against
  pefile and LIEF (`tests/differential/diff.py`).
- .NET metadata (ECMA-335): assembly name and version, assembly references,
  type and method counts, P/Invoke declarations, manifest resources and name
  statistics. It reads names and references; it does not decode IL or
  decompile.

### Analysis
- Shannon entropy per section, ASCII and UTF-16 strings with offsets, and
  indicators (URLs, IPs, domains, emails, paths, registry keys, command lines)
  with false-positive filters tuned on real binaries.
- Build fingerprint: language, compiler and runtime as ranked hypotheses with
  the signals behind each (Go, Rust, .NET, MSVC, GCC/Clang/MinGW, Delphi, VB6,
  PyInstaller, Nuitka, Swift, Objective-C).
- Packing assessment (`unpacked`, `likely-packed`, `confirmed-packed`,
  `unknown`, `obfuscated`) from independent signals.
- Capability inference with ATT&CK mapping, API relationship chains and an
  explicit evidence class (`imported`, `string-referenced`, `structural`).
- Obfuscation detection: hidden strings recovered from single-byte XOR/ADD
  encodings without knowing the key, stack-built strings, and embedded base64
  executables. With `-d`, a bounded disassembly pass looks for PEB module
  walking, API-name hash loops and control-flow flattening (x86 and x86-64).
- Hostile-structure checks for files built to break parsers (flooded export
  tables, unreadable import directories, data directories outside the image).
- With `-r`, radare2 runs inside the sandbox to say which functions call the
  APIs behind each reported capability.

### Unpacking and extraction
- `-u` unpacks UPX. The output is validated (regular file, size and expansion
  limits, parses as the same kind of executable, entry point maps) before it is
  trusted, then analysed like any sample and compared with the packed file.
- `-x` extracts PyInstaller bundles with a native reader (scripts and modules
  are saved as `.pyc` with a correct header) and ZIP, RAR, 7z or CAB archives
  appended to an executable (with a sandboxed 7-Zip). Entries are re-verified by
  hash in the parent process, links are rejected, extracted files are mode 0600,
  and encrypted archives are reported, never guessed.
- Nothing extracted or unpacked is ever run.

### Reports, memory and workflow
- Reports as terminal text, JSON, Markdown, CSV and a single self-contained HTML
  file (no script, no external resource, strict content-security policy, dark
  mode, print stylesheet, anchors from each finding to its evidence).
- A local sample memory (a JSON index plus compressed reports, pure Go, no
  server) keyed by SHA-256. It stores hashes, reports and notes, **never
  samples**, and tells you when you have seen a file before and what changed.
- Cases (`unpackr case ...`) group samples, searchable notes and an automatic
  timeline, with a report of the indicators shared across samples.
- Similarity with ssdeep and TLSH (checked byte-for-byte against the reference
  implementations) plus a documented structural overlap. Always shown as a
  measurement, never as a probability or an attribution.
- `unpackr inspect` is an interactive terminal browser for a report.
- `unpackr yara` drafts a YARA rule from a sample and tests it against files you
  choose (rules are tested, not just generated).
- Batch analysis of directories with bounded concurrency, and a before-and-after
  integrity check on every input.

### ArtVault
Every run opens with a banner from the ArtVault: 85 original ASCII pieces in
eight categories, from stack-frame diagrams to a cow that reads assembly,
coloured with gradients that match your terminal's colour depth. Browse them
with `unpackr art list`, try a style with `unpackr art show 064 --style matrix`,
or drop your own into `~/.config/unpackr/artvault/custom/`.

## Install

Requires Go 1.26 to build from source (the module pins it, and the Go toolchain
fetches it on demand).

```bash
git clone https://github.com/Yanliangchan/unpackr.git
cd unpackr
make build          # bin/unpackr and bin/unpackr-inspect
sudo make install   # to /usr/local/bin
```

Debian/Ubuntu/Kali packages for amd64 and arm64 are built with `make package`.
`install.sh` installs a package only after checking it against `SHA256SUMS`.

## Usage

```bash
unpackr sample.exe                      # full static analysis
unpackr -q ./samples/ --output-dir out  # fast triage of a directory
unpackr -i sample.exe -o report.html    # self-contained HTML report
unpackr -i -d -r sample.exe             # add disassembly and radare2 passes
unpackr -u packed.exe                   # unpack UPX, validate, re-analyse
unpackr -x dropper.exe                  # extract embedded content
unpackr -c a.exe b.exe                  # compare two files
unpackr inspect sample.exe              # interactive browser
unpackr doctor                          # what this system can and cannot do
```

`unpackr doctor` shows which confinement the running kernel provides and proves
it by attempting forbidden actions. See [docs/COMMANDS.md](docs/COMMANDS.md) for
every flag, exit code and configuration option.

### Optional tools

None are required. Each one adds capability when present, and the report says
when a stage was skipped because its tool is missing.

| Tool | Used by |
|---|---|
| `upx` | `-u`, unpacking UPX |
| 7-Zip (`7zz`, or the real `7z` executable) | `-x`, archives appended to an executable |
| `radare2` | `-r`, call sites of imported APIs |

## What it does not do

- It does not run, emulate or detonate anything. It is not a sandbox for
  behaviour.
- It does not name malware families or attribute samples. Similarity is a
  distance, not an identification.
- UPX is the only packer it unpacks, and PyInstaller plus ZIP/RAR/7z/CAB
  overlays are the only containers it extracts.
- It was developed mostly against Windows and Linux x86 and x86-64 samples. The
  radare2 integration has been verified on one version (5.5.0). Mach-O support
  covers parsing, not deep analysis.

## Project layout

```
cmd/unpackr            the command-line tool
cmd/unpackr-inspect    the interactive viewer (a separate executable on purpose)
internal/              identification, formats, analysis, sandboxed workers, reports
pkg/models             the report data model
assets/                rules and ArtVault banners (embedded in the binary)
tests/                 unit, integration, differential and fixture helpers
docs/                  design, command reference, verification evidence
```

## Documentation

- [Command reference](docs/COMMANDS.md)
- [Architecture and design decisions](docs/ARCHITECTURE.md)
- [Verification: the evidence behind each technology choice](docs/VERIFICATION.md)
- [Obfuscation detection](docs/OBFUSCATION.md), [.NET support](docs/DOTNET.md),
  [similarity](docs/SIMILARITY.md), [performance and size](docs/PERFORMANCE.md)
- [Third-party components](docs/THIRD-PARTY.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE).
