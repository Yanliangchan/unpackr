# UNPACKR

*Know What's Inside.*

UNPACKR is an offline, evidence-driven toolkit for static analysis of
executables on Linux. Samples are never executed.

> **Status: early development.** What works today is listed below. Everything
> else is refused with a clear message rather than approximated.

## What works now

- Content-based format identification (PE/PE+, ELF, Mach-O and universal
  binaries, Java class/JAR, ZIP, several container and script types) with the
  structural checks and offsets that justify each result
- Executable structure for PE/PE+, ELF (including files with missing or damaged section headers) and Mach-O (thin and universal): headers, sections and segments with permissions, entry point mapped to section and file offset, imports, exports, linked libraries, overlay, pefile-compatible import hash, and the parser's own list of structural anomalies. Parsers run inside the sandboxed worker and are checked against pefile and LIEF (`tests/differential/diff.py`)
- Shannon entropy per section and overlay; ASCII and UTF-16 string extraction with offsets; indicator-shaped strings (URLs, IPv4, domains, emails, Windows/Unix paths, registry keys, command lines) with false-positive filters tuned on real binaries
- Build fingerprint: language, compiler and runtime as ranked hypotheses with the signals behind each (Go, Rust, .NET, MSVC, GCC/Clang/MinGW, Delphi, VB6, PyInstaller/Nuitka, Swift/Objective-C). C and C++ stay listed as alternatives because compiled binaries cannot reliably be told apart
- Packing assessment (`unpacked` / `likely-packed` / `confirmed-packed` / `unknown`) from independent signals: UPX and other packer signatures, default section names, entry-point placement, empty executable sections, sparse imports, .NET protector markers. Entropy alone can never produce a packed verdict (tested)
- Capability inference (40 rules across network, process creation, injection, persistence, credential access, collection, encryption, anti-debugging/VM, discovery) with ATT&CK mapping, API relationship chains and an explicit evidence class (`imported` / `string-referenced` / `structural`). Wording is always "references X, consistent with Y": an imported API is never presented as behaviour, and tests enforce that
- Structural anomaly catalogue (PE, ELF, Mach-O): each entry states the fact, why it is notable and where it is common and harmless; tuned so ordinary toolchain output raises nothing above informational
- `-u` unpacks UPX-packed files and `-c` compares two files. UPX runs only inside a confined exec worker (Landlock + seccomp: it can read its private copy of the input, write to its private work directory, start nothing else, and use no network); the output is validated (regular file, size and expansion-ratio limits, parses as the same kind of executable, entry point maps) before it is trusted, stored under a content-derived name with mode 0600, analysed like any sample, and compared with the packed file. Only a validated unpack raises the packing verdict to `definitive`. UPX is the only packer supported; nothing else is unpacked
- `-x` extracts PyInstaller bundles with a native reader (checked against a real PyInstaller 6 build): Python version, every entry with its file offset, size, content type and SHA-256, scripts and modules saved as `.pyc` with a correct header for the bundled Python version so bytecode tools accept them. The reader runs in a sandboxed worker that can write only one private directory; names with `..` or absolute paths are skipped (never rewritten), decompression bombs and lying length fields are rejected per entry, and the parent re-verifies every produced file (type, mode, size, hash, no symlinks, no extras) before moving it into `<output-dir>/artifacts/pyinstaller-<sha256 prefix>/`. Extracted files are mode 0600 and never run. Other containers are not extracted
- Reports: `-o report.html|.md|.csv|.json` (or `--format html|markdown|csv|json` to stdout). The HTML report is one self-contained file: no script, no external resource, a strict content-security policy, dark mode and a print stylesheet, and anchors from every finding to its evidence. It opens with an executive summary derived only from what the analysis established, and states its limits (not executed, confidence is not probability, stages not run). Every string in a report passes through a sanitiser (control and escape bytes, bidirectional overrides) and network-looking text is defanged (`hxxp://`, `[.]`) so nothing can be clicked or resolved by accident; CSV cells that could be read as spreadsheet formulas are neutralised. Batch (`-q dir -o x.html`) gives a summary table; `-c a b -o x.html` a comparison
- A local sample memory (SQLite, pure Go, no server; `~/.local/share/unpackr/db.sqlite`, mode 0600) keyed by SHA-256. It stores hashes, reports and notes, **never the samples**. A file seen before is recognised by content, not name, with the date, the cases it is in, and what changed since the last analysis (including when only the UNPACKR version changed). Unpacked layers are linked to their parent. `unpackr db find <value>` pivots on indicators, hosts, import hashes, rules, capabilities or ATT&CK ids; `db forget` deletes a sample. `--no-db` or `use_database: false` turns it off
- Cases: `unpackr case new|add|note|search|timeline|close|reopen|report`. A case groups samples, analyst notes (full-text searchable) and an automatic timeline, and its report shows the indicators and hosts shared across samples (HTML, Markdown, CSV, JSON, defanged)
- MD5 / SHA-1 / SHA-256, with a before-and-after integrity check on the input
- Format identification runs in a separate worker process that confines itself
  with Landlock, seccomp-bpf, `no_new_privs` and resource limits; `unpackr doctor`
  shows what the current kernel provides and proves it by trying forbidden actions
- JSON reports, batch analysis of directories with bounded concurrency
- ArtVault startup banners (16 so far) with custom artwork support
- Findings carry a class (observation / inference / hypothesis), an ordinal
  confidence with its reason, and references to evidence

Every report lists the analysis stages this build does **not** perform
(PE resources/relocations/debug directory/Authenticode validation, Mach-O code signature, .NET metadata, disassembly-backed capability analysis), so a missing stage cannot be
mistaken for a clean result.

## Build

Requires Go 1.26 (the module pins it; the Go toolchain downloads it on demand).

```bash
make build      # bin/unpackr
make test
```

```bash
./bin/unpackr -i sample.bin
./bin/unpackr -q ./samples/ --output-dir ./results/
./bin/unpackr doctor
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for every flag and its status,
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, and
[docs/VERIFICATION.md](docs/VERIFICATION.md) for the evidence behind the
technology choices.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
