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
