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
- MD5 / SHA-1 / SHA-256, with a before-and-after integrity check on the input
- Format identification runs in a separate worker process that confines itself
  with Landlock, seccomp-bpf, `no_new_privs` and resource limits; `unpackr doctor`
  shows what the current kernel provides and proves it by trying forbidden actions
- JSON reports, batch analysis of directories with bounded concurrency
- ArtVault startup banners (16 so far) with custom artwork support
- Findings carry a class (observation / inference / hypothesis), an ordinal
  confidence with its reason, and references to evidence

Every report lists the analysis stages this build does **not** perform
(PE resources/TLS/relocations/Authenticode, Mach-O code signature, language/compiler identification, packing assessment,
strings, capabilities, indicators, anomalies), so a missing stage cannot be
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
