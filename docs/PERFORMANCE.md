# Performance and size

Measured on a 4-core x86-64 container, Go 1.26, `make build` (stripped, trimpath).
Run `make bench` to reproduce the benchmarks.

## Speed

| Input | Before tuning | Now |
|---|---|---|
| 14 MB Go executable (`unpackr` itself), full profile | 1.83 s | 0.83 s |
| `-q` quick profile, same file | 1.83 s | about 0.55 s (no fuzzy hashing) |
| 2.4 MB Go executable, analysis core only (`BenchmarkAnalyzeBytes`) | | 123 ms (19 MB/s); quick 84 ms |
| Encoded-string search (`BenchmarkFind16MB`) | | about 4 ms per MB |
| Startup (`--version`) | | 6 ms |

What dominates now (profile of the 14 MB file): TLSH about 25%, indicator regexes
about 20%, ssdeep about 18% (runs concurrently with TLSH). The remaining
indicator cost is regexp matching on strings that really do contain a dot, URL
or path; each pattern is skipped unless a literal it requires is present, and
`TestGuardsAreNecessary` checks that a skipped pattern could never have matched.

Peak memory is about 22 MB for a 2 MB scan; inputs are read once and capped at
256 MiB for parsing and 64 MiB for the encoded-string stage.

## Binary size

14.6 MB stripped; the amd64 `.deb` is 4.5 MB compressed.

| Part | Size | Notes |
|---|---|---|
| code (`.text`) | 7.0 MB | SQLite (pure Go) is about 2.6 MB of this |
| Go function tables (`.gopclntab`) | 5.0 MB | scales with code size |
| read-only data | 1.7 MB | rules, banners, tables |

Findings: nothing large is avoidable without removing a feature. SQLite is the
biggest single piece; replacing it with the system library would need cgo and
break the pure-Go static build and the sandbox model. `html/template` is about
70 KB and `crypto/x509` about 107 KB (pulled in by the PE parser for
Authenticode). Compressing the executable with a packer was rejected: a malware
analysis tool should not look like packed software.
