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

11.0 MB stripped (it was 15.3 MB while the sample database used SQLite); xz-compressed it is 3.2 MB (4.7 MB before), plus 1.1 MB for the viewer.

| Part | Size | Notes |
|---|---|---|
| code (`.text`) | 7.0 MB |  |
| Go function tables (`.gopclntab`) | 5.0 MB | scales with code size |
| read-only data | 1.7 MB | rules, banners, tables |

Findings: nothing large is avoidable without removing a feature. SQLite is the
biggest single piece; replacing it with the system library would need cgo and
break the pure-Go static build and the sandbox model. `html/template` is about
70 KB and `crypto/x509` about 107 KB (pulled in by the PE parser for
Authenticode). Compressing the executable with a packer was rejected: a malware
analysis tool should not look like packed software.

### Why the sample database is not SQLite

SQLite (pure Go, `modernc.org/sqlite`) alone added about 4.4 MB to the
executable; a Go program that only opens it is already 6.4 MB. The database is
small and single-user, so it is now a JSON index (`db.json`) plus one gzip file
per stored report (`db.json.reports/<sha256>/<n>.json.gz`). Writes go to a
temporary file that is synced and renamed over the old one, and a lock file
(`flock`, released by the kernel if a process dies) makes concurrent runs take
turns: eight parallel analyses were checked to all be recorded. The index is
read whole on open, so it suits thousands of samples, not millions. An older
`db.sqlite` is not read; point `database_path` at it only to find it again.
